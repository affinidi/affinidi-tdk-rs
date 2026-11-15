//! The upstream half of an agent name lookup, shared by the HTTP endpoint and
//! the WebSocket path.
//!
//! Every lookup that is not answered from memory turns one inbound request into
//! one outbound fetch from a host the caller chose. Three things bound that:
//!
//! - **Single-flight.** Concurrent lookups of the same (canonical) name share
//!   one upstream fetch, so a burst of identical requests costs one fetch and
//!   one permit, not one each.
//! - **A global ceiling** (`agent_name_concurrency`, the semaphore in
//!   [`SharedData::agent_name_permits`]). A lookup that finds every permit taken
//!   is shed (HTTP `503` with `Retry-After`), never queued.
//! - **A negative cache.** A *definitive* failure (the host answered without a
//!   redirect, the target is not a DID, the name is refused by the SSRF guard,
//!   too many hops, no resolver) is remembered for `agent_name_negative_cache_ttl`
//!   seconds, so repeating a failing name does not re-fetch it. A *transient*
//!   failure (transport error, timeout, upstream `5xx`, `408`, `429`) is
//!   remembered for at most [`TRANSIENT_FAILURE_TTL`]: long enough that
//!   hammering one failing name cannot turn this server into a steady stream of
//!   requests at that host, short enough that a blip does not become an outage
//!   for the name.
//!
//! Successes are not cached here: the name's redirect may change, and the
//! document the resulting DID resolves to is cached by the DID cache already.

use std::time::Duration;

use agent_names::{AgentName, AgentNameError, AgentNameResolver};
use http::StatusCode;
use moka::Expiry;
use tracing::{debug, warn};

use crate::{SharedData, handlers::ClientError};

/// The longest a transient upstream failure is remembered. The configured
/// negative TTL caps it, so `agent_name_negative_cache_ttl = 0` disables both.
pub const TRANSIENT_FAILURE_TTL: Duration = Duration::from_secs(5);

/// A failed lookup, as every caller of the same name is told about it.
#[derive(Debug, Clone)]
pub(crate) struct LookupFailure {
    /// The HTTP status the endpoint answers with.
    pub(crate) status: StatusCode,
    /// What the client is told. A `5xx` carries a reference; the detail was
    /// logged once, under it, when the failure happened.
    pub(crate) error: ClientError,
    /// How long the failure is remembered.
    ttl: Duration,
}

/// The outcome of one lookup.
#[derive(Debug, Clone)]
pub(crate) enum LookupOutcome {
    /// The name redirected to this DID.
    Resolved(String),
    /// The lookup failed (possibly answered from the negative cache).
    Failed(LookupFailure),
    /// Every outbound-fetch permit was taken; nothing was fetched.
    Shed,
}

/// Per-entry expiry: each failure carries its own TTL.
struct FailureExpiry;

impl Expiry<String, LookupFailure> for FailureExpiry {
    fn expire_after_create(
        &self,
        _key: &String,
        value: &LookupFailure,
        _created_at: std::time::Instant,
    ) -> Option<Duration> {
        Some(value.ttl)
    }
}

/// Negative cache and single-flight for agent name lookups.
///
/// Cheap to clone (the cache is reference counted).
#[derive(Clone)]
pub struct AgentNameLookups {
    /// Failures, keyed by canonical name. It is also the single-flight point:
    /// `try_get_with` runs one fetch per key and hands every concurrent caller
    /// its result, whether that result is cached or not.
    failures: moka::future::Cache<String, LookupFailure>,
    negative_ttl: Duration,
}

impl std::fmt::Debug for AgentNameLookups {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentNameLookups")
            .field("negative_ttl", &self.negative_ttl)
            .field("entries", &self.failures.entry_count())
            .finish()
    }
}

impl AgentNameLookups {
    /// `capacity` bounds the number of remembered failures; `negative_ttl` is
    /// how long a definitive failure is remembered (`0` caches nothing, but
    /// identical concurrent lookups are still coalesced).
    pub fn new(capacity: u64, negative_ttl: Duration) -> Self {
        Self {
            failures: moka::future::Cache::builder()
                .max_capacity(capacity)
                .expire_after(FailureExpiry)
                .build(),
            negative_ttl,
        }
    }

    /// The TTL for a failure of `kind`, or `None` to not cache it.
    fn ttl(&self, transient: bool) -> Option<Duration> {
        let ttl = if transient {
            self.negative_ttl.min(TRANSIENT_FAILURE_TTL)
        } else {
            self.negative_ttl
        };
        (!ttl.is_zero()).then_some(ttl)
    }
}

/// Is this resolver error worth retrying soon (as opposed to an answer)?
///
/// Unknown variants (the enum is `#[non_exhaustive]`) count as transient: the
/// conservative choice, since it caches for the shorter time.
fn is_transient(e: &AgentNameError) -> bool {
    let transient_status = |status: u16| status >= 500 || status == 408 || status == 429;
    match e {
        AgentNameError::InvalidName { .. }
        | AgentNameError::InsecureScheme(_)
        | AgentNameError::NotAuthorized { .. }
        | AgentNameError::NotADid { .. }
        | AgentNameError::TooManyRedirects { .. }
        | AgentNameError::ResponseTooLarge { .. }
        | AgentNameError::BlockedAddress { .. }
        | AgentNameError::BlockedHost { .. }
        | AgentNameError::Unresolvable(_) => false,
        AgentNameError::NoRedirect { status, .. } => transient_status(*status),
        AgentNameError::CacheServer { status, .. } => transient_status(*status),
        _ => true,
    }
}

/// Look `name` up: from the negative cache, by joining an identical lookup in
/// flight, or by fetching it (under an outbound-fetch permit).
pub(crate) async fn lookup(
    state: &SharedData,
    resolver: &agent_names::HttpRedirectResolver,
    name: &AgentName,
) -> LookupOutcome {
    let lookups = &state.agent_name_lookups;
    let result = lookups
        .failures
        .try_get_with(name.as_str().to_string(), async {
            match fetch(state, resolver, name).await {
                Fetched::Failed {
                    mut failure,
                    transient,
                } => match lookups.ttl(transient) {
                    Some(ttl) => {
                        failure.ttl = ttl;
                        Ok(failure)
                    }
                    None => Err(LookupOutcome::Failed(failure)),
                },
                Fetched::Resolved(did) => Err(LookupOutcome::Resolved(did)),
                Fetched::Shed => Err(LookupOutcome::Shed),
            }
        })
        .await;
    match result {
        // A failure: just fetched by this or a coalesced lookup, or remembered.
        Ok(failure) => {
            debug!("agent name lookup '{name}': failed ({})", failure.status);
            LookupOutcome::Failed(failure)
        }
        // Not cached, but shared with every coalesced caller.
        Err(outcome) => (*outcome).clone(),
    }
}

enum Fetched {
    Resolved(String),
    Failed {
        failure: LookupFailure,
        transient: bool,
    },
    Shed,
}

/// One upstream fetch, under a permit and the resolve timeout.
async fn fetch(
    state: &SharedData,
    resolver: &agent_names::HttpRedirectResolver,
    name: &AgentName,
) -> Fetched {
    // `try_acquire` rather than `acquire` is the point: queueing here would
    // convert a fetch ceiling into an unbounded backlog, which is the thing
    // being defended against.
    let Ok(_permit) = state.agent_name_permits.try_acquire() else {
        warn!("shedding agent name lookup '{name}': outbound fetch ceiling reached");
        return Fetched::Shed;
    };

    let failed = |status: StatusCode, error: ClientError, transient: bool| Fetched::Failed {
        failure: LookupFailure {
            status,
            error,
            ttl: Duration::ZERO,
        },
        transient,
    };

    match tokio::time::timeout(state.resolve_timeout, resolver.resolve(name)).await {
        Ok(Some(Ok(did))) => {
            debug!("resolved agent name '{name}' -> '{did}'");
            Fetched::Resolved(did)
        }
        Ok(Some(Err(e))) => {
            // The detail (which may name the address the name led to) is
            // logged under a reference, not returned.
            let status = StatusCode::BAD_GATEWAY;
            let transient = is_transient(&e);
            let error = ClientError::new(
                status,
                &e,
                &format!("failed to resolve agent name '{name}'"),
            );
            failed(status, error, transient)
        }
        Ok(None) => failed(
            StatusCode::NOT_FOUND,
            ClientError {
                message: format!("No resolver could resolve '{name}'"),
                reference: None,
            },
            false,
        ),
        Err(_elapsed) => {
            warn!("timed out resolving agent name '{name}'");
            failed(
                StatusCode::GATEWAY_TIMEOUT,
                ClientError {
                    message: format!(
                        "Timed out after {} seconds resolving agent name",
                        state.resolve_timeout.as_secs()
                    ),
                    reference: None,
                },
                true,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn definitive_and_transient_failures_are_told_apart() {
        let name = || "https://example.com/@alice".to_string();
        assert!(!is_transient(&AgentNameError::NoRedirect {
            name: name(),
            status: 404
        }));
        assert!(!is_transient(&AgentNameError::NoRedirect {
            name: name(),
            status: 200
        }));
        assert!(!is_transient(&AgentNameError::BlockedHost {
            name: name(),
            host: "localhost".into()
        }));
        assert!(!is_transient(&AgentNameError::Unresolvable(name())));
        for status in [500, 503, 408, 429] {
            assert!(is_transient(&AgentNameError::NoRedirect {
                name: name(),
                status
            }));
        }
    }

    #[test]
    fn transient_ttl_is_capped_and_zero_disables() {
        let lookups = AgentNameLookups::new(10, Duration::from_secs(60));
        assert_eq!(lookups.ttl(false), Some(Duration::from_secs(60)));
        assert_eq!(lookups.ttl(true), Some(TRANSIENT_FAILURE_TTL));
        let lookups = AgentNameLookups::new(10, Duration::from_secs(2));
        assert_eq!(lookups.ttl(true), Some(Duration::from_secs(2)));
        let lookups = AgentNameLookups::new(10, Duration::ZERO);
        assert_eq!(lookups.ttl(false), None);
        assert_eq!(lookups.ttl(true), None);
    }
}
