//! Per-DID rate limiting for authenticated HTTP requests.
//!
//! Unlike the per-IP rate limiter (which runs as Tower middleware), this limiter
//! operates at the application level because the DID is only known after JWT
//! validation. It is charged in exactly one place:
//! [`authenticate_token`](crate::common::jwt_auth::authenticate_token), once the
//! token has been fully validated. That covers every route that authenticates a
//! caller — `/inbound` (DIDComm and TSP), `/outbound`, `/fetch`, `/list`,
//! `/delete`, `/whoami`, `/oob`, `/admin/status` and the `/ws` upgrade — and a
//! refusal is a `429` carrying the mediator's rate-limit attribution contract
//! (see [`refusal_response`]).
//!
//! # What is deliberately not charged
//!
//! - **Frames on an established WebSocket.** The socket's upgrade request is
//!   charged; the messages it then carries are not. A refusal mid-session has
//!   no HTTP status to carry it, DIDComm's problem-report registry has no
//!   rate-limit descriptor, and closing the socket would drop a frame the
//!   client already believes it sent. Choosing a signal is a protocol decision,
//!   so none is invented here.
//! - **Anonymous sessions** — the inter-mediator relay session and the DIDComm
//!   v1 anonymous-forward session. They carry no DID, so there is nothing to key
//!   on, and keying them all on one shared bucket would let one busy peer
//!   mediator throttle every other peer's forwards. They never reach
//!   `authenticate_token`; the per-IP limiter still applies to them.
//! - **The mediator's own DID and the configured admin DID**
//!   ([`DidRateLimiter::with_exempt_did_hashes`]). Throttling the operator's own
//!   management plane is how an incident response locks itself out.
//!
//! Charging happens only *after* the token is validated. Charging earlier would
//! let anyone exhaust a victim DID's bucket by presenting a forged token whose
//! `sub` names it.

use affinidi_rate_limit::{RATE_LIMITED_ERROR, SOURCE_HEADER};
use axum::{
    Json,
    response::{IntoResponse, Response},
};
use governor::{
    Quota, RateLimiter,
    clock::{Clock, DefaultClock},
    state::keyed::DashMapStateStore,
};
use http::{HeaderName, HeaderValue, StatusCode, header};
use std::{collections::HashSet, num::NonZeroU32, sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;
use tracing::debug;

type KeyedLimiter = RateLimiter<String, DashMapStateStore<String>, DefaultClock>;

/// How often to sweep fully-replenished buckets out of the keyed state store.
const GC_INTERVAL: Duration = Duration::from_secs(60);

/// The `scope` a per-DID refusal names, in its JSON body and as the
/// `rate_limited_total` metric label. The per-IP limiter's label is `ip`.
pub const PER_DID_SCOPE: &str = "did";

const PER_DID_MESSAGE: &str = "Per-DID rate limit exceeded. Please try again later.";

/// A DID has spent its quota.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct DidRateLimited {
    /// Seconds until the next token, rounded up to whole seconds (minimum 1),
    /// ready for `Retry-After`.
    pub retry_after_secs: u64,
}

/// Application-level rate limiter keyed by DID hash.
#[derive(Clone)]
pub struct DidRateLimiter {
    limiter: Option<Arc<KeyedLimiter>>,
    exempt: Arc<HashSet<String>>,
}

impl std::fmt::Debug for DidRateLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DidRateLimiter")
            .field("enabled", &self.limiter.is_some())
            .field("exempt", &self.exempt.len())
            .finish()
    }
}

impl DidRateLimiter {
    /// Create a new per-DID rate limiter.
    ///
    /// If `per_second` is 0, rate limiting is disabled and `check()` always
    /// returns `true`. `burst == 0` is treated as 1.
    pub fn new(per_second: u32, burst: u32) -> Self {
        let Some(per_second) = NonZeroU32::new(per_second) else {
            return Self {
                limiter: None,
                exempt: Arc::default(),
            };
        };
        let burst = NonZeroU32::new(burst).unwrap_or(NonZeroU32::MIN);
        let quota = Quota::per_second(per_second).allow_burst(burst);
        Self {
            limiter: Some(Arc::new(RateLimiter::keyed(quota))),
            exempt: Arc::default(),
        }
    }

    /// Never limit these DID hashes. The mediator exempts its own DID and the
    /// configured admin DID; see the module docs.
    pub fn with_exempt_did_hashes(mut self, did_hashes: impl IntoIterator<Item = String>) -> Self {
        self.exempt = Arc::new(
            did_hashes
                .into_iter()
                .filter(|hash| !hash.is_empty())
                .collect(),
        );
        self
    }

    /// Is limiting active?
    pub fn is_enabled(&self) -> bool {
        self.limiter.is_some()
    }

    /// Charge one request against `did_hash`'s bucket.
    ///
    /// Always allowed when limiting is disabled, when the DID is exempt, and
    /// for an empty hash — an anonymous session has no DID to attribute the
    /// request to, and sharing one bucket across all of them would let one
    /// relaying peer starve the rest.
    pub fn try_acquire(&self, did_hash: &str) -> Result<(), DidRateLimited> {
        let Some(limiter) = &self.limiter else {
            return Ok(());
        };
        if did_hash.is_empty() || self.exempt.contains(did_hash) {
            return Ok(());
        }
        limiter
            .check_key(&did_hash.to_owned())
            .map_err(|not_until| {
                // governor reports the instant the next token is available;
                // Retry-After wants whole seconds, and 0 would invite an immediate
                // retry that is guaranteed to fail.
                DidRateLimited {
                    retry_after_secs: not_until
                        .wait_time_from(DefaultClock::default().now())
                        .as_secs()
                        .max(1),
                }
            })
    }

    /// Check whether the given DID hash is within its rate limit.
    ///
    /// Returns `true` if the request is allowed, `false` if rate-limited. Same
    /// decision as [`Self::try_acquire`], without the retry hint.
    pub fn check(&self, did_hash: &str) -> bool {
        self.try_acquire(did_hash).is_ok()
    }

    /// Spawn the background sweep that reclaims idle buckets.
    ///
    /// Same reclamation gap as the per-IP limiter: `governor` never drops keys
    /// on its own, so every DID that has ever authenticated would keep a
    /// `DashMap` entry for the process lifetime. `retain_recent` only drops
    /// buckets that have fully replenished, so it cannot let a DID exceed its
    /// quota.
    ///
    /// No-op when rate limiting is disabled (the default: `per_second == 0`).
    pub fn spawn_gc(&self, shutdown: CancellationToken) {
        let Some(limiter) = self.limiter.clone() else {
            return;
        };
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(GC_INTERVAL);
            ticker.tick().await; // the first tick fires immediately
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    _ = ticker.tick() => {
                        let before = limiter.len();
                        limiter.retain_recent();
                        limiter.shrink_to_fit();
                        let after = limiter.len();
                        if before != after {
                            debug!(
                                "Per-DID rate limiter GC: reclaimed {} idle bucket(s), {} live",
                                before - after,
                                after
                            );
                        }
                    }
                }
            }
        });
    }
}

/// The `429` for a per-DID refusal.
///
/// The same attribution contract as the per-IP limiter's refusal
/// (`affinidi-rate-limit`): `x-rate-limit-source: mediator`, `Retry-After`, and
/// a JSON body whose `limiter` is the refusing *service*. `limiter` stays
/// `mediator` rather than naming this limiter because clients read it as the
/// source when a proxy strips the header. Which of the mediator's limiters
/// refused is carried by the additional `scope` member (`did`), which is also
/// what tells an operator to tune `did_rate_limit_*` rather than
/// `rate_limit_per_ip`.
pub fn refusal_response(retry_after_secs: u64) -> Response {
    let mut response = (
        StatusCode::TOO_MANY_REQUESTS,
        Json(serde_json::json!({
            "error": RATE_LIMITED_ERROR,
            "limiter": crate::server::RATE_LIMIT_SOURCE,
            "scope": PER_DID_SCOPE,
            "message": PER_DID_MESSAGE,
            "retryAfterSecs": retry_after_secs,
        })),
    )
        .into_response();
    let headers = response.headers_mut();
    headers.insert(
        HeaderName::from_static(SOURCE_HEADER),
        HeaderValue::from_static(crate::server::RATE_LIMIT_SOURCE),
    );
    headers.insert(header::RETRY_AFTER, HeaderValue::from(retry_after_secs));
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_messaging_sdk::errors::HttpStatusError;

    #[test]
    fn disabled_limiter_always_allows() {
        let limiter = DidRateLimiter::new(0, 10);
        assert!(!limiter.is_enabled());
        for _ in 0..1000 {
            assert!(limiter.check("did:example:123"));
        }
    }

    #[test]
    fn enabled_limiter_eventually_rejects() {
        // 1 request per second, burst of 2
        let limiter = DidRateLimiter::new(1, 2);
        let did = "did:example:456";

        // First two should succeed (burst)
        assert!(limiter.check(did));
        assert!(limiter.check(did));

        // Third should be rejected (burst exhausted, no time has passed)
        assert!(!limiter.check(did));
    }

    #[test]
    fn different_dids_have_independent_limits() {
        let limiter = DidRateLimiter::new(1, 1);

        assert!(limiter.check("did:example:aaa"));
        assert!(!limiter.check("did:example:aaa"));

        // Different DID should still be allowed
        assert!(limiter.check("did:example:bbb"));
    }

    #[test]
    fn refusal_carries_a_retry_hint_of_at_least_one_second() {
        let limiter = DidRateLimiter::new(1, 1);
        assert!(limiter.try_acquire("aaa").is_ok());
        let refused = limiter.try_acquire("aaa").unwrap_err();
        assert!(refused.retry_after_secs >= 1, "{refused:?}");
    }

    /// The mediator's own DID and the admin DID are never throttled.
    #[test]
    fn exempt_dids_are_never_limited() {
        let limiter = DidRateLimiter::new(1, 1)
            .with_exempt_did_hashes(["mediator".to_string(), "admin".to_string()]);
        for _ in 0..100 {
            assert!(limiter.try_acquire("mediator").is_ok());
            assert!(limiter.try_acquire("admin").is_ok());
        }
        assert!(limiter.try_acquire("user").is_ok());
        assert!(limiter.try_acquire("user").is_err());
    }

    /// An anonymous (relay) session has no DID hash. It must not be charged —
    /// every relaying peer would otherwise share one bucket.
    #[test]
    fn an_empty_did_hash_is_never_charged() {
        let limiter = DidRateLimiter::new(1, 1);
        for _ in 0..100 {
            assert!(limiter.try_acquire("").is_ok());
        }
    }

    /// The per-DID `429` carries the attribution contract, and the SDK reads it
    /// back as a rate-limit refusal from the mediator.
    #[tokio::test]
    async fn refusal_response_carries_the_attribution_contract() {
        let response = refusal_response(3);
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        let source = response.headers()[SOURCE_HEADER]
            .to_str()
            .unwrap()
            .to_owned();
        let retry_after = response.headers()[header::RETRY_AFTER]
            .to_str()
            .unwrap()
            .to_owned();
        assert_eq!(source, "mediator");
        assert_eq!(retry_after, "3");

        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            body,
            serde_json::json!({
                "error": "rate_limited",
                "limiter": "mediator",
                "scope": "did",
                "message": PER_DID_MESSAGE,
                "retryAfterSecs": 3,
            })
        );

        let parsed = HttpStatusError::from_parts(
            "send",
            429,
            Some(&source),
            Some(&retry_after),
            String::from_utf8(bytes.to_vec()).unwrap(),
        );
        assert!(parsed.is_rate_limited());
        assert_eq!(parsed.rate_limit_source.as_deref(), Some("mediator"));
        assert_eq!(parsed.retry_after_secs, Some(3));

        // A proxy that strips the headers still leaves an attributable body.
        let stripped = HttpStatusError::from_parts(
            "send",
            429,
            None,
            None,
            String::from_utf8(bytes.to_vec()).unwrap(),
        );
        assert_eq!(stripped.rate_limit_source.as_deref(), Some("mediator"));
        assert_eq!(stripped.retry_after_secs, Some(3));
    }
}
