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
    nanos::Nanos,
    state::{
        StateStore,
        keyed::{DashMapStateStore, ShrinkableKeyedStateStore},
    },
};
use http::{HeaderName, HeaderValue, StatusCode, header};
use std::{
    collections::HashSet,
    num::NonZeroU32,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;
use tracing::debug;

/// A `governor` DashMap state store shared behind an `Arc`.
///
/// `governor`'s `RateLimiter::keyed` owns its state store privately and exposes
/// only `len` / `retain_recent` / `shrink_to_fit` — enough to *sweep* the map
/// but not to ask whether a given key is already present. The distinct-DID cap
/// ([`MAX_TRACKED_DIDS`]) needs exactly that question: a DID already being
/// tracked must always be admitted to its bucket (never refused by the cap),
/// while a brand-new DID is what the cap gates. So the limiter is built over a
/// store we also hold an `Arc` to, and membership / length are read straight
/// from it.
///
/// `DashMapStateStore<K>` is a type alias for `DashMap<K, InMemoryState>`, so
/// the trait impls below are pure delegation.
#[derive(Clone)]
struct SharedDashMapStore(Arc<DashMapStateStore<String>>);

impl StateStore for SharedDashMapStore {
    type Key = String;

    fn measure_and_replace<T, F, E>(&self, key: &Self::Key, f: F) -> Result<T, E>
    where
        F: Fn(Option<Nanos>) -> Result<(T, Nanos), E>,
    {
        self.0.measure_and_replace(key, f)
    }
}

impl ShrinkableKeyedStateStore<String> for SharedDashMapStore {
    fn retain_recent(&self, drop_below: Nanos) {
        self.0.retain_recent(drop_below);
    }

    fn shrink_to_fit(&self) {
        self.0.shrink_to_fit();
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

type KeyedLimiter = RateLimiter<String, SharedDashMapStore, DefaultClock>;

/// How often to sweep fully-replenished buckets out of the keyed state store.
const GC_INTERVAL: Duration = Duration::from_secs(60);

/// Hard cap on the number of *distinct* DIDs tracked at once.
///
/// `governor` bounds the request rate *within* each key's bucket but never the
/// *number* of keys — and [`spawn_gc`](DidRateLimiter::spawn_gc) only reclaims
/// buckets that have fully replenished, on a 60s tick. Between sweeps, an
/// adversary cycling through many distinct *authenticated* DIDs faster than
/// they replenish would grow the `DashMap` without bound: one `String` key plus
/// a bucket per DID, memory O(requests) rather than O(distinct live clients)
/// (CWE-770). The cap makes the worst case O(`MAX_TRACKED_DIDS`) instead.
///
/// Mitigating context, stated but not relied on alone: every DID reaching this
/// limiter has already passed JWT validation, and the per-IP Tower limiter has
/// already run — so driving this path at volume means minting authenticated
/// tokens for distinct DIDs across many source IPs. The cap is the backstop for
/// exactly that.
///
/// 100_000 is deliberately generous. A single mediator fronts one operator's
/// client fleet — realistically thousands, at most low tens of thousands of
/// distinct client DIDs active within any 60s GC window — so a legitimate
/// steady state sits comfortably below the cap and is never refused by it,
/// while the ceiling still bounds a flood to a small, fixed `DashMap` (each
/// entry is a short hash string plus a few words of bucket state, so the whole
/// map is on the order of tens of MB at the cap). It is a module constant
/// rather than a config knob because the existing `LimitsConfigRaw` schema is a
/// struct-literal-constructed type in a separate crate: threading one more
/// field through it, its `TryFrom`, and every test literal is a large,
/// cross-crate change for a value operators have no reason to tune.
const MAX_TRACKED_DIDS: usize = 100_000;

/// `Retry-After` hint (seconds) on a *capacity* refusal — the cap is full, as
/// opposed to a per-DID quota refusal. Tied to the GC interval: by the next
/// sweep, fully-replenished buckets have been reclaimed and space is free
/// again. Advisory; the inline reclaim on the refusal path often frees space
/// sooner.
const CAPACITY_RETRY_AFTER_SECS: u64 = GC_INTERVAL.as_secs();

/// Minimum spacing between *inline* reclaim passes on the refusal path.
///
/// The refusal path may run `retain_recent`, an O(tracked) scan, to make room
/// before failing closed. Running that unconditionally on every full-map
/// request would make the cap itself a CPU-exhaustion lever (fixing unbounded
/// memory by adding unbounded CPU). Throttling it to at most one pass per
/// window keeps the refusal path O(1) amortised while still reclaiming promptly;
/// the periodic [`GC_INTERVAL`] sweep is the unconditional backstop.
const INLINE_RECLAIM_MIN_INTERVAL: Duration = Duration::from_millis(100);

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

/// The live limiter, present only when limiting is enabled. Bundles the
/// `governor` limiter with the shared handle to its state store (for the
/// distinct-DID cap) and the cap itself, so the three can never drift apart.
#[derive(Clone)]
struct Active {
    limiter: Arc<KeyedLimiter>,
    store: SharedDashMapStore,
    max_tracked: usize,
    /// Monotonic reference for the inline-reclaim throttle. Backdated by
    /// [`INLINE_RECLAIM_MIN_INTERVAL`] at construction so the first reclaim
    /// after the map fills fires immediately rather than waiting out a window.
    epoch: Instant,
    /// Milliseconds (since `epoch`) of the last inline reclaim, `0` until the
    /// first. Shared so all clones throttle against one another.
    last_reclaim_ms: Arc<AtomicU64>,
}

impl Active {
    /// Number of distinct DIDs currently tracked.
    fn tracked(&self) -> usize {
        self.store.0.len()
    }

    /// Is this DID already tracked? An already-tracked DID is exempt from the
    /// cap — it is charged against its existing bucket, never refused for
    /// capacity.
    fn is_tracked(&self, did_hash: &str) -> bool {
        self.store.0.contains_key(did_hash)
    }

    /// Reclaim fully-replenished buckets, at most once per
    /// [`INLINE_RECLAIM_MIN_INTERVAL`]. A no-op if another reclaim ran within
    /// the window, which is what keeps the refusal path from amplifying an
    /// O(tracked) scan across every request in a flood.
    fn throttled_reclaim(&self) {
        let now_ms = self.epoch.elapsed().as_millis() as u64;
        let last = self.last_reclaim_ms.load(Ordering::Relaxed);
        let window_ms = INLINE_RECLAIM_MIN_INTERVAL.as_millis() as u64;
        if now_ms.saturating_sub(last) >= window_ms
            && self
                .last_reclaim_ms
                .compare_exchange(last, now_ms, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
        {
            self.limiter.retain_recent();
        }
    }
}

/// Application-level rate limiter keyed by DID hash.
#[derive(Clone)]
pub struct DidRateLimiter {
    active: Option<Active>,
    exempt: Arc<HashSet<String>>,
}

impl std::fmt::Debug for DidRateLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DidRateLimiter")
            .field("enabled", &self.active.is_some())
            .field("tracked", &self.active.as_ref().map_or(0, |a| a.tracked()))
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
        Self::with_capacity(per_second, burst, MAX_TRACKED_DIDS)
    }

    /// As [`Self::new`], but with an explicit distinct-DID cap. The public
    /// constructor always uses [`MAX_TRACKED_DIDS`]; tests use a small cap so
    /// the admission-control path can be exercised without inserting 100k keys.
    fn with_capacity(per_second: u32, burst: u32, max_tracked: usize) -> Self {
        let Some(per_second) = NonZeroU32::new(per_second) else {
            return Self {
                active: None,
                exempt: Arc::default(),
            };
        };
        let burst = NonZeroU32::new(burst).unwrap_or(NonZeroU32::MIN);
        let quota = Quota::per_second(per_second).allow_burst(burst);
        // Build the limiter over a store we keep an `Arc` to, so the cap can
        // read membership/length from the exact map the limiter mutates.
        let store = SharedDashMapStore(Arc::new(DashMapStateStore::default()));
        let limiter = RateLimiter::new(quota, store.clone(), DefaultClock::default());
        Self {
            active: Some(Active {
                limiter: Arc::new(limiter),
                store,
                // A cap of 0 would refuse every DID; clamp so a misconfigured
                // caller degrades to "track one" rather than "deny all".
                max_tracked: max_tracked.max(1),
                epoch: Instant::now()
                    .checked_sub(INLINE_RECLAIM_MIN_INTERVAL)
                    .unwrap_or_else(Instant::now),
                last_reclaim_ms: Arc::new(AtomicU64::new(0)),
            }),
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
        self.active.is_some()
    }

    /// Charge one request against `did_hash`'s bucket.
    ///
    /// Always allowed when limiting is disabled, when the DID is exempt, and
    /// for an empty hash — an anonymous session has no DID to attribute the
    /// request to, and sharing one bucket across all of them would let one
    /// relaying peer starve the rest.
    pub fn try_acquire(&self, did_hash: &str) -> Result<(), DidRateLimited> {
        let Some(active) = &self.active else {
            return Ok(());
        };
        if did_hash.is_empty() || self.exempt.contains(did_hash) {
            return Ok(());
        }

        // Admission control (CWE-770). `governor` never caps the number of
        // distinct keys, so a flood of one-shot authenticated DIDs would grow
        // the map without bound between GC sweeps. Only the *insertion of a new
        // key* is gated here: a DID already being tracked always falls through
        // to its bucket below, so a legitimate steady-state fleet under the cap
        // is never refused and no in-window DID is evicted by this path.
        if !active.is_tracked(did_hash) && active.tracked() >= active.max_tracked {
            // Try to make room before refusing: reclaim any fully-replenished
            // buckets (what the periodic GC does), throttled so this can't
            // amplify an O(tracked) scan across a flood — see
            // `throttled_reclaim`. A burst of one-shot DIDs replenishes fast, so
            // one pass often frees space at once.
            active.throttled_reclaim();
            if !active.is_tracked(did_hash) && active.tracked() >= active.max_tracked {
                // Still full: fail closed for the new DID rather than grow
                // unbounded. Same 429 contract as a quota refusal. (A small,
                // bounded overshoot is possible if many *new* DIDs race here at
                // once — acceptable; the invariant is "bounded", not "exact".)
                return Err(DidRateLimited {
                    retry_after_secs: CAPACITY_RETRY_AFTER_SECS,
                });
            }
        }

        active
            .limiter
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
        let Some(limiter) = self.active.as_ref().map(|a| a.limiter.clone()) else {
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

    /// The distinct-DID cap refuses a *new* DID once the store is full, but an
    /// already-tracked DID keeps flowing — the cap gates key insertion, not use.
    ///
    /// Rate is generous (burst 5) so nothing is refused for exceeding its quota;
    /// the only refusal here is the capacity one. `per_second = 1` keeps buckets
    /// from fully replenishing within the test, so the inline reclaim on the
    /// refusal path finds nothing to drop and the map stays full.
    #[test]
    fn cap_fails_closed_for_a_new_did_when_full() {
        let limiter = DidRateLimiter::with_capacity(1, 5, 2);

        // Fill the two slots.
        assert!(limiter.check("did:example:aaa"));
        assert!(limiter.check("did:example:bbb"));

        // A third, new DID is refused for capacity — not quota.
        let refused = limiter.try_acquire("did:example:ccc").unwrap_err();
        assert_eq!(refused.retry_after_secs, CAPACITY_RETRY_AFTER_SECS);
        assert!(!limiter.check("did:example:ccc"));

        // An already-tracked DID still has quota and is never refused by the
        // cap, even though the store is full.
        assert!(limiter.check("did:example:aaa"));
    }

    /// Disabled mode (`per_second == 0`) has no store and therefore no cap:
    /// unlimited distinct DIDs all pass.
    #[test]
    fn disabled_mode_ignores_the_cap() {
        let limiter = DidRateLimiter::new(0, 10);
        assert!(!limiter.is_enabled());
        for i in 0..(MAX_TRACKED_DIDS as u64 / 10 + 5) {
            assert!(limiter.check(&format!("did:example:{i}")));
        }
    }

    /// A fleet of distinct DIDs comfortably under the cap is never refused by
    /// it — the steady-state case.
    #[test]
    fn a_fleet_under_the_cap_is_never_refused() {
        let limiter = DidRateLimiter::with_capacity(1000, 1000, 200);
        for i in 0..150 {
            assert!(
                limiter.check(&format!("did:example:{i}")),
                "DID {i} (under the cap) must be admitted"
            );
        }
    }

    /// Once buckets replenish, GC (here the inline reclaim on the refusal path)
    /// reclaims their slots and new DIDs are admitted again — the cap is a live
    /// ceiling, not a permanent one.
    #[test]
    fn gc_reclaims_capacity_for_new_dids() {
        // burst 1 at 1000/s: a charged bucket fully replenishes in ~1ms.
        let limiter = DidRateLimiter::with_capacity(1000, 1, 2);
        assert!(limiter.check("did:example:aaa"));
        assert!(limiter.check("did:example:bbb"));

        // Let both buckets fully replenish so they become reclaimable.
        std::thread::sleep(Duration::from_millis(50));

        // A new DID now succeeds: the refusal-path reclaim drops the two
        // replenished buckets, freeing a slot.
        assert!(limiter.check("did:example:ccc"));
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
