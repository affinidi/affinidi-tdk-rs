//! Per-DID rate limiting for authenticated endpoints.
//!
//! Unlike the per-IP rate limiter (which runs as Tower middleware), this limiter
//! operates at the application level because the DID is only known after JWT
//! validation. Handlers call `check()` with the authenticated DID hash to
//! determine whether the request should proceed.

use governor::{Quota, RateLimiter, clock::DefaultClock, state::keyed::DashMapStateStore};
use std::{num::NonZeroU32, sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;
use tracing::debug;

type KeyedLimiter = RateLimiter<String, DashMapStateStore<String>, DefaultClock>;

/// How often to sweep fully-replenished buckets out of the keyed state store.
const GC_INTERVAL: Duration = Duration::from_secs(60);

/// Application-level rate limiter keyed by DID hash.
#[derive(Clone)]
pub struct DidRateLimiter {
    limiter: Option<Arc<KeyedLimiter>>,
}

impl DidRateLimiter {
    /// Create a new per-DID rate limiter.
    ///
    /// If `per_second` is 0, rate limiting is disabled and `check()` always
    /// returns `true`.
    pub fn new(per_second: u32, burst: u32) -> Self {
        let Some(per_second) = NonZeroU32::new(per_second) else {
            return Self { limiter: None };
        };
        let burst = NonZeroU32::new(burst).unwrap_or(NonZeroU32::MIN);
        let quota = Quota::per_second(per_second).allow_burst(burst);
        Self {
            limiter: Some(Arc::new(RateLimiter::keyed(quota))),
        }
    }

    /// Check whether the given DID hash is within its rate limit.
    ///
    /// Returns `true` if the request is allowed, `false` if rate-limited.
    pub fn check(&self, did_hash: &str) -> bool {
        match &self.limiter {
            None => true,
            Some(limiter) => limiter.check_key(&did_hash.to_owned()).is_ok(),
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_limiter_always_allows() {
        let limiter = DidRateLimiter::new(0, 10);
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
}
