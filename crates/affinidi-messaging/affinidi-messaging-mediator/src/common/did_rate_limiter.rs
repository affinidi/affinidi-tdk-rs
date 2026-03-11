//! Per-DID rate limiting for authenticated endpoints.
//!
//! Unlike the per-IP rate limiter (which runs as Tower middleware), this limiter
//! operates at the application level because the DID is only known after JWT
//! validation. Handlers call `check()` with the authenticated DID hash to
//! determine whether the request should proceed.

use governor::{Quota, RateLimiter, clock::DefaultClock, state::keyed::DashMapStateStore};
use std::{num::NonZeroU32, sync::Arc};

type KeyedLimiter = RateLimiter<String, DashMapStateStore<String>, DefaultClock>;

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
        if per_second == 0 {
            return Self { limiter: None };
        }

        let quota = Quota::per_second(
            NonZeroU32::new(per_second).expect("per_second checked non-zero above"),
        )
        .allow_burst(NonZeroU32::new(burst.max(1)).expect("burst.max(1) is always non-zero"));

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
