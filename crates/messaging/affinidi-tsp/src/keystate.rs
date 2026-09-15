//! Key-state freshness policy (spec Rev 3 §3.7, §7.4.2).
//!
//! A VID's keys change. Rev 3 distinguishes two deployments and asks different
//! things of each.
//!
//! Where the VID implementation maintains key state itself — a key event log
//! with watchers, a verifiable history with witnesses — the endpoint does
//! nothing: its key mappings reflect a rotation without being asked, and
//! messages that failed during the interval simply resume verifying.
//!
//! Where the endpoint resolves key state for itself, it holds a cached value
//! whose authority remains the VID's provenance chain, and §7.4.2 gives it two
//! occasions to refresh:
//!
//! * **On a verification failure**, within an established relationship: the
//!   failure may be a rotation not yet observed, so the VID is re-resolved and
//!   the verification retried once before the message is discarded.
//! * **After a silence** longer than the re-verification threshold, before
//!   acting on the message at all.
//!
//! The second is the one that matters under compromise. Stale key state is
//! internally consistent, so a message signed with a compromised key verifies
//! and gives no warning — but an attacker must send a message to exploit it,
//! and that message is itself what triggers the refresh.
//!
//! Both occasions can be provoked by messages the endpoint has not
//! authenticated, so §7.4.2 also requires bounding how often any one peer's VID
//! is resolved. Rotations are infrequent, so a limit that permits one
//! resolution per interval constrains an adversary without materially delaying
//! recovery.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// A source of monotonic time, injectable so the freshness rules can be tested
/// without sleeping.
pub trait Clock: Send + Sync + std::fmt::Debug {
    /// Milliseconds since an arbitrary fixed origin. Must be monotonic.
    fn now_ms(&self) -> u64;
}

impl<T: Clock + ?Sized> Clock for std::sync::Arc<T> {
    fn now_ms(&self) -> u64 {
        (**self).now_ms()
    }
}

/// The real clock, measured from the first call in this process.
#[derive(Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        static ORIGIN: OnceLock<Instant> = OnceLock::new();
        ORIGIN.get_or_init(Instant::now).elapsed().as_millis() as u64
    }
}

/// A clock a test drives by hand.
#[derive(Debug, Default)]
pub struct ManualClock {
    now_ms: AtomicU64,
}

impl ManualClock {
    /// A clock reading zero.
    pub fn new() -> Self {
        Self::default()
    }

    /// Move time forward.
    pub fn advance(&self, by: Duration) {
        self.now_ms
            .fetch_add(by.as_millis() as u64, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now_ms(&self) -> u64 {
        self.now_ms.load(Ordering::SeqCst)
    }
}

/// How this endpoint keeps a peer's key state fresh.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyStatePolicy {
    /// Whether this endpoint resolves key state for itself (§7.4.2) or relies
    /// on the VID implementation to maintain it (§7.4.1).
    ///
    /// When false, none of the rules below apply: the key mappings are assumed
    /// current and no refresh is ever attempted.
    pub self_resolving: bool,
    /// The silence after which a peer's VID is re-resolved before its message
    /// is acted on.
    ///
    /// A local policy choice: endpoints need not agree on it and it is not
    /// communicated. §11 advises choosing it against the consequence of acting
    /// on a message rather than against the cost of resolving, since the check
    /// falls once when a dormant relationship resumes rather than periodically.
    pub reverification_threshold: Duration,
    /// The minimum interval between resolutions of any one peer's VID.
    ///
    /// Re-resolution can be provoked by an unauthenticated message, and
    /// resolution is more expensive than the message that provokes it, so this
    /// bounds what an adversary can direct at a peer's infrastructure.
    pub resolution_rate_limit: Duration,
}

impl Default for KeyStatePolicy {
    fn default() -> Self {
        Self {
            self_resolving: true,
            reverification_threshold: Duration::from_secs(60 * 60 * 24),
            resolution_rate_limit: Duration::from_secs(60),
        }
    }
}

/// Per-peer freshness bookkeeping: when we last heard from a VID, and when we
/// last resolved it.
#[derive(Debug, Default)]
pub struct KeyStateTracker {
    last_seen_ms: Mutex<std::collections::HashMap<String, u64>>,
    last_resolved_ms: Mutex<std::collections::HashMap<String, u64>>,
}

impl KeyStateTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that a message from `vid` was accepted.
    pub fn record_seen(&self, vid: &str, now_ms: u64) {
        self.last_seen_ms
            .lock()
            .unwrap()
            .insert(vid.to_string(), now_ms);
    }

    /// Record that `vid` was resolved.
    pub fn record_resolved(&self, vid: &str, now_ms: u64) {
        self.last_resolved_ms
            .lock()
            .unwrap()
            .insert(vid.to_string(), now_ms);
    }

    /// Has `vid` been silent for longer than `threshold`?
    ///
    /// A peer with no record has no observed silence to measure, so this is
    /// false — otherwise an agent loaded from storage would re-resolve every
    /// VID it holds the moment it started.
    pub fn silent_longer_than(&self, vid: &str, threshold: Duration, now_ms: u64) -> bool {
        match self.last_seen_ms.lock().unwrap().get(vid) {
            Some(seen) => now_ms.saturating_sub(*seen) > threshold.as_millis() as u64,
            None => false,
        }
    }

    /// May `vid` be resolved now, or is it inside its rate limit?
    pub fn may_resolve(&self, vid: &str, limit: Duration, now_ms: u64) -> bool {
        match self.last_resolved_ms.lock().unwrap().get(vid) {
            Some(last) => now_ms.saturating_sub(*last) >= limit.as_millis() as u64,
            None => true,
        }
    }

    /// Forget everything about `vid`.
    pub fn forget(&self, vid: &str) {
        self.last_seen_ms.lock().unwrap().remove(vid);
        self.last_resolved_ms.lock().unwrap().remove(vid);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_peer_with_no_record_has_no_silence_to_measure() {
        let t = KeyStateTracker::new();
        assert!(!t.silent_longer_than("did:example:alice", Duration::from_secs(1), 10_000));
    }

    #[test]
    fn silence_is_measured_from_the_last_message() {
        let t = KeyStateTracker::new();
        t.record_seen("did:example:alice", 1_000);
        assert!(!t.silent_longer_than("did:example:alice", Duration::from_secs(10), 5_000));
        assert!(t.silent_longer_than("did:example:alice", Duration::from_secs(10), 12_000));
    }

    #[test]
    fn resolution_is_rate_limited_per_peer() {
        let t = KeyStateTracker::new();
        let limit = Duration::from_secs(60);

        // Never resolved: allowed.
        assert!(t.may_resolve("did:example:alice", limit, 0));

        t.record_resolved("did:example:alice", 0);
        assert!(!t.may_resolve("did:example:alice", limit, 30_000));
        assert!(t.may_resolve("did:example:alice", limit, 60_000));

        // The limit is per peer, so another VID is unaffected.
        assert!(t.may_resolve("did:example:bob", limit, 30_000));
    }

    #[test]
    fn the_manual_clock_advances_only_when_told() {
        let c = ManualClock::new();
        assert_eq!(c.now_ms(), 0);
        c.advance(Duration::from_secs(5));
        assert_eq!(c.now_ms(), 5_000);
    }
}
