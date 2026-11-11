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
//!
//! The rate limit bounds resolutions; it does not excuse a refresh that is
//! still owed. Key state counts as confirmed only after a refresh succeeds, so
//! a failed refresh after a silence leaves the peer's messages discarded until
//! one does, and consecutive failures lengthen the interval between attempts
//! up to a fixed bound.

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

/// How many times the interval between resolutions doubles after consecutive
/// failed refreshes: after the fourth failure in a row a peer's VID is retried
/// at most once per eight rate-limit intervals.
const MAX_BACKOFF_DOUBLINGS: u32 = 3;

/// The outcome of the resolutions of one VID so far.
#[derive(Debug, Clone, Copy)]
struct ResolutionRecord {
    last_attempt_ms: u64,
    in_flight: bool,
    consecutive_failures: u32,
}

/// Per-peer freshness bookkeeping: when we last heard from a VID, when we last
/// tried to resolve it, and whether that worked.
#[derive(Debug, Default)]
pub struct KeyStateTracker {
    last_seen_ms: Mutex<std::collections::HashMap<String, u64>>,
    resolutions: Mutex<std::collections::HashMap<String, ResolutionRecord>>,
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

    /// Record that a resolution of `vid` was started. This is what the rate
    /// limit counts. Until [`record_refresh_succeeded`] follows, the key state
    /// for `vid` is not confirmed.
    ///
    /// [`record_refresh_succeeded`]: Self::record_refresh_succeeded
    pub fn record_resolved(&self, vid: &str, now_ms: u64) {
        let mut resolutions = self.resolutions.lock().unwrap();
        let record = resolutions
            .entry(vid.to_string())
            .or_insert(ResolutionRecord {
                last_attempt_ms: now_ms,
                in_flight: true,
                consecutive_failures: 0,
            });
        record.last_attempt_ms = now_ms;
        record.in_flight = true;
    }

    /// Record that the resolution of `vid` started last returned fresh key
    /// state.
    pub fn record_refresh_succeeded(&self, vid: &str) {
        if let Some(record) = self.resolutions.lock().unwrap().get_mut(vid) {
            record.in_flight = false;
            record.consecutive_failures = 0;
        }
    }

    /// Record that the resolution of `vid` started last failed, and return how
    /// many have failed in a row. Each failure in a row doubles the interval
    /// before the next attempt, up to eight times the rate limit.
    pub fn record_refresh_failed(&self, vid: &str) -> u32 {
        match self.resolutions.lock().unwrap().get_mut(vid) {
            Some(record) => {
                record.in_flight = false;
                record.consecutive_failures = record.consecutive_failures.saturating_add(1);
                record.consecutive_failures
            }
            None => 0,
        }
    }

    /// Did the last resolution of `vid` finish and return fresh key state?
    ///
    /// False when `vid` was never resolved, when a resolution is still in
    /// progress, and when the last one failed.
    pub fn refresh_confirmed(&self, vid: &str) -> bool {
        self.resolutions
            .lock()
            .unwrap()
            .get(vid)
            .is_some_and(|record| !record.in_flight && record.consecutive_failures == 0)
    }

    /// How many resolutions of `vid` have failed in a row (zero after a
    /// success, or when it was never resolved).
    pub fn consecutive_refresh_failures(&self, vid: &str) -> u32 {
        self.resolutions
            .lock()
            .unwrap()
            .get(vid)
            .map_or(0, |record| record.consecutive_failures)
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

    /// The earliest time `vid` may be resolved again: one `limit` after the
    /// last attempt, doubled for each failure in a row after the first, up to
    /// eight `limit`s. Zero when it was never resolved.
    pub fn next_resolution_at_ms(&self, vid: &str, limit: Duration) -> u64 {
        match self.resolutions.lock().unwrap().get(vid) {
            Some(record) => {
                let doublings = record
                    .consecutive_failures
                    .saturating_sub(1)
                    .min(MAX_BACKOFF_DOUBLINGS);
                let interval = (limit.as_millis() as u64).saturating_mul(1 << doublings);
                record.last_attempt_ms.saturating_add(interval)
            }
            None => 0,
        }
    }

    /// May `vid` be resolved now, or is it inside its rate limit (or the
    /// longer interval that follows failed refreshes)?
    pub fn may_resolve(&self, vid: &str, limit: Duration, now_ms: u64) -> bool {
        now_ms >= self.next_resolution_at_ms(vid, limit)
    }

    /// Forget everything about `vid`.
    pub fn forget(&self, vid: &str) {
        self.last_seen_ms.lock().unwrap().remove(vid);
        self.resolutions.lock().unwrap().remove(vid);
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
    fn a_refresh_is_confirmed_only_once_it_has_succeeded() {
        let t = KeyStateTracker::new();
        let vid = "did:example:alice";
        assert!(!t.refresh_confirmed(vid));

        t.record_resolved(vid, 0);
        assert!(!t.refresh_confirmed(vid), "in progress is not confirmed");

        assert_eq!(t.record_refresh_failed(vid), 1);
        assert!(!t.refresh_confirmed(vid));
        assert_eq!(t.consecutive_refresh_failures(vid), 1);

        t.record_resolved(vid, 60_000);
        t.record_refresh_succeeded(vid);
        assert!(t.refresh_confirmed(vid));
        assert_eq!(t.consecutive_refresh_failures(vid), 0);
    }

    #[test]
    fn failed_refreshes_back_off_up_to_a_bound() {
        let t = KeyStateTracker::new();
        let vid = "did:example:alice";
        let limit = Duration::from_secs(60);

        let mut now = 0;
        for (failures, interval) in [
            (1, 60_000),
            (2, 120_000),
            (3, 240_000),
            (4, 480_000),
            (5, 480_000),
        ] {
            t.record_resolved(vid, now);
            assert_eq!(t.record_refresh_failed(vid), failures);
            assert_eq!(t.next_resolution_at_ms(vid, limit), now + interval);
            assert!(!t.may_resolve(vid, limit, now + interval - 1));
            assert!(t.may_resolve(vid, limit, now + interval));
            now += interval;
        }

        t.record_resolved(vid, now);
        t.record_refresh_succeeded(vid);
        assert_eq!(t.next_resolution_at_ms(vid, limit), now + 60_000);
    }

    #[test]
    fn the_manual_clock_advances_only_when_told() {
        let c = ManualClock::new();
        assert_eq!(c.now_ms(), 0);
        c.advance(Duration::from_secs(5));
        assert_eq!(c.now_ms(), 5_000);
    }
}
