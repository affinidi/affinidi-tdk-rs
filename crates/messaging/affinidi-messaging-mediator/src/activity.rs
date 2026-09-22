//! Records when each account was last active: the last message the mediator
//! accepted for it, and its last completed authentication.
//!
//! An authentication is recorded every time. A message is not: that would add
//! a store write to every message, so each account's received time is written
//! at most once per [`RECEIVED_EVERY`], and may lag by that much.
//!
//! **Two bounds, because one is not enough.** The per-account throttle bounds
//! how often *one* account is written, which a sender with many DIDs can
//! sidestep: a thousand accounts, one message each, is a thousand writes the
//! throttle permits. So the whole recorder also holds a budget of
//! [`MAX_WRITES_PER_SECOND`] writes a second, across every account. Past it,
//! recording is skipped until the next second, and the times simply lag — they
//! are observability, not state anything depends on.
//!
//! Recording is best-effort in the same spirit: a failed write never fails the
//! message or the authentication that caused it. It is not silent, though —
//! every failure increments
//! [`ACCOUNT_ACTIVITY_WRITE_FAILURES_TOTAL`](crate::common::metrics::names::ACCOUNT_ACTIVITY_WRITE_FAILURES_TOTAL)
//! and warns at most once per [`WARN_EVERY`], so a store that has stopped
//! accepting these writes is visible to an operator rather than showing up as
//! account times that quietly stopped moving.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use affinidi_messaging_mediator_common::types::accounts::ActivityKind;
use tracing::warn;

use crate::SharedData;
use crate::common::metrics::names::ACCOUNT_ACTIVITY_WRITE_FAILURES_TOTAL;

/// The most often an account's received time is written, in seconds.
pub const RECEIVED_EVERY: u64 = 60;

/// The most activity writes a second, across every account. A mediator busier
/// than this keeps serving; only the recording lags.
pub const MAX_WRITES_PER_SECOND: u32 = 200;

/// The most often a failed write is warned about, in seconds. The counter
/// carries the rate; the log line carries the reason.
const WARN_EVERY: u64 = 60;

/// Most accounts whose last write the throttle remembers. Beyond it, entries
/// older than [`RECEIVED_EVERY`] are dropped (they no longer throttle
/// anything); if every entry is recent, the oldest half gives way, which costs
/// at most one extra write for each account dropped — and the per-second
/// budget bounds that anyway.
const MAX_TRACKED: usize = 50_000;

/// What the recorder remembers between writes.
#[derive(Debug, Default)]
struct Throttle {
    /// When each account's received time was last written.
    written: HashMap<String, u64>,
    /// The second the budget below is counting, and how much of it is spent.
    second: u64,
    spent: u32,
    /// When a failed write was last warned about.
    warned: Option<u64>,
}

impl Throttle {
    /// Spend one write from this second's budget, or report it exhausted.
    fn spend(&mut self, now: u64) -> bool {
        if self.second != now {
            self.second = now;
            self.spent = 0;
        }
        if self.spent >= MAX_WRITES_PER_SECOND {
            return false;
        }
        self.spent += 1;
        true
    }

    /// Whether an account's received time is due at `now`; if so, it is marked
    /// as written.
    fn received_due(&mut self, did_hash: &str, now: u64) -> bool {
        if let Some(&at) = self.written.get(did_hash)
            && now < at.saturating_add(RECEIVED_EVERY)
        {
            return false;
        }
        if self.written.len() >= MAX_TRACKED && !self.written.contains_key(did_hash) {
            self.written
                .retain(|_, at| now < at.saturating_add(RECEIVED_EVERY));
            if self.written.len() >= MAX_TRACKED {
                // Every entry is recent. Drop the half written longest ago —
                // by count, so entries sharing a second don't take each other
                // with them — and the throttle keeps working for the rest.
                let mut entries: Vec<(String, u64)> = self
                    .written
                    .iter()
                    .map(|(hash, at)| (hash.clone(), *at))
                    .collect();
                entries.sort_unstable_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
                for (hash, _) in entries.into_iter().take(MAX_TRACKED / 2) {
                    self.written.remove(&hash);
                }
            }
        }
        self.written.insert(did_hash.to_string(), now);
        true
    }

    /// Whether to warn about a failed write now.
    fn warn_due(&mut self, now: u64) -> bool {
        if self
            .warned
            .is_some_and(|at| now < at.saturating_add(WARN_EVERY))
        {
            return false;
        }
        self.warned = Some(now);
        true
    }
}

/// Records account activity, under the bounds described in the module docs.
#[derive(Clone, Debug, Default)]
pub struct ActivityRecorder {
    throttle: Arc<Mutex<Throttle>>,
}

impl ActivityRecorder {
    /// A message addressed to `did_hash` was accepted.
    pub(crate) async fn received(&self, state: &SharedData, did_hash: &str) {
        let now = state.clock.unix_secs();
        let due = {
            let mut throttle = self.lock();
            throttle.received_due(did_hash, now) && throttle.spend(now)
        };
        if due {
            self.record(state, did_hash, ActivityKind::Received, now)
                .await;
        }
    }

    /// `did_hash` completed authentication.
    pub(crate) async fn authenticated(&self, state: &SharedData, did_hash: &str) {
        let now = state.clock.unix_secs();
        if self.lock().spend(now) {
            self.record(state, did_hash, ActivityKind::Authenticated, now)
                .await;
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Throttle> {
        self.throttle.lock().unwrap_or_else(|e| e.into_inner())
    }

    async fn record(&self, state: &SharedData, did_hash: &str, kind: ActivityKind, at: u64) {
        let Err(e) = state
            .database
            .account_activity_record(did_hash, kind, at)
            .await
        else {
            return;
        };
        metrics::counter!(ACCOUNT_ACTIVITY_WRITE_FAILURES_TOTAL).increment(1);
        if self.lock().warn_due(at) {
            warn!(
                "couldn't record account activity ({kind:?}): {e}. Account activity times will \
                 be stale while this lasts; see {ACCOUNT_ACTIVITY_WRITE_FAILURES_TOTAL} for the \
                 rate (further warnings are suppressed for {WARN_EVERY}s)"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn received_is_written_at_most_once_a_minute_per_account() {
        let mut t = Throttle::default();
        assert!(t.received_due("a", 1_000));
        assert!(!t.received_due("a", 1_030), "within the minute");
        assert!(t.received_due("b", 1_030), "another account is independent");
        assert!(t.received_due("a", 1_000 + RECEIVED_EVERY), "a minute on");
    }

    #[test]
    fn many_accounts_cannot_spend_more_than_the_budget() {
        let mut t = Throttle::default();
        // A distinct account each time, so the per-account throttle permits
        // every one of them: only the budget holds them back.
        let allowed = (0..MAX_WRITES_PER_SECOND as usize + 500)
            .filter(|i| t.received_due(&format!("acct-{i}"), 1_000) && t.spend(1_000))
            .count();
        assert_eq!(allowed, MAX_WRITES_PER_SECOND as usize);
        // The next second starts a fresh budget.
        assert!(t.spend(1_001));
    }

    #[test]
    fn the_throttle_stays_bounded() {
        let mut t = Throttle::default();
        for i in 0..MAX_TRACKED {
            assert!(t.received_due(&format!("acct-{i}"), 1_000));
        }
        // Full of entries written in the same second: the older half gives way
        // rather than the map growing or emptying.
        assert!(t.received_due("one-more", 1_001));
        assert!(t.written.len() <= MAX_TRACKED);
        assert!(t.written.len() > MAX_TRACKED / 4, "not emptied wholesale");

        // A minute later the stale entries give way instead.
        let mut t = Throttle::default();
        for i in 0..MAX_TRACKED {
            t.received_due(&format!("acct-{i}"), 1_000);
        }
        assert!(t.received_due("late", 1_000 + RECEIVED_EVERY));
        assert_eq!(t.written.len(), 1);
    }

    #[test]
    fn failures_warn_at_most_once_a_minute() {
        let mut t = Throttle::default();
        assert!(t.warn_due(1_000));
        assert!(!t.warn_due(1_030));
        assert!(t.warn_due(1_000 + WARN_EVERY));
    }
}
