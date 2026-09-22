//! Records when each account was last active: the last message the mediator
//! accepted for it, and its last completed authentication.
//!
//! An authentication is recorded every time. A message is not: that would add
//! a store write to every message, so each account's received time is written
//! at most once per [`RECEIVED_EVERY`], and may lag by that much.
//!
//! Recording is best-effort. A failed write is logged and never fails the
//! message or the authentication that caused it.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use affinidi_messaging_mediator_common::types::accounts::ActivityKind;
use tracing::debug;

use crate::SharedData;

/// The most often an account's received time is written, in seconds.
pub const RECEIVED_EVERY: u64 = 60;

/// Most accounts whose last write the throttle remembers. Beyond it, entries
/// older than [`RECEIVED_EVERY`] are dropped (they no longer throttle
/// anything); if every entry is recent, the throttle starts over, which costs
/// at most one extra write per account.
const MAX_TRACKED: usize = 50_000;

/// When each account's received time was last written.
#[derive(Clone, Debug, Default)]
pub struct ActivityRecorder {
    written: Arc<Mutex<HashMap<String, u64>>>,
}

impl ActivityRecorder {
    /// Whether an account's received time is due to be written at `now`; if
    /// so, it is marked as written.
    fn received_due(&self, did_hash: &str, now: u64) -> bool {
        let mut written = self.written.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(&at) = written.get(did_hash)
            && now < at.saturating_add(RECEIVED_EVERY)
        {
            return false;
        }
        if written.len() >= MAX_TRACKED && !written.contains_key(did_hash) {
            written.retain(|_, at| now < at.saturating_add(RECEIVED_EVERY));
            if written.len() >= MAX_TRACKED {
                written.clear();
            }
        }
        written.insert(did_hash.to_string(), now);
        true
    }

    /// A message addressed to `did_hash` was accepted.
    pub(crate) async fn received(&self, state: &SharedData, did_hash: &str) {
        let now = state.clock.unix_secs();
        if self.received_due(did_hash, now) {
            record(state, did_hash, ActivityKind::Received, now).await;
        }
    }

    /// `did_hash` completed authentication.
    pub(crate) async fn authenticated(&self, state: &SharedData, did_hash: &str) {
        let now = state.clock.unix_secs();
        record(state, did_hash, ActivityKind::Authenticated, now).await;
    }
}

async fn record(state: &SharedData, did_hash: &str, kind: ActivityKind, at: u64) {
    if let Err(e) = state
        .database
        .account_activity_record(did_hash, kind, at)
        .await
    {
        debug!("couldn't record {kind:?} activity for {did_hash}: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn received_is_written_at_most_once_a_minute_per_account() {
        let r = ActivityRecorder::default();
        assert!(r.received_due("a", 1_000));
        assert!(!r.received_due("a", 1_030), "within the minute");
        assert!(r.received_due("b", 1_030), "another account is independent");
        assert!(r.received_due("a", 1_000 + RECEIVED_EVERY), "a minute on");
    }

    #[test]
    fn the_throttle_stays_bounded() {
        let r = ActivityRecorder::default();
        for i in 0..MAX_TRACKED {
            assert!(r.received_due(&format!("acct-{i}"), 1_000));
        }
        // Full of recent entries: the next account still gets written, and the
        // map starts over rather than growing.
        assert!(r.received_due("one-more", 1_001));
        assert!(r.written.lock().unwrap().len() <= MAX_TRACKED);

        // A minute later the stale entries give way instead.
        let r = ActivityRecorder::default();
        for i in 0..MAX_TRACKED {
            r.received_due(&format!("acct-{i}"), 1_000);
        }
        assert!(r.received_due("late", 1_000 + RECEIVED_EVERY));
        assert_eq!(r.written.lock().unwrap().len(), 1);
    }
}
