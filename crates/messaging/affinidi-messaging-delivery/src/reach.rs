//! Which recipients are known to send delivery receipts (VTI-TRN-064 item 1).
//!
//! A receipt is requested, never owed: a recipient may not support receipts,
//! and one that does may decline. So a missing receipt means something only
//! for a recipient that has sent one before. For such a recipient silence is
//! silence, and an expired delivery is escalated as VTI-TRN-042 requires. For
//! anyone else a relayed delivery with no receipt had no evidence path at all,
//! and escalating it would send a second copy of a message the recipient may
//! have had for an hour.
//!
//! [`ReceiptReach`] is that memory. The inbound dispatcher records a recipient
//! each time one of its receipts settles a delivery addressed to it
//! (VTI-TRN-062), and the confirmation sweep consults it when a relayed
//! delivery's window closes. It is in memory: after a restart every recipient
//! is unknown until it sends a receipt again, which errs toward recording
//! deliveries unconfirmable rather than re-sending them.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use affinidi_did_common::scid::strip_scid_src;

/// Recipients recently seen sending delivery receipts, each remembered for a
/// stated period (VTI-TRN-064 item 1: "within a period the sender states").
#[derive(Debug)]
pub struct ReceiptReach {
    period_ms: u64,
    seen: Mutex<HashMap<String, u64>>,
}

impl Default for ReceiptReach {
    fn default() -> Self {
        Self::new()
    }
}

impl ReceiptReach {
    /// How long a recipient counts as sending receipts after its last one.
    ///
    /// As long as the longest delivery window a service commonly uses, so a
    /// recipient that receipted the previous long-window notice still counts
    /// when the next one expires.
    pub const DEFAULT_PERIOD: Duration = Duration::from_secs(30 * 24 * 60 * 60);

    /// The most recipients remembered. Only recipients whose receipts settled
    /// one of this service's own deliveries are recorded, so this bounds a
    /// service with that many distinct receipting recipients, not an attacker.
    /// Past it, the recipient heard from longest ago is forgotten first.
    pub const MAX_PEERS: usize = 16_384;

    /// A memory with the [`DEFAULT_PERIOD`](Self::DEFAULT_PERIOD).
    pub fn new() -> Self {
        Self::with_period(Self::DEFAULT_PERIOD)
    }

    /// A memory that keeps each recipient for `period` after its last receipt.
    pub fn with_period(period: Duration) -> Self {
        Self {
            period_ms: period.as_millis().min(u64::MAX as u128) as u64,
            seen: Mutex::new(HashMap::new()),
        }
    }

    /// The period this memory states.
    pub fn period(&self) -> Duration {
        Duration::from_millis(self.period_ms)
    }

    /// Record that `peer` sent a receipt that settled a delivery addressed to
    /// it, at `now_ms`. Call only for a receipt that satisfied VTI-TRN-062: its
    /// `confirms` named a delivery this service stamped, and its authenticated
    /// sender was that delivery's recipient.
    pub fn record(&self, peer: &str, now_ms: u64) {
        let mut seen = self.lock();
        seen.insert(key(peer), now_ms);
        if seen.len() > Self::MAX_PEERS {
            let horizon = now_ms.saturating_sub(self.period_ms);
            seen.retain(|_, last| *last >= horizon);
        }
        while seen.len() > Self::MAX_PEERS {
            let Some(oldest) = seen
                .iter()
                .min_by_key(|(_, last)| **last)
                .map(|(peer, _)| peer.clone())
            else {
                break;
            };
            seen.remove(&oldest);
        }
    }

    /// Whether `peer` sent a receipt within the period before `now_ms`.
    pub fn sends_receipts(&self, peer: &str, now_ms: u64) -> bool {
        self.lock()
            .get(&key(peer))
            .is_some_and(|last| now_ms.saturating_sub(*last) <= self.period_ms)
    }

    /// Forget `peer`, for a caller that learns it no longer sends receipts.
    pub fn forget(&self, peer: &str) {
        self.lock().remove(&key(peer));
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, u64>> {
        self.seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// The DID a recipient is remembered under, ignoring a `did:scid` `src`
/// locator, as the outbox compares recipients.
fn key(peer: &str) -> String {
    strip_scid_src(peer).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY_MS: u64 = 24 * 60 * 60 * 1000;

    #[test]
    fn a_recipient_never_heard_from_is_not_known_to_send_receipts() {
        let reach = ReceiptReach::new();
        assert!(!reach.sends_receipts("did:example:bob", 1_000));
    }

    #[test]
    fn a_receipt_counts_for_the_stated_period_and_no_longer() {
        let reach = ReceiptReach::with_period(Duration::from_millis(DAY_MS));
        reach.record("did:example:bob", 1_000);
        assert!(reach.sends_receipts("did:example:bob", 1_000 + DAY_MS));
        assert!(!reach.sends_receipts("did:example:bob", 1_001 + DAY_MS));
    }

    #[test]
    fn a_did_scid_recipient_is_known_whatever_its_src() {
        let reach = ReceiptReach::new();
        reach.record("did:scid:vh:1:Qm?src=example.com", 1_000);
        assert!(reach.sends_receipts("did:scid:vh:1:Qm", 2_000));
        assert!(reach.sends_receipts("did:scid:vh:1:Qm?src=other.example", 2_000));
    }

    #[test]
    fn forgetting_a_recipient_makes_it_unknown() {
        let reach = ReceiptReach::new();
        reach.record("did:example:bob", 1_000);
        reach.forget("did:example:bob");
        assert!(!reach.sends_receipts("did:example:bob", 1_000));
    }

    #[test]
    fn past_the_cap_the_recipient_heard_from_longest_ago_goes_first() {
        let reach = ReceiptReach::new();
        for index in 0..=ReceiptReach::MAX_PEERS as u64 {
            reach.record(&format!("did:example:{index}"), 1_000 + index);
        }
        let now = 2_000 + ReceiptReach::MAX_PEERS as u64;
        assert!(!reach.sends_receipts("did:example:0", now));
        assert!(reach.sends_receipts("did:example:1", now));
        assert!(reach.sends_receipts(&format!("did:example:{}", ReceiptReach::MAX_PEERS), now));
    }
}
