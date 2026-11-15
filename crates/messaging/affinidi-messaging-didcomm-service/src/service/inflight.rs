//! One owner per queued message (R1.7).
//!
//! A listener receives queued messages two ways: the live websocket stream and
//! the periodic offline drain. Both see a message that is still queued at the
//! mediator — the live path acks only after its handler returns, so until then
//! the offline drain's `delivery-request` returns it too. Without a shared
//! record the same message reached the handler twice.
//!
//! [`InFlight`] is that record, keyed by the mediator's id for the message
//! (`UnpackMetadata::sha256_hash`, the delivery attachment id). A path that
//! wants to dispatch a message must [`claim`](InFlight::claim) it first; a
//! claim held by the other path, or a message that was handled and acked a
//! moment ago, is skipped and left to its owner.

use std::collections::{HashSet, VecDeque};
use std::sync::{Arc, Mutex};

/// How many recently acked ids are remembered, so a copy that the other path
/// fetched before the ack landed is not dispatched a second time.
const RECENT_CAPACITY: usize = 4096;

#[derive(Default)]
struct Inner {
    active: HashSet<String>,
    recent: HashSet<String>,
    recent_order: VecDeque<String>,
}

/// Queue ids currently being handled by this listener, plus a bounded memory of
/// ids handled and acked recently.
#[derive(Default)]
pub(crate) struct InFlight {
    inner: Mutex<Inner>,
}

impl InFlight {
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Take ownership of `id`. `None` when another path is handling it or it
    /// was handled and acked recently: the caller must neither dispatch nor
    /// ack it.
    pub(crate) fn claim(self: &Arc<Self>, id: &str) -> Option<Claim> {
        let mut inner = self.lock();
        if inner.recent.contains(id) || !inner.active.insert(id.to_string()) {
            return None;
        }
        Some(Claim {
            owner: self.clone(),
            id: id.to_string(),
            released: false,
        })
    }

    fn release(&self, id: &str, acked: bool) {
        let mut inner = self.lock();
        inner.active.remove(id);
        if acked && inner.recent.insert(id.to_string()) {
            inner.recent_order.push_back(id.to_string());
            while inner.recent_order.len() > RECENT_CAPACITY {
                if let Some(old) = inner.recent_order.pop_front() {
                    inner.recent.remove(&old);
                }
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn is_active(&self, id: &str) -> bool {
        self.lock().active.contains(id)
    }

    /// Whether `id` was handled and acked recently.
    #[cfg(all(test, feature = "tsp"))]
    pub(crate) fn is_recent(&self, id: &str) -> bool {
        self.lock().recent.contains(id)
    }
}

/// Ownership of one queued message. Dropping it without
/// [`finish`](Claim::finish) releases the id (the message is still queued at
/// the mediator and may be dispatched again).
pub(crate) struct Claim {
    owner: Arc<InFlight>,
    id: String,
    released: bool,
}

impl Claim {
    /// The queue id this claim owns.
    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    /// Release the id. `acked` records that the message was deleted from the
    /// mediator, so a copy fetched before the delete landed is skipped.
    pub(crate) fn finish(mut self, acked: bool) {
        self.owner.release(&self.id, acked);
        self.released = true;
    }
}

impl Drop for Claim {
    fn drop(&mut self) {
        if !self.released {
            self.owner.release(&self.id, false);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_claimed_id_cannot_be_claimed_again_until_released() {
        let f = Arc::new(InFlight::default());
        let c = f.claim("h1").expect("first claim");
        assert!(f.claim("h1").is_none(), "the other path must skip it");
        assert!(f.claim("h2").is_some(), "other ids are independent");
        drop(c);
        assert!(!f.is_active("h1"));
        assert!(
            f.claim("h1").is_some(),
            "released without an ack: still queued, may be dispatched again"
        );
    }

    #[test]
    fn an_acked_id_is_not_dispatched_again() {
        let f = Arc::new(InFlight::default());
        f.claim("h1").unwrap().finish(true);
        assert!(
            f.claim("h1").is_none(),
            "a copy fetched before the ack landed is skipped"
        );
        f.claim("h2").unwrap().finish(false);
        assert!(f.claim("h2").is_some(), "not acked: may be redelivered");
    }

    #[test]
    fn the_recent_set_is_bounded() {
        let f = Arc::new(InFlight::default());
        for i in 0..(RECENT_CAPACITY + 10) {
            f.claim(&format!("h{i}")).unwrap().finish(true);
        }
        let inner = f.lock();
        assert_eq!(inner.recent.len(), RECENT_CAPACITY);
        assert_eq!(inner.recent_order.len(), RECENT_CAPACITY);
        assert!(!inner.recent.contains("h0"), "oldest evicted");
    }
}
