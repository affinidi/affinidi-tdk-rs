//! Global byte budget for WebSocket live-delivery send queues.
//!
//! # Why a byte budget rather than a slot count
//!
//! Each live WebSocket connection has an mpsc queue of messages waiting to be
//! written to the socket. Bounding that queue by *slots* bounds nothing useful:
//! a slot holds a whole packed message, so the real cost is
//! `slots × message_size × connections`. At the shipped defaults that is
//! `5 × 10 MiB × 10 000` — half a terabyte of headroom for a buffer nobody
//! intends to be large. The slot count says nothing about bytes, which is the
//! resource that actually runs out.
//!
//! So the queues share one pool of *bytes*. A message reserves its own length
//! from the pool before it is queued and releases it once the connection's
//! writer has taken it off the queue. The aggregate across every connection is
//! therefore capped at `total_bytes`, no matter how many connections exist or
//! how big their messages are. Per-connection depth is still capped by the mpsc
//! slot count, so one client cannot drain the whole pool by itself.
//!
//! # Why reservation failure drops the notification
//!
//! Reserving is non-blocking and gives up immediately when the pool is
//! exhausted. It must be: the streaming task dispatches to every DID from a
//! single loop, so *awaiting* a slow client's queue there would head-of-line
//! block live delivery for every other DID on the mediator.
//!
//! Dropping is safe because live delivery is an optimisation, not the delivery
//! guarantee. The message is already durably in the recipient's inbox before it
//! is ever published here — a dropped push just means the client picks it up on
//! its next poll or on inbox redelivery when it reconnects. This is the same
//! contract the pub/sub layer already relies on when a subscriber lags.

use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// A byte reservation held for as long as a message sits in a connection's send
/// queue. Dropping it returns the bytes to the pool, so the queue item must own
/// it — see [`crate::tasks::websocket_streaming::QueuedCommand`].
pub type SendPermit = OwnedSemaphorePermit;

/// Shared, cloneable handle to the global WebSocket send-buffer pool.
#[derive(Clone)]
pub struct WsSendBudget {
    pool: Arc<Semaphore>,
    total_bytes: usize,
}

impl WsSendBudget {
    /// `total_bytes` is the aggregate ceiling across *all* live connections.
    ///
    /// Clamped to `Semaphore::MAX_PERMITS`, which is far above any sane budget;
    /// the clamp exists so a misconfigured value degrades to "very large" rather
    /// than panicking inside tokio.
    pub fn new(total_bytes: usize) -> Self {
        let total_bytes = total_bytes.min(Semaphore::MAX_PERMITS);
        Self {
            pool: Arc::new(Semaphore::new(total_bytes)),
            total_bytes,
        }
    }

    /// Reserve `bytes` from the pool, or return `None` if it cannot be covered
    /// right now. Never blocks.
    ///
    /// A message larger than the entire pool would otherwise be unsendable
    /// forever, so it is clamped to the full budget: it can still go out, but
    /// only when the pool is completely free. That keeps an oversized message
    /// stalled rather than permanently undeliverable, and `message_size` is
    /// enforced at ingress anyway, so it should not arise unless the budget is
    /// configured below `message_size`.
    pub fn try_reserve(&self, bytes: usize) -> Option<SendPermit> {
        let want = bytes.clamp(1, self.total_bytes);
        // `try_acquire_many_owned` takes a u32; the clamp above already bounds
        // `want` by the pool size, which is itself a u32-safe permit count.
        let want = u32::try_from(want).unwrap_or(u32::MAX);
        self.pool.clone().try_acquire_many_owned(want).ok()
    }

    /// Bytes currently available. Diagnostics and metrics only.
    pub fn available_bytes(&self) -> usize {
        self.pool.available_permits()
    }

    /// The configured ceiling.
    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reservations_are_capped_by_the_pool() {
        let budget = WsSendBudget::new(1000);

        let a = budget.try_reserve(600).expect("first fits");
        assert_eq!(budget.available_bytes(), 400);

        // 600 + 600 > 1000, so the second must be refused rather than queued.
        assert!(
            budget.try_reserve(600).is_none(),
            "pool must refuse a reservation it cannot cover"
        );

        // Releasing the first makes room again.
        drop(a);
        assert_eq!(budget.available_bytes(), 1000);
        assert!(budget.try_reserve(600).is_some());
    }

    #[test]
    fn oversized_message_clamps_to_the_whole_pool() {
        let budget = WsSendBudget::new(100);

        // Larger than the entire pool: allowed, but only by taking all of it.
        let p = budget.try_reserve(10_000).expect("clamps to the full pool");
        assert_eq!(budget.available_bytes(), 0);
        assert!(budget.try_reserve(1).is_none());

        drop(p);
        assert_eq!(budget.available_bytes(), 100);
    }

    #[test]
    fn permits_release_when_the_queue_item_drops() {
        let budget = WsSendBudget::new(500);
        {
            let _held = budget.try_reserve(500).expect("fits");
            assert_eq!(budget.available_bytes(), 0);
        }
        // Scope exit == the websocket writer consumed the item.
        assert_eq!(budget.available_bytes(), 500);
    }
}
