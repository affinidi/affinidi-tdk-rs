//! Acks that could not be delivered when they fell due, and the counters that
//! make a message held-but-never-released visible.
//!
//! # The failure this closes
//!
//! An ack is a delete at the mediator, and the dispatcher issues it over the
//! transport the message arrived on. Two paths ended with no ack and no
//! durable trace of that:
//!
//! - **the source transport was gone.** A transport removed or torn down
//!   between forwarding an inbound and acking it left the ack with nowhere to
//!   go. It was logged at `debug` and dropped — which is to say, in a default
//!   deployment, not recorded at all.
//! - **the ack call failed.** Logged at `warn` and dropped, with no retry.
//!
//! Neither loses the message: the mediator still holds it and offers it again
//! on the next pickup, where it is handled and acked. But until that happens
//! the message stays queued **against its sender**, counting toward the
//! sender's queue-depth limits. A sender can therefore be refused over
//! messages its recipient has already processed, which is the shape reported
//! upstream as a stuck outbound queue that never drained.
//!
//! # What this does instead
//!
//! An ack that cannot be delivered is parked and retried, and everything that
//! happens to it is counted.
//!
//! Retries are same-transport-only. It is tempting to ack over any transport
//! that happens to be installed, and wrong: a transport id identifies a wire
//! to a particular mediator, and an ack is a delete of a message id *at that
//! mediator*. Replaying it elsewhere would at best do nothing and at worst
//! delete an unrelated message that happens to share an id. A transport
//! reinstalled under the same id — the ordinary reconnect — is the same wire
//! and does settle the parked ack, which is the case that matters.
//!
//! Both bounds are deliberate and neither loses data:
//!
//! - the queue holds at most [`MAX_PENDING`]; past that the **oldest** entry is
//!   dropped, because the oldest is the one most likely to have been settled
//!   already by a redelivery;
//! - an entry older than [`MAX_AGE`] is abandoned.
//!
//! Abandoning is safe for the same reason the original bug was survivable: the
//! mediator still holds the message and will offer it again. What is *not*
//! safe is abandoning it silently, so every abandonment is counted and logged.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use affinidi_messaging_core::transport::InboundAck;
use tokio::time::Instant;

/// Maximum parked acks. Past this the oldest is dropped.
pub(crate) const MAX_PENDING: usize = 4_096;

/// How often parked acks are retried.
pub(crate) const RETRY_INTERVAL: Duration = Duration::from_secs(2);

/// How long an ack is retried before being abandoned.
pub(crate) const MAX_AGE: Duration = Duration::from_secs(300);

/// An ack that had nowhere to go when it fell due.
#[derive(Debug, Clone)]
struct PendingAck {
    /// The transport it must go back over. Never substituted — see the module
    /// docs on why an ack is not portable between transports.
    src_id: String,
    ack: InboundAck,
    /// When it first failed, for the [`MAX_AGE`] bound.
    first_failed: Instant,
    attempts: u32,
}

/// A snapshot of ack health.
///
/// Exposed rather than published as metrics because this crate is a library
/// with a deliberately small dependency set; a host that scrapes Prometheus
/// reads these and publishes them under its own names. The counters are
/// cumulative since process start, except `pending`, which is a depth.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AckStats {
    /// Acks delivered on the first attempt.
    pub acked: u64,
    /// Acks parked because the transport was gone or the call failed.
    ///
    /// Non-zero is not itself a fault — a transport reconnecting under load
    /// produces it — but it should be matched by `settled` shortly after.
    pub deferred: u64,
    /// Parked acks later delivered successfully.
    pub settled: u64,
    /// Parked acks given up on after [`MAX_AGE`].
    ///
    /// **The number that matters.** Each one is a message the recipient
    /// processed that is still queued against its sender until the mediator
    /// expires it or a redelivery settles it. Sustained non-zero means senders
    /// are accumulating queue depth for work that is already done.
    pub abandoned: u64,
    /// Parked acks discarded because the queue was full.
    pub overflowed: u64,
    /// Inbound messages that reached no consumer and so were deliberately
    /// **not** acked, leaving the mediator to redeliver them.
    ///
    /// Distinct from the others: this is the contract working, not a failure.
    /// It is counted because "correct and invisible" is how a startup ordering
    /// bug survives — a consumer that never subscribes produces a steady climb
    /// here and nothing else.
    pub no_consumer: u64,
    /// Acks parked right now.
    pub pending: u64,
}

/// Parked acks plus the counters describing what has happened to acks overall.
#[derive(Debug, Default)]
pub(crate) struct AckQueue {
    queue: Mutex<VecDeque<PendingAck>>,
    acked: AtomicU64,
    deferred: AtomicU64,
    settled: AtomicU64,
    abandoned: AtomicU64,
    overflowed: AtomicU64,
    no_consumer: AtomicU64,
}

impl AckQueue {
    pub(crate) fn record_acked(&self) {
        self.acked.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_no_consumer(&self) {
        self.no_consumer.fetch_add(1, Ordering::Relaxed);
    }

    /// Park an ack for retry. Drops the oldest entry when full.
    pub(crate) fn park(&self, src_id: &str, ack: InboundAck) {
        self.deferred.fetch_add(1, Ordering::Relaxed);
        let mut queue = self.queue.lock().expect("pending-ack mutex");
        if queue.len() >= MAX_PENDING {
            // Oldest first: it is the entry most likely already settled by a
            // redelivery, and dropping the newest would discard the ack for
            // the message most recently handled.
            queue.pop_front();
            self.overflowed.fetch_add(1, Ordering::Relaxed);
        }
        queue.push_back(PendingAck {
            src_id: src_id.to_string(),
            ack,
            first_failed: Instant::now(),
            attempts: 0,
        });
    }

    /// Take everything currently parked, for a retry pass.
    fn take_all(&self) -> Vec<PendingAck> {
        self.queue
            .lock()
            .expect("pending-ack mutex")
            .drain(..)
            .collect()
    }

    /// Put an entry back after a failed retry.
    fn requeue(&self, mut entry: PendingAck) {
        entry.attempts += 1;
        let mut queue = self.queue.lock().expect("pending-ack mutex");
        if queue.len() >= MAX_PENDING {
            queue.pop_front();
            self.overflowed.fetch_add(1, Ordering::Relaxed);
        }
        queue.push_back(entry);
    }

    fn record_settled(&self) {
        self.settled.fetch_add(1, Ordering::Relaxed);
    }

    fn record_abandoned(&self) {
        self.abandoned.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn stats(&self) -> AckStats {
        AckStats {
            acked: self.acked.load(Ordering::Relaxed),
            deferred: self.deferred.load(Ordering::Relaxed),
            settled: self.settled.load(Ordering::Relaxed),
            abandoned: self.abandoned.load(Ordering::Relaxed),
            overflowed: self.overflowed.load(Ordering::Relaxed),
            no_consumer: self.no_consumer.load(Ordering::Relaxed),
            pending: self.queue.lock().expect("pending-ack mutex").len() as u64,
        }
    }
}

/// One retry pass. `attempt` acks over the transport with the given id, or
/// yields `None` when that transport is not currently installed.
///
/// Split from the task loop, and taking the attempt as a closure, so it can be
/// driven directly in tests without waiting on a timer or building a transport.
pub(crate) async fn retry_pass<F, Fut>(queue: &AckQueue, now: Instant, attempt: F)
where
    F: Fn(&str, InboundAck) -> Option<Fut>,
    Fut: std::future::Future<Output = Result<(), affinidi_messaging_core::error::MessagingError>>,
{
    for entry in queue.take_all() {
        // Age is checked before the attempt, so an entry that has been parked
        // too long is abandoned rather than retried once more and then aged
        // out — the log then names the last thing that happened to it.
        if now.duration_since(entry.first_failed) >= MAX_AGE {
            queue.record_abandoned();
            tracing::warn!(
                transport = %entry.src_id,
                attempts = entry.attempts,
                "giving up on an ack after {MAX_AGE:?} — the mediator still holds this \
                 message and will offer it again, but until then it stays queued against \
                 its sender"
            );
            continue;
        }

        match attempt(&entry.src_id, entry.ack.clone()) {
            Some(fut) => match fut.await {
                Ok(()) => {
                    queue.record_settled();
                    tracing::debug!(
                        transport = %entry.src_id,
                        attempts = entry.attempts,
                        "deferred ack settled"
                    );
                }
                Err(e) => {
                    tracing::debug!(
                        transport = %entry.src_id,
                        error = %e,
                        "deferred ack failed again; still parked"
                    );
                    queue.requeue(entry);
                }
            },
            // Transport still not installed. Keep it: a reconnect reinstalls
            // the same id and settles it.
            None => queue.requeue(entry),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_messaging_core::error::MessagingError;

    fn ack(id: &str) -> InboundAck {
        InboundAck(id.to_string())
    }

    #[test]
    fn parking_counts_as_deferred_and_shows_as_pending() {
        let q = AckQueue::default();
        q.park("t1", ack("m1"));
        let s = q.stats();
        assert_eq!(s.deferred, 1);
        assert_eq!(s.pending, 1);
        assert_eq!(s.settled, 0);
    }

    #[test]
    fn a_full_queue_drops_the_oldest_and_says_so() {
        let q = AckQueue::default();
        for i in 0..MAX_PENDING + 5 {
            q.park("t1", ack(&format!("m{i}")));
        }
        let s = q.stats();
        assert_eq!(s.pending as usize, MAX_PENDING);
        assert_eq!(s.overflowed, 5);
        // Nothing is lost silently: every park is still counted.
        assert_eq!(s.deferred as usize, MAX_PENDING + 5);
    }

    #[tokio::test]
    async fn a_retry_settles_once_the_transport_is_back() {
        let q = AckQueue::default();
        q.park("t1", ack("m1"));

        // Transport still missing: the entry stays parked, not abandoned.
        retry_pass(&q, Instant::now(), |_, _| {
            None::<std::future::Ready<Result<(), MessagingError>>>
        })
        .await;
        assert_eq!(q.stats().pending, 1);
        assert_eq!(q.stats().settled, 0);

        // Transport reinstalled under the same id: settled and gone.
        retry_pass(&q, Instant::now(), |_, _| {
            Some(std::future::ready(Ok::<(), MessagingError>(())))
        })
        .await;
        let s = q.stats();
        assert_eq!(s.pending, 0);
        assert_eq!(s.settled, 1);
        assert_eq!(s.abandoned, 0);
    }

    #[tokio::test]
    async fn a_failing_ack_stays_parked_rather_than_being_lost() {
        let q = AckQueue::default();
        q.park("t1", ack("m1"));
        retry_pass(&q, Instant::now(), |_, _| {
            Some(std::future::ready(Err::<(), MessagingError>(
                MessagingError::Transport("still down".into()),
            )))
        })
        .await;
        let s = q.stats();
        assert_eq!(s.pending, 1, "a failed retry must not discard the ack");
        assert_eq!(s.settled, 0);
        assert_eq!(s.abandoned, 0);
    }

    #[tokio::test]
    async fn an_ack_older_than_the_bound_is_abandoned_and_counted() {
        let q = AckQueue::default();
        q.park("t1", ack("m1"));
        // Far enough past the bound that the entry is aged out.
        let later = Instant::now() + MAX_AGE + Duration::from_secs(1);
        retry_pass(&q, later, |_, _| {
            Some(std::future::ready(Ok::<(), MessagingError>(())))
        })
        .await;
        let s = q.stats();
        assert_eq!(s.pending, 0);
        assert_eq!(s.abandoned, 1, "abandoning must be counted, never silent");
        assert_eq!(s.settled, 0, "an aged-out entry is not a success");
    }

    /// The contract from #710 is not a failure and must not be counted as one,
    /// but it must be counted: a consumer that never subscribes otherwise
    /// produces no signal at all.
    #[test]
    fn no_consumer_is_counted_separately_from_every_failure() {
        let q = AckQueue::default();
        q.record_no_consumer();
        q.record_no_consumer();
        let s = q.stats();
        assert_eq!(s.no_consumer, 2);
        assert_eq!(s.deferred, 0);
        assert_eq!(s.abandoned, 0);
        assert_eq!(s.pending, 0);
    }

    #[test]
    fn a_successful_ack_is_counted_without_touching_the_queue() {
        let q = AckQueue::default();
        q.record_acked();
        let s = q.stats();
        assert_eq!(s.acked, 1);
        assert_eq!(s.pending, 0);
        assert_eq!(s.deferred, 0);
    }
}
