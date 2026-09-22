//! What became of each forward, for whoever is watching.
//!
//! The processor learns the fate of every relay attempt — accepted by the
//! peer, failed and queued for retry, abandoned, or expired in the queue — but
//! the mediator's traffic monitor lives in the mediator crate, which this one
//! cannot depend on. So, like [`SystemMessagePacker`](super::SystemMessagePacker),
//! the observer is injected: [`ForwardingProcessor::with_observer`](super::ForwardingProcessor::with_observer).
//! The standalone `forwarding_processor` binary has no monitor and supplies
//! none.
//!
//! Observing must be cheap and must never fail or block: it is called inline
//! on the delivery path, once per entry per attempt.

use crate::store::types::ForwardQueueEntry;

/// How a relay reached the peer mediator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ForwardTransport {
    Rest,
    Websocket,
}

/// The fate of one attempt to relay one queued entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ForwardOutcome {
    /// The peer accepted it: a 2xx over REST, or a positive relay-ack over a
    /// websocket. The entry has left the queue.
    Relayed { transport: ForwardTransport },
    /// This attempt failed, and the entry is queued again. `attempt` counts
    /// from 1; the entry is abandoned after `max_retries` retries.
    Retrying { attempt: u32, max_retries: u32 },
    /// The entry was dropped undelivered: its retries are exhausted (the
    /// sender is then sent a problem report, when the processor can pack one),
    /// or it could not be queued again for its retry.
    Abandoned { attempts: u32 },
    /// The entry outlived its expiry before it could be relayed, and was
    /// dropped.
    Expired,
}

/// Told the outcome of every relay attempt.
pub trait ForwardingObserver: Send + Sync {
    fn observe(&self, entry: &ForwardQueueEntry, outcome: ForwardOutcome);
}
