//! Reliable messaging delivery layer over the [`MessageTransport`] contract.
//!
//! The layer turns a transport's *truthful send* into effectively-once delivery
//! for delivery-critical (`Guaranteed`) traffic, independent of the wire. This
//! crate's first increment is the **durable outbox** ([`outbox`]) and its
//! **drain** ([`drain`]):
//!
//! - an [`OutboxEntry`] is a transport-independent unit of delivery-critical
//!   work, keyed by an idempotency key, with a lifecycle
//!   `Queued → Sent → Delivered | Unconfirmed | Failed`;
//! - an [`OutboxStore`] persists entries (an in-memory store ships here;
//!   services back it with a durable store);
//! - [`drain_once`] / [`drain_loop`] pick due entries, send them over a
//!   [`MessageTransport`], mark `Sent` on hop-acceptance (and stop re-sending —
//!   the mediator owns redelivery), or retry with exponential backoff.
//!
//! End-to-end confirmation (`Sent → Delivered`) and the `MessagingService`
//! front-end build on this in later increments.
//!
//! [`MessageTransport`]: affinidi_messaging_core::MessageTransport

pub mod confirm;
/// The `MessageTransport` conformance suite (design §11), parameterized over the
/// wire. Available under the `conformance` feature (and in tests).
#[cfg(any(test, feature = "conformance"))]
pub mod conformance;
pub mod drain;
pub mod outbox;
pub mod receipt;
pub mod service;

pub use confirm::{
    ConfirmReport, DrainPollReport, Escalation, ExpiryEscalator, confirm_delivered,
    confirmation_loop, confirmation_loop_with, outbox_drain_loop, poll_outbox_drain,
    sweep_confirmations, sweep_confirmations_with,
};
pub use drain::{DrainReport, drain_loop, drain_once};
pub use outbox::{InMemoryOutboxStore, Key, OutboxEntry, OutboxError, OutboxState, OutboxStore};
pub use receipt::{RECEIPT_TYPE, Receipt, ReceiptPacker, receipt_key, receipt_of};
pub use service::{Delivery, MessagingService, MessagingStatus, Sent};
