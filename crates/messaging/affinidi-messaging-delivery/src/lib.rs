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
pub mod drain;
pub mod outbox;
pub mod service;

pub use confirm::{ConfirmReport, confirm_delivered, confirmation_loop, sweep_confirmations};
pub use drain::{DrainReport, drain_loop, drain_once};
pub use outbox::{InMemoryOutboxStore, Key, OutboxEntry, OutboxError, OutboxState, OutboxStore};
pub use service::{Delivery, MessagingService, MessagingStatus, Sent};
