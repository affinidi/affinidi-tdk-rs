//! Reliable messaging delivery layer over the [`MessageTransport`] contract.
//!
//! The layer turns a transport's *truthful send* into tracked, retried
//! delivery for delivery-critical (`Guaranteed`) traffic, independent of the
//! wire (DIDComm, TSP, REST). Its parts:
//!
//! - [`outbox`] — an [`OutboxEntry`] is a transport-independent unit of
//!   delivery-critical work, keyed by an idempotency key, with a lifecycle
//!   `Queued → Sent → Delivered | Unconfirmed | Failed`. An [`OutboxStore`]
//!   persists entries; [`InMemoryOutboxStore`] ships here, and services back it
//!   with a durable store. Every state change is a guarded
//!   [`OutboxStore::transition`], so concurrent loops cannot undo each other.
//! - [`drain`] — [`drain_once`] / [`drain_loop`] send due entries over a
//!   transport, mark them `Sent` on hop-acceptance (and stop re-sending: the
//!   mediator owns redelivery), or retry with backoff.
//! - [`confirm`] — end-to-end evidence (`Sent → Delivered`), the expiry sweep
//!   ([`confirmation_loop`] and its variants), and the mediator status poll
//!   ([`outbox_drain_loop`]).
//! - [`receipt`] — `messaging/receipt/0.1` delivery receipts: consumed by every
//!   [`MessagingService`], emitted by one built
//!   [`with_receipts`](MessagingService::with_receipts) over a
//!   [`ReceiptPacker`].
//! - [`reap`] — [`reap_loop`] / [`reap_terminal`] remove settled entries once
//!   their retention has passed.
//! - [`service`] — [`MessagingService`], the front-end: `send` / `request` /
//!   `subscribe` over N transports, with one inbound dispatcher that routes,
//!   acks once after handoff, and consumes receipts.
//! - [`inbox`] — the receiving side's [`InboxStore`]: an unsolicited message
//!   is recorded before it is acked or receipted, and a re-sent copy of one
//!   already recorded is acked and receipted without reaching subscribers
//!   again. [`InMemoryInboxStore`] is the default; back it with a durable
//!   store ([`MessagingService::with_inbox`]) for a receipt to mean the
//!   message survives a restart.
//!
//! # Wiring
//!
//! [`MessagingService::new`] starts only the inbound dispatcher and the ack
//! retry. **A `Guaranteed` send transmits nothing until the host runs a drain
//! loop**, and entries settle only if the confirmation, status-poll and reap
//! loops run too. A complete single-transport service:
//!
//! ```no_run
//! use std::sync::Arc;
//! use std::time::Duration;
//!
//! use affinidi_messaging_core::MessageTransport;
//! use affinidi_messaging_delivery::{
//!     Escalation, ExpiryEscalator, InMemoryOutboxStore, MessagingService, OutboxEntry,
//!     OutboxStore, ReceiptPacker, TERMINAL_RETENTION, confirmation_loop_with_reach,
//!     drain_loop, outbox_drain_loop, reap_loop,
//! };
//!
//! /// Settle every expired entry `Unconfirmed`; a real service may re-send
//! /// over an alternate binding instead.
//! struct NoRebind;
//!
//! #[async_trait::async_trait]
//! impl ExpiryEscalator for NoRebind {
//!     async fn escalate(&self, _entry: &OutboxEntry) -> Escalation {
//!         Escalation::Unconfirmed
//!     }
//! }
//!
//! fn start(
//!     transport: Arc<dyn MessageTransport>,
//!     packer: Arc<dyn ReceiptPacker>,
//! ) -> MessagingService {
//!     let store: Arc<dyn OutboxStore> = Arc::new(InMemoryOutboxStore::new());
//!     let svc = MessagingService::with_receipts(transport, store.clone(), packer);
//!
//!     // Send queued entries over whatever transport is primary.
//!     tokio::spawn(drain_loop(store.clone(), svc.primary_handle(), Duration::from_secs(1)));
//!     // Settle entries whose window has passed (and fail queued ones that
//!     // never went out).
//!     tokio::spawn(confirmation_loop_with_reach(
//!         store.clone(),
//!         Duration::from_secs(10),
//!         Arc::new(NoRebind),
//!         svc.receipt_reach(),
//!     ));
//!     // Ask the sender's mediator what became of messages it still holds.
//!     tokio::spawn(outbox_drain_loop(svc.primary_handle(), store.clone(), Duration::from_secs(10)));
//!     // Remove settled entries after their retention.
//!     tokio::spawn(reap_loop(store, Duration::from_secs(3600), TERMINAL_RETENTION));
//!     svc
//! }
//! ```
//!
//! A multi-identity service runs [`drain_loop_via`] per transport for entries
//! sent with [`MessagingService::send_via`].
//!
//! # What the layer does not do
//!
//! - **Deduplicate everything inbound.** The [`inbox`] dedups application
//!   messages from an authenticated sender, by the sender's idempotency key or
//!   message id. A message without an authenticated sender, a relationship
//!   control message, a reply handed to a `request` waiter, and a message that
//!   reached only some subscribers before being offered again can still reach
//!   the application twice (see [`MessagingService::subscribe`]).
//! - **Persist inbound messages durably by default.** The default
//!   [`InMemoryInboxStore`] holds records for the life of the process only; a
//!   host that needs a receipt to survive a restart supplies a durable
//!   [`InboxStore`] and calls [`MessagingService::redeliver_pending`] after
//!   subscribing at startup.
//!
//! [`MessageTransport`]: affinidi_messaging_core::MessageTransport

/// Acks that could not be delivered when they fell due, and the counters that
/// make a message held-but-never-released visible.
pub mod ack;
mod clock;
pub mod confirm;
/// The `MessageTransport` conformance suite (design §11), parameterized over the
/// wire. Available under the `conformance` feature (and in tests).
#[cfg(any(test, feature = "conformance"))]
pub mod conformance;
pub mod drain;
/// The receiving side's record of inbound messages: durable handoff and
/// receiver-side dedup.
pub mod inbox;
pub mod outbox;
/// Which recipients are known to send delivery receipts (VTI-TRN-064).
pub mod reach;
/// Removing outbox entries that are finished with — the trait had no way to
/// remove anything, so a keyspace grew for the life of the deployment.
pub mod reap;
pub mod receipt;
pub mod service;

pub use ack::AckStats;
pub use confirm::{
    ConfirmReport, DrainPollReport, Escalation, ExpiryEscalator, StatusPacer, confirm_delivered,
    confirm_delivered_by, confirmation_loop, confirmation_loop_with, confirmation_loop_with_reach,
    outbox_drain_loop, poll_outbox_drain, poll_outbox_drain_paced, sweep_confirmations,
    sweep_confirmations_with, sweep_confirmations_with_reach,
};
pub use drain::{DrainReport, drain_loop, drain_loop_via, drain_once, drain_once_via};
pub use inbox::{
    InMemoryInboxStore, InboxError, InboxKey, InboxRecord, InboxState, InboxStore, Recorded,
};
pub use outbox::{
    InMemoryOutboxStore, Key, OutboxEntry, OutboxError, OutboxState, OutboxStore, Transition,
    UnconfirmedReason,
};
pub use reach::ReceiptReach;
pub use reap::{ReapReport, TERMINAL_RETENTION, reap_loop, reap_terminal};
pub use receipt::{
    PackedReceipt, RECEIPT_TASK_TYPE, RECEIPT_TYPE, Receipt, ReceiptPacker, ReceiptRequest,
    receipt_key, receipt_of,
};
pub use service::{Delivery, MessagingService, MessagingStatus, Sent};
