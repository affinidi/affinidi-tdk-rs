//! The inbox: the receiving side's record of what it has taken from a
//! transport, for durable handoff and receiver-side dedup (#1140).
//!
//! The dispatcher of a [`MessagingService`](crate::MessagingService) records
//! an unsolicited application message from an authenticated sender in an
//! [`InboxStore`] **before** it acks the message (a delete at the mediator) and
//! before it sends any delivery receipt the message asked for. So with a
//! durable store:
//!
//! - **A receipt means the message is recorded.** The sender's entry settles
//!   `Delivered` only for a message this receiver can still produce after a
//!   restart. A store that cannot record leaves the message unacked and
//!   unreceipted, for the mediator to offer again.
//! - **A re-send is not delivered twice.** The record is keyed by the sender
//!   and the sender's idempotency key (the delivery id it stamped to ask for a
//!   receipt) or, when it asked for none, the message id. A copy of a message
//!   whose record is [`Consumed`](InboxState::Consumed), or which is still
//!   queued to a subscriber in this process, is acked and receipted again (the
//!   sender evidently missed the first receipt) and not handed to subscribers.
//! - **A message buffered when the process stops is not lost.** A record stays
//!   [`Pending`](InboxState::Pending) until every subscriber it was queued to
//!   has taken it from its `subscribe()` stream.
//!   [`MessagingService::redeliver_pending`](crate::MessagingService::redeliver_pending)
//!   hands pending records to the current subscribers — call it after
//!   subscribing at startup.
//!
//! [`InMemoryInboxStore`] is the default. It dedups re-sends for the life of
//! the process, but it is not durable: with it, "recorded" lasts only as long
//! as the process. A service that sends receipts backs the inbox with a
//! durable store ([`MessagingService::with_inbox`](crate::MessagingService::with_inbox)).
//!
//! Records are not removed by the layer. A consumed record is the dedup
//! anchor for later copies, so it must outlive any duplicate that can still
//! arrive (the sender's delivery window plus the mediator's retention); a host
//! removes older ones with [`InboxStore::reap_consumed`].

use std::collections::HashMap;
use std::sync::Mutex;

use affinidi_messaging_core::{Inbound, InboundAck, InboundKind, Protocol, ReceivedMessage};
use serde::{Deserialize, Serialize};

/// What identifies an inbound message for dedup: who sent it, and the id the
/// sender gave it.
///
/// Scoped by the sender because an idempotency key is chosen by its sender: two
/// senders may use the same one, and one sender must not be able to suppress
/// another's message by reusing its key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct InboxKey {
    /// The transport-authenticated sender.
    pub sender: String,
    /// The sender's idempotency key (its delivery id) or, when the message
    /// asked for no receipt, the message id.
    pub id: String,
}

impl InboxKey {
    /// A key for `id` from `sender`.
    pub fn new(sender: impl Into<String>, id: impl Into<String>) -> Self {
        Self {
            sender: sender.into(),
            id: id.into(),
        }
    }

    /// The key the dispatcher records `inbound` under, or `None` when it does
    /// not go through the inbox: a message without a transport-authenticated
    /// sender (anyone could forge its id), or one that is not application
    /// traffic (relationship control is recorded by its transport).
    pub fn of(inbound: &Inbound) -> Option<Self> {
        if inbound.kind != InboundKind::Application || !inbound.message.verified {
            return None;
        }
        let sender = inbound.message.sender.as_deref()?;
        let id = inbound
            .delivery_id
            .as_deref()
            .unwrap_or(inbound.message.id.as_str());
        Some(Self::new(sender, id))
    }
}

/// Where a recorded inbound message is in its handoff to the application.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum InboxState {
    /// Recorded (and acked to the transport), not yet taken by every
    /// subscriber it was queued to. Redelivered by
    /// [`MessagingService::redeliver_pending`](crate::MessagingService::redeliver_pending)
    /// and when a copy arrives that no subscriber in this process holds.
    Pending,
    /// Taken from the `subscribe()` stream of every subscriber it was queued
    /// to. A later copy is acked and receipted, not delivered.
    Consumed,
}

/// One inbound message as the inbox records it — everything needed to hand it
/// to a subscriber again after a restart.
///
/// `Serialize`/`Deserialize` so a durable store can persist it in any format.
/// `#[non_exhaustive]`: build one with [`InboxRecord::from_inbound`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct InboxRecord {
    /// The dedup key.
    pub key: InboxKey,
    /// The message id ([`ReceivedMessage::id`]).
    pub message_id: String,
    /// The recipient ([`ReceivedMessage::recipient`]).
    pub recipient: String,
    /// The decrypted payload.
    pub payload: Vec<u8>,
    /// The protocol that produced the message.
    pub protocol: Protocol,
    /// Whether the message was encrypted.
    pub encrypted: bool,
    /// The thread id, when present.
    pub thread_id: Option<String>,
    /// The delivery id the sender stamped to ask for a receipt, when present.
    pub delivery_id: Option<String>,
    /// The transport's ack handle for the original delivery. Already acked by
    /// the time a subscriber sees the record; kept so a redelivered
    /// [`Inbound`] carries the handle it arrived with.
    pub ack: String,
    /// When the dispatcher recorded it, in Unix milliseconds.
    pub received_at_ms: u64,
    /// Where it is in its handoff.
    pub state: InboxState,
}

impl InboxRecord {
    /// A [`Pending`](InboxState::Pending) record of `inbound` under `key`,
    /// received at `received_at_ms`.
    pub fn from_inbound(key: InboxKey, inbound: &Inbound, received_at_ms: u64) -> Self {
        Self {
            key,
            message_id: inbound.message.id.clone(),
            recipient: inbound.message.recipient.clone(),
            payload: inbound.message.payload.clone(),
            protocol: inbound.message.protocol,
            encrypted: inbound.message.encrypted,
            thread_id: inbound.thread_id.clone(),
            delivery_id: inbound.delivery_id.clone(),
            ack: inbound.ack.0.clone(),
            received_at_ms,
            state: InboxState::Pending,
        }
    }

    /// The [`Inbound`] a subscriber is handed for this record. Its sender is
    /// the authenticated sender it was recorded under.
    pub fn to_inbound(&self) -> Inbound {
        let message = ReceivedMessage {
            id: self.message_id.clone(),
            sender: Some(self.key.sender.clone()),
            recipient: self.recipient.clone(),
            payload: self.payload.clone(),
            protocol: self.protocol,
            verified: true,
            encrypted: self.encrypted,
        };
        let inbound = Inbound::new(
            message,
            self.thread_id.clone(),
            InboundAck(self.ack.clone()),
        );
        match self.delivery_id.as_deref() {
            Some(id) => inbound.with_delivery_id(id),
            None => inbound,
        }
    }
}

/// What [`InboxStore::record`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Recorded {
    /// No record existed; this one was stored.
    New,
    /// A record already existed under the key and was left unchanged. Its
    /// state says whether it was handed to the application already.
    Duplicate(InboxState),
}

/// Failures of an [`InboxStore`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum InboxError {
    /// The backing store failed (I/O, serialization, lock poisoning, …).
    #[error("inbox store backend error: {0}")]
    Backend(String),
}

/// Storage for the inbox. Services implement this over a durable store (the
/// same one their [`OutboxStore`](crate::OutboxStore) uses, typically);
/// [`InMemoryInboxStore`] is the default and is not durable.
///
/// # Implementing a durable store
///
/// [`record`](Self::record) must be atomic: insert-if-absent, returning the
/// existing record's state when there is one. It must also be durable by the
/// time it returns — the dispatcher acks the message (deleting the
/// mediator's copy) and sends its receipt as soon as it does. The conformance
/// checks in [`conformance`] exercise the contract.
#[async_trait::async_trait]
pub trait InboxStore: Send + Sync {
    /// Store `record` unless one exists under its key. Returns
    /// [`Recorded::New`] if it was stored, or the existing record's state.
    async fn record(&self, record: InboxRecord) -> Result<Recorded, InboxError>;

    /// The record under `key`, if any.
    async fn get(&self, key: &InboxKey) -> Result<Option<InboxRecord>, InboxError>;

    /// Mark the record under `key` [`Consumed`](InboxState::Consumed). Returns
    /// whether a record was found.
    async fn mark_consumed(&self, key: &InboxKey) -> Result<bool, InboxError>;

    /// Every [`Pending`](InboxState::Pending) record, oldest first.
    async fn pending(&self) -> Result<Vec<InboxRecord>, InboxError>;

    /// Remove [`Consumed`](InboxState::Consumed) records received before
    /// `cutoff_ms` (Unix milliseconds). Returns how many were removed. Pending
    /// records are never removed: they hold messages the application has not
    /// taken.
    async fn reap_consumed(&self, cutoff_ms: u64) -> Result<usize, InboxError>;
}

/// An in-memory [`InboxStore`]: dedups for the life of the process, durable
/// for none of it. The default for a [`MessagingService`](crate::MessagingService).
///
/// Shared through an `Arc`, it outlives a service built over it, which is how
/// the tests model a restart.
#[derive(Debug, Default)]
pub struct InMemoryInboxStore {
    records: Mutex<HashMap<InboxKey, InboxRecord>>,
}

impl InMemoryInboxStore {
    /// A new, empty store.
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, HashMap<InboxKey, InboxRecord>>, InboxError> {
        self.records
            .lock()
            .map_err(|e| InboxError::Backend(format!("inbox lock poisoned: {e}")))
    }
}

#[async_trait::async_trait]
impl InboxStore for InMemoryInboxStore {
    async fn record(&self, record: InboxRecord) -> Result<Recorded, InboxError> {
        let mut records = self.lock()?;
        if let Some(existing) = records.get(&record.key) {
            return Ok(Recorded::Duplicate(existing.state));
        }
        records.insert(record.key.clone(), record);
        Ok(Recorded::New)
    }

    async fn get(&self, key: &InboxKey) -> Result<Option<InboxRecord>, InboxError> {
        Ok(self.lock()?.get(key).cloned())
    }

    async fn mark_consumed(&self, key: &InboxKey) -> Result<bool, InboxError> {
        Ok(match self.lock()?.get_mut(key) {
            Some(record) => {
                record.state = InboxState::Consumed;
                true
            }
            None => false,
        })
    }

    async fn pending(&self) -> Result<Vec<InboxRecord>, InboxError> {
        let mut pending: Vec<InboxRecord> = self
            .lock()?
            .values()
            .filter(|r| r.state == InboxState::Pending)
            .cloned()
            .collect();
        pending.sort_by(|a, b| {
            a.received_at_ms
                .cmp(&b.received_at_ms)
                .then_with(|| a.key.cmp(&b.key))
        });
        Ok(pending)
    }

    async fn reap_consumed(&self, cutoff_ms: u64) -> Result<usize, InboxError> {
        let mut records = self.lock()?;
        let before = records.len();
        records.retain(|_, r| !(r.state == InboxState::Consumed && r.received_at_ms < cutoff_ms));
        Ok(before - records.len())
    }
}

/// Conformance checks for an [`InboxStore`] implementation. Each panics on a
/// violation; run them against a fresh, empty store.
#[cfg(any(test, feature = "conformance"))]
pub mod conformance {
    use super::*;

    fn record(sender: &str, id: &str, at: u64) -> InboxRecord {
        let message = ReceivedMessage {
            id: format!("msg-{id}"),
            sender: Some(sender.to_string()),
            recipient: "did:example:me".to_string(),
            payload: id.as_bytes().to_vec(),
            protocol: Protocol::DIDComm,
            verified: true,
            encrypted: true,
        };
        let inbound = Inbound::new(
            message,
            Some("thid".into()),
            InboundAck(format!("ack-{id}")),
        )
        .with_delivery_id(id);
        let key = InboxKey::of(&inbound).expect("an authenticated application message");
        InboxRecord::from_inbound(key, &inbound, at)
    }

    /// Run every check against `store`, which must start empty.
    pub async fn check_inbox_store(store: &dyn InboxStore) {
        check_record_is_insert_if_absent(store).await;
        check_keys_are_scoped_by_sender(store).await;
        check_consume_and_pending(store).await;
        check_reap_keeps_pending(store).await;
    }

    /// `record` stores a new record and reports a second one under the same
    /// key as a duplicate, leaving the first unchanged.
    pub async fn check_record_is_insert_if_absent(store: &dyn InboxStore) {
        let first = record("did:example:a", "k1", 10);
        assert_eq!(store.record(first.clone()).await.unwrap(), Recorded::New);
        let mut second = first.clone();
        second.payload = b"other".to_vec();
        assert_eq!(
            store.record(second).await.unwrap(),
            Recorded::Duplicate(InboxState::Pending),
            "a second record under one key is a duplicate"
        );
        assert_eq!(
            store.get(&first.key).await.unwrap().as_ref(),
            Some(&first),
            "a duplicate does not replace the record"
        );
    }

    /// The same id from two senders is two records.
    pub async fn check_keys_are_scoped_by_sender(store: &dyn InboxStore) {
        let a = record("did:example:a", "shared", 20);
        let b = record("did:example:b", "shared", 20);
        assert_eq!(store.record(a).await.unwrap(), Recorded::New);
        assert_eq!(
            store.record(b).await.unwrap(),
            Recorded::New,
            "another sender's key does not collide"
        );
    }

    /// `mark_consumed` takes a record out of `pending` and a later `record`
    /// reports it consumed.
    pub async fn check_consume_and_pending(store: &dyn InboxStore) {
        let r = record("did:example:c", "k2", 30);
        store.record(r.clone()).await.unwrap();
        assert!(
            store
                .pending()
                .await
                .unwrap()
                .iter()
                .any(|p| p.key == r.key),
            "a new record is pending"
        );
        assert!(store.mark_consumed(&r.key).await.unwrap());
        assert!(
            !store
                .pending()
                .await
                .unwrap()
                .iter()
                .any(|p| p.key == r.key),
            "a consumed record is not pending"
        );
        assert_eq!(
            store.record(r).await.unwrap(),
            Recorded::Duplicate(InboxState::Consumed)
        );
        assert!(
            !store
                .mark_consumed(&InboxKey::new("did:example:c", "absent"))
                .await
                .unwrap(),
            "marking an absent key finds nothing"
        );
    }

    /// `reap_consumed` removes old consumed records and never a pending one.
    pub async fn check_reap_keeps_pending(store: &dyn InboxStore) {
        let old_consumed = record("did:example:d", "old", 1);
        let old_pending = record("did:example:d", "pending", 1);
        store.record(old_consumed.clone()).await.unwrap();
        store.record(old_pending.clone()).await.unwrap();
        store.mark_consumed(&old_consumed.key).await.unwrap();
        assert!(store.reap_consumed(5).await.unwrap() >= 1);
        assert!(store.get(&old_consumed.key).await.unwrap().is_none());
        assert!(
            store.get(&old_pending.key).await.unwrap().is_some(),
            "a pending record is never reaped"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn in_memory_store_conforms() {
        conformance::check_inbox_store(&InMemoryInboxStore::new()).await;
    }

    #[test]
    fn unauthenticated_or_control_messages_have_no_key() {
        let message = ReceivedMessage {
            id: "m".into(),
            sender: Some("did:example:a".into()),
            recipient: "did:example:me".into(),
            payload: vec![],
            protocol: Protocol::DIDComm,
            verified: false,
            encrypted: true,
        };
        let inbound = Inbound::new(message.clone(), None, InboundAck("a".into()));
        assert!(InboxKey::of(&inbound).is_none(), "unverified sender");

        let verified = ReceivedMessage {
            verified: true,
            ..message
        };
        let inbound = Inbound::new(verified, None, InboundAck("a".into()));
        assert_eq!(
            InboxKey::of(&inbound),
            Some(InboxKey::new("did:example:a", "m")),
            "falls back to the message id without a delivery id"
        );
        let with_id = inbound.with_delivery_id("idem-1");
        assert_eq!(
            InboxKey::of(&with_id),
            Some(InboxKey::new("did:example:a", "idem-1"))
        );
    }

    #[test]
    fn a_record_round_trips_to_the_inbound_it_was_made_from() {
        let message = ReceivedMessage {
            id: "m".into(),
            sender: Some("did:example:a".into()),
            recipient: "did:example:me".into(),
            payload: b"hi".to_vec(),
            protocol: Protocol::TSP,
            verified: true,
            encrypted: false,
        };
        let inbound =
            Inbound::new(message, Some("t".into()), InboundAck("ack".into())).with_delivery_id("d");
        let key = InboxKey::of(&inbound).unwrap();
        let back = InboxRecord::from_inbound(key, &inbound, 1).to_inbound();
        assert_eq!(back.message.id, "m");
        assert_eq!(back.message.payload, b"hi");
        assert_eq!(back.message.sender.as_deref(), Some("did:example:a"));
        assert!(back.message.verified);
        assert!(!back.message.encrypted);
        assert_eq!(back.thread_id.as_deref(), Some("t"));
        assert_eq!(back.delivery_id.as_deref(), Some("d"));
        assert_eq!(back.ack.0, "ack");
    }
}
