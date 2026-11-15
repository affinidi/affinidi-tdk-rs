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
//!   restart. A store that cannot record — a backend failure, or a sender over
//!   its quota ([`Recorded::Refused`]) — leaves the message unacked and
//!   unreceipted, for the mediator to offer again: backpressure, not loss.
//! - **A re-send is not delivered twice.** The record is keyed by the sender,
//!   the sender's idempotency key (the delivery id it stamped to ask for a
//!   receipt) or, when it asked for none, the message id, **and the digest of
//!   the payload** ([`InboxKey`]). A copy with the same key whose record is
//!   [`Consumed`](InboxState::Consumed), or which is still queued to a
//!   subscriber in this process, is acked and receipted again (the sender
//!   evidently missed the first receipt) and not handed to subscribers. A
//!   message that reuses an id with *different* content is not a copy: it is
//!   recorded and delivered as a message of its own, and the reuse is logged.
//! - **A message some subscribers missed is re-offered only to them.** When a
//!   subscriber's queue cannot take a message in time while others' did, the
//!   subscribers that took it are recorded on the record
//!   ([`InboxRecord::handed_to`], [`InboxStore::mark_handed_off`]); a later
//!   copy, or [`redeliver_pending`](crate::MessagingService::redeliver_pending),
//!   offers it only to live subscribers not listed there.
//! - **A message buffered when the process stops is not lost.** A record stays
//!   [`Pending`](InboxState::Pending) until a subscriber it was queued to has
//!   taken it from its `subscribe()` stream and every other one has taken it
//!   or gone away.
//!   [`MessagingService::redeliver_pending`](crate::MessagingService::redeliver_pending)
//!   hands pending records to the current subscribers — call it after
//!   subscribing at startup.
//!
//! # Bounded
//!
//! An inbox is fed by remote senders, so it must not grow with what they
//! send. Every store keeps:
//!
//! - **a per-sender quota** on pending records and their payload bytes, so one
//!   sender cannot starve the others ([`InboxRefusal::SenderQuota`]);
//! - **an admission policy for unknown senders** ([`InboxAdmission`]): a
//!   sender the service's [`SenderClassifier`] does not know — no established
//!   relationship, not on an allow-list — gets a lower per-sender quota, and
//!   all unknown senders together share a sub-cap of the total
//!   ([`InboxRefusal::UnknownSenders`]). Identities are cheap (a `did:key`
//!   costs nothing), so without it one actor spread across many senders could
//!   fill the total bound and starve known senders until reaping freed space;
//!   with it, unknown senders can take at most their sub-cap. A refusal leaves
//!   the message at the mediator, so nothing is lost. Without a classifier
//!   every sender is [`SenderClass::Known`] — the behaviour before the policy
//!   existed;
//! - **a total bound** ([`InboxRefusal::StoreFull`]), reached only by pending
//!   records: a consumed record is only a dedup anchor, holds no payload
//!   ([`InboxStore::mark_consumed`] drops it), and is evicted oldest-first to
//!   make room;
//! - **retention** ([`InboxRetention`]), applied by [`InboxStore::reap`], which
//!   the service runs on its own every [`INBOX_REAP_INTERVAL`].
//!
//! The dedup window is therefore bounded too: a copy arriving after its record
//! was reaped or evicted is delivered again.
//!
//! [`InMemoryInboxStore`] is the default. It is not durable: with it,
//! "recorded" lasts only as long as the process. A service that sends receipts
//! backs the inbox with a durable store
//! ([`MessagingService::with_inbox`](crate::MessagingService::with_inbox)),
//! which must meet the same contract; [`conformance`] checks it.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Mutex;
use std::time::Duration;

use affinidi_messaging_core::{Inbound, InboundAck, InboundKind, Protocol, ReceivedMessage};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// How often a [`MessagingService`](crate::MessagingService) runs
/// [`InboxStore::reap`].
pub const INBOX_REAP_INTERVAL: Duration = Duration::from_secs(60);

/// The SHA-256 of a payload, as an inbox key binds it.
pub fn payload_digest(payload: &[u8]) -> [u8; 32] {
    Sha256::digest(payload).into()
}

/// What identifies an inbound message for dedup: who sent it, the id the
/// sender gave it, and what it says.
///
/// Scoped by the sender because an idempotency key is chosen by its sender: two
/// senders may use the same one, and one sender must not be able to suppress
/// another's message by reusing its key. Bound to the payload digest because a
/// key reused for different content is a different message — treating it as a
/// copy would ack and receipt a message the application never saw.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct InboxKey {
    /// The transport-authenticated sender.
    pub sender: String,
    /// The sender's idempotency key (its delivery id) or, when the message
    /// asked for no receipt, the message id.
    pub id: String,
    /// SHA-256 of the payload ([`payload_digest`]).
    pub payload_digest: [u8; 32],
}

impl InboxKey {
    /// A key for `id` from `sender` with payload digest `payload_digest`.
    pub fn new(sender: impl Into<String>, id: impl Into<String>, payload_digest: [u8; 32]) -> Self {
        Self {
            sender: sender.into(),
            id: id.into(),
            payload_digest,
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
        Some(Self::new(
            sender,
            id,
            payload_digest(&inbound.message.payload),
        ))
    }
}

/// Where a recorded inbound message is in its handoff to the application.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum InboxState {
    /// Recorded, not yet taken by the subscribers it was queued to.
    /// Redelivered by
    /// [`MessagingService::redeliver_pending`](crate::MessagingService::redeliver_pending)
    /// and when a copy arrives that no subscriber in this process holds.
    Pending,
    /// Taken from the `subscribe()` stream of a subscriber it was queued to
    /// (and every other one took it or went away). The payload is no longer
    /// held; the record remains as the dedup anchor. A later copy is acked and
    /// receipted, not delivered.
    Consumed,
}

/// How the inbox admits a sender ([`InboxAdmission`]): known senders under the
/// ordinary quotas, unknown ones under lower quotas and a shared sub-cap.
///
/// Decided by the service's [`SenderClassifier`] when a message is first
/// recorded, and stored with the record so the store accounts for it.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SenderClass {
    /// A sender this receiver knows — an established relationship, an
    /// allow-list entry — or any sender when no classifier is installed.
    #[default]
    Known,
    /// A sender this receiver has no relationship with.
    Unknown,
}

/// Decides whether an authenticated sender is [`Known`](SenderClass::Known)
/// to this receiver, for the inbox's admission policy
/// ([`MessagingService::with_sender_classifier`](crate::MessagingService::with_sender_classifier)).
///
/// It runs on the inbound dispatcher before a new record is stored, bounded
/// by [`CLASSIFY_TIMEOUT`]: a classifier that does not answer in time counts
/// the sender as [`Unknown`](SenderClass::Unknown) (the stricter quota, not a
/// refusal). Keep it to a local lookup.
#[async_trait::async_trait]
pub trait SenderClassifier: Send + Sync {
    /// The class of `sender`, a transport-authenticated identifier.
    async fn classify(&self, sender: &str) -> SenderClass;
}

/// How long the dispatcher waits for a [`SenderClassifier`] before counting the
/// sender as [`Unknown`](SenderClass::Unknown).
pub const CLASSIFY_TIMEOUT: Duration = Duration::from_millis(500);

/// A fixed set of known senders: each is [`Known`](SenderClass::Known), every
/// other sender [`Unknown`](SenderClass::Unknown). Compared exactly.
#[derive(Debug, Clone, Default)]
pub struct AllowList {
    senders: HashSet<String>,
}

impl AllowList {
    /// An allow-list of `senders`.
    pub fn new<I, S>(senders: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            senders: senders.into_iter().map(Into::into).collect(),
        }
    }

    /// Whether `sender` is on the list.
    pub fn contains(&self, sender: &str) -> bool {
        self.senders.contains(sender)
    }
}

#[async_trait::async_trait]
impl SenderClassifier for AllowList {
    async fn classify(&self, sender: &str) -> SenderClass {
        if self.contains(sender) {
            SenderClass::Known
        } else {
            SenderClass::Unknown
        }
    }
}

/// One inbound message as the inbox records it — everything needed to hand it
/// to a subscriber again after a restart, while it is pending.
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
    /// The decrypted payload while the record is pending; empty once it is
    /// consumed (the key keeps its digest).
    pub payload: Vec<u8>,
    /// The protocol that produced the message.
    pub protocol: Protocol,
    /// Whether the message was encrypted.
    pub encrypted: bool,
    /// The thread id, when present.
    pub thread_id: Option<String>,
    /// The delivery id the sender stamped to ask for a receipt, when present.
    pub delivery_id: Option<String>,
    /// The transport's ack handle for the original delivery.
    pub ack: String,
    /// When the dispatcher recorded it, in Unix milliseconds.
    pub received_at_ms: u64,
    /// Whether the message has been acked to its transport (deleted at the
    /// mediator). A pending record that is acked exists nowhere else, so it is
    /// not reaped like an unacked one (see [`InboxRetention`]).
    pub acked: bool,
    /// When it was consumed, in Unix milliseconds.
    pub consumed_at_ms: Option<u64>,
    /// Where it is in its handoff.
    pub state: InboxState,
    /// How the sender was admitted ([`InboxAdmission`]). Records from before
    /// the policy existed deserialize as [`SenderClass::Known`].
    #[serde(default)]
    pub sender_class: SenderClass,
    /// The subscribers (by the service's process-unique subscriber id) whose
    /// queue took this pending record in a handoff that did not reach every
    /// subscriber, so a re-offer skips them. At most [`MAX_HANDED_TO`] ids;
    /// empty until a handoff is partial. An id names one `subscribe()` stream
    /// of one process, so after a restart none matches and every subscriber
    /// is offered the record again.
    #[serde(default)]
    pub handed_to: Vec<String>,
}

/// The most subscriber ids an [`InboxRecord::handed_to`] keeps. Past it the
/// oldest is forgotten, and that subscriber may be offered the record again.
pub const MAX_HANDED_TO: usize = 64;

impl InboxRecord {
    /// A [`Pending`](InboxState::Pending), unacked record of `inbound` under
    /// `key`, received at `received_at_ms`.
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
            acked: false,
            consumed_at_ms: None,
            state: InboxState::Pending,
            sender_class: SenderClass::Known,
            handed_to: Vec::new(),
        }
    }

    /// This record with its sender admitted as `class`.
    pub fn with_sender_class(mut self, class: SenderClass) -> Self {
        self.sender_class = class;
        self
    }

    /// The [`Inbound`] a subscriber is handed for this (pending) record. Its
    /// sender is the authenticated sender it was recorded under.
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

/// Why a store would not take a new record. The message is left unacked and
/// unreceipted: the mediator keeps it and offers it again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum InboxRefusal {
    /// The sender holds as many pending records, or pending payload bytes, as
    /// it may.
    SenderQuota,
    /// The store holds as many pending records, or pending payload bytes, as
    /// it may, and has no consumed record left to evict.
    StoreFull,
    /// The sender is [`Unknown`](SenderClass::Unknown) and unknown senders
    /// together hold as many pending records, or pending payload bytes, as
    /// the [`InboxAdmission`] sub-cap admits. Known senders are not affected.
    UnknownSenders,
}

/// What [`InboxStore::record`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Recorded {
    /// No record existed under the key; this one was stored. `id_reused`: the
    /// sender already has a record under the same id with a different payload
    /// — a key reused for different content, delivered as a message of its
    /// own.
    New {
        /// Another record has the same sender and id but another digest.
        id_reused: bool,
    },
    /// A record already existed under the key and was left unchanged. Its
    /// state says whether it was handed to the application already.
    Duplicate(InboxState),
    /// Not stored; see [`InboxRefusal`].
    Refused(InboxRefusal),
}

/// Failures of an [`InboxStore`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum InboxError {
    /// The backing store failed (I/O, serialization, lock poisoning, …).
    #[error("inbox store backend error: {0}")]
    Backend(String),
}

/// How long records are kept ([`InboxStore::reap`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InboxRetention {
    /// A consumed record (the dedup anchor) is removed this long after it was
    /// consumed. Size it to the senders' delivery window plus the mediator's
    /// retention: a copy arriving later is delivered again.
    pub consumed_ttl: Duration,
    /// A pending record that was **not** acked is removed this long after it
    /// was received: the mediator still holds the message and offers it again.
    /// A pending record that **was** acked and is older than this is reported
    /// as overdue (logged at error by the service) and kept.
    pub pending_max_age: Duration,
    /// A pending, acked record — which exists nowhere else — is removed only
    /// past this age, and only when it is set. `None` (the default) keeps it
    /// until it is consumed; the per-sender and total bounds still apply.
    pub acked_pending_max_age: Option<Duration>,
}

impl Default for InboxRetention {
    fn default() -> Self {
        Self {
            consumed_ttl: Duration::from_secs(7 * 24 * 60 * 60),
            pending_max_age: Duration::from_secs(24 * 60 * 60),
            acked_pending_max_age: None,
        }
    }
}

/// What one [`InboxStore::reap`] pass did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct InboxReapReport {
    /// Consumed records past [`InboxRetention::consumed_ttl`], removed.
    pub consumed_removed: usize,
    /// Pending, unacked records past [`InboxRetention::pending_max_age`],
    /// removed (the mediator still holds them).
    pub unacked_pending_removed: usize,
    /// Pending, acked records past [`InboxRetention::pending_max_age`], kept:
    /// messages acked to the mediator that no subscriber has taken.
    pub acked_pending_overdue: usize,
    /// Pending, acked records past [`InboxRetention::acked_pending_max_age`],
    /// removed: **lost** messages, logged at error by the service.
    pub acked_pending_removed: usize,
}

/// Storage for the inbox. Services implement this over a durable store (the
/// same one their [`OutboxStore`](crate::OutboxStore) uses, typically);
/// [`InMemoryInboxStore`] is the default and is not durable.
///
/// # The contract
///
/// - [`record`](Self::record) is atomic insert-if-absent on the full
///   [`InboxKey`] (sender, id **and** payload digest), durable by the time it
///   returns — the dispatcher acks the message (deleting the mediator's copy)
///   and sends its receipt as soon as it does. It reports a record that reuses
///   an existing (sender, id) with another digest as
///   [`Recorded::New`]` { id_reused: true }`.
/// - **Bounded:** it refuses ([`Recorded::Refused`]) rather than grow without
///   limit — a per-sender quota on pending records and bytes, and a total
///   bound, evicting the oldest consumed records before refusing — and it
///   applies a stricter quota and a shared sub-cap to records whose
///   [`sender_class`](InboxRecord::sender_class) is
///   [`Unknown`](SenderClass::Unknown) ([`InboxAdmission`]).
/// - [`mark_consumed`](Self::mark_consumed) drops the stored payload.
/// - [`reap`](Self::reap) applies [`InboxRetention`] and never removes a
///   pending, acked record before `acked_pending_max_age`.
///
/// The checks in [`conformance`] exercise it.
#[async_trait::async_trait]
pub trait InboxStore: Send + Sync {
    /// Store `record` unless one exists under its key. See the trait docs.
    async fn record(&self, record: InboxRecord) -> Result<Recorded, InboxError>;

    /// The record under `key`, if any.
    async fn get(&self, key: &InboxKey) -> Result<Option<InboxRecord>, InboxError>;

    /// Note that the record under `key` was acked to its transport. Returns
    /// whether a record was found.
    async fn mark_acked(&self, key: &InboxKey) -> Result<bool, InboxError>;

    /// Mark the record under `key` [`Consumed`](InboxState::Consumed) at
    /// `now_ms`, dropping its payload. Returns whether a record was found.
    async fn mark_consumed(&self, key: &InboxKey, now_ms: u64) -> Result<bool, InboxError>;

    /// Every [`Pending`](InboxState::Pending) record, oldest first.
    async fn pending(&self) -> Result<Vec<InboxRecord>, InboxError>;

    /// Add `subscribers` to the record's [`handed_to`](InboxRecord::handed_to)
    /// — the subscribers whose queue took it in a handoff that missed others —
    /// keeping at most [`MAX_HANDED_TO`] ids, the most recent. Returns whether
    /// the store tracks it: `Ok(false)` when there is no such record, or when
    /// the store does not track handoff.
    ///
    /// The default does not track it and returns `Ok(false)`: a re-offer then
    /// goes to every subscriber that does not still hold the message in this
    /// process, and one that already took it may get it again. Implement it
    /// (and persist `handed_to`) to re-offer only to the subscribers that
    /// missed it; [`conformance::check_handoff_tracking`] checks it.
    async fn mark_handed_off(
        &self,
        _key: &InboxKey,
        _subscribers: &[String],
    ) -> Result<bool, InboxError> {
        Ok(false)
    }

    /// Apply `retention` at `now_ms` (Unix milliseconds).
    async fn reap(
        &self,
        now_ms: u64,
        retention: &InboxRetention,
    ) -> Result<InboxReapReport, InboxError>;
}

/// The bounds of an [`InMemoryInboxStore`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InboxLimits {
    /// Records of every state, all senders. Past it the oldest consumed record
    /// is evicted; with none to evict, [`InboxRefusal::StoreFull`].
    pub max_records: usize,
    /// Records of every state from one sender. Past it that sender's oldest
    /// consumed record is evicted; with none, [`InboxRefusal::SenderQuota`].
    pub max_records_per_sender: usize,
    /// Pending records from one sender ([`InboxRefusal::SenderQuota`]).
    pub max_pending_per_sender: usize,
    /// Pending payload bytes from one sender ([`InboxRefusal::SenderQuota`]).
    pub max_pending_bytes_per_sender: usize,
    /// Pending payload bytes, all senders ([`InboxRefusal::StoreFull`]).
    pub max_pending_bytes: usize,
}

impl Default for InboxLimits {
    fn default() -> Self {
        Self {
            max_records: 100_000,
            max_records_per_sender: 10_000,
            max_pending_per_sender: 1_000,
            max_pending_bytes_per_sender: 16 * 1024 * 1024,
            max_pending_bytes: 128 * 1024 * 1024,
        }
    }
}

/// The admission policy for [`Unknown`](SenderClass::Unknown) senders: a
/// lower per-sender quota, and a sub-cap that all of them share, inside the
/// store's [`InboxLimits`] (which still apply). Only records the service
/// classified as unknown count against it — see
/// [`MessagingService::with_sender_classifier`](crate::MessagingService::with_sender_classifier).
///
/// `#[non_exhaustive]`: start from [`InboxAdmission::default`] and set fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct InboxAdmission {
    /// Pending records from one unknown sender
    /// ([`InboxRefusal::SenderQuota`]).
    pub unknown_max_pending_per_sender: usize,
    /// Pending payload bytes from one unknown sender
    /// ([`InboxRefusal::SenderQuota`]).
    pub unknown_max_pending_bytes_per_sender: usize,
    /// Pending records from all unknown senders together
    /// ([`InboxRefusal::UnknownSenders`]).
    pub unknown_max_pending: usize,
    /// Pending payload bytes from all unknown senders together
    /// ([`InboxRefusal::UnknownSenders`]).
    pub unknown_max_pending_bytes: usize,
}

impl Default for InboxAdmission {
    /// A tenth of the default [`InboxLimits`] for the shared sub-cap, and a
    /// tenth of a known sender's quota per unknown sender.
    fn default() -> Self {
        Self {
            unknown_max_pending_per_sender: 100,
            unknown_max_pending_bytes_per_sender: 1024 * 1024,
            unknown_max_pending: 10_000,
            unknown_max_pending_bytes: 16 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Default)]
struct SenderUsage {
    pending: usize,
    pending_bytes: usize,
    /// This sender's consumed records, oldest first, by consumption sequence.
    consumed: BTreeMap<u64, InboxKey>,
}

impl SenderUsage {
    fn records(&self) -> usize {
        self.pending + self.consumed.len()
    }
}

#[derive(Debug, Default)]
struct StoreState {
    records: HashMap<InboxKey, InboxRecord>,
    /// Every consumed record, oldest first, by consumption sequence.
    consumed_order: BTreeMap<u64, InboxKey>,
    consumed_seq: HashMap<InboxKey, u64>,
    senders: HashMap<String, SenderUsage>,
    /// Records per (sender, id), to notice an id reused for other content.
    ids: HashMap<(String, String), usize>,
    pending_bytes: usize,
    /// Pending records, and their payload bytes, from unknown senders.
    unknown_pending: usize,
    unknown_pending_bytes: usize,
    next_seq: u64,
}

impl StoreState {
    fn remove(&mut self, key: &InboxKey) -> Option<InboxRecord> {
        let record = self.records.remove(key)?;
        let id = (key.sender.clone(), key.id.clone());
        if let Some(n) = self.ids.get_mut(&id) {
            *n -= 1;
            if *n == 0 {
                self.ids.remove(&id);
            }
        }
        if let Some(usage) = self.senders.get_mut(&key.sender) {
            match record.state {
                InboxState::Pending => {
                    usage.pending -= 1;
                    usage.pending_bytes -= record.payload.len();
                    self.pending_bytes -= record.payload.len();
                    if record.sender_class == SenderClass::Unknown {
                        self.unknown_pending -= 1;
                        self.unknown_pending_bytes -= record.payload.len();
                    }
                }
                InboxState::Consumed => {
                    if let Some(seq) = self.consumed_seq.remove(key) {
                        usage.consumed.remove(&seq);
                        self.consumed_order.remove(&seq);
                    }
                }
            }
            if usage.records() == 0 {
                self.senders.remove(&key.sender);
            }
        }
        Some(record)
    }

    fn evict_oldest_consumed(&mut self) -> bool {
        let Some(key) = self.consumed_order.values().next().cloned() else {
            return false;
        };
        self.remove(&key).is_some()
    }

    fn evict_oldest_consumed_of(&mut self, sender: &str) -> bool {
        let Some(key) = self
            .senders
            .get(sender)
            .and_then(|u| u.consumed.values().next().cloned())
        else {
            return false;
        };
        self.remove(&key).is_some()
    }
}

/// An in-memory [`InboxStore`], bounded by [`InboxLimits`]: dedups for the life
/// of the process, durable for none of it. The default for a
/// [`MessagingService`](crate::MessagingService).
///
/// Shared through an `Arc`, it outlives a service built over it, which is how
/// the tests model a restart.
#[derive(Debug)]
pub struct InMemoryInboxStore {
    limits: InboxLimits,
    admission: InboxAdmission,
    state: Mutex<StoreState>,
}

impl Default for InMemoryInboxStore {
    fn default() -> Self {
        Self::with_limits(InboxLimits::default())
    }
}

impl InMemoryInboxStore {
    /// A new, empty store with the default [`InboxLimits`].
    pub fn new() -> Self {
        Self::default()
    }

    /// A new, empty store with `limits`.
    pub fn with_limits(limits: InboxLimits) -> Self {
        Self {
            limits,
            admission: InboxAdmission::default(),
            state: Mutex::new(StoreState::default()),
        }
    }

    /// This store with `admission` for unknown senders in place of the
    /// default [`InboxAdmission`].
    pub fn with_admission(mut self, admission: InboxAdmission) -> Self {
        self.admission = admission;
        self
    }

    /// How many records it holds, of every state.
    pub fn len(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .records
            .len()
    }

    /// Whether it holds no record.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, StoreState>, InboxError> {
        self.state
            .lock()
            .map_err(|e| InboxError::Backend(format!("inbox lock poisoned: {e}")))
    }
}

#[async_trait::async_trait]
impl InboxStore for InMemoryInboxStore {
    async fn record(&self, record: InboxRecord) -> Result<Recorded, InboxError> {
        let limits = self.limits;
        let admission = self.admission;
        let mut state = self.lock()?;
        if let Some(existing) = state.records.get(&record.key) {
            return Ok(Recorded::Duplicate(existing.state));
        }
        let sender = record.key.sender.clone();
        let len = record.payload.len();
        let unknown = record.sender_class == SenderClass::Unknown;

        // Pending work is bounded per sender first, so one sender cannot
        // take the store's whole allowance from the others — more tightly
        // for a sender this receiver does not know.
        let (max_pending, max_pending_bytes) = if unknown {
            (
                limits
                    .max_pending_per_sender
                    .min(admission.unknown_max_pending_per_sender),
                limits
                    .max_pending_bytes_per_sender
                    .min(admission.unknown_max_pending_bytes_per_sender),
            )
        } else {
            (
                limits.max_pending_per_sender,
                limits.max_pending_bytes_per_sender,
            )
        };
        let usage = state.senders.get(&sender);
        let (pending, pending_bytes) = usage.map_or((0, 0), |u| (u.pending, u.pending_bytes));
        if pending >= max_pending || pending_bytes.saturating_add(len) > max_pending_bytes {
            return Ok(Recorded::Refused(InboxRefusal::SenderQuota));
        }
        // Unknown senders together stay inside their sub-cap, so however many
        // identities one actor uses, known senders keep the rest.
        if unknown
            && (state.unknown_pending >= admission.unknown_max_pending
                || state.unknown_pending_bytes.saturating_add(len)
                    > admission.unknown_max_pending_bytes)
        {
            return Ok(Recorded::Refused(InboxRefusal::UnknownSenders));
        }
        if state.pending_bytes + len > limits.max_pending_bytes {
            return Ok(Recorded::Refused(InboxRefusal::StoreFull));
        }
        // Consumed records are only dedup anchors: make room by evicting the
        // oldest, the sender's own first.
        while state.senders.get(&sender).map_or(0, SenderUsage::records)
            >= limits.max_records_per_sender
        {
            if !state.evict_oldest_consumed_of(&sender) {
                return Ok(Recorded::Refused(InboxRefusal::SenderQuota));
            }
        }
        while state.records.len() >= limits.max_records {
            if !state.evict_oldest_consumed() {
                return Ok(Recorded::Refused(InboxRefusal::StoreFull));
            }
        }

        let id = (sender.clone(), record.key.id.clone());
        let id_reused = state.ids.get(&id).is_some_and(|n| *n > 0);
        *state.ids.entry(id).or_default() += 1;
        let usage = state.senders.entry(sender).or_default();
        usage.pending += 1;
        usage.pending_bytes += len;
        state.pending_bytes += len;
        if unknown {
            state.unknown_pending += 1;
            state.unknown_pending_bytes += len;
        }
        let mut record = record;
        record.state = InboxState::Pending;
        state.records.insert(record.key.clone(), record);
        Ok(Recorded::New { id_reused })
    }

    async fn get(&self, key: &InboxKey) -> Result<Option<InboxRecord>, InboxError> {
        Ok(self.lock()?.records.get(key).cloned())
    }

    async fn mark_acked(&self, key: &InboxKey) -> Result<bool, InboxError> {
        Ok(match self.lock()?.records.get_mut(key) {
            Some(record) => {
                record.acked = true;
                true
            }
            None => false,
        })
    }

    async fn mark_consumed(&self, key: &InboxKey, now_ms: u64) -> Result<bool, InboxError> {
        let mut state = self.lock()?;
        let state = &mut *state;
        let Some(record) = state.records.get_mut(key) else {
            return Ok(false);
        };
        if record.state == InboxState::Consumed {
            return Ok(true);
        }
        let len = record.payload.len();
        let unknown = record.sender_class == SenderClass::Unknown;
        record.state = InboxState::Consumed;
        record.consumed_at_ms = Some(now_ms);
        record.payload = Vec::new();
        state.pending_bytes -= len;
        if unknown {
            state.unknown_pending -= 1;
            state.unknown_pending_bytes -= len;
        }
        let seq = state.next_seq;
        state.next_seq += 1;
        state.consumed_order.insert(seq, key.clone());
        state.consumed_seq.insert(key.clone(), seq);
        if let Some(usage) = state.senders.get_mut(&key.sender) {
            usage.pending -= 1;
            usage.pending_bytes -= len;
            usage.consumed.insert(seq, key.clone());
        }
        Ok(true)
    }

    async fn mark_handed_off(
        &self,
        key: &InboxKey,
        subscribers: &[String],
    ) -> Result<bool, InboxError> {
        let mut state = self.lock()?;
        let Some(record) = state.records.get_mut(key) else {
            return Ok(false);
        };
        for id in subscribers {
            if !record.handed_to.contains(id) {
                record.handed_to.push(id.clone());
            }
        }
        if record.handed_to.len() > MAX_HANDED_TO {
            let excess = record.handed_to.len() - MAX_HANDED_TO;
            record.handed_to.drain(..excess);
        }
        Ok(true)
    }

    async fn pending(&self) -> Result<Vec<InboxRecord>, InboxError> {
        let mut pending: Vec<InboxRecord> = self
            .lock()?
            .records
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

    async fn reap(
        &self,
        now_ms: u64,
        retention: &InboxRetention,
    ) -> Result<InboxReapReport, InboxError> {
        let older_than = |since: u64, age: Duration| {
            now_ms.saturating_sub(since) > age.as_millis().min(u64::MAX as u128) as u64
        };
        let mut state = self.lock()?;
        let mut report = InboxReapReport::default();
        let mut remove = Vec::new();
        for record in state.records.values() {
            match record.state {
                InboxState::Consumed => {
                    let at = record.consumed_at_ms.unwrap_or(record.received_at_ms);
                    if older_than(at, retention.consumed_ttl) {
                        remove.push(record.key.clone());
                        report.consumed_removed += 1;
                    }
                }
                InboxState::Pending => {
                    if !older_than(record.received_at_ms, retention.pending_max_age) {
                        continue;
                    }
                    if !record.acked {
                        remove.push(record.key.clone());
                        report.unacked_pending_removed += 1;
                    } else if retention
                        .acked_pending_max_age
                        .is_some_and(|max| older_than(record.received_at_ms, max))
                    {
                        remove.push(record.key.clone());
                        report.acked_pending_removed += 1;
                    } else {
                        report.acked_pending_overdue += 1;
                    }
                }
            }
        }
        for key in remove {
            state.remove(&key);
        }
        Ok(report)
    }
}

/// Conformance checks for an [`InboxStore`] implementation. Each panics on a
/// violation; run them against a fresh, empty store.
#[cfg(any(test, feature = "conformance"))]
pub mod conformance {
    use super::*;

    /// A pending record of a message `id` from `sender` with `payload`,
    /// received at `at`.
    pub fn record_of(sender: &str, id: &str, payload: &[u8], at: u64) -> InboxRecord {
        let message = ReceivedMessage {
            id: format!("msg-{id}"),
            sender: Some(sender.to_string()),
            recipient: "did:example:me".to_string(),
            payload: payload.to_vec(),
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

    fn record(sender: &str, id: &str, at: u64) -> InboxRecord {
        record_of(sender, id, id.as_bytes(), at)
    }

    /// Run every check that holds for any limits against `store`, which must
    /// start empty. Run [`check_sender_quota`] separately, on a store built
    /// with a small per-sender pending quota.
    pub async fn check_inbox_store(store: &dyn InboxStore) {
        check_record_is_insert_if_absent(store).await;
        check_keys_are_scoped_by_sender(store).await;
        check_keys_are_bound_to_content(store).await;
        check_consume_drops_the_payload(store).await;
        check_reap(store).await;
    }

    /// `record` stores a new record and reports a second one under the same
    /// key as a duplicate, leaving the first unchanged.
    pub async fn check_record_is_insert_if_absent(store: &dyn InboxStore) {
        let first = record("did:example:a", "k1", 10);
        assert_eq!(
            store.record(first.clone()).await.unwrap(),
            Recorded::New { id_reused: false }
        );
        let mut second = first.clone();
        second.message_id = "another transmission".into();
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
        assert!(matches!(
            store.record(a).await.unwrap(),
            Recorded::New { .. }
        ));
        assert_eq!(
            store.record(b).await.unwrap(),
            Recorded::New { id_reused: false },
            "another sender's key does not collide"
        );
    }

    /// The same id with other content is a new record, reported as a reuse.
    pub async fn check_keys_are_bound_to_content(store: &dyn InboxStore) {
        let first = record_of("did:example:e", "reused", b"one", 25);
        let other = record_of("did:example:e", "reused", b"two", 26);
        assert_eq!(
            store.record(first).await.unwrap(),
            Recorded::New { id_reused: false }
        );
        assert_eq!(
            store.record(other).await.unwrap(),
            Recorded::New { id_reused: true },
            "an id reused for other content is not a duplicate"
        );
    }

    /// `mark_consumed` takes a record out of `pending`, drops its payload, and
    /// a later `record` reports it consumed.
    pub async fn check_consume_drops_the_payload(store: &dyn InboxStore) {
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
        assert!(store.mark_acked(&r.key).await.unwrap());
        assert!(store.mark_consumed(&r.key, 31).await.unwrap());
        let consumed = store.get(&r.key).await.unwrap().expect("kept as an anchor");
        assert_eq!(consumed.state, InboxState::Consumed);
        assert!(consumed.payload.is_empty(), "the payload is dropped");
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
                .mark_consumed(&InboxKey::new("did:example:c", "absent", [0; 32]), 31)
                .await
                .unwrap(),
            "marking an absent key finds nothing"
        );
    }

    /// `reap` removes old consumed and old unacked pending records, keeps old
    /// acked pending ones (reporting them) until `acked_pending_max_age`.
    pub async fn check_reap(store: &dyn InboxStore) {
        let consumed = record("did:example:d", "old-consumed", 1);
        let unacked = record("did:example:d", "old-unacked", 1);
        let acked = record("did:example:d", "old-acked", 1);
        for r in [&consumed, &unacked, &acked] {
            store.record(r.clone()).await.unwrap();
        }
        store.mark_consumed(&consumed.key, 1).await.unwrap();
        store.mark_acked(&acked.key).await.unwrap();

        let retention = InboxRetention {
            consumed_ttl: Duration::from_millis(10),
            pending_max_age: Duration::from_millis(10),
            acked_pending_max_age: None,
        };
        let report = store.reap(1_000, &retention).await.unwrap();
        assert!(report.consumed_removed >= 1);
        assert!(report.unacked_pending_removed >= 1);
        assert!(report.acked_pending_overdue >= 1);
        assert!(store.get(&consumed.key).await.unwrap().is_none());
        assert!(store.get(&unacked.key).await.unwrap().is_none());
        assert!(
            store.get(&acked.key).await.unwrap().is_some(),
            "an acked pending record exists nowhere else and is kept"
        );

        let retention = InboxRetention {
            acked_pending_max_age: Some(Duration::from_millis(100)),
            ..retention
        };
        let report = store.reap(1_000, &retention).await.unwrap();
        assert!(report.acked_pending_removed >= 1);
        assert!(store.get(&acked.key).await.unwrap().is_none());
    }

    /// `mark_handed_off` adds to a record's `handed_to` without duplicates,
    /// keeps at most [`MAX_HANDED_TO`] (the most recent), survives in
    /// `pending`, and finds no absent record. Not part of
    /// [`check_inbox_store`]: a store may leave handoff untracked (the
    /// default method).
    pub async fn check_handoff_tracking(store: &dyn InboxStore) {
        let r = record("did:example:h", "handed", 40);
        store.record(r.clone()).await.unwrap();
        assert!(
            store
                .mark_handed_off(&r.key, &["s1".into(), "s2".into()])
                .await
                .unwrap()
        );
        assert!(
            store
                .mark_handed_off(&r.key, &["s2".into(), "s3".into()])
                .await
                .unwrap()
        );
        let got = store.get(&r.key).await.unwrap().unwrap();
        assert_eq!(got.handed_to, ["s1", "s2", "s3"]);
        let pending = store.pending().await.unwrap();
        let listed = pending.iter().find(|p| p.key == r.key).unwrap();
        assert_eq!(listed.handed_to, ["s1", "s2", "s3"], "kept with the record");

        let many: Vec<String> = (0..MAX_HANDED_TO + 5).map(|i| format!("m{i}")).collect();
        store.mark_handed_off(&r.key, &many).await.unwrap();
        let got = store.get(&r.key).await.unwrap().unwrap();
        assert_eq!(got.handed_to.len(), MAX_HANDED_TO, "bounded");
        assert_eq!(
            got.handed_to.last(),
            many.last(),
            "the most recent are kept"
        );

        assert!(
            !store
                .mark_handed_off(
                    &InboxKey::new("did:example:h", "absent", [0; 32]),
                    &["s".into()]
                )
                .await
                .unwrap()
        );
    }

    /// On a store whose admission policy gives an unknown sender a pending
    /// quota of `per_sender` records and all unknown senders together a
    /// sub-cap of `sub_cap` records (`per_sender < sub_cap`, both well below
    /// the store's own limits): an unknown sender is refused past its quota;
    /// unknown senders together are refused past the sub-cap; a known sender
    /// is still admitted; and consuming an unknown sender's record frees its
    /// place.
    pub async fn check_unknown_sender_admission(
        store: &dyn InboxStore,
        per_sender: usize,
        sub_cap: usize,
    ) {
        let unknown =
            |sender: &str, id: &str| record(sender, id, 0).with_sender_class(SenderClass::Unknown);
        for i in 0..per_sender {
            assert!(matches!(
                store
                    .record(unknown("did:key:z1", &format!("a{i}")))
                    .await
                    .unwrap(),
                Recorded::New { .. }
            ));
        }
        assert_eq!(
            store.record(unknown("did:key:z1", "over")).await.unwrap(),
            Recorded::Refused(InboxRefusal::SenderQuota),
            "an unknown sender is held to the lower quota"
        );
        // Spread across many cheap identities, unknown senders fill only the
        // sub-cap.
        let mut admitted = per_sender;
        let mut sender = 2;
        let mut first_of_another = None;
        while admitted < sub_cap {
            let who = format!("did:key:z{sender}");
            let r = unknown(&who, "x");
            first_of_another.get_or_insert_with(|| r.key.clone());
            assert!(matches!(
                store.record(r).await.unwrap(),
                Recorded::New { .. }
            ));
            admitted += 1;
            sender += 1;
        }
        assert_eq!(
            store.record(unknown("did:key:zfresh", "x")).await.unwrap(),
            Recorded::Refused(InboxRefusal::UnknownSenders),
            "unknown senders together are held to the sub-cap"
        );
        assert!(
            matches!(
                store
                    .record(record("did:example:known", "k", 0))
                    .await
                    .unwrap(),
                Recorded::New { .. }
            ),
            "a known sender is not starved by unknown ones"
        );
        let freed = first_of_another.expect("a second unknown sender was admitted");
        assert!(store.mark_consumed(&freed, 1).await.unwrap());
        assert!(
            matches!(
                store.record(unknown("did:key:zfresh", "x")).await.unwrap(),
                Recorded::New { .. }
            ),
            "consuming an unknown sender's record frees its place"
        );
    }

    /// On a store built with a per-sender pending quota of `quota` records:
    /// one sender is refused past it, and another sender is not affected.
    pub async fn check_sender_quota(store: &dyn InboxStore, quota: usize) {
        for i in 0..quota {
            let r = record("did:example:flood", &format!("f{i}"), i as u64);
            assert!(matches!(
                store.record(r).await.unwrap(),
                Recorded::New { .. }
            ));
        }
        let over = record("did:example:flood", "one-more", 0);
        assert_eq!(
            store.record(over).await.unwrap(),
            Recorded::Refused(InboxRefusal::SenderQuota),
            "a sender over its quota is refused"
        );
        let other = record("did:example:quiet", "q1", 0);
        assert!(
            matches!(store.record(other).await.unwrap(), Recorded::New { .. }),
            "another sender is not starved"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn in_memory_store_applies_the_unknown_sender_admission() {
        let admission = InboxAdmission {
            unknown_max_pending_per_sender: 3,
            unknown_max_pending: 10,
            ..InboxAdmission::default()
        };
        let store = InMemoryInboxStore::new().with_admission(admission);
        conformance::check_unknown_sender_admission(&store, 3, 10).await;
    }

    /// The bytes sub-cap holds too, and reaping an unknown record releases
    /// it.
    #[tokio::test]
    async fn unknown_sender_bytes_are_capped_and_released() {
        let admission = InboxAdmission {
            unknown_max_pending_bytes: 10,
            ..InboxAdmission::default()
        };
        let store = InMemoryInboxStore::new().with_admission(admission);
        let a = conformance::record_of("did:key:za", "a", &[0; 8], 0)
            .with_sender_class(SenderClass::Unknown);
        assert!(matches!(
            store.record(a.clone()).await.unwrap(),
            Recorded::New { .. }
        ));
        let b = conformance::record_of("did:key:zb", "b", &[0; 8], 0)
            .with_sender_class(SenderClass::Unknown);
        assert_eq!(
            store.record(b.clone()).await.unwrap(),
            Recorded::Refused(InboxRefusal::UnknownSenders)
        );
        let retention = InboxRetention {
            pending_max_age: Duration::from_millis(1),
            ..InboxRetention::default()
        };
        assert_eq!(
            store
                .reap(1_000, &retention)
                .await
                .unwrap()
                .unacked_pending_removed,
            1
        );
        assert!(matches!(
            store.record(b).await.unwrap(),
            Recorded::New { .. }
        ));
    }

    #[tokio::test]
    async fn an_allow_list_classifies_exactly() {
        let list = AllowList::new(["did:example:friend"]);
        assert_eq!(
            list.classify("did:example:friend").await,
            SenderClass::Known
        );
        assert_eq!(
            list.classify("did:example:friend2").await,
            SenderClass::Unknown
        );
    }

    #[test]
    fn a_record_from_before_the_policy_is_known() {
        let r = conformance::record_of("did:example:a", "x", b"p", 1);
        let mut json = serde_json::to_value(&r).unwrap();
        json.as_object_mut().unwrap().remove("sender_class");
        let back: InboxRecord = serde_json::from_value(json).unwrap();
        assert_eq!(back.sender_class, SenderClass::Known);
    }

    #[tokio::test]
    async fn in_memory_store_conforms() {
        conformance::check_inbox_store(&InMemoryInboxStore::new()).await;
        conformance::check_handoff_tracking(&InMemoryInboxStore::new()).await;
        let limits = InboxLimits {
            max_pending_per_sender: 5,
            ..InboxLimits::default()
        };
        conformance::check_sender_quota(&InMemoryInboxStore::with_limits(limits), 5).await;
    }

    /// One sender flooding unique ids that are consumed costs at most its
    /// record quota: its oldest consumed anchors are evicted, and the store
    /// stays bounded.
    #[tokio::test]
    async fn a_flood_of_unique_ids_stays_bounded() {
        let limits = InboxLimits {
            max_records: 50,
            max_records_per_sender: 20,
            ..InboxLimits::default()
        };
        let store = InMemoryInboxStore::with_limits(limits);
        for i in 0..1_000u64 {
            let r = conformance::record_of("did:example:flood", &format!("u{i}"), b"x", i);
            assert!(matches!(
                store.record(r.clone()).await.unwrap(),
                Recorded::New { .. }
            ));
            store.mark_consumed(&r.key, i).await.unwrap();
        }
        assert!(store.len() <= 20, "bounded by the sender's quota");
        // Another sender still gets in.
        let r = conformance::record_of("did:example:other", "o1", b"y", 0);
        assert!(matches!(
            store.record(r).await.unwrap(),
            Recorded::New { .. }
        ));
    }

    /// The total bound evicts consumed anchors, and refuses only when every
    /// record is pending.
    #[tokio::test]
    async fn the_total_bound_refuses_only_pending_work() {
        let limits = InboxLimits {
            max_records: 3,
            ..InboxLimits::default()
        };
        let store = InMemoryInboxStore::with_limits(limits);
        for (i, sender) in ["did:example:a", "did:example:b", "did:example:c"]
            .iter()
            .enumerate()
        {
            let r = conformance::record_of(sender, "p", b"x", i as u64);
            store.record(r).await.unwrap();
        }
        let r = conformance::record_of("did:example:d", "p", b"x", 9);
        assert_eq!(
            store.record(r).await.unwrap(),
            Recorded::Refused(InboxRefusal::StoreFull)
        );
        let a = conformance::record_of("did:example:a", "p", b"x", 0);
        store.mark_consumed(&a.key, 10).await.unwrap();
        let r = conformance::record_of("did:example:d", "p", b"x", 9);
        assert!(
            matches!(store.record(r).await.unwrap(), Recorded::New { .. }),
            "a consumed anchor makes room"
        );
        assert_eq!(store.len(), 3);
    }

    #[tokio::test]
    async fn pending_bytes_are_bounded_per_sender() {
        let limits = InboxLimits {
            max_pending_bytes_per_sender: 10,
            ..InboxLimits::default()
        };
        let store = InMemoryInboxStore::with_limits(limits);
        let big = conformance::record_of("did:example:a", "big", &[0; 8], 0);
        store.record(big.clone()).await.unwrap();
        let more = conformance::record_of("did:example:a", "more", &[0; 8], 0);
        assert_eq!(
            store.record(more.clone()).await.unwrap(),
            Recorded::Refused(InboxRefusal::SenderQuota)
        );
        // Consuming frees its bytes.
        store.mark_consumed(&big.key, 1).await.unwrap();
        assert!(matches!(
            store.record(more).await.unwrap(),
            Recorded::New { .. }
        ));
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
            Some(InboxKey::new("did:example:a", "m", payload_digest(b""))),
            "falls back to the message id without a delivery id"
        );
        let with_id = inbound.with_delivery_id("idem-1");
        assert_eq!(
            InboxKey::of(&with_id),
            Some(InboxKey::new(
                "did:example:a",
                "idem-1",
                payload_digest(b"")
            ))
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
