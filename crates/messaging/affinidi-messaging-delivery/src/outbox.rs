//! The durable outbox: the model, the [`OutboxStore`] storage abstraction, and
//! an in-memory implementation.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use affinidi_messaging_core::DeliveryScope;
use serde::{Deserialize, Serialize};

/// An idempotency or ordering key. The idempotency key is the dedup anchor; the
/// ordering key groups entries into a per-key FIFO.
pub type Key = String;

/// Lifecycle state of an outbox entry. Terminal states are `Delivered`,
/// `Unconfirmed`, and `Failed`.
///
/// `Sent` is **not** terminal and **not** "delivered": it means the next hop
/// accepted the bytes (durably queued at the mediator) and we are awaiting
/// end-to-end evidence. A `Sent` entry is not re-sent; evidence
/// ([`confirm_delivered`](crate::confirm_delivered)) settles it `Delivered`,
/// and the confirmation sweep settles it when its window passes.
///
/// Terminal states are absorbing for the layer's own transitions: every state
/// change goes through [`OutboxStore::transition`], guarded on the state it
/// expects, so a slow task holding a stale snapshot cannot undo a `Delivered`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum OutboxState {
    /// Not yet handed off, or a failed attempt awaiting its next retry.
    Queued,
    /// Hop-accepted; awaiting end-to-end evidence. Not re-sent.
    Sent,
    /// Positive end-to-end evidence received.
    Delivered,
    /// The delivery window passed with no evidence possible — a truthful "we
    /// can't know", never a false "delivered".
    Unconfirmed,
    /// The delivery window passed with delivery expected but unconfirmed —
    /// escalated (surfaced), never silently dropped.
    Failed,
}

impl OutboxState {
    /// Whether no further work will change this entry.
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            OutboxState::Delivered | OutboxState::Unconfirmed | OutboxState::Failed
        )
    }
}

/// Why an entry settled [`OutboxState::Unconfirmed`].
///
/// Two different facts end the same way, and a reader of the outbox needs to
/// tell them apart: a path that could have produced evidence and stayed
/// silent, and a path that never could. Only the first says anything about the
/// recipient.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum UnconfirmedReason {
    /// The delivery window passed on a path that could have produced evidence
    /// — the sender's mediator held the message, or the recipient is known to
    /// send receipts — and none came.
    WindowPassed,
    /// No class of evidence was available on the path (VTI-TRN-064): the
    /// message was relayed to the recipient's own mediator, which cannot
    /// answer the sender, and the recipient is not known to send receipts.
    /// The delivery is *unconfirmable*, which is neither delivered nor failed
    /// (VTI-TRN-042), and it is not escalated.
    NoEvidencePath,
}

/// A durable, transport-independent unit of delivery-critical work.
///
/// The entry records **who** the message is for (`dest_did`), not which wire —
/// the transport is resolved at drain time. The one exception is
/// [`via`](Self::via), which pins an entry to a specific transport when the
/// sending *identity* matters; see its docs. Timestamps are Unix milliseconds;
/// the drain takes the clock as a parameter so it stays deterministic in tests.
///
/// `Serialize`/`Deserialize` so a durable [`OutboxStore`] can persist entries
/// (e.g. a service backing the outbox with an on-disk keyspace). The derive is
/// format-agnostic — a JSON store encodes `packed` as a byte array, a CBOR/
/// bincode store compactly.
///
/// `#[non_exhaustive]`: build one with [`OutboxEntry::new`] and the `with_*`
/// builders, so a field added later is not a break for every caller.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct OutboxEntry {
    /// Dedup anchor on the sending side: [`MessagingService::send`] with a key
    /// that already has an entry returns that entry's state and neither
    /// enqueues nor transmits again.
    ///
    /// The delivery layer does **not** deduplicate on the receiving side. A
    /// retried transmission (a send that timed out but arrived, a rebind) can
    /// reach the recipient twice, and a receiving application that must act
    /// once deduplicates on an identifier it carries in its own payload.
    ///
    /// [`MessagingService::send`]: crate::MessagingService::send
    pub idempotency_key: Key,
    /// The recipient DID (who), not the wire.
    pub dest_did: String,
    /// `None` = no ordering constraint; `Some(k)` = per-`k` FIFO of
    /// **hop-acceptance**: an entry is due only once every earlier-enqueued
    /// entry with the same key has left `Queued` (been hop-accepted, or
    /// settled). It does not wait for the earlier entry's end-to-end
    /// confirmation, and a rebind of an earlier entry by an
    /// [`ExpiryEscalator`](crate::ExpiryEscalator) can re-send it after its
    /// followers.
    ///
    /// Either way the drain sends one entry at a time, in due order; "no
    /// ordering constraint" means an entry does not wait for others, not that
    /// entries are sent concurrently.
    pub ordering_key: Option<Key>,
    /// The transport (by `MessagingService` transport id) this entry **must** go
    /// out over, or `None` for "whichever transport is primary at drain time".
    ///
    /// `None` is the right default for a single-identity service, and is what
    /// makes mediator migration work: a queued entry follows `promote` to the new
    /// primary rather than being pinned to the mediator that was current when it
    /// was enqueued.
    ///
    /// `Some(id)` exists for the case where the transport *is* the identity — a
    /// service holding one transport per DID (per persona, per agent). There the
    /// wire is not interchangeable: draining a message enqueued for identity A
    /// over identity B's socket sends it from the wrong sender, which the
    /// recipient authenticates and the mediator ACL judges. Such an entry is
    /// drained only by [`drain_once_via`](crate::drain_once_via) for the matching
    /// id, never by [`drain_once`](crate::drain_once).
    ///
    /// `#[serde(default)]` so entries persisted before this field existed load as
    /// unbound.
    #[serde(default)]
    pub via: Option<String>,
    /// The already-packed message to hand to `MessageTransport::send`.
    pub packed: Vec<u8>,
    /// Lifecycle state.
    pub state: OutboxState,
    /// Number of send attempts made so far.
    pub attempts: u32,
    /// Unix-ms time this entry is next eligible for a send attempt (backoff).
    pub next_attempt_at_ms: u64,
    /// Unix-ms time the entry was enqueued (FIFO ordering anchor).
    pub created_at_ms: u64,
    /// Enqueue order within this process, the FIFO tie-breaker for entries
    /// created in the same millisecond (`created_at_ms` alone made every one
    /// of them a head, sent in key order). Assigned by [`OutboxEntry::new`]
    /// from a process-wide counter.
    ///
    /// `#[serde(default)]`: entries persisted before it existed load as `0`
    /// and order by `created_at_ms`, then key, as before.
    #[serde(default)]
    pub enqueue_seq: u64,
    /// Unix-ms delivery-window deadline — the acceptable recovery time. Past
    /// this without success the entry settles visibly, never a silent success.
    pub deliver_by_ms: u64,
    /// The transport hop-id for the accepted frame, recorded when the entry
    /// becomes `Sent`; `None` until sent, or if the transport returns none.
    ///
    /// For a DIDComm send this is the identifier the **recipient's** mediator
    /// stores the message under (`sha256` of the packed message a `forward`
    /// carries), whichever mediator that is. Two things use it:
    ///
    /// - the status poll, for a [`DeliveryScope::Local`] entry, where the
    ///   sender's mediator is the one holding it; and
    /// - a `messaging/wake/request` to the recipient's mediator, which names
    ///   the queued message by exactly this id (VTI-TRN-070). That holds for a
    ///   [`DeliveryScope::Relayed`] entry too: the relay carries the same bytes.
    pub hop_id: Option<String>,
    /// Whether `hop_id` has been seen present in the transport's outbox at least
    /// once. Guards the outbox-drain check against the mediator's eventual
    /// consistency: a hop-id "absent" right after send may simply not be indexed
    /// yet, so absence is only reported as a drain *after* it was observed
    /// present. A drain is not delivery evidence (pickup and expiry look the
    /// same); see [`poll_outbox_drain`](crate::poll_outbox_drain).
    pub outbox_observed: bool,
    /// Whether the sender's own mediator holds this message for its recipient
    /// ([`DeliveryScope`]). Set by the caller ([`with_scope`](Self::with_scope))
    /// or, when left `Unknown`, by the drain from
    /// [`MessageTransport::delivery_scope`] when the entry is first sent.
    ///
    /// A [`DeliveryScope::Relayed`] entry is never polled for status, and with
    /// no receipt it settles `Unconfirmed` with
    /// [`UnconfirmedReason::NoEvidencePath`] instead of being escalated —
    /// unless its recipient is known to send receipts
    /// ([`ReceiptReach`](crate::ReceiptReach)).
    ///
    /// `#[serde(default)]` so entries persisted before this field existed load
    /// as `Unknown`, which is polled as before.
    ///
    /// [`MessageTransport::delivery_scope`]: affinidi_messaging_core::MessageTransport::delivery_scope
    #[serde(default)]
    pub scope: DeliveryScope,
    /// Why the entry settled `Unconfirmed`, once it has; `None` otherwise.
    /// `#[serde(default)]` for entries persisted before it existed.
    #[serde(default)]
    pub unconfirmed_reason: Option<UnconfirmedReason>,
    /// Unix-ms time the entry reached a terminal state, or `None` if it has
    /// not (or settled before this field existed). The reap measures
    /// retention from here — see [`settled_basis_ms`](Self::settled_basis_ms).
    ///
    /// `#[serde(default)]`: no migration needed for entries already on disk.
    #[serde(default)]
    pub settled_at_ms: Option<u64>,
}

impl OutboxEntry {
    /// A fresh `Queued` entry, eligible for an immediate first attempt.
    pub fn new(
        idempotency_key: impl Into<Key>,
        dest_did: impl Into<String>,
        packed: Vec<u8>,
        created_at_ms: u64,
        deliver_by_ms: u64,
    ) -> Self {
        Self {
            idempotency_key: idempotency_key.into(),
            dest_did: dest_did.into(),
            ordering_key: None,
            via: None,
            packed,
            state: OutboxState::Queued,
            attempts: 0,
            next_attempt_at_ms: created_at_ms,
            created_at_ms,
            deliver_by_ms,
            hop_id: None,
            outbox_observed: false,
            scope: DeliveryScope::Unknown,
            unconfirmed_reason: None,
            enqueue_seq: ENQUEUE_SEQ.fetch_add(1, Ordering::Relaxed),
            settled_at_ms: None,
        }
    }

    /// The time retention of a terminal entry is measured from: when it
    /// settled, or — for an entry settled before
    /// [`settled_at_ms`](Self::settled_at_ms) existed, or by code that does
    /// not set it — the later of its creation and its delivery deadline. An
    /// entry settled early, by evidence, then looks younger than it is, which
    /// errs the safe way: it is kept longer, never reaped sooner.
    pub fn settled_basis_ms(&self) -> u64 {
        self.settled_at_ms
            .unwrap_or_else(|| self.created_at_ms.max(self.deliver_by_ms))
    }

    /// Move to the terminal `state`, recording when (`now_ms`; `None` leaves
    /// [`settled_at_ms`](Self::settled_at_ms) unset if the clock could not be
    /// read).
    pub(crate) fn settle(&mut self, state: OutboxState, now_ms: Option<u64>) {
        debug_assert!(state.is_terminal());
        self.state = state;
        self.settled_at_ms = now_ms.or(self.settled_at_ms);
    }

    /// The FIFO order of entries: enqueue time, then enqueue sequence, then key.
    fn fifo_order(&self) -> (u64, u64, &str) {
        (self.created_at_ms, self.enqueue_seq, &self.idempotency_key)
    }

    /// Builder-style: state whether the recipient shares the sender's mediator,
    /// when the caller already knows (see [`scope`](Self::scope)). Left
    /// `Unknown`, the drain asks the transport.
    pub fn with_scope(mut self, scope: DeliveryScope) -> Self {
        self.scope = scope;
        self
    }

    /// Builder-style: set the ordering key (per-key FIFO drain).
    pub fn with_ordering_key(mut self, key: impl Into<Key>) -> Self {
        self.ordering_key = Some(key.into());
        self
    }

    /// Builder-style: pin this entry to one transport (see [`via`](Self::via)).
    pub fn with_via(mut self, transport_id: impl Into<String>) -> Self {
        self.via = Some(transport_id.into());
        self
    }
}

/// Process-wide source of [`OutboxEntry::enqueue_seq`].
static ENQUEUE_SEQ: AtomicU64 = AtomicU64::new(1);

/// A state change applied by [`OutboxStore::transition`].
pub type Transition<'a> = Box<dyn FnOnce(&mut OutboxEntry) + Send + 'a>;

/// Errors from an [`OutboxStore`] backend.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum OutboxError {
    /// The backing store failed (I/O, serialization, lock poisoning, …).
    #[error("outbox store backend error: {0}")]
    Backend(String),
}

/// Durable storage for outbox entries. Services implement this over a durable
/// store (e.g. fjall); [`InMemoryOutboxStore`] is provided for tests and
/// ephemeral use.
///
/// `put` is an unconditional upsert keyed by `idempotency_key`. The delivery
/// layer itself no longer uses it for state changes: an enqueue goes through
/// [`insert_if_absent`](Self::insert_if_absent) and every later change through
/// [`transition`](Self::transition), both conditional. `put` remains for a
/// caller that means to overwrite — re-queueing an `Unconfirmed` entry by hand,
/// or seeding a store. `due` encodes the ordering-key FIFO gate so the drain
/// doesn't have to.
///
/// # Implementing a durable store
///
/// Override [`insert_if_absent`](Self::insert_if_absent) and
/// [`transition`](Self::transition) so each runs as one atomic step (a
/// transaction, a compare-and-swap) — their defaults are a read followed by a
/// write and can lose a race between the layer's concurrent loops. Override
/// [`awaiting_confirmation`](Self::awaiting_confirmation),
/// [`expired_queued`](Self::expired_queued),
/// [`terminal_before`](Self::terminal_before) and
/// [`remove_if_terminal`](Self::remove_if_terminal), or the corresponding
/// sweeps silently do nothing.
#[async_trait::async_trait]
pub trait OutboxStore: Send + Sync {
    /// Insert or replace an entry, keyed by its `idempotency_key`.
    async fn put(&self, entry: OutboxEntry) -> Result<(), OutboxError>;

    /// Insert `entry` unless an entry with its `idempotency_key` exists.
    /// Returns `None` if it was inserted, or the existing entry (unchanged)
    /// if not.
    ///
    /// What [`MessagingService::send`](crate::MessagingService::send) enqueues
    /// with: re-sending under an idempotency key must not reset a `Sent` or
    /// `Delivered` entry to `Queued` and transmit it again.
    ///
    /// The default is `get` then `put`, which is not atomic: two concurrent
    /// inserts of one key can both succeed, the later replacing the earlier. A
    /// store that can do better SHOULD override it.
    async fn insert_if_absent(
        &self,
        entry: OutboxEntry,
    ) -> Result<Option<OutboxEntry>, OutboxError> {
        if let Some(existing) = self.get(&entry.idempotency_key).await? {
            return Ok(Some(existing));
        }
        self.put(entry).await?;
        Ok(None)
    }

    /// Apply `change` to the entry for `idempotency_key` **only if** its
    /// current state is one of `expected`, and persist the result. Returns
    /// whether it was applied: `false` for an absent entry or one in another
    /// state, which is left untouched.
    ///
    /// Every state change the delivery layer makes goes through this. Its
    /// loops run on separate tasks and each holds a snapshot across a slow
    /// `.await` — an escalation re-send, a status poll, a transport send — so
    /// writing the snapshot back with `put` could overwrite what another task
    /// recorded in the meantime: a receipt's `Delivered` undone by a sweep's
    /// `Failed`. Guarding on the expected state makes terminal states
    /// absorbing: no transition the layer makes expects one.
    ///
    /// `change` must not alter `idempotency_key`; an implementation keeps the
    /// key it looked up.
    ///
    /// The default is `get`, check, `put` — correct against a stale snapshot
    /// taken before a slow operation, but not atomic against a concurrent
    /// writer between its own read and write. A durable store SHOULD override
    /// it to evaluate the guard and write in one step, as
    /// [`InMemoryOutboxStore`] does under its lock.
    async fn transition(
        &self,
        idempotency_key: &str,
        expected: &[OutboxState],
        change: Transition<'_>,
    ) -> Result<bool, OutboxError> {
        let Some(mut entry) = self.get(idempotency_key).await? else {
            return Ok(false);
        };
        if !expected.contains(&entry.state) {
            return Ok(false);
        }
        change(&mut entry);
        entry.idempotency_key = idempotency_key.to_string();
        self.put(entry).await?;
        Ok(true)
    }

    /// `Queued` entries whose delivery window has closed
    /// (`deliver_by_ms <= now_ms`), whatever their backoff, ordering key or
    /// [`via`](OutboxEntry::via).
    ///
    /// The drain fails an expired entry only when `due()` hands it over and
    /// the drain claims it, which never happens for an entry pinned to a
    /// transport that is gone, one deferred past its deadline, or a FIFO
    /// follower stuck behind its head. The confirmation sweep settles these
    /// from this query instead.
    ///
    /// The default returns none, so a store that does not override it keeps
    /// the old behaviour: those entries stay `Queued`. A durable store SHOULD
    /// override it.
    async fn expired_queued(&self, _now_ms: u64) -> Result<Vec<OutboxEntry>, OutboxError> {
        Ok(Vec::new())
    }

    /// Look up an entry by idempotency key.
    async fn get(&self, idempotency_key: &str) -> Result<Option<OutboxEntry>, OutboxError>;

    /// Entries that are ready for a send attempt now: `Queued`, with
    /// `next_attempt_at_ms <= now_ms`, and — for entries with an `ordering_key`
    /// — only the earliest-enqueued `Queued` entry per key, so a per-key FIFO
    /// of hop-acceptance is preserved (see [`OutboxEntry::ordering_key`]).
    /// "Earliest" is by `created_at_ms`, then `enqueue_seq`, then key, so
    /// exactly one entry heads each key. Returned oldest-first in that order.
    async fn due(&self, now_ms: u64) -> Result<Vec<OutboxEntry>, OutboxError>;

    /// All `Sent` entries — hop-accepted and awaiting end-to-end evidence (§5a).
    /// The confirmation sweep ([`crate::confirm::sweep_confirmations`]) checks
    /// these against `deliver_by_ms`.
    ///
    /// The default returns none, so a store that doesn't override it simply
    /// never sweeps confirmations (safe, but a `Sent` entry never settles
    /// `Unconfirmed`). A durable store SHOULD override this.
    async fn awaiting_confirmation(&self) -> Result<Vec<OutboxEntry>, OutboxError> {
        Ok(Vec::new())
    }

    /// Delete an entry **only if it is still terminal**, atomically. Returns
    /// whether it was removed.
    ///
    /// The trait had no way to remove anything: entries were upserted by `put`
    /// and only ever changed *state*, so an outbox keyspace grew for the life
    /// of the deployment and `due()` re-read and re-decoded every entry ever
    /// written, on every tick. A queue that cannot be emptied is not a queue.
    ///
    /// # Why conditional, and why atomic
    ///
    /// A plain `remove(key)` would be a check-then-act race (CWE-367). The
    /// reaper reads a snapshot with [`terminal_before`](Self::terminal_before)
    /// and deletes from it, and an entry can be re-queued by `put` in between —
    /// a retry of an `Unconfirmed` send, say. A reaper holding a general delete
    /// would then remove live work on the strength of a stale read, which is
    /// losing a message rather than tidying up after one.
    ///
    /// Re-reading before deleting narrows that window but does not close it.
    /// The condition has to be evaluated where the delete happens, under
    /// whatever the store uses to make `put` atomic, so this is the primitive
    /// rather than a `remove` the caller is trusted to guard.
    ///
    /// Defaulted to `Ok(false)` — "removed nothing" — to match
    /// [`terminal_before`](Self::terminal_before): a store opts into reaping by
    /// implementing both, and one that implements neither keeps its previous
    /// behaviour exactly. Implementing `terminal_before` *without* this is the
    /// one incoherent combination, and it is visible rather than silent:
    /// [`ReapReport::skipped`](crate::reap::ReapReport::skipped) counts entries
    /// the store offered and then declined to remove.
    async fn remove_if_terminal(&self, _idempotency_key: &str) -> Result<bool, OutboxError> {
        Ok(false)
    }

    /// Terminal entries that settled at or before `cutoff_ms`
    /// ([`OutboxEntry::settled_basis_ms`]), oldest first — the input to
    /// [`reap_terminal`](crate::reap::reap_terminal).
    ///
    /// Age is measured from when the entry settled, not from when it was
    /// created: with a delivery window longer than the retention, creation
    /// time made an entry eligible for reaping the moment it settled, and its
    /// outcome vanished before anyone could read it.
    ///
    /// Defaulted to none: enumerating by settle time is store-specific, and a
    /// store that cannot do it efficiently should keep working rather than fail
    /// to compile. **A store that does not override this never reaps**, so a
    /// durable one SHOULD.
    async fn terminal_before(&self, _cutoff_ms: u64) -> Result<Vec<OutboxEntry>, OutboxError> {
        Ok(Vec::new())
    }
}

/// A non-durable [`OutboxStore`] backed by a `HashMap`. For tests and ephemeral
/// use — a process restart loses queued work, so services back the outbox with
/// a durable store in production.
#[derive(Debug, Default)]
pub struct InMemoryOutboxStore {
    entries: Mutex<HashMap<Key, OutboxEntry>>,
}

impl InMemoryOutboxStore {
    /// A new, empty store.
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, HashMap<Key, OutboxEntry>>, OutboxError> {
        self.entries
            .lock()
            .map_err(|_| OutboxError::Backend("outbox mutex poisoned".to_string()))
    }
}

#[async_trait::async_trait]
impl OutboxStore for InMemoryOutboxStore {
    async fn put(&self, entry: OutboxEntry) -> Result<(), OutboxError> {
        self.lock()?.insert(entry.idempotency_key.clone(), entry);
        Ok(())
    }

    async fn get(&self, idempotency_key: &str) -> Result<Option<OutboxEntry>, OutboxError> {
        Ok(self.lock()?.get(idempotency_key).cloned())
    }

    async fn due(&self, now_ms: u64) -> Result<Vec<OutboxEntry>, OutboxError> {
        let entries = self.lock()?;

        // Per ordering-key FIFO head: the earliest-enqueued entry still
        // `Queued` for each key gates the rest. An entry that has been
        // hop-accepted (`Sent`) or settled no longer holds its followers back.
        // Entries with no ordering key are independent.
        let mut head: HashMap<&Key, &OutboxEntry> = HashMap::new();
        for e in entries.values() {
            if e.state != OutboxState::Queued {
                continue;
            }
            if let Some(key) = &e.ordering_key {
                let current = head.entry(key).or_insert(e);
                if e.fifo_order() < current.fifo_order() {
                    *current = e;
                }
            }
        }

        let mut due: Vec<OutboxEntry> = entries
            .values()
            .filter(|e| e.state == OutboxState::Queued && e.next_attempt_at_ms <= now_ms)
            .filter(|e| match &e.ordering_key {
                // Only the FIFO head for this key is eligible.
                Some(key) => head
                    .get(key)
                    .is_some_and(|h| h.idempotency_key == e.idempotency_key),
                None => true,
            })
            .cloned()
            .collect();

        // Oldest-first, in enqueue order.
        due.sort_by(|a, b| a.fifo_order().cmp(&b.fifo_order()));
        Ok(due)
    }

    async fn insert_if_absent(
        &self,
        entry: OutboxEntry,
    ) -> Result<Option<OutboxEntry>, OutboxError> {
        let mut entries = self.lock()?;
        if let Some(existing) = entries.get(&entry.idempotency_key) {
            return Ok(Some(existing.clone()));
        }
        entries.insert(entry.idempotency_key.clone(), entry);
        Ok(None)
    }

    async fn transition(
        &self,
        idempotency_key: &str,
        expected: &[OutboxState],
        change: Transition<'_>,
    ) -> Result<bool, OutboxError> {
        // The guard and the write under one lock: that is the whole point.
        let mut entries = self.lock()?;
        let Some(entry) = entries.get_mut(idempotency_key) else {
            return Ok(false);
        };
        if !expected.contains(&entry.state) {
            return Ok(false);
        }
        change(entry);
        entry.idempotency_key = idempotency_key.to_string();
        Ok(true)
    }

    async fn expired_queued(&self, now_ms: u64) -> Result<Vec<OutboxEntry>, OutboxError> {
        let mut out: Vec<OutboxEntry> = self
            .lock()?
            .values()
            .filter(|e| e.state == OutboxState::Queued && e.deliver_by_ms <= now_ms)
            .cloned()
            .collect();
        out.sort_by(|a, b| a.fifo_order().cmp(&b.fifo_order()));
        Ok(out)
    }

    async fn remove_if_terminal(&self, idempotency_key: &str) -> Result<bool, OutboxError> {
        // One lock for the test and the delete: taking them separately is the
        // race this method exists to avoid.
        let mut entries = self.lock()?;
        match entries.get(idempotency_key) {
            Some(e) if e.state.is_terminal() => {
                entries.remove(idempotency_key);
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    async fn terminal_before(&self, cutoff_ms: u64) -> Result<Vec<OutboxEntry>, OutboxError> {
        let mut out: Vec<OutboxEntry> = self
            .lock()?
            .values()
            .filter(|e| e.state.is_terminal() && e.settled_basis_ms() <= cutoff_ms)
            .cloned()
            .collect();
        out.sort_by_key(OutboxEntry::settled_basis_ms);
        Ok(out)
    }

    async fn awaiting_confirmation(&self) -> Result<Vec<OutboxEntry>, OutboxError> {
        Ok(self
            .lock()?
            .values()
            .filter(|e| e.state == OutboxState::Sent)
            .cloned()
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(key: &str, created: u64) -> OutboxEntry {
        OutboxEntry::new(
            key,
            "did:example:bob",
            vec![1, 2, 3],
            created,
            created + 60_000,
        )
    }

    #[test]
    fn entry_survives_a_serde_roundtrip() {
        // A durable OutboxStore persists entries via serde; every field must
        // survive the round trip (incl. the §5a hop_id / outbox_observed and a
        // non-Queued state).
        let mut e = entry("k1", 1_000).with_ordering_key("ord");
        e.state = OutboxState::Sent;
        e.attempts = 3;
        e.next_attempt_at_ms = 1_500;
        e.hop_id = Some("hop-abc".to_string());
        e.outbox_observed = true;
        e.scope = DeliveryScope::Relayed;
        e.unconfirmed_reason = Some(UnconfirmedReason::NoEvidencePath);

        let json = serde_json::to_vec(&e).unwrap();
        let back: OutboxEntry = serde_json::from_slice(&json).unwrap();

        assert_eq!(back.idempotency_key, "k1");
        assert_eq!(back.dest_did, "did:example:bob");
        assert_eq!(back.ordering_key.as_deref(), Some("ord"));
        assert_eq!(back.packed, vec![1, 2, 3]);
        assert_eq!(back.state, OutboxState::Sent);
        assert_eq!(back.attempts, 3);
        assert_eq!(back.next_attempt_at_ms, 1_500);
        assert_eq!(back.created_at_ms, 1_000);
        assert_eq!(back.deliver_by_ms, 61_000);
        assert_eq!(back.hop_id.as_deref(), Some("hop-abc"));
        assert!(back.outbox_observed);
        assert_eq!(back.scope, DeliveryScope::Relayed);
        assert_eq!(
            back.unconfirmed_reason,
            Some(UnconfirmedReason::NoEvidencePath)
        );
    }

    /// Entries on disk from before scope and reason existed load as an
    /// unknown scope (polled as before) with no reason.
    #[test]
    fn an_entry_persisted_without_scope_loads_as_unknown() {
        let mut old = serde_json::to_value(entry("k1", 1_000)).unwrap();
        let fields = old.as_object_mut().expect("entry serialises as an object");
        fields.remove("scope").expect("scope serialises");
        fields
            .remove("unconfirmed_reason")
            .expect("unconfirmed_reason serialises");

        let loaded: OutboxEntry = serde_json::from_value(old).unwrap();
        assert_eq!(loaded.scope, DeliveryScope::Unknown);
        assert_eq!(loaded.unconfirmed_reason, None);
    }

    #[tokio::test]
    async fn put_get_roundtrip_and_replace() {
        let store = InMemoryOutboxStore::new();
        store.put(entry("k1", 100)).await.unwrap();
        assert_eq!(store.get("k1").await.unwrap().unwrap().attempts, 0);

        // Upsert by idempotency key: a mutated copy replaces the original.
        let mut e = store.get("k1").await.unwrap().unwrap();
        e.attempts = 3;
        e.state = OutboxState::Sent;
        store.put(e).await.unwrap();
        let got = store.get("k1").await.unwrap().unwrap();
        assert_eq!(got.attempts, 3);
        assert_eq!(got.state, OutboxState::Sent);
    }

    #[tokio::test]
    async fn due_excludes_future_backoff_terminal_and_sent() {
        let store = InMemoryOutboxStore::new();
        store.put(entry("ready", 100)).await.unwrap();

        let mut future = entry("future", 100);
        future.next_attempt_at_ms = 10_000; // not yet due
        store.put(future).await.unwrap();

        let mut sent = entry("sent", 100);
        sent.state = OutboxState::Sent; // awaiting confirmation, not re-sent
        store.put(sent).await.unwrap();

        let mut done = entry("done", 100);
        done.state = OutboxState::Delivered; // terminal
        store.put(done).await.unwrap();

        let due = store.due(1_000).await.unwrap();
        let keys: Vec<_> = due.iter().map(|e| e.idempotency_key.as_str()).collect();
        assert_eq!(keys, vec!["ready"]);
    }

    #[tokio::test]
    async fn ordering_key_gates_to_the_fifo_head() {
        let store = InMemoryOutboxStore::new();
        // Two entries share an ordering key; only the earliest-enqueued is due.
        store
            .put(entry("a", 100).with_ordering_key("did:webvh:x"))
            .await
            .unwrap();
        store
            .put(entry("b", 200).with_ordering_key("did:webvh:x"))
            .await
            .unwrap();
        // An independent (no ordering key) entry is always due.
        store.put(entry("c", 150)).await.unwrap();

        let due = store.due(1_000).await.unwrap();
        let keys: Vec<_> = due.iter().map(|e| e.idempotency_key.as_str()).collect();
        // "a" (head of the ordered key) + "c" (independent); "b" waits behind "a".
        assert_eq!(keys, vec!["a", "c"]);

        // Once "a" reaches a terminal state, "b" becomes the head and is due.
        let mut a = store.get("a").await.unwrap().unwrap();
        a.state = OutboxState::Delivered;
        store.put(a).await.unwrap();
        let due = store.due(1_000).await.unwrap();
        let keys: Vec<_> = due.iter().map(|e| e.idempotency_key.as_str()).collect();
        assert_eq!(keys, vec!["c", "b"]);
    }

    #[test]
    fn a_fresh_entry_is_unbound() {
        assert_eq!(entry("k1", 1_000).via, None);
    }

    #[test]
    fn with_via_pins_the_entry() {
        assert_eq!(
            entry("k1", 1_000).with_via("persona-a").via.as_deref(),
            Some("persona-a")
        );
    }

    /// A durable store holds entries written before `via` existed. They must load
    /// as unbound rather than failing the whole store open.
    #[test]
    fn an_entry_persisted_without_via_loads_as_unbound() {
        let mut without_via = serde_json::to_value(entry("k1", 1_000)).unwrap();
        without_via
            .as_object_mut()
            .expect("entry serialises as an object")
            .remove("via")
            .expect("the current struct serialises via");

        let loaded: OutboxEntry = serde_json::from_value(without_via).unwrap();
        assert_eq!(loaded.via, None);
        assert_eq!(loaded.idempotency_key, "k1");
    }

    /// #1023: entries created in the same millisecond have one head, the
    /// first enqueued, not one per entry in key order.
    #[tokio::test]
    async fn same_millisecond_entries_drain_in_enqueue_order() {
        let store = InMemoryOutboxStore::new();
        // Enqueued "z" then "a", both at t=100.
        store
            .put(entry("z", 100).with_ordering_key("ord"))
            .await
            .unwrap();
        store
            .put(entry("a", 100).with_ordering_key("ord"))
            .await
            .unwrap();
        let due = store.due(1_000).await.unwrap();
        let keys: Vec<_> = due.iter().map(|e| e.idempotency_key.as_str()).collect();
        assert_eq!(keys, vec!["z"]);
    }

    /// #1023: FIFO is of hop-acceptance — a `Sent` head releases its follower.
    #[tokio::test]
    async fn a_sent_head_releases_its_follower() {
        let store = InMemoryOutboxStore::new();
        store
            .put(entry("a", 100).with_ordering_key("ord"))
            .await
            .unwrap();
        store
            .put(entry("b", 200).with_ordering_key("ord"))
            .await
            .unwrap();
        assert!(
            store
                .transition(
                    "a",
                    &[OutboxState::Queued],
                    Box::new(|e| e.state = OutboxState::Sent)
                )
                .await
                .unwrap()
        );
        let due = store.due(1_000).await.unwrap();
        let keys: Vec<_> = due.iter().map(|e| e.idempotency_key.as_str()).collect();
        assert_eq!(keys, vec!["b"]);
    }

    #[tokio::test]
    async fn insert_if_absent_keeps_the_existing_entry() {
        let store = InMemoryOutboxStore::new();
        assert!(
            store
                .insert_if_absent(entry("k", 100))
                .await
                .unwrap()
                .is_none()
        );
        let mut changed = entry("k", 999);
        changed.packed = vec![9];
        let existing = store.insert_if_absent(changed).await.unwrap().unwrap();
        assert_eq!(existing.created_at_ms, 100);
        assert_eq!(store.get("k").await.unwrap().unwrap().packed, vec![1, 2, 3]);
    }

    /// #1022: a transition guarded on `Sent` cannot overwrite `Delivered`.
    #[tokio::test]
    async fn a_guarded_transition_cannot_undo_a_terminal_state() {
        let store = InMemoryOutboxStore::new();
        let mut e = entry("k", 100);
        e.state = OutboxState::Delivered;
        store.put(e).await.unwrap();
        let applied = store
            .transition(
                "k",
                &[OutboxState::Sent],
                Box::new(|e| e.state = OutboxState::Failed),
            )
            .await
            .unwrap();
        assert!(!applied);
        assert_eq!(
            store.get("k").await.unwrap().unwrap().state,
            OutboxState::Delivered
        );
        assert!(
            !store
                .transition("absent", &[OutboxState::Sent], Box::new(|_| {}))
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn expired_queued_ignores_backoff_and_ordering() {
        let store = InMemoryOutboxStore::new();
        let mut deferred = entry("deferred", 100);
        deferred.next_attempt_at_ms = 10_000_000;
        store.put(deferred).await.unwrap();
        store
            .put(entry("head", 100).with_ordering_key("ord"))
            .await
            .unwrap();
        store
            .put(entry("follower", 200).with_ordering_key("ord"))
            .await
            .unwrap();
        let mut sent = entry("sent", 100);
        sent.state = OutboxState::Sent;
        store.put(sent).await.unwrap();

        let expired = store.expired_queued(1_000_000).await.unwrap();
        let mut keys: Vec<_> = expired.iter().map(|e| e.idempotency_key.as_str()).collect();
        keys.sort();
        assert_eq!(keys, vec!["deferred", "follower", "head"]);
    }

    #[test]
    fn settled_basis_falls_back_to_the_later_of_creation_and_deadline() {
        let mut e = entry("k", 1_000);
        assert_eq!(e.settled_basis_ms(), 61_000);
        e.settle(OutboxState::Failed, Some(70_000));
        assert_eq!(e.settled_at_ms, Some(70_000));
        assert_eq!(e.settled_basis_ms(), 70_000);
    }
}
