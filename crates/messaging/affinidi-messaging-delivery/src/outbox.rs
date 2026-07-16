//! The durable outbox: the model, the [`OutboxStore`] storage abstraction, and
//! an in-memory implementation.

use std::collections::HashMap;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

/// An idempotency or ordering key. The idempotency key is the dedup anchor; the
/// ordering key groups entries into a per-key FIFO.
pub type Key = String;

/// Lifecycle state of an outbox entry. Terminal states are `Delivered`,
/// `Unconfirmed`, and `Failed`.
///
/// `Sent` is **not** terminal and **not** "delivered": it means the next hop
/// accepted the bytes (durably queued at the mediator) and we are awaiting
/// end-to-end evidence. Confirmation (`Sent → Delivered`) lands in a later
/// increment; until then a `Sent` entry is simply not re-sent.
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

/// A durable, transport-independent unit of delivery-critical work.
///
/// The entry records **who** the message is for (`dest_did`), not which wire —
/// the transport is resolved at drain time. Timestamps are Unix milliseconds;
/// the drain takes the clock as a parameter so it stays deterministic in tests.
///
/// `Serialize`/`Deserialize` so a durable [`OutboxStore`] can persist entries
/// (e.g. a service backing the outbox with an on-disk keyspace). The derive is
/// format-agnostic — a JSON store encodes `packed` as a byte array, a CBOR/
/// bincode store compactly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboxEntry {
    /// Dedup anchor. The receiver drops a duplicate carrying the same key, which
    /// is what makes at-least-once retry safe.
    pub idempotency_key: Key,
    /// The recipient DID (who), not the wire.
    pub dest_did: String,
    /// `None` = drain in parallel; `Some(k)` = per-`k` FIFO (an entry is due only
    /// if no earlier-enqueued entry with the same key is still non-terminal).
    pub ordering_key: Option<Key>,
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
    /// Unix-ms delivery-window deadline — the acceptable recovery time. Past
    /// this without success the entry settles visibly, never a silent success.
    pub deliver_by_ms: u64,
    /// The transport hop-id (mediator queue-id) for the accepted frame, recorded
    /// when the entry becomes `Sent`. Used to watch this exact message drain from
    /// the sender's outbox (§5a outbox-drain evidence). `None` until sent, or if
    /// the transport returns no hop-id.
    pub hop_id: Option<String>,
    /// Whether `hop_id` has been seen present in the transport's outbox at least
    /// once. Guards the outbox-drain check against the mediator's eventual
    /// consistency: a hop-id "absent" right after send may simply not be indexed
    /// yet, so drain (absent) only counts as pickup *after* it was observed
    /// present.
    pub outbox_observed: bool,
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
            packed,
            state: OutboxState::Queued,
            attempts: 0,
            next_attempt_at_ms: created_at_ms,
            created_at_ms,
            deliver_by_ms,
            hop_id: None,
            outbox_observed: false,
        }
    }

    /// Builder-style: set the ordering key (per-key FIFO drain).
    pub fn with_ordering_key(mut self, key: impl Into<Key>) -> Self {
        self.ordering_key = Some(key.into());
        self
    }
}

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
/// `put` is an upsert keyed by `idempotency_key`, so re-persisting a mutated
/// entry (new state / attempts / backoff) replaces it. `due` encodes the
/// ordering-key FIFO gate so the drain doesn't have to.
#[async_trait::async_trait]
pub trait OutboxStore: Send + Sync {
    /// Insert or replace an entry, keyed by its `idempotency_key`.
    async fn put(&self, entry: OutboxEntry) -> Result<(), OutboxError>;

    /// Look up an entry by idempotency key.
    async fn get(&self, idempotency_key: &str) -> Result<Option<OutboxEntry>, OutboxError>;

    /// Entries that are ready for a send attempt now: `Queued`, with
    /// `next_attempt_at_ms <= now_ms`, and — for entries with an `ordering_key`
    /// — only the earliest-enqueued non-terminal entry per key (so a per-key
    /// FIFO is preserved). Returned oldest-first.
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

        // Per ordering-key FIFO head: the earliest-enqueued NON-TERMINAL entry
        // for each key gates the rest. Entries with no ordering key are
        // independent.
        let mut head_created_at: HashMap<&Key, u64> = HashMap::new();
        for e in entries.values() {
            if e.state.is_terminal() {
                continue;
            }
            if let Some(key) = &e.ordering_key {
                let head = head_created_at.entry(key).or_insert(e.created_at_ms);
                if e.created_at_ms < *head {
                    *head = e.created_at_ms;
                }
            }
        }

        let mut due: Vec<OutboxEntry> = entries
            .values()
            .filter(|e| e.state == OutboxState::Queued && e.next_attempt_at_ms <= now_ms)
            .filter(|e| match &e.ordering_key {
                // Only the FIFO head for this key is eligible.
                Some(key) => head_created_at.get(key) == Some(&e.created_at_ms),
                None => true,
            })
            .cloned()
            .collect();

        // Oldest-first, tie-broken by key for determinism.
        due.sort_by(|a, b| {
            a.created_at_ms
                .cmp(&b.created_at_ms)
                .then_with(|| a.idempotency_key.cmp(&b.idempotency_key))
        });
        Ok(due)
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
}
