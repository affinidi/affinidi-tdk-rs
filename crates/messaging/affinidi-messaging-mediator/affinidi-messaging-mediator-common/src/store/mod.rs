//! Storage backend trait for the Affinidi Messaging Mediator.
//!
//! [`MediatorStore`] is the semantic interface every backend must satisfy.
//! It is shaped from the *consumer* perspective — what the mediator's
//! request handlers, background tasks, and processors actually need —
//! rather than wrapping any one backend's primitives.
//!
//! # Backend selection
//!
//! Three feature-flagged implementations live alongside this trait:
//!
//! | Feature           | Backend       | Use case                                          |
//! |-------------------|---------------|---------------------------------------------------|
//! | `redis-backend`   | `RedisStore`  | Multi-mediator clusters, cross-process pub/sub    |
//! | `fjall-backend`   | `FjallStore`  | Single-node persistent deployments (no Redis dep) |
//! | `memory-backend`  | `MemoryStore` | Tests; in-process only, no persistence            |
//!
//! Default backend for the mediator binary is `redis-backend`. The mediator
//! binary instantiates one impl, boxes it as `Arc<dyn MediatorStore>`, and
//! wires it through `MediatorBuilder`.
//!
//! # Multi-process semantics
//!
//! Only `RedisStore` supports multiple mediator processes sharing one
//! storage backend. `FjallStore` and `MemoryStore` are single-process by
//! construction — their pub/sub channels and consumer-group semantics
//! exist only within the running mediator. Methods whose contract differs
//! between single-process and multi-process backends call this out.
//!
//! # Atomicity
//!
//! Every method is atomic at its own scope: a single trait method either
//! succeeds in full or fails leaving no partial state. Composite operations
//! that span multiple methods are not transactional — callers must accept
//! that intermediate states are observable.
//!
//! # Error model
//!
//! All methods return [`MediatorError`]. Backends translate native errors
//! (Redis `RedisError`, Fjall `Error`, Tokio sync errors) into the
//! mediator's error type. The error variants carry enough context for
//! request handlers to map them to HTTP/DIDComm problem reports.

use crate::errors::MediatorError;
use crate::types::{
    accounts::{Account, AccountActivity, AccountType, ActivityKind, MediatorAccountList},
    acls::{AccessListModeType, MediatorACLSet},
    acls_handler::{
        MediatorACLGetResponse, MediatorAccessListAddResponse, MediatorAccessListGetResponse,
        MediatorAccessListListResponse,
    },
    administration::MediatorAdminList,
    audit::{AuditLogEntry, MediatorAuditLogList},
    messages::{
        FetchDeletePolicy, FetchOptions, Folder, GetMessagesResponse, MessageList,
        MessageListElement,
    },
};
pub mod fair_pickup;

/// How much of the queue a fair pickup looks at, as a multiple of the caller's
/// limit.
///
/// Enough to see past one sender's burst without reading the whole queue: at
/// the default per-relationship cap of 50, a window of ten times a typical
/// pickup limit reaches well past any single sender's share.
pub const FAIR_WINDOW_FACTOR: usize = 10;

/// Hard ceiling on that window, so a caller asking for a large limit cannot
/// turn one pickup into a queue scan.
pub const MAX_FAIR_WINDOW: usize = 500;

use async_trait::async_trait;

/// How many handovers make a message worth reporting as possibly poison.
///
/// A threshold for **classification only**. Nothing is evicted because of it,
/// and that is deliberate: `attempts` is driven by the recipient, which decides
/// when to fetch, so acting on it would let a recipient destroy a sender's
/// messages by doing nothing but collecting them repeatedly. See
/// [`DeliveryState::attempts`](crate::store::types::DeliveryState::attempts).
pub const POISON_ATTEMPTS: u32 = 5;

/// Metric names emitted by [`MediatorStore::fetch_messages_delivering`].
///
/// Defined here, beside the code that emits them, and re-exported from the
/// mediator's own `metrics::names` where every other metric is documented —
/// one definition, discoverable in the usual place.
pub mod delivery_metrics {
    /// counter: messages handed to a recipient for the first time.
    pub const FIRST_DELIVERED: &str = "messages_first_delivered_total";
    /// counter: handovers of a message that had already been delivered.
    pub const REDELIVERED: &str = "messages_redelivered_total";
    /// counter: handovers of a message already delivered at least
    /// [`POISON_ATTEMPTS`](super::POISON_ATTEMPTS) times.
    pub const POISON_SUSPECTED: &str = "messages_poison_suspected_total";
    /// counter: messages whose expiry was brought forward because they had
    /// been delivered.
    pub const DELIVERED_EXPIRY_ADVANCED: &str = "messages_delivered_expiry_advanced_total";
}

/// What one [`mark_delivered`](MediatorStore::mark_delivered) call did.
///
/// Returned rather than logged so the caller decides what to do with it — the
/// shared fetch wrapper turns it into counters, and a backend that records
/// nothing returns it empty.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DeliveryMarkReport {
    /// Messages handed over for the first time.
    pub first_delivered: usize,
    /// Messages that had been handed over before.
    pub redelivered: usize,
    /// Redeliveries of a message already past [`POISON_ATTEMPTS`].
    pub poison_suspected: usize,
    /// Messages whose expiry was brought forward.
    pub expiry_advanced: usize,
}

/// Turn a [`DeliveryMarkReport`] into counters.
///
/// Only non-zero fields are touched, so a deployment with the delivered-expiry
/// shortening off never emits that series at all rather than emitting a flat
/// zero — the two look different on a dashboard and mean different things.
fn publish_delivery_metrics(report: &DeliveryMarkReport) {
    for (name, value) in [
        (delivery_metrics::FIRST_DELIVERED, report.first_delivered),
        (delivery_metrics::REDELIVERED, report.redelivered),
        (delivery_metrics::POISON_SUSPECTED, report.poison_suspected),
        (
            delivery_metrics::DELIVERED_EXPIRY_ADVANCED,
            report.expiry_advanced,
        ),
    ] {
        if value > 0 {
            metrics::counter!(name).increment(value as u64);
        }
    }
}

/// Ceiling on messages one filtered purge will examine.
///
/// A filtered purge walks the folder, and a **dry run walks it without
/// shrinking it** — so, unlike the real purge, it is perfectly repeatable at
/// full cost. That makes it the most expensive thing an authenticated DID can
/// ask for per request, by roughly two orders of magnitude over `/list`, which
/// is capped at 100. The per-DID rate limiter bounds how often a caller may
/// ask; this bounds how much each ask costs.
///
/// A caller with a deeper queue than this gets a partial purge that reports
/// itself as such, and re-running continues against a folder that is now
/// shorter.
pub const MAX_PURGE_SCAN: usize = 10_000;

/// Whether a delete failed because the message was already gone.
///
/// Every backend signals this the same way — the in-memory and Fjall stores and
/// the Redis stored function all produce a `NOT_FOUND:` message — but it is
/// matched on text, which is fragile. It is safe fragility: if the wording ever
/// changes, an already-gone message is counted as a *failure* rather than a
/// success, so a purge would under-report what it removed rather than
/// over-report it. The test in `memory_store` pins the current wording so the
/// change is noticed rather than merely survived.
fn is_not_found(err: &MediatorError) -> bool {
    err.to_string().contains("NOT_FOUND")
}

/// Which messages a [`purge_folder_filtered`](MediatorStore::purge_folder_filtered)
/// call should remove.
///
/// An empty filter matches everything, which is what the unfiltered
/// [`purge_folder`](MediatorStore::purge_folder) already does faster — so a
/// caller with nothing to narrow by should use that instead.
#[derive(Debug, Default, Clone)]
pub struct PurgeFilter {
    /// Only messages exchanged with this counterparty (a DID *hash*).
    ///
    /// "Counterparty" rather than "recipient" because which end that is
    /// depends on the folder: in an outbox it is who the message was sent to,
    /// in an inbox who sent it. Naming it for one of those would be wrong half
    /// the time.
    pub peer: Option<String>,
    /// Only messages that arrived at or before this Unix millisecond.
    ///
    /// Arrival, not expiry: expiry is `min(client_expires_time, now + TTL)`
    /// and a client may set a short one, so ordering by it does not order by
    /// age. The stream id carries the arrival stamp and a client cannot
    /// reorder it.
    pub arrived_before_ms: Option<u64>,
    /// Count what would be removed and remove nothing.
    ///
    /// A purge is destructive and unrecoverable, and the operator reaching for
    /// it is usually reacting to an incident. Being able to ask first is the
    /// difference between a recovery tool and a second incident.
    pub dry_run: bool,
}

impl PurgeFilter {
    /// Whether `element` in `folder` is in scope.
    pub fn matches(&self, element: &MessageListElement, folder: &Folder) -> bool {
        if let Some(peer) = &self.peer {
            let counterparty = match folder {
                Folder::Inbox => element.from_address.as_deref(),
                Folder::Outbox => element.to_address.as_deref(),
            };
            // A message whose counterparty is unrecorded (an anonymous sender)
            // never matches a `peer` filter: it cannot be shown to be the peer
            // asked for, and a purge must not delete on a maybe.
            if counterparty != Some(peer.as_str()) {
                return false;
            }
        }
        if let Some(before) = self.arrived_before_ms
            && element.timestamp > before
        {
            return false;
        }
        true
    }
}

/// What a filtered purge did, or would have done.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PurgeReport {
    /// Messages matched **and actually removed** — or, for a dry run, matched
    /// and would have been.
    ///
    /// Deliberately not "matched": a purge that reported a message it had
    /// failed to delete would be telling the caller the queue is emptier than
    /// it is, which is the one lie a recovery tool must not tell.
    pub count: usize,
    /// Bytes counted in [`count`](Self::count).
    pub bytes: usize,
    /// Messages examined. `scanned` far above `count` means the filter is
    /// narrow, which is the point; it is reported so a caller can tell "the
    /// filter matched nothing" from "the folder was empty".
    pub scanned: usize,
    /// Messages that matched the filter but could **not** be removed.
    ///
    /// A message that was already gone is not counted here — the caller asked
    /// for it to be absent and it is. This is for real refusals: a backend
    /// error, or an authorisation failure. Non-zero means the queue is not as
    /// empty as `count` alone would suggest, and the operator should look
    /// before concluding the recovery worked.
    pub failed: usize,
    /// The walk stopped at its scan ceiling with messages still unexamined.
    ///
    /// The purge is partial, not wrong: everything reported was really removed.
    /// Re-running the same filter continues from a folder that is now shorter.
    pub truncated: bool,
}

/// The next stream id strictly after `id`, for paging a filtered walk.
///
/// Stream ids are `"<unix-ms>-<sequence>"` in every backend — Redis natively,
/// and the Fjall and in-memory stores format their `(ms, seq)` pairs the same
/// way — so incrementing the sequence gives the exclusive successor without
/// needing a backend-specific exclusive-range syntax.
fn exclusive_successor(id: &str) -> Option<String> {
    let (ms, seq) = id.split_once('-')?;
    let ms: u64 = ms.parse().ok()?;
    let seq: u64 = seq.parse().ok()?;
    Some(format!("{ms}-{}", seq.checked_add(1)?))
}
use std::time::Duration;
use tokio::sync::broadcast;

pub mod types;

/// Backend-agnostic decision logic (authorization checks shared by the
/// in-process Rust backends), extracted so it can't drift between them.
pub mod ops;

#[cfg(feature = "redis-backend")]
pub mod redis;

pub use types::{
    DeletionAuthority, DeliveryDecision, DeliveryState, ExpiryReport, ForwardQueueEntry,
    InboxStatusReply, MessageMetaData, MetadataStats, PubSubRecord, Session, SessionClaims,
    SessionState, SessionSweepReport, StatCounter, StoreHealth, StreamingClientState,
};

/// Fail-closed session rename used by the default
/// [`MediatorStore::update_session_authenticated`]: delete the old session
/// *before* writing the new one.
///
/// Why ordering matters for a backend without an atomic rename: if the new
/// session were written first, a crash (or a failed delete) between the two
/// steps would leave the old session id valid alongside the new. Deleting
/// first means an interruption can only *lose* the new session — the client
/// re-authenticates — and the two never coexist. When `old == new` the
/// delete is skipped (an in-place overwrite, so there is no gap).
///
/// Backends with an atomic rename (Redis `RENAME`+`HSET`, Fjall `Batch`)
/// override the trait method and don't use this.
pub(crate) async fn rename_session_fail_closed<DF, PF>(
    old_session_id: &str,
    new_session_id: &str,
    delete_old: impl FnOnce() -> DF,
    put_new: impl FnOnce() -> PF,
) -> Result<(), MediatorError>
where
    DF: std::future::Future<Output = Result<(), MediatorError>>,
    PF: std::future::Future<Output = Result<(), MediatorError>>,
{
    if old_session_id != new_session_id {
        delete_old().await?;
    }
    put_new().await?;
    Ok(())
}

// ─── Trait ───────────────────────────────────────────────────────────────────

/// Semantic storage interface for the Affinidi Messaging Mediator.
///
/// Backends are held as `Arc<dyn MediatorStore>` and shared across all
/// request handlers and background tasks. Every method takes `&self`;
/// backends use interior mutability (connection pools, locks, atomics).
///
/// See the module-level docs for backend feature flags, multi-process
/// guarantees, atomicity, and the error model.
/// Outcome of [`MediatorStore::trust_task_claim`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrustTaskClaim {
    /// First sight of this document: execute it.
    Fresh,
    /// The same document again: do not execute it a second time.
    Duplicate,
    /// A different document under an id already used: refuse it.
    Conflict,
}

/// Told of each message the expiry sweep removes: its id, and its metadata as
/// it was just before the delete. See
/// [`MediatorStore::sweep_expired_messages_observed`].
pub type OnExpired<'a> = &'a (dyn Fn(&str, &MessageMetaData) + Send + Sync);

#[async_trait]
pub trait MediatorStore: Send + Sync + std::fmt::Debug {
    // ─── Bootstrap & health ──────────────────────────────────────────────────

    /// One-time backend setup. Called once during mediator startup, after
    /// the store is constructed but before any request handlers spin up.
    /// Backends use this to run their migrations, register Lua functions,
    /// open partitions, etc. Idempotent: safe to call against an already-
    /// initialised backend.
    async fn initialize(&self) -> Result<(), MediatorError>;

    /// Liveness check used by `/readyz`. Should be cheap (single round-trip
    /// or in-memory state read). Returns [`StoreHealth::Unavailable`] when
    /// the backend is short-circuiting requests.
    async fn health(&self) -> StoreHealth;

    /// Cleanup at mediator shutdown. Flush in-flight writes, close
    /// connections, release file handles. Called from the shutdown task
    /// after all request handlers have drained.
    async fn shutdown(&self) -> Result<(), MediatorError>;

    // ─── Messages ────────────────────────────────────────────────────────────

    /// Store a message in the database and enqueue it on both the
    /// recipient's inbox and (if non-anonymous) the sender's outbox.
    ///
    /// Returns the message ID (SHA-256 of the message body). The ID is
    /// idempotent — re-storing the same body returns the same ID and is a
    /// no-op.
    ///
    /// `queue_maxlen` bounds the per-DID inbox/outbox stream; `0` means
    /// unbounded. Backends may apply approximate trimming for performance.
    ///
    /// `expires_at` is a Unix timestamp in seconds. The message expiry
    /// processor deletes the message after this time.
    async fn store_message(
        &self,
        session_id: &str,
        message: &str,
        to_did_hash: &str,
        from_hash: Option<&str>,
        expires_at: u64,
        queue_maxlen: usize,
    ) -> Result<String, MediatorError>;

    /// Delete a message by ID.
    ///
    /// Authorisation is encoded in [`DeletionAuthority`]:
    /// - `Owner { did_hash }`: must match the message's TO or FROM, else
    ///   the backend returns `permission_denied`.
    /// - `Admin { admin_did_hash }`: bypasses ownership (used by the
    ///   expiry processor and account removal).
    ///
    /// Returns `not_found` when the message is unknown. Tracing context
    /// (session_id, request_msg_id) comes from `tracing::span` at the
    /// call site and is not part of the storage contract.
    ///
    /// Removes the message body, both stream entries (inbox + outbox),
    /// and the metadata record atomically.
    async fn delete_message(
        &self,
        message_hash: &str,
        by: DeletionAuthority,
    ) -> Result<(), MediatorError>;

    /// Retrieve one message by ID with the body and metadata.
    ///
    /// Returns `None` when the requesting DID is neither sender nor
    /// recipient — leaking a permission-denied error here would reveal
    /// that the message exists.
    async fn get_message(
        &self,
        did_hash: &str,
        msg_id: &str,
    ) -> Result<Option<MessageListElement>, MediatorError>;

    /// Several messages by id, with bodies, in the order asked.
    ///
    /// The single-message [`get_message`](Self::get_message) is a round trip
    /// each; a fair pickup needs a whole batch, so backends that can read them
    /// together should. The default loops, which is no worse than the caller
    /// doing it.
    ///
    /// A message that has gone since it was listed comes back as `None` rather
    /// than an error — a concurrent delete is normal, not a failure.
    async fn get_messages(
        &self,
        did_hash: &str,
        msg_ids: &[String],
    ) -> Result<Vec<Option<MessageListElement>>, MediatorError> {
        let mut out = Vec::with_capacity(msg_ids.len());
        for id in msg_ids {
            out.push(self.get_message(did_hash, id).await?);
        }
        Ok(out)
    }

    /// Fetch, giving each sender a turn rather than serving the queue strictly
    /// head-first.
    ///
    /// # Why this is a separate path
    ///
    /// An inbox is an arrival-ordered stream and a plain fetch reads it from
    /// the head, so a sender that queued fifty messages ahead of another's is
    /// fifty messages the recipient must get through first — and if it cannot
    /// process them and does not delete them, it never reaches the other
    /// sender at all. The per-relationship cap bounds how bad that gets; it
    /// does not change its shape.
    ///
    /// Order **within** a sender is preserved exactly. Only the interleaving
    /// between senders changes, which no ordering guarantee covers — two
    /// senders' messages arrive in whatever order the network delivered them.
    ///
    /// # Cost, and why it is two round trips rather than one
    ///
    /// Listing is cheap and bodies are not, so this lists a window, chooses
    /// from it, and reads only the chosen bodies: one listing plus one batched
    /// get, against the single stored-function call a plain fetch makes. The
    /// window is `limit * `[`FAIR_WINDOW_FACTOR`], capped at
    /// [`MAX_FAIR_WINDOW`], so the extra cost is bounded and does not grow with
    /// the queue.
    ///
    /// # It ignores `start_id`, and the caller must not pass one
    ///
    /// A round-robin selection is not a contiguous stream range, so "continue
    /// after the last id I got" has no meaning against it — a client paging
    /// that way would skip messages. Callers use this only for a fresh pickup;
    /// a paging drain wants stream order anyway and should call
    /// [`fetch_messages`](Self::fetch_messages).
    async fn fetch_messages_fair(
        &self,
        session_id: &str,
        did_hash: &str,
        options: &FetchOptions,
    ) -> Result<GetMessagesResponse, MediatorError> {
        let window_size = options
            .limit
            .saturating_mul(FAIR_WINDOW_FACTOR)
            .min(MAX_FAIR_WINDOW);

        let window = self
            .list_messages(
                did_hash,
                Folder::Inbox,
                Some(("-", "+")),
                window_size as u32,
            )
            .await?;
        let chosen = fair_pickup::round_robin_select(&window, options.limit);
        if chosen.is_empty() {
            return Ok(GetMessagesResponse::default());
        }

        let mut response = GetMessagesResponse::default();
        for (id, message) in chosen
            .iter()
            .zip(self.get_messages(did_hash, &chosen).await?)
        {
            // Listed a moment ago and gone now: a concurrent pickup or the
            // expiry sweeper. Not an error, and not something to report as a
            // failed read.
            let Some(message) = message else { continue };
            response.success.push(message);

            if matches!(options.delete_policy, FetchDeletePolicy::Optimistic)
                && let Err(e) = self
                    .delete_message(
                        id,
                        DeletionAuthority::Owner {
                            did_hash: did_hash.to_string(),
                        },
                    )
                    .await
            {
                response.delete_errors.push((id.clone(), e.to_string()));
            }
        }

        let _ = session_id;
        Ok(response)
    }

    /// Fetch messages and record that they were handed over.
    ///
    /// The delivery paths call this rather than [`fetch_messages`] so the
    /// marking lives in one place. There are five call sites — REST fetch, the
    /// websocket handler, the streaming task, message-pickup and v1 mediation
    /// — and a stamp that five callers have to remember is a stamp that will be
    /// missing from the sixth.
    ///
    /// Marking failures are swallowed by [`mark_delivered`]'s contract, so this
    /// returns exactly what `fetch_messages` returned. A pickup that succeeded
    /// is not failed because its bookkeeping did not.
    ///
    /// [`fetch_messages`]: Self::fetch_messages
    /// [`mark_delivered`]: Self::mark_delivered
    async fn fetch_messages_delivering(
        &self,
        session_id: &str,
        did_hash: &str,
        options: &FetchOptions,
        now_ms: u64,
        delivered_ttl_secs: u64,
        round_robin: bool,
    ) -> Result<GetMessagesResponse, MediatorError> {
        // A round-robin selection is not a contiguous stream range, so a caller
        // that is paging with `start_id` must get stream order — "continue
        // after the last id I got" has no meaning against an interleaved
        // result, and honouring it would skip messages. A paging drain wants
        // stream order anyway.
        let response = if round_robin && options.start_id.is_none() {
            self.fetch_messages_fair(session_id, did_hash, options)
                .await?
        } else {
            self.fetch_messages(session_id, did_hash, options).await?
        };

        // An optimistic fetch deletes each message as it reads it, so by the
        // time this runs there is nothing left to stamp — and stamping anyway
        // is not merely wasted work. On Redis the delivery fields live on the
        // message's own `MSG:META` hash, and `HSETNX` against a **missing** key
        // creates it, so marking a message the fetch has already deleted would
        // resurrect an orphaned hash with no body — on every message, for ever.
        //
        // Checked here rather than in each backend because this is where the
        // policy is known, and because a backend that merely skips absent
        // messages (as the in-memory and Fjall stores do) would still be doing
        // a pointless read per message.
        if matches!(options.delete_policy, FetchDeletePolicy::Optimistic) {
            return Ok(response);
        }

        // Only what actually came back: `get_errors` are messages the fetch
        // could not read, and stamping those would record a handover that
        // never happened.
        let delivered: Vec<String> = response.success.iter().map(|m| m.msg_id.clone()).collect();
        if !delivered.is_empty() {
            let report = self
                .mark_delivered(&delivered, now_ms, delivered_ttl_secs)
                .await?;
            publish_delivery_metrics(&report);
        }
        Ok(response)
    }

    /// Record that `msg_ids` have been handed to their recipient: stamp the
    /// first-delivery time if unset, and bump the attempt count.
    ///
    /// Called by the mediator after a pickup or a live push, **not** inside the
    /// read itself. On Redis the read is a stored Lua function, so stamping
    /// atomically would mean putting it in `atm-functions.lua` — and that is
    /// exactly where it must not be.
    ///
    /// Not because operators would have to reload: they would not.
    /// `Database::load_scripts` issues `FUNCTION LOAD REPLACE` at boot from
    /// whatever `functions_file` names, unattended, and fails loudly if Redis
    /// rejects it. The hazard is narrower and worse — **the file it loads can
    /// be stale**, and then the load succeeds, correctly and loudly, with the
    /// wrong library. That is what happened when the per-relationship
    /// accounting was added to one copy of the file and not the copy a test
    /// deployment pointed at.
    ///
    /// Which is the argument for keeping the stamp out of the Lua, and it is
    /// the opposite of "this field does not matter much". Eviction of
    /// delivered-but-unacknowledged messages, poison-message detection and
    /// tiered expiry are all meant to be built on it. A stale library would
    /// silently not stamp, and every one of those would silently not work — a
    /// *mechanism* that quietly does nothing, where the earlier casualty was a
    /// *gate* that failed safe. It belongs in Rust precisely **because** things
    /// will depend on it.
    ///
    /// The cost is that marking is not atomic with the read, and the test that
    /// makes that acceptable is that **both** error directions are safe: a
    /// crash in between leaves `first_delivered_at_ms` unset, so eviction does
    /// not fire early, and it undercounts `attempts`, so poison detection stays
    /// lenient. Nothing becomes more aggressive when an update is lost. A
    /// future field on this record that fails that test — one where a missed
    /// update makes the mediator *do* something rather than not do it — needs
    /// different treatment and should not be added here without saying so.
    ///
    /// Best-effort by contract: an implementation that cannot record this
    /// returns `Ok(())` having done nothing, and callers must not treat the
    /// absence of a stamp as evidence a message was never delivered.
    ///
    /// # `delivered_ttl_secs`
    ///
    /// When non-zero, a message marked delivered **for the first time** also
    /// has its expiry brought forward to `now + delivered_ttl_secs`, so a
    /// message the recipient has already collected stops occupying its
    /// sender's queue allowance for a full week. `0` disables that and is the
    /// default.
    ///
    /// The index entry is **added, not moved**. Removing the original would
    /// need each backend to know the prior expiry, which the Redis metadata
    /// hash does not carry — and it is unnecessary, because every sweeper
    /// already counts a message that is gone as `already_deleted` rather than
    /// failing. The earlier slot deletes the message; the later slot resolves
    /// to a no-op. That is how the Redis backend has always behaved anyway,
    /// since its stored `delete_message` never removed the expiry entry.
    ///
    /// **Only the first delivery moves it.** A redelivery must not keep pushing
    /// the deadline out, or a client that reconnects often would pin its
    /// sender's allowance indefinitely — the mirror of the bug this exists to
    /// fix. It is also the reason this cannot be driven by `attempts`: that
    /// number is recipient-controlled, and anything keyed on it alone lets a
    /// recipient decide when a sender's messages die.
    async fn mark_delivered(
        &self,
        _msg_ids: &[String],
        _now_ms: u64,
        _delivered_ttl_secs: u64,
    ) -> Result<DeliveryMarkReport, MediatorError> {
        Ok(DeliveryMarkReport::default())
    }

    /// What the mediator knows about `msg_id` having been handed over.
    ///
    /// `None` when the message does not exist. A message that exists but has
    /// never been delivered returns a default [`DeliveryState`], which is the
    /// honest answer — not an error, and not the same as "not found".
    async fn delivery_state(&self, _msg_id: &str) -> Result<Option<DeliveryState>, MediatorError> {
        Ok(None)
    }

    /// Delivery state for several messages at once, in the order asked.
    ///
    /// The single-message [`delivery_state`](Self::delivery_state) is one round
    /// trip per message, which is fine for a lookup and wrong for a sample of a
    /// hundred. This is the batched form; a backend with no batching answers by
    /// looping, which is no worse than the caller doing it.
    async fn delivery_states(
        &self,
        msg_ids: &[String],
    ) -> Result<Vec<Option<DeliveryState>>, MediatorError> {
        let mut out = Vec::with_capacity(msg_ids.len());
        for id in msg_ids {
            out.push(self.delivery_state(id).await?);
        }
        Ok(out)
    }

    /// Retrieve message metadata without the body. Used by handlers that
    /// need to authorise an action before fetching the (potentially large)
    /// body.
    async fn get_message_metadata(
        &self,
        session_id: &str,
        message_hash: &str,
    ) -> Result<MessageMetaData, MediatorError>;

    // ─── Inbox & outbox ─────────────────────────────────────────────────────

    /// List messages in a folder (inbox or outbox) with stream-ID range
    /// filtering. Returns lightweight metadata only — bodies are fetched
    /// separately via [`fetch_messages`] or [`get_message`].
    ///
    /// `range = None` is equivalent to `("-", "+")` (the full stream).
    async fn list_messages(
        &self,
        did_hash: &str,
        folder: Folder,
        range: Option<(&str, &str)>,
        limit: u32,
    ) -> Result<MessageList, MediatorError>;

    /// Fetch messages with bodies and apply the configured delete policy.
    /// Honours [`FetchOptions::start_id`] as an exclusive cursor and
    /// [`FetchOptions::limit`] as the maximum batch size.
    ///
    /// When `delete_policy = Optimistic`, each message is deleted after
    /// successful retrieval; failures are reported in
    /// [`GetMessagesResponse::delete_errors`] and do not abort the fetch.
    async fn fetch_messages(
        &self,
        session_id: &str,
        did_hash: &str,
        options: &FetchOptions,
    ) -> Result<GetMessagesResponse, MediatorError>;

    /// Delete every message in a folder for the given DID. Returns
    /// `(count_purged, bytes_purged)`. After purging, removes the
    /// underlying stream key.
    async fn purge_folder(
        &self,
        session_id: &str,
        did_hash: &str,
        folder: Folder,
    ) -> Result<(usize, usize), MediatorError>;

    /// Purge only the messages in a folder that match `filter`, and report
    /// what was (or would be) removed.
    ///
    /// # Why this is not `purge_folder`
    ///
    /// [`purge_folder`](Self::purge_folder) is all-or-nothing, and the queue
    /// that strands a deployment is rarely one where destroying everything is
    /// the right answer. The operation an operator actually wants is "drop what
    /// I have been holding for this dead peer" or "drop anything older than a
    /// week" — with, first, "tell me what that would be". Without those, the
    /// only recovery from a full queue is to destroy an entire outbox including
    /// the messages that were about to be delivered.
    ///
    /// # Implementation
    ///
    /// Defaulted here rather than implemented per backend, over
    /// [`list_messages`](Self::list_messages) and
    /// [`delete_message`](Self::delete_message). Those are the same primitives
    /// the paged client-side workaround used, so every backend gets this with
    /// no new storage code and no new invariants to keep true — the cost is one
    /// paged walk of the folder, which is the right trade for a recovery path
    /// that runs when something has already gone wrong.
    ///
    /// Paging advances by the exclusive successor of the last stream id seen,
    /// because a filtered purge leaves non-matching entries in place: restarting
    /// from the beginning each round, as the unfiltered purge can, would spin on
    /// them forever.
    async fn purge_folder_filtered(
        &self,
        did_hash: &str,
        folder: Folder,
        filter: &PurgeFilter,
    ) -> Result<PurgeReport, MediatorError> {
        const PAGE: u32 = 100;
        let mut report = PurgeReport::default();
        let mut cursor = "-".to_string();

        loop {
            // Bound the work one call can ask for. A filtered purge walks the
            // folder, and a dry run walks it without shrinking it — so, unlike
            // the real purge, it is perfectly repeatable at full cost. That
            // makes it the most expensive thing an authenticated DID can ask
            // for per request, by roughly two orders of magnitude over `/list`,
            // which is capped at 100.
            //
            // The per-DID rate limiter bounds how often; this bounds how much.
            // A caller with more than this queued gets a partial purge that
            // says so, and re-running continues — the same shape the queue
            // survey uses, for the same reason.
            if report.scanned >= MAX_PURGE_SCAN {
                report.truncated = true;
                break;
            }

            let page = self
                .list_messages(did_hash, folder.clone(), Some((&cursor, "+")), PAGE)
                .await?;
            if page.is_empty() {
                break;
            }

            let mut last_id = None;
            for element in &page {
                let stream_id = match folder {
                    Folder::Inbox => element.receive_id.as_deref(),
                    Folder::Outbox => element.send_id.as_deref(),
                };
                last_id = stream_id.map(str::to_string).or(last_id);
                report.scanned += 1;

                if !filter.matches(element, &folder) {
                    continue;
                }
                if filter.dry_run {
                    report.count += 1;
                    report.bytes += element.size as usize;
                    continue;
                }

                match self
                    .delete_message(
                        &element.msg_id,
                        DeletionAuthority::Owner {
                            did_hash: did_hash.to_string(),
                        },
                    )
                    .await
                {
                    Ok(()) => {
                        report.count += 1;
                        report.bytes += element.size as usize;
                    }
                    // A message already gone — a concurrent pickup, or the
                    // expiry sweeper — is not a failure: the caller asked for
                    // it to be absent and it is. It is not counted as removed
                    // either, because this call did not remove it.
                    Err(e) if is_not_found(&e) => {}
                    // Anything else is a message still sitting in the queue.
                    // Counting it as purged would report the queue emptier
                    // than it is, to an operator who is reaching for this
                    // precisely because a full queue is causing an outage.
                    Err(e) => {
                        report.failed += 1;
                        tracing::warn!(
                            msg_id = %element.msg_id,
                            error = %e,
                            "filtered purge could not remove a matching message"
                        );
                    }
                }
            }

            // No usable stream id on the whole page: refuse to loop rather
            // than page from the same place for ever.
            let Some(last_id) = last_id else { break };
            let Some(next) = exclusive_successor(&last_id) else {
                break;
            };
            cursor = next;
        }

        Ok(report)
    }

    /// Remove the stream key for a folder without purging the messages
    /// it references. Used when account removal needs to drop the
    /// recipient's inbox view but leave the actual messages in place
    /// (e.g., they may still need to be read by their senders).
    async fn delete_folder_stream(
        &self,
        session_id: &str,
        did_hash: &str,
        folder: Folder,
    ) -> Result<(), MediatorError>;

    /// Build the Message Pickup 3.0 status reply for one DID.
    async fn inbox_status(&self, did_hash: &str) -> Result<InboxStatusReply, MediatorError>;

    /// How many messages `from_hash` currently has queued **for `to_hash`
    /// specifically** — the per-relationship counterpart to the per-DID
    /// totals on [`Account`].
    ///
    /// This exists because a per-DID send total cannot tell fan-out from
    /// flooding. A community sending one membership card each to two hundred
    /// members, none of whom have collected yet, is indistinguishable from a
    /// sender aiming two hundred messages at a single victim — and capping the
    /// total punishes the first case, silencing a sender because *somebody
    /// else* went offline. The pair count separates them: flooding one peer
    /// moves it, fanning out to many peers does not.
    ///
    /// The count covers messages actually queued, so it falls as the recipient
    /// collects and the entries are deleted.
    ///
    /// The default returns `Ok(0)`, which leaves any gate built on it inert.
    /// A backend without per-pair tracking therefore behaves exactly as it did
    /// before this method existed, and is still covered by the recipient-total
    /// and sender-total gates. Overriding it is what turns the gate on.
    async fn peer_queue_count(
        &self,
        _from_hash: &str,
        _to_hash: &str,
    ) -> Result<u32, MediatorError> {
        Ok(0)
    }

    // ─── Sessions ────────────────────────────────────────────────────────────

    /// Upsert a session record with an explicit TTL.
    ///
    /// Covers all session writes: initial challenge creation (typical TTL
    /// 900s), promotion to authenticated (TTL 86400s, written under a new
    /// `session_id`), and refresh-token rotation (write back the same
    /// session with a new `refresh_token_hash`).
    ///
    /// The post-auth rename is fail-closed: the default
    /// [`update_session_authenticated`](Self::update_session_authenticated)
    /// does `delete_session(old)` *then* `put_session(new)`, so an
    /// interruption can only lose the new session, never leave both. Redis
    /// and Fjall override it with a single atomic operation.
    async fn put_session(&self, session: &Session, ttl: Duration) -> Result<(), MediatorError>;

    /// Retrieve a session by ID and join with the corresponding `DID:`
    /// record so the returned `Session` has populated `acls` and
    /// `account_type` fields. The handler uses these to authorise
    /// downstream requests without a separate account lookup.
    async fn get_session(&self, session_id: &str, did: &str) -> Result<Session, MediatorError>;

    /// Delete a session record. Used for logout and as the *first* step
    /// of the fail-closed post-auth rename (delete old, then write new).
    async fn delete_session(&self, session_id: &str) -> Result<(), MediatorError>;

    // ─── Accounts ────────────────────────────────────────────────────────────

    /// Whether a DID has a local account record on this mediator.
    async fn account_exists(&self, did_hash: &str) -> Result<bool, MediatorError>;

    /// Retrieve an account by DID hash. Returns `None` when the account
    /// doesn't exist.
    async fn account_get(&self, did_hash: &str) -> Result<Option<Account>, MediatorError>;

    /// Create a new account with the given ACLs and optional queue limit.
    /// Returns the created account.
    async fn account_add(
        &self,
        did_hash: &str,
        acls: &MediatorACLSet,
        queue_limit: Option<u32>,
    ) -> Result<Account, MediatorError>;

    /// Remove an account from the mediator.
    ///
    /// This is a composite operation: it blocks the account, drops the
    /// outbox stream key (without purging downstream copies that have
    /// already been delivered), purges the inbox, strips admin
    /// privileges, and removes the DID record. Mediator and root-admin
    /// accounts cannot be removed. Forwarded messages already queued on
    /// the FORWARD_Q are intentionally left alone — letting them flush
    /// is preferable to a queue scan, and the protocol exposes no
    /// option to override.
    async fn account_remove(
        &self,
        session: &Session,
        did_hash: &str,
    ) -> Result<bool, MediatorError>;

    /// List up to 100 accounts using a server-side cursor.
    async fn account_list(
        &self,
        cursor: u32,
        limit: u32,
    ) -> Result<MediatorAccountList, MediatorError>;

    /// Change an account's role type. When promoting to `Admin` /
    /// `RootAdmin` / `Mediator` the backend also adds the DID to the
    /// admin set; when demoting back to `Standard` it removes from the
    /// admin set. Atomic with respect to the role + admin-set update.
    async fn account_set_role(
        &self,
        did_hash: &str,
        account_type: &AccountType,
    ) -> Result<(), MediatorError>;

    /// Change an account's queue limits.
    ///
    /// Limit values: `None` = no change; `Some(-1)` = unlimited;
    /// `Some(-2)` = reset to default; `Some(n)` = explicit cap.
    async fn account_change_queue_limits(
        &self,
        did_hash: &str,
        send_queue_limit: Option<i32>,
        receive_queue_limit: Option<i32>,
    ) -> Result<(), MediatorError>;

    // ─── DIDComm v1 routing keys ─────────────────────────────────────────────

    /// Whether this backend implements the DIDComm v1 routing-key index below.
    ///
    /// Defaults to `false` so a third-party backend written against an earlier
    /// version of this trait keeps compiling. The mediator checks this at
    /// startup and **refuses to start** with the `didcomm-v1` feature enabled
    /// on a backend that returns `false`, rather than accepting v1 traffic it
    /// would then silently fail to route.
    fn supports_v1_routing_keys(&self) -> bool {
        false
    }

    /// Bind a base58 Ed25519 routing verkey to a local account's DID.
    ///
    /// DIDComm v1 addresses a forward's destination by **verkey**, not DID,
    /// while every routing, ACL, and storage decision in this mediator is
    /// keyed by DID (or its hash). This index is the bridge.
    ///
    /// Takes and returns the **DID**, not its hash: forward ingress hands the
    /// looked-up value straight to the message-store path, which addresses a
    /// recipient by DID and hashes it itself — and a hash cannot be turned back
    /// into a DID. The *reverse* index ([`Self::v1_routing_keys_for`]) is still
    /// keyed by hash, because that is what account removal works from.
    ///
    /// # Security
    ///
    /// A verkey binds to **at most one** DID. An implementation MUST reject a
    /// bind whose verkey is already bound to a *different* DID, because
    /// otherwise any account could claim another account's routing key and
    /// capture its inbound v1 traffic. Re-binding a verkey to the DID that
    /// already holds it is idempotent and succeeds.
    async fn v1_routing_key_bind(&self, _verkey: &str, _did: &str) -> Result<(), MediatorError> {
        Err(MediatorError::ConfigError(
            12,
            "NA".into(),
            "this storage backend does not implement DIDComm v1 routing keys".into(),
        ))
    }

    /// The **DID** bound to `verkey`, or `None` when the verkey is unknown.
    async fn v1_routing_key_lookup(&self, _verkey: &str) -> Result<Option<String>, MediatorError> {
        Ok(None)
    }

    /// Drop a binding. Returns whether one was removed.
    async fn v1_routing_key_unbind(&self, _verkey: &str) -> Result<bool, MediatorError> {
        Ok(false)
    }

    /// Every routing verkey bound to the account with this DID **hash**.
    ///
    /// Used by account removal (so a deleted account's keys stop resolving)
    /// and, once the coordinate-mediation protocol lands, by `keylist-query`.
    async fn v1_routing_keys_for(&self, _did_hash: &str) -> Result<Vec<String>, MediatorError> {
        Ok(Vec::new())
    }

    // ─── ACLs ────────────────────────────────────────────────────────────────

    /// Replace the ACL bitmask for a DID. Caller is responsible for
    /// permission checks (e.g., admin-only ACL changes).
    async fn set_did_acl(
        &self,
        did_hash: &str,
        acls: &MediatorACLSet,
    ) -> Result<MediatorACLSet, MediatorError>;

    /// Read the ACL bitmask for a DID. Returns `None` when the account
    /// has no ACL record.
    async fn get_did_acl(&self, did_hash: &str) -> Result<Option<MediatorACLSet>, MediatorError>;

    /// Read ACL bitmasks for up to 100 DIDs in one call.
    async fn get_did_acls(
        &self,
        dids: &[String],
        mediator_acl_mode: AccessListModeType,
    ) -> Result<MediatorACLGetResponse, MediatorError>;

    /// Decide whether `from_hash` is allowed to send to `to_hash` under
    /// `to_hash`'s configured access-list mode (ExplicitAllow vs
    /// ExplicitDeny). For anonymous senders (`from_hash = None`),
    /// consults `to_hash`'s `anon_receive` ACL bit.
    async fn access_list_allowed(&self, to_hash: &str, from_hash: Option<&str>) -> bool;

    /// Everything the recipient-side delivery gate needs about `to_hash`, in
    /// as few round trips as the backend can manage. Returns `None` when the
    /// account does not exist.
    ///
    /// The direct-delivery path needs three facts about one recipient — does
    /// the account exist, does it grant `RECEIVE_MESSAGES`, and does its
    /// access list admit this sender — which are all derivable from the same
    /// stored record. Fetching them via `account_exists` + `get_did_acl` +
    /// `access_list_allowed` costs three reads of that record; this method
    /// exists so a backend can serve all three from one.
    ///
    /// The default implementation is the unoptimised two-call version, so
    /// third-party backends keep working unchanged. Backends that can batch
    /// should override it — [`RedisStore`] already pipelines the membership
    /// probe and the ACL read into a single round trip, and the in-process
    /// backends read one record.
    async fn delivery_decision(
        &self,
        to_hash: &str,
        from_hash: Option<&str>,
    ) -> Result<Option<DeliveryDecision>, MediatorError> {
        let Some(acls) = self.get_did_acl(to_hash).await? else {
            return Ok(None);
        };
        let access_list_allows = self.access_list_allowed(to_hash, from_hash).await;
        Ok(Some(DeliveryDecision {
            acls,
            access_list_allows,
        }))
    }

    /// Page through a DID's access list using a server-side cursor. Pass `0` to
    /// start; feed the returned `cursor` back in for the next page.
    ///
    /// **Terminal-cursor convention differs by backend.** The in-process
    /// backends (memory, fjall) return `cursor: None` when the listing is
    /// exhausted; the Redis backend pages via `SSCAN`, whose end-of-iteration
    /// cursor is `0`, so it returns `cursor: Some(0)`. Callers MUST treat both
    /// `None` and `Some(0)` as "no more pages" — a loop that stops only on
    /// `None` runs forever against Redis. (The conformance suite's
    /// `access_list_len` helper documents and exercises this.)
    async fn access_list_list(
        &self,
        did_hash: &str,
        cursor: u64,
    ) -> Result<MediatorAccessListListResponse, MediatorError>;

    /// Add `hashes` to a DID's access list. Truncates if the addition
    /// would exceed `access_list_limit`; the response signals truncation
    /// and reports which hashes were actually inserted.
    async fn access_list_add(
        &self,
        access_list_limit: usize,
        did_hash: &str,
        hashes: &[String],
    ) -> Result<MediatorAccessListAddResponse, MediatorError>;

    /// Remove `hashes` from a DID's access list. Returns the number of
    /// entries actually removed.
    async fn access_list_remove(
        &self,
        did_hash: &str,
        hashes: &[String],
    ) -> Result<usize, MediatorError>;

    /// Drop the entire access list for a DID.
    async fn access_list_clear(&self, did_hash: &str) -> Result<(), MediatorError>;

    /// Filter `hashes` to those present in the given DID's access list.
    async fn access_list_get(
        &self,
        did_hash: &str,
        hashes: &[String],
    ) -> Result<MediatorAccessListGetResponse, MediatorError>;

    // ─── Admin accounts ─────────────────────────────────────────────────────

    /// Ensure an admin account exists with the given role and ACLs.
    /// Creates the account if missing, updates the role + admin-set
    /// membership otherwise. Idempotent; safe to call on every startup.
    ///
    /// For batch promote/demote, callers loop over `account_set_role`
    /// directly — a "promote 100 DIDs" primitive doesn't earn its keep
    /// at the storage layer.
    async fn setup_admin_account(
        &self,
        admin_did_hash: &str,
        admin_type: AccountType,
        acls: &MediatorACLSet,
    ) -> Result<(), MediatorError>;

    /// Whether the given DID is an Admin or RootAdmin account.
    async fn check_admin_account(&self, did_hash: &str) -> Result<bool, MediatorError>;

    /// Page through admin accounts with role-type info.
    async fn list_admin_accounts(
        &self,
        cursor: u32,
        limit: u32,
    ) -> Result<MediatorAdminList, MediatorError>;

    // ─── Audit log ───────────────────────────────────────────────────────────

    /// Append a privileged-change record to the audit log.
    ///
    /// The log is a bounded ring of [`AUDIT_LOG_MAX_ENTRIES`](crate::types::audit::AUDIT_LOG_MAX_ENTRIES):
    /// once full, recording drops the oldest entry. The entry arrives fully
    /// formed (the caller stamps `timestamp` and the actor/target), so backends
    /// only persist + trim; ordering is the backend's insertion order.
    ///
    /// Recording is best-effort at the call sites (a failure here must not abort
    /// the privileged change that already succeeded), so callers log and
    /// continue rather than propagate.
    async fn audit_log_record(&self, entry: &AuditLogEntry) -> Result<(), MediatorError>;

    /// Page through the audit log, newest-first. Pass `0` to start; feed the
    /// returned `cursor` back in for the next page. A returned `cursor` of `0`
    /// means the listing is exhausted (same convention as `account_list`).
    async fn audit_log_list(
        &self,
        cursor: u32,
        limit: u32,
    ) -> Result<MediatorAuditLogList, MediatorError>;

    // ─── OOB Discovery invitations ──────────────────────────────────────────

    /// Store an OOB Discovery invitation. The caller is responsible for
    /// serialising the DIDComm `Message` to JSON and base64-url-encoding
    /// it (so the trait doesn't depend on the didcomm crate, which is
    /// optional in the mediator). The caller also resolves the final
    /// `expires_at` (Unix seconds) from the invitation's `expires_time`
    /// and the configured `oob_invite_ttl`.
    ///
    /// Returns the invitation hash used as its lookup key. Increments
    /// the global "invites created" counter.
    async fn oob_discovery_store(
        &self,
        did_hash: &str,
        invite_b64: &str,
        expires_at: u64,
    ) -> Result<String, MediatorError>;

    /// Retrieve an OOB invitation by hash. Returns `Some((invite_b64,
    /// did_hash))` when the invitation exists and hasn't expired,
    /// `None` otherwise. Increments the global "invites claimed" counter.
    async fn oob_discovery_get(
        &self,
        oob_id: &str,
    ) -> Result<Option<(String, String)>, MediatorError>;

    /// Delete an OOB invitation. Returns `true` when an entry was deleted.
    async fn oob_discovery_delete(&self, oob_id: &str) -> Result<bool, MediatorError>;

    // ─── Trust Task duplicate-execution record ──────────────────────────────

    /// Claim a Trust Task for execution — the Trust Tasks §7.2 item 11
    /// duplicate-execution record.
    ///
    /// `key` identifies the document (the caller scopes it to the issuer, so
    /// one party cannot burn another's ids); `digest` is the document's
    /// content digest. The first claim of a key records `digest` until
    /// `retain_until` (Unix seconds) and is [`TrustTaskClaim::Fresh`]; a later
    /// claim of the same key before then is [`TrustTaskClaim::Duplicate`] when
    /// the digest matches and [`TrustTaskClaim::Conflict`] when it does not. A
    /// record whose `retain_until` has passed (by `now`) is treated as absent.
    ///
    /// The check-and-record must be atomic across every mediator instance
    /// sharing the store — that is what makes a replay to a *second* instance
    /// fail too.
    ///
    /// **The default refuses.** A store that does not implement this cannot
    /// say whether a document was already executed, and executing anyway is
    /// the double execution the rule forbids; the caller fails closed on the
    /// error. Every built-in backend overrides it.
    async fn trust_task_claim(
        &self,
        key: &str,
        digest: &str,
        retain_until: u64,
        now: u64,
    ) -> Result<TrustTaskClaim, MediatorError> {
        let _ = (key, digest, retain_until, now);
        Err(MediatorError::InternalError(
            14,
            "NA".into(),
            "this store keeps no Trust Task duplicate-execution record".into(),
        ))
    }

    /// Drop Trust Task claims whose `retain_until` is at or before `now`.
    /// Returns how many were removed. Backends with native key expiry (Redis)
    /// keep the default no-op.
    async fn sweep_expired_trust_task_claims(&self, now: u64) -> Result<usize, MediatorError> {
        let _ = now;
        Ok(0)
    }

    // ─── Account activity ───────────────────────────────────────────────────

    /// Record that the account `did_hash` did `kind` at `at` (Unix epoch
    /// seconds), replacing the time recorded before. Nothing is recorded for
    /// an account that does not exist.
    ///
    /// Adding an account clears whatever was recorded for that hash, so an
    /// account never starts life holding a predecessor's times — including a
    /// record written by a message that was in flight while the predecessor
    /// was being removed, which the existence check cannot rule out on a
    /// store without a transaction across both.
    ///
    /// Activity is observability, not state anything depends on, so the
    /// default keeps nothing and succeeds; [`account_activity`] then reports
    /// nothing recorded. Every built-in backend overrides both. Removing the
    /// account removes its activity.
    ///
    /// [`account_activity`]: Self::account_activity
    async fn account_activity_record(
        &self,
        did_hash: &str,
        kind: ActivityKind,
        at: u64,
    ) -> Result<(), MediatorError> {
        let _ = (did_hash, kind, at);
        Ok(())
    }

    /// The recorded activity of each account in `did_hashes`, in the same
    /// order. An account with nothing recorded, or none at all, gets
    /// [`AccountActivity::default`].
    async fn account_activity(
        &self,
        did_hashes: &[String],
    ) -> Result<Vec<AccountActivity>, MediatorError> {
        Ok(vec![AccountActivity::default(); did_hashes.len()])
    }

    // ─── Configuration overrides ────────────────────────────────────────────

    /// The mediator's stored configuration overrides, as a JSON object of
    /// `key → value` (keys like `limits.queued_send_messages_hard`), or `None`
    /// when none have been stored. Written by `config/patch` and layered over
    /// the file/env configuration at startup.
    ///
    /// The default has none, which is the truth for a store that cannot keep
    /// them.
    async fn config_overrides_get(&self) -> Result<Option<String>, MediatorError> {
        Ok(None)
    }

    /// Replace the stored configuration overrides with `overrides`, a JSON
    /// object. An empty object clears them.
    ///
    /// This replaces the whole document, so a caller changing it must read,
    /// modify and write under one lock; the mediator does all of that under
    /// its patch lock (`LiveLimits::lock_for_patch`).
    ///
    /// **The default refuses**: a patch must not report a value as stored when
    /// the store kept nothing. Every built-in backend overrides it.
    async fn config_overrides_set(&self, overrides: &str) -> Result<(), MediatorError> {
        let _ = overrides;
        Err(MediatorError::InternalError(
            14,
            "NA".into(),
            "this store cannot keep configuration overrides".into(),
        ))
    }

    // ─── Stats / counters ───────────────────────────────────────────────────

    /// Snapshot the global counters for the stats thread, the admin status
    /// endpoint, and `/readyz`.
    async fn get_global_stats(&self) -> Result<MetadataStats, MediatorError>;

    /// Increment a global counter by `by` (typically `1`, but bytes
    /// counters use the message size). Backends apply this atomically.
    async fn stats_increment(&self, counter: StatCounter, by: i64) -> Result<(), MediatorError>;

    // ─── Forwarding queue ───────────────────────────────────────────────────

    /// Enqueue a message for forwarding. `max_len = 0` means unbounded;
    /// otherwise the backend approximately trims the queue at that length.
    /// Returns the assigned stream ID.
    async fn forward_queue_enqueue(
        &self,
        entry: &ForwardQueueEntry,
        max_len: usize,
    ) -> Result<String, MediatorError>;

    /// Length of the forwarding queue. Used by load-shedding decisions
    /// and surfaced in `/readyz`.
    async fn forward_queue_len(&self) -> Result<usize, MediatorError>;

    /// Read up to `count` queued messages, blocking up to `block` waiting
    /// for new entries. Reads claim ownership of returned entries until
    /// they're acked (see [`forward_queue_ack`]) or autoclaimed.
    ///
    /// The backend lazily creates the consumer group on first call; no
    /// separate `ensure_group` step is required.
    ///
    /// Multi-process backends share the queue across consumers; single-
    /// process backends serve only consumers within the same process.
    ///
    /// Returns an empty `Vec` on timeout.
    async fn forward_queue_read(
        &self,
        group_name: &str,
        consumer_name: &str,
        count: usize,
        block: Duration,
    ) -> Result<Vec<ForwardQueueEntry>, MediatorError>;

    /// Acknowledge that a batch of stream IDs were processed successfully.
    /// Removes them from the consumer's pending list.
    async fn forward_queue_ack(
        &self,
        group_name: &str,
        stream_ids: &[&str],
    ) -> Result<(), MediatorError>;

    /// Delete acked entries from the queue's storage to free space.
    /// Separate from `ack` because some pipelines want to keep audit logs
    /// of acked-but-not-yet-deleted entries.
    async fn forward_queue_delete(&self, stream_ids: &[&str]) -> Result<(), MediatorError>;

    /// Reclaim entries idle for longer than `min_idle` (typical: a
    /// crashed/timed-out consumer). The reclaiming consumer becomes the
    /// new owner of the returned entries.
    async fn forward_queue_autoclaim(
        &self,
        group_name: &str,
        consumer_name: &str,
        min_idle: Duration,
        count: usize,
    ) -> Result<Vec<ForwardQueueEntry>, MediatorError>;

    // ─── Live streaming (WebSocket pub/sub) ─────────────────────────────────

    /// Reset the streaming session set for this mediator instance.
    /// Called once at startup to clean up state from previous runs.
    async fn streaming_clean_start(&self, mediator_uuid: &str) -> Result<(), MediatorError>;

    /// Set the streaming state for a DID on this mediator instance.
    ///
    /// State transitions:
    /// - `Registered`: client connected via WebSocket, queue messages normally
    /// - `Live`: client enabled live delivery, push instead of (or in
    ///   addition to) queueing
    /// - `Deregistered`: client disconnected, drop all streaming state
    ///
    /// Idempotent; safe to set the same state repeatedly.
    async fn streaming_set_state(
        &self,
        did_hash: &str,
        mediator_uuid: &str,
        state: StreamingClientState,
    ) -> Result<(), MediatorError>;

    /// Whether `did_hash` has a streaming subscriber on any mediator
    /// instance, returning the mediator UUID hosting the subscriber.
    /// With `force_delivery = true`, returns the UUID even when the
    /// subscriber is `Registered` but not `Live` (used to push status
    /// messages on live-delivery transitions).
    async fn streaming_is_client_live(
        &self,
        did_hash: &str,
        force_delivery: bool,
    ) -> Option<String>;

    /// Publish a delivery notification to the streaming channel for
    /// `mediator_uuid`. Subscribers (the WebSocket task on that mediator
    /// instance) deliver the message to the connected client.
    ///
    /// On `RedisStore` this delivers cross-process via `PUBLISH`; on
    /// `MemoryStore`/`FjallStore` it delivers in-process only.
    async fn streaming_publish_message(
        &self,
        did_hash: &str,
        mediator_uuid: &str,
        message: &str,
        force_delivery: bool,
    ) -> Result<(), MediatorError>;

    /// Subscribe to live-streaming delivery notifications for one
    /// mediator UUID. Returns a [`broadcast::Receiver`]; lagged
    /// subscribers see [`broadcast::error::RecvError::Lagged`] which
    /// matches Redis pub/sub's "late subscribers miss messages" model.
    /// Dropping the receiver unsubscribes; backends keep the underlying
    /// channel alive as long as the store is alive.
    ///
    /// Called once per mediator instance by the WebSocket streaming task.
    async fn streaming_subscribe(
        &self,
        mediator_uuid: &str,
    ) -> Result<broadcast::Receiver<PubSubRecord>, MediatorError>;

    // ─── Message expiry processor ───────────────────────────────────────────

    /// Run one pass of the message expiry sweep. Inspects all expiry
    /// indices whose timestamp is `<= now_secs`, deletes the messages
    /// they reference using `Admin { admin_did_hash }` authorisation,
    /// and drops the now-empty indices.
    ///
    /// Backends may chunk the work internally to avoid blocking the
    /// runtime — the processor calls this on a fixed cadence and
    /// accepts that one call may not drain everything overdue.
    async fn sweep_expired_messages(
        &self,
        now_secs: u64,
        admin_did_hash: &str,
    ) -> Result<ExpiryReport, MediatorError>;

    /// [`sweep_expired_messages`](Self::sweep_expired_messages), telling
    /// `on_expired` (when given) the id and metadata of each message it
    /// removes. The metadata is read before the delete, and only when an
    /// observer is given, so an unobserved sweep costs no more than before.
    ///
    /// The built-in stores implement this. The default sweeps without
    /// reporting individual messages, so a store written before this method
    /// existed still compiles and still expires messages.
    async fn sweep_expired_messages_observed(
        &self,
        now_secs: u64,
        admin_did_hash: &str,
        on_expired: Option<OnExpired<'_>>,
    ) -> Result<ExpiryReport, MediatorError> {
        let _ = on_expired;
        self.sweep_expired_messages(now_secs, admin_did_hash).await
    }

    /// Run one pass of the session expiry sweep, removing session
    /// records whose TTL has elapsed (`expires_at <= now_secs`).
    ///
    /// Backends with native TTL (Redis `EXPIRE`) reclaim expired
    /// sessions themselves, so the default is a no-op. Backends without
    /// (Fjall, memory) expire sessions lazily on [`get_session`], which
    /// means a session that is created but never read again — e.g. a
    /// one-off DID that runs `/authenticate/challenge` and disappears —
    /// lingers on disk/in the map indefinitely. The session processor
    /// calls this on a fixed cadence so those orphaned records are
    /// reclaimed regardless of whether they're ever read.
    ///
    /// `now_secs` contract (note the backend divergence, asserted by the
    /// `store_conformance` suite): `FjallStore` honors it as the wall-clock
    /// cutoff (`expires_at_unix <= now_secs`). `MemoryStore` **ignores** it and
    /// sweeps against its own monotonic `Instant::now()` — its TTLs are tracked
    /// as `Instant`s, which can't be compared to a unix `now_secs`. Production
    /// callers (`tasks::session_expiry`) always pass the real clock, so the two
    /// reclaim the same lapsed sessions; only a caller passing a *synthetic*
    /// `now_secs` would observe the difference.
    async fn sweep_expired_sessions(
        &self,
        now_secs: u64,
    ) -> Result<SessionSweepReport, MediatorError> {
        let _ = now_secs;
        Ok(SessionSweepReport::default())
    }

    // ─── Legacy aliases ─────────────────────────────────────────────────────
    //
    // The mediator's pre-trait codebase uses different names and shapes
    // for many of the methods above. These default-implemented aliases
    // preserve those names so the bulk of the call-site refactor can
    // happen mechanically without touching every handler. Each alias
    // delegates to its canonical counterpart. New code should call the
    // canonical method directly.

    /// Legacy: synchronous health summary. Default impl calls the async
    /// [`health`](Self::health) and stringifies, but the cost of an
    /// async call from a sync context is real — backends with cheap
    /// in-memory state should override and return directly. Returns
    /// `"closed"` / `"half_open"` / `"open"` to match the names the
    /// admin status handler already shows in operator dashboards.
    fn circuit_breaker_state(&self) -> &'static str {
        "closed"
    }

    /// Legacy: increment the GLOBAL "sent" counters in one call.
    /// Records `bytes` against `SentBytes` and `1` against `SentCount`.
    /// Both increments are independent — if one fails the other still
    /// completes (or both fail — caller doesn't get partial-success
    /// signal).
    async fn update_send_stats(&self, sent_bytes: i64) -> Result<(), MediatorError> {
        self.stats_increment(StatCounter::SentBytes, sent_bytes)
            .await?;
        self.stats_increment(StatCounter::SentCount, 1).await
    }

    /// Legacy: promote up to `accounts.len()` standard accounts to
    /// `Admin`. Default impl loops over [`setup_admin_account`].
    async fn add_admin_accounts(
        &self,
        accounts: Vec<String>,
        acls: &MediatorACLSet,
    ) -> Result<usize, MediatorError> {
        let count = accounts.len();
        for did_hash in &accounts {
            self.setup_admin_account(did_hash, AccountType::Admin, acls)
                .await?;
        }
        Ok(count)
    }

    /// Legacy: demote up to `accounts.len()` admin accounts to
    /// `Standard`. Default impl loops over [`account_set_role`].
    async fn strip_admin_accounts(&self, accounts: Vec<String>) -> Result<i32, MediatorError> {
        let mut count: i32 = 0;
        for did_hash in &accounts {
            self.account_set_role(did_hash, &AccountType::Standard)
                .await?;
            count += 1;
        }
        Ok(count)
    }

    /// Legacy: `create_session` was the original challenge-creation
    /// entry point. Maps onto [`put_session`] with the standard 15-minute
    /// TTL and bumps the `SessionsCreated` counter (which the original
    /// implementation did inline).
    async fn create_session(&self, session: &Session) -> Result<(), MediatorError> {
        self.put_session(session, std::time::Duration::from_secs(900))
            .await?;
        self.stats_increment(StatCounter::SessionsCreated, 1).await
    }

    /// Legacy: promote a `ChallengeSent` session to `Authenticated`,
    /// renaming the session ID and recording the refresh-token hash.
    /// Default impl does this as `delete(old) + put(new)` since session
    /// IDs are unguessable; backends with `RENAME` semantics can
    /// override for atomicity.
    ///
    /// `did` is the **raw DID string** (e.g. `did:peer:2.*`), not the
    /// SHA-256 hash. The default impl re-reads the old session via
    /// [`get_session`](Self::get_session), which expects the raw DID
    /// to join the session record with the matching `DID:` account
    /// row; passing a hash here silently corrupts the rewritten session
    /// (`session.did = ""`) and downstream auth checks fail with an
    /// empty session DID.
    async fn update_session_authenticated(
        &self,
        old_session_id: &str,
        new_session_id: &str,
        did: &str,
        refresh_token_hash: &str,
    ) -> Result<(), MediatorError> {
        let did_hash = sha256::digest(did);
        let mut session = self
            .get_session(old_session_id, did)
            .await
            .unwrap_or_else(|_| Session {
                session_id: new_session_id.to_string(),
                did: did.to_string(),
                did_hash: did_hash.clone(),
                ..Default::default()
            });
        session.session_id = new_session_id.to_string();
        // Defensive: if get_session returned a session with an empty
        // `did` (e.g. from a partially-populated legacy record), fill
        // it from our authenticated input so the rewritten session is
        // never blank-DID.
        if session.did.is_empty() {
            session.did = did.to_string();
            session.did_hash = did_hash;
        }
        session.state = SessionState::Authenticated;
        session.authenticated = true;
        session.refresh_token_hash = Some(refresh_token_hash.to_string());

        // Fail-closed rename: delete the old (challenge) session BEFORE
        // writing the new authenticated one. An interruption (crash, or a
        // failed write) can then only *lose* the new session — forcing the
        // client to re-authenticate — and can never leave the old session id
        // valid alongside the new. Redis (`RENAME`+`HSET`) and Fjall (a
        // single `Batch`) override this with one atomic operation; this
        // ordering is what protects any backend (incl. MemoryStore) that
        // falls back to the default.
        rename_session_fail_closed(
            old_session_id,
            new_session_id,
            || self.delete_session(old_session_id),
            || self.put_session(&session, std::time::Duration::from_secs(86_400)),
        )
        .await?;
        self.stats_increment(StatCounter::SessionsSuccess, 1).await
    }

    /// Legacy: rotate the refresh-token hash on an existing session.
    /// Loads, updates, writes back with a 24h TTL.
    async fn update_refresh_token_hash(
        &self,
        session_id: &str,
        refresh_token_hash: &str,
    ) -> Result<(), MediatorError> {
        // We don't know the DID at this layer; pass empty so the
        // join-with-account in `get_session` is best-effort. Backends
        // that need the DID for the refresh path should override.
        let mut session = self
            .get_session(session_id, "")
            .await
            .unwrap_or_else(|_| Session {
                session_id: session_id.to_string(),
                ..Default::default()
            });
        session.refresh_token_hash = Some(refresh_token_hash.to_string());
        self.put_session(&session, std::time::Duration::from_secs(86_400))
            .await
    }

    /// Legacy: read just the refresh-token hash for a session. Default
    /// impl loads the whole session and returns the field.
    async fn get_refresh_token_hash(
        &self,
        session_id: &str,
    ) -> Result<Option<String>, MediatorError> {
        match self.get_session(session_id, "").await {
            Ok(s) => Ok(s.refresh_token_hash),
            Err(_) => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::rename_session_fail_closed;
    use crate::errors::MediatorError;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU8, Ordering};

    /// Records the order in which delete/put run by stamping a shared
    /// counter, so a test can assert delete happened strictly before put.
    fn step_recorder() -> (Arc<AtomicU8>, Arc<AtomicU8>, Arc<AtomicU8>) {
        // (next-step-counter, delete-step, put-step)
        (
            Arc::new(AtomicU8::new(0)),
            Arc::new(AtomicU8::new(0)),
            Arc::new(AtomicU8::new(0)),
        )
    }

    #[tokio::test]
    async fn deletes_old_before_writing_new() {
        let (counter, delete_step, put_step) = step_recorder();
        let (c1, c2) = (counter.clone(), counter.clone());
        let (ds, ps) = (delete_step.clone(), put_step.clone());

        rename_session_fail_closed(
            "old",
            "new",
            || async move {
                ds.store(c1.fetch_add(1, Ordering::SeqCst) + 1, Ordering::SeqCst);
                Ok(())
            },
            || async move {
                ps.store(c2.fetch_add(1, Ordering::SeqCst) + 1, Ordering::SeqCst);
                Ok(())
            },
        )
        .await
        .expect("rename succeeds");

        assert_eq!(delete_step.load(Ordering::SeqCst), 1, "delete ran first");
        assert_eq!(put_step.load(Ordering::SeqCst), 2, "put ran second");
    }

    #[tokio::test]
    async fn a_failed_put_after_delete_is_fail_closed() {
        // Simulates a crash/failure at the write step: the old session was
        // already removed, the new one fails to land. The operation returns
        // Err (so the caller does NOT mark the session authenticated) and
        // the old session is gone — never left valid alongside a new one.
        let deleted = Arc::new(AtomicU8::new(0));
        let d = deleted.clone();

        let result = rename_session_fail_closed(
            "old",
            "new",
            || async move {
                d.store(1, Ordering::SeqCst);
                Ok(())
            },
            || async move {
                Err(MediatorError::DatabaseError(
                    14,
                    "sess".into(),
                    "simulated write failure".into(),
                ))
            },
        )
        .await;

        assert_eq!(deleted.load(Ordering::SeqCst), 1, "old session was deleted");
        assert!(
            matches!(result, Err(MediatorError::DatabaseError(..))),
            "a failed write must surface as an error (fail-closed), got {result:?}"
        );
    }

    #[tokio::test]
    async fn a_failed_delete_does_not_write_the_new_session() {
        // If the delete itself fails, the new session must not be written —
        // otherwise both could coexist. The put closure must never run.
        let put_ran = Arc::new(AtomicU8::new(0));
        let p = put_ran.clone();

        let result = rename_session_fail_closed(
            "old",
            "new",
            || async {
                Err::<(), _>(MediatorError::DatabaseError(
                    14,
                    "sess".into(),
                    "simulated delete failure".into(),
                ))
            },
            || async move {
                p.store(1, Ordering::SeqCst);
                Ok(())
            },
        )
        .await;

        assert!(result.is_err(), "a failed delete aborts the rename");
        assert_eq!(
            put_ran.load(Ordering::SeqCst),
            0,
            "new session was NOT written"
        );
    }

    #[tokio::test]
    async fn same_old_and_new_id_skips_delete_and_overwrites_in_place() {
        // An in-place overwrite (old == new) must not delete the key it is
        // about to (re)write, which would open a gap.
        let deleted = Arc::new(AtomicU8::new(0));
        let put_ran = Arc::new(AtomicU8::new(0));
        let (d, p) = (deleted.clone(), put_ran.clone());

        rename_session_fail_closed(
            "same",
            "same",
            || async move {
                d.store(1, Ordering::SeqCst);
                Ok(())
            },
            || async move {
                p.store(1, Ordering::SeqCst);
                Ok(())
            },
        )
        .await
        .expect("in-place rename succeeds");

        assert_eq!(
            deleted.load(Ordering::SeqCst),
            0,
            "delete skipped for old == new"
        );
        assert_eq!(
            put_ran.load(Ordering::SeqCst),
            1,
            "new session written in place"
        );
    }

    use super::{PurgeFilter, exclusive_successor};
    use crate::types::messages::{Folder, MessageListElement};

    fn element(ts: u64, from: Option<&str>, to: Option<&str>) -> MessageListElement {
        MessageListElement {
            msg_id: "m".into(),
            timestamp: ts,
            size: 10,
            from_address: from.map(str::to_string),
            to_address: to.map(str::to_string),
            ..Default::default()
        }
    }

    #[test]
    fn an_empty_filter_matches_everything() {
        let f = PurgeFilter::default();
        assert!(f.matches(&element(1, Some("alice"), Some("bob")), &Folder::Inbox));
        assert!(f.matches(&element(u64::MAX, None, None), &Folder::Outbox));
    }

    /// Which end "peer" means depends on the folder: in an outbox it is who
    /// the message went to, in an inbox who sent it. Getting this backwards
    /// would purge the wrong messages.
    #[test]
    fn peer_is_the_counterparty_for_the_folder() {
        let f = PurgeFilter {
            peer: Some("bob".into()),
            ..Default::default()
        };
        let msg = element(1, Some("alice"), Some("bob"));
        assert!(
            f.matches(&msg, &Folder::Outbox),
            "in an outbox, the peer is the recipient"
        );
        assert!(
            !f.matches(&msg, &Folder::Inbox),
            "in an inbox, the peer is the sender — bob did not send this"
        );

        let f = PurgeFilter {
            peer: Some("alice".into()),
            ..Default::default()
        };
        assert!(f.matches(&msg, &Folder::Inbox));
        assert!(!f.matches(&msg, &Folder::Outbox));
    }

    /// A purge is unrecoverable, so an unrecorded counterparty never matches a
    /// `peer` filter — it cannot be shown to be the peer asked for.
    #[test]
    fn an_unknown_counterparty_never_matches_a_peer_filter() {
        let f = PurgeFilter {
            peer: Some("bob".into()),
            ..Default::default()
        };
        assert!(!f.matches(&element(1, None, None), &Folder::Inbox));
        assert!(!f.matches(&element(1, None, None), &Folder::Outbox));
    }

    #[test]
    fn the_age_cutoff_is_inclusive_and_keeps_newer_messages() {
        let f = PurgeFilter {
            arrived_before_ms: Some(1_000),
            ..Default::default()
        };
        assert!(f.matches(&element(999, None, None), &Folder::Inbox));
        assert!(f.matches(&element(1_000, None, None), &Folder::Inbox));
        assert!(
            !f.matches(&element(1_001, None, None), &Folder::Inbox),
            "a message newer than the cutoff must survive"
        );
    }

    /// Both narrowings apply together: "this peer AND older than that".
    #[test]
    fn peer_and_age_are_both_required_when_both_are_set() {
        let f = PurgeFilter {
            peer: Some("bob".into()),
            arrived_before_ms: Some(1_000),
            ..Default::default()
        };
        assert!(f.matches(&element(500, None, Some("bob")), &Folder::Outbox));
        assert!(
            !f.matches(&element(2_000, None, Some("bob")), &Folder::Outbox),
            "right peer, too new"
        );
        assert!(
            !f.matches(&element(500, None, Some("carol")), &Folder::Outbox),
            "old enough, wrong peer"
        );
    }

    /// Paging a *filtered* walk cannot restart from the beginning: entries that
    /// did not match stay in place, so it would spin on them forever. The
    /// successor must be strictly greater than the id it came from.
    #[test]
    fn the_cursor_advances_past_the_id_it_came_from() {
        assert_eq!(
            exclusive_successor("1700000000000-0").as_deref(),
            Some("1700000000000-1")
        );
        assert_eq!(exclusive_successor("5-41").as_deref(), Some("5-42"));
    }

    #[test]
    fn an_unparseable_cursor_stops_the_walk_rather_than_guessing() {
        assert_eq!(exclusive_successor("not-a-stream-id"), None);
        assert_eq!(exclusive_successor("12345"), None);
        assert_eq!(exclusive_successor(""), None);
        // Sequence at the ceiling: no successor exists, so stop rather than wrap
        // back to the start of the stream and re-walk it.
        assert_eq!(exclusive_successor(&format!("1-{}", u64::MAX)), None);
    }
}
