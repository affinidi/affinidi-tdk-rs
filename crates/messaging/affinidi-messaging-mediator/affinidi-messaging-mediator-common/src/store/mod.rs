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
    accounts::{Account, AccountType, MediatorAccountList},
    acls::{AccessListModeType, MediatorACLSet},
    acls_handler::{
        MediatorACLGetResponse, MediatorAccessListAddResponse, MediatorAccessListGetResponse,
        MediatorAccessListListResponse,
    },
    administration::MediatorAdminList,
    messages::{FetchOptions, Folder, GetMessagesResponse, MessageList, MessageListElement},
};
use async_trait::async_trait;
use std::time::Duration;
use tokio::sync::broadcast;

pub mod types;

/// Backend-agnostic decision logic (authorization checks shared by the
/// in-process Rust backends), extracted so it can't drift between them.
pub mod ops;

#[cfg(feature = "redis-backend")]
pub mod redis;

pub use types::{
    DeletionAuthority, ExpiryReport, ForwardQueueEntry, InboxStatusReply, MessageMetaData,
    MetadataStats, PubSubRecord, Session, SessionClaims, SessionState, SessionSweepReport,
    StatCounter, StoreHealth, StreamingClientState,
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

    /// Page through a DID's access list using a server-side cursor.
    async fn access_list_list(
        &self,
        did_hash: &str,
        cursor: u64,
    ) -> Result<MediatorAccessListListResponse, MediatorError>;

    /// Number of entries currently in a DID's access list.
    async fn access_list_count(&self, did_hash: &str) -> Result<usize, MediatorError>;

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
}
