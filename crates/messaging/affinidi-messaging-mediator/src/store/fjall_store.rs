//! Fjall-backed [`MediatorStore`] implementation.
//!
//! Single-process embedded LSM-tree backend. Targets self-hosted
//! mediator deployments that don't want to operate Redis. Cross-process
//! pub/sub and consumer-group ownership are **not** supported — the
//! implementation panics or returns errors when called in
//! configurations that require multiple mediator instances sharing
//! storage.
//!
//! # Status: skeleton
//!
//! This file is the structural foundation. All [`MediatorStore`] trait
//! methods are present so the type satisfies the trait, but most
//! return `MediatorError::InternalError(..., "FjallStore::method not
//! yet implemented")`. Subsequent commits land actual implementations.
//!
//! # Partition layout (planned)
//!
//! - `messages`           — `msg_id` → message body (UTF-8)
//! - `message_meta`       — `msg_id` → JSON-serialised
//!   [`MessageMetaData`]
//! - `inbox`              — `{did_hash}:{stream_id}` → inbox entry
//! - `outbox`             — `{did_hash}:{stream_id}` → outbox entry
//! - `expiry`             — `{expires_at_secs}:{msg_id}` → empty
//! - `sessions`           — `session_id` → JSON-serialised [`Session`]
//! - `accounts`           — `did_hash` → JSON-serialised account record
//! - `acls`               — `did_hash` → ACL bitmask hex
//! - `access_lists`       — `{did_hash}:{member_did_hash}` → empty
//! - `admins`             — `did_hash` → role flag (1=Admin,
//!   2=RootAdmin, 3=Mediator)
//! - `oob_invites`        — `oob_id` → JSON `{ invite_b64, did_hash,
//!   expires_at }`
//! - `forward_queue`      — `stream_id` → JSON-serialised
//!   [`ForwardQueueEntry`]
//! - `forward_pending`    — `{group}:{stream_id}` → claim metadata
//! - `globals`            — counter name → `i64` little-endian
//! - `streaming_clients`  — `{uuid}:{did_hash}` →
//!   [`StreamingClientState`] tag byte
//!
//! # In-process state
//!
//! Live-streaming pub/sub uses a per-mediator-UUID
//! [`broadcast::channel`] with no Fjall-side persistence — subscribers
//! disconnect on mediator restart. Forward-queue blocking reads use a
//! [`Notify`] that fires on each `forward_queue_enqueue`.

use affinidi_messaging_mediator_common::{
    errors::MediatorError,
    store::{
        DeletionAuthority, ExpiryReport, ForwardQueueEntry, InboxStatusReply, MediatorStore,
        MessageMetaData, MetadataStats, PubSubRecord, Session, StatCounter, StoreHealth,
        StreamingClientState,
    },
};
use affinidi_messaging_sdk::{
    messages::{
        FetchDeletePolicy, Folder, GetMessagesResponse, MessageList, MessageListElement,
        fetch::FetchOptions,
    },
    protocols::mediator::{
        accounts::{Account, AccountType, MediatorAccountList},
        acls::{AccessListModeType, MediatorACLSet},
        acls_handler::{
            MediatorACLGetResponse, MediatorAccessListAddResponse, MediatorAccessListGetResponse,
            MediatorAccessListListResponse,
        },
        administration::MediatorAdminList,
    },
};
use async_trait::async_trait;
use fjall::{Config as FjallConfig, Database, Keyspace, KeyspaceCreateOptions};
use serde::{Deserialize, Serialize};
use sha256::digest;
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{Mutex, Notify, broadcast};

const PUBSUB_BROADCAST_CAPACITY: usize = 1024;

const PARTITION_MESSAGES: &str = "messages";
const PARTITION_MESSAGE_META: &str = "message_meta";
const PARTITION_INBOX: &str = "inbox";
const PARTITION_OUTBOX: &str = "outbox";
const PARTITION_EXPIRY: &str = "expiry";
const PARTITION_SESSIONS: &str = "sessions";
const PARTITION_ACCOUNTS: &str = "accounts";
const PARTITION_ACLS: &str = "acls";
const PARTITION_ACCESS_LISTS: &str = "access_lists";
const PARTITION_ADMINS: &str = "admins";
const PARTITION_OOB_INVITES: &str = "oob_invites";
const PARTITION_FORWARD_QUEUE: &str = "forward_queue";
const PARTITION_FORWARD_PENDING: &str = "forward_pending";
const PARTITION_GLOBALS: &str = "globals";
const PARTITION_STREAMING_CLIENTS: &str = "streaming_clients";

/// Fjall-backed [`MediatorStore`].
///
/// Construct with [`FjallStore::open`] and a path to a directory the
/// mediator may write to. Drops the underlying [`Database`] on shutdown
/// — outstanding readers must be released first.
//
// Many fields are unused at the moment because the trait methods are
// stubbed; subsequent commits land per-method implementations that
// read/write each partition. The `dead_code` allowance is removed
// once enough methods land.
#[allow(dead_code)]
pub struct FjallStore {
    /// Top-level Fjall database. Cloned cheaply (internal `Arc`).
    db: Database,
    /// On-disk path the database was opened from. Kept for diagnostics
    /// and for `Debug` output.
    path: PathBuf,

    // ─── Partitions ─────────────────────────────────────────────────
    messages: Keyspace,
    message_meta: Keyspace,
    inbox: Keyspace,
    outbox: Keyspace,
    expiry: Keyspace,
    sessions: Keyspace,
    accounts: Keyspace,
    acls: Keyspace,
    access_lists: Keyspace,
    admins: Keyspace,
    oob_invites: Keyspace,
    forward_queue: Keyspace,
    forward_pending: Keyspace,
    globals: Keyspace,
    streaming_clients: Keyspace,

    // ─── In-process state ───────────────────────────────────────────
    /// Serializes writes across multiple partitions so composite ops
    /// (`store_message`, `delete_message`, `account_remove`) are
    /// effectively atomic. Reads happen inside the lock too, so each
    /// method sees a consistent snapshot.
    write_lock: Arc<Mutex<()>>,
    /// Most-recently-allocated stream millisecond timestamp. Used by
    /// `alloc_stream_id` to bump the sequence within a single ms.
    last_stream_ms: AtomicU64,
    /// Sequence number within the current millisecond.
    next_stream_seq: AtomicU64,
    /// Per-mediator-UUID broadcast channels for live streaming.
    /// First subscribe creates the channel; subsequent calls reuse it.
    broadcast_channels: Arc<Mutex<HashMap<String, broadcast::Sender<PubSubRecord>>>>,
    /// Fires on every `forward_queue_enqueue` so blocking
    /// `forward_queue_read` callers wake up immediately.
    forward_notify: Arc<Notify>,
}

// ─── Stream IDs and key encoding ────────────────────────────────────────────

/// 16-byte big-endian encoding of a `(ms, seq)` stream ID. Used as
/// the suffix of inbox/outbox keys and the sole key of forward-queue
/// entries. Big-endian gives byte-lex == numeric ordering, so Fjall's
/// range scans iterate in stream-ID order.
fn encode_stream_id(ms: u64, seq: u64) -> [u8; 16] {
    let mut buf = [0u8; 16];
    buf[..8].copy_from_slice(&ms.to_be_bytes());
    buf[8..].copy_from_slice(&seq.to_be_bytes());
    buf
}

fn decode_stream_id(bytes: &[u8]) -> Option<(u64, u64)> {
    if bytes.len() != 16 {
        return None;
    }
    let ms = u64::from_be_bytes(bytes[..8].try_into().ok()?);
    let seq = u64::from_be_bytes(bytes[8..].try_into().ok()?);
    Some((ms, seq))
}

fn format_stream_id(ms: u64, seq: u64) -> String {
    format!("{ms}-{seq}")
}

fn parse_stream_id_string(s: &str) -> Option<(u64, u64)> {
    let (ms, seq) = s.split_once('-')?;
    Some((ms.parse().ok()?, seq.parse().ok()?))
}

/// `did_hash || encoded_stream_id` — used as the key for inbox/outbox
/// stream entries. did_hash is fixed-width SHA-256 hex (64 bytes), so
/// concatenation is unambiguous.
fn stream_key(did_hash: &str, ms: u64, seq: u64) -> Vec<u8> {
    let mut k = Vec::with_capacity(did_hash.len() + 16);
    k.extend_from_slice(did_hash.as_bytes());
    k.extend_from_slice(&encode_stream_id(ms, seq));
    k
}

fn stream_key_from_id(did_hash: &str, sid: (u64, u64)) -> Vec<u8> {
    stream_key(did_hash, sid.0, sid.1)
}

/// `expires_at_be || msg_id` — sortable composite key for the expiry
/// index. Fjall scans `< now` to find expired messages.
fn expiry_key(expires_at: u64, msg_id: &str) -> Vec<u8> {
    let mut k = Vec::with_capacity(8 + msg_id.len());
    k.extend_from_slice(&expires_at.to_be_bytes());
    k.extend_from_slice(msg_id.as_bytes());
    k
}

/// `group_name || 0x00 || stream_id_be` — composite key for entries
/// in the `forward_pending` partition. The null byte ensures
/// unambiguous parsing when group names vary in length.
fn pending_key(group: &str, stream_id: (u64, u64)) -> Vec<u8> {
    let mut k = Vec::with_capacity(group.len() + 1 + 16);
    k.extend_from_slice(group.as_bytes());
    k.push(0x00);
    k.extend_from_slice(&encode_stream_id(stream_id.0, stream_id.1));
    k
}

/// Globals partition key for a consumer group's `last_delivered`
/// cursor. Reusing `globals` here avoids opening yet another
/// partition for what's essentially a tiny per-group integer.
fn group_cursor_key(group: &str) -> Vec<u8> {
    let mut k = b"FWD_LAST:".to_vec();
    k.extend_from_slice(group.as_bytes());
    k
}

fn now_ms_u64() -> u64 {
    now_ms()
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ─── On-disk record shapes ─────────────────────────────────────────────────

/// Wire format for the `messages` partition. JSON-encoded so on-disk
/// inspection is trivial; future commits may switch to bincode for
/// compactness.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredMessage {
    body: String,
    bytes: usize,
    to_did_hash: String,
    from_did_hash: Option<String>,
    /// Unix milliseconds when the message was received.
    timestamp_ms: u128,
    /// Stream ID (ms, seq) of the inbox entry — always present.
    receive_id: (u64, u64),
    /// Stream ID of the sender's outbox entry, when non-anonymous.
    send_id: Option<(u64, u64)>,
    /// Unix-seconds expiry. `0` means no expiry.
    expires_at: u64,
}

/// Wire format for inbox/outbox stream entries.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredStreamEntry {
    msg_id: String,
    bytes: usize,
    /// For inbox entries this is the sender's DID hash (or
    /// "ANONYMOUS"); for outbox entries it's the recipient's.
    peer_did: String,
}

/// Persisted account record. Mirrors the shape MemoryStore keeps in
/// memory.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct StoredAccount {
    role: AccountType,
    /// ACL bitmask (u64 form).
    acls: u64,
    send_queue_count: u32,
    send_queue_bytes: u64,
    receive_queue_count: u32,
    receive_queue_bytes: u64,
    queue_send_limit: Option<i32>,
    queue_receive_limit: Option<i32>,
}

impl StoredAccount {
    fn into_account(self, did_hash: String, access_list_count: u32) -> Account {
        Account {
            did_hash,
            acls: self.acls,
            _type: self.role,
            access_list_count,
            queue_send_limit: self.queue_send_limit,
            queue_receive_limit: self.queue_receive_limit,
            send_queue_count: self.send_queue_count,
            send_queue_bytes: self.send_queue_bytes,
            receive_queue_count: self.receive_queue_count,
            receive_queue_bytes: self.receive_queue_bytes,
        }
    }
}

/// Persisted session record. The `expires_at_unix` is checked
/// lazily on read — Fjall has no native TTL, so expired sessions
/// linger on disk until they're either touched or swept by an
/// external janitor.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredSession {
    session: Session,
    /// Unix-seconds wall-clock expiry.
    expires_at_unix: u64,
}

/// Persisted OOB invitation record.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredOobInvite {
    invite_b64: String,
    did_hash: String,
    /// Unix-seconds wall-clock expiry. `0` means no expiry.
    expires_at_unix: u64,
}

/// Consumer-group claim metadata for a single forward-queue entry.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredPendingClaim {
    consumer: String,
    /// Unix milliseconds when the entry was last claimed/redelivered.
    claimed_at_ms: u64,
    delivery_count: u32,
}

/// Persisted streaming-client state. Keyed by DID hash so each DID
/// has at most one streaming registration at a time (matches Redis'
/// `GLOBAL_STREAMING` hash layout).
#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredStreamingClient {
    mediator_uuid: String,
    state: StreamingClientState,
}

impl FjallStore {
    /// Open or create a Fjall-backed store at the given directory path.
    /// The directory is created if it doesn't exist; existing data is
    /// recovered.
    ///
    /// All partitions named in the module-level docs are eagerly
    /// created so subsequent operations don't pay the overhead of
    /// checking for partition existence on every call.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, MediatorError> {
        let path = path.as_ref().to_path_buf();
        let cfg = FjallConfig::new(&path);
        let db = Database::create_or_recover(cfg).map_err(|e| {
            MediatorError::InternalError(
                500,
                "fjall".into(),
                format!("FjallStore::open: failed to open database at {path:?}: {e}"),
            )
        })?;

        let open_partition = |name: &str| -> Result<Keyspace, MediatorError> {
            db.keyspace(name, KeyspaceCreateOptions::default)
                .map_err(|e| {
                    MediatorError::InternalError(
                        500,
                        "fjall".into(),
                        format!("FjallStore::open: failed to open partition '{name}': {e}"),
                    )
                })
        };

        Ok(Self {
            messages: open_partition(PARTITION_MESSAGES)?,
            message_meta: open_partition(PARTITION_MESSAGE_META)?,
            inbox: open_partition(PARTITION_INBOX)?,
            outbox: open_partition(PARTITION_OUTBOX)?,
            expiry: open_partition(PARTITION_EXPIRY)?,
            sessions: open_partition(PARTITION_SESSIONS)?,
            accounts: open_partition(PARTITION_ACCOUNTS)?,
            acls: open_partition(PARTITION_ACLS)?,
            access_lists: open_partition(PARTITION_ACCESS_LISTS)?,
            admins: open_partition(PARTITION_ADMINS)?,
            oob_invites: open_partition(PARTITION_OOB_INVITES)?,
            forward_queue: open_partition(PARTITION_FORWARD_QUEUE)?,
            forward_pending: open_partition(PARTITION_FORWARD_PENDING)?,
            globals: open_partition(PARTITION_GLOBALS)?,
            streaming_clients: open_partition(PARTITION_STREAMING_CLIENTS)?,
            db,
            path,
            write_lock: Arc::new(Mutex::new(())),
            last_stream_ms: AtomicU64::new(0),
            next_stream_seq: AtomicU64::new(0),
            broadcast_channels: Arc::new(Mutex::new(HashMap::new())),
            forward_notify: Arc::new(Notify::new()),
        })
    }

    /// Allocate a fresh `(ms, seq)` stream ID. Monotonic across calls;
    /// sequence resets when the millisecond advances. Caller MUST hold
    /// `write_lock` so the alloc + write happen as one unit.
    fn alloc_stream_id(&self) -> (u64, u64) {
        let now = now_ms();
        let last = self.last_stream_ms.load(Ordering::Relaxed);
        if now > last {
            self.last_stream_ms.store(now, Ordering::Relaxed);
            self.next_stream_seq.store(0, Ordering::Relaxed);
            (now, 0)
        } else {
            let seq = self.next_stream_seq.fetch_add(1, Ordering::Relaxed) + 1;
            (last, seq)
        }
    }

    /// Helper: encode any serde value as JSON bytes, mapping errors to
    /// `MediatorError::InternalError`.
    fn encode<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, MediatorError> {
        serde_json::to_vec(value).map_err(|e| {
            MediatorError::InternalError(500, "fjall".into(), format!("encode failed: {e}"))
        })
    }

    /// Helper: decode JSON bytes into the target type.
    fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, MediatorError> {
        serde_json::from_slice(bytes).map_err(|e| {
            MediatorError::InternalError(500, "fjall".into(), format!("decode failed: {e}"))
        })
    }

    fn db_err(method: &str, e: fjall::Error) -> MediatorError {
        MediatorError::DatabaseError(
            14,
            "fjall".into(),
            format!("FjallStore::{method} failed: {e}"),
        )
    }

    /// Atomically read-modify-write a counter in the `globals`
    /// partition. Counters are stored as little-endian `i64`.
    fn bump_global(&self, name: &str, by: i64) -> Result<(), MediatorError> {
        let key = name.as_bytes();
        let current: i64 = self
            .globals
            .get(key)
            .map_err(|e| Self::db_err("bump_global:get", e))?
            .and_then(|v| {
                let bytes: [u8; 8] = v.as_ref().try_into().ok()?;
                Some(i64::from_le_bytes(bytes))
            })
            .unwrap_or(0);
        let new = current.saturating_add(by);
        self.globals
            .insert(key, new.to_le_bytes().to_vec())
            .map_err(|e| Self::db_err("bump_global:insert", e))?;
        Ok(())
    }

    /// O(n) count of access-list entries for a DID. Sufficient for
    /// the typical "tens to low-thousands" entries; switch to a
    /// counter partition if it ever shows up in profiling.
    fn access_list_count_inner(&self, did_hash: &str) -> Result<usize, MediatorError> {
        let mut count = 0usize;
        for guard in self.access_lists.prefix(did_hash.as_bytes()) {
            let _ = guard
                .into_inner()
                .map_err(|e| Self::db_err("access_list_count:prefix", e))?;
            count += 1;
        }
        Ok(count)
    }

    fn access_list_contains(&self, did_hash: &str, member: &str) -> Result<bool, MediatorError> {
        let mut k = did_hash.as_bytes().to_vec();
        k.extend_from_slice(member.as_bytes());
        self.access_lists
            .contains_key(&k)
            .map_err(|e| Self::db_err("access_list_contains", e))
    }

    /// O(n) count of entries currently in the forward queue. Used by
    /// `forward_queue_len` and the `max_len` trim in
    /// `forward_queue_enqueue`.
    fn forward_queue_count_inner(&self) -> Result<usize, MediatorError> {
        let mut count = 0usize;
        for guard in self.forward_queue.iter() {
            let _ = guard
                .into_inner()
                .map_err(|e| Self::db_err("forward_queue_count:iter", e))?;
            count += 1;
        }
        Ok(count)
    }

    /// Read a consumer group's `last_delivered` stream ID from the
    /// `globals` partition. Returns `None` when the group hasn't been
    /// used yet — callers treat that as "deliver from the beginning."
    fn read_group_cursor(&self, group: &str) -> Option<(u64, u64)> {
        self.globals
            .get(group_cursor_key(group))
            .ok()
            .flatten()
            .and_then(|v| decode_stream_id(v.as_ref()))
    }

    fn read_global(&self, name: &str) -> i64 {
        self.globals
            .get(name.as_bytes())
            .ok()
            .flatten()
            .and_then(|v| {
                let bytes: [u8; 8] = v.as_ref().try_into().ok()?;
                Some(i64::from_le_bytes(bytes))
            })
            .unwrap_or(0)
    }

    /// Path the database was opened from.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl std::fmt::Debug for FjallStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FjallStore")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl MediatorStore for FjallStore {
    // ─── Bootstrap & health ─────────────────────────────────────────────────

    async fn initialize(&self) -> Result<(), MediatorError> {
        // All partitions opened in `open`; nothing further to do at
        // the moment. Future commits may seed schema versions or run
        // migrations here.
        Ok(())
    }

    async fn health(&self) -> StoreHealth {
        StoreHealth::Healthy
    }

    async fn shutdown(&self) -> Result<(), MediatorError> {
        // Drop in-process broadcast channels; subscribers see Closed.
        // The Fjall database itself is dropped when `FjallStore` is
        // dropped — there's no separate flush API call needed.
        self.broadcast_channels.lock().await.clear();
        Ok(())
    }

    // ─── Messages ───────────────────────────────────────────────────────────

    async fn store_message(
        &self,
        _session_id: &str,
        message: &str,
        to_did_hash: &str,
        from_hash: Option<&str>,
        expires_at: u64,
        _queue_maxlen: usize,
    ) -> Result<String, MediatorError> {
        let msg_id = digest(message.as_bytes());
        let bytes = message.len();
        let from = from_hash.unwrap_or("ANONYMOUS").to_string();

        let _guard = self.write_lock.lock().await;

        let receive_id = self.alloc_stream_id();
        let send_id = if from != "ANONYMOUS" {
            Some(self.alloc_stream_id())
        } else {
            None
        };

        let stored = StoredMessage {
            body: message.to_string(),
            bytes,
            to_did_hash: to_did_hash.to_string(),
            from_did_hash: if from == "ANONYMOUS" {
                None
            } else {
                Some(from.clone())
            },
            timestamp_ms: now_ms() as u128,
            receive_id,
            send_id,
            expires_at,
        };

        // Read-modify-write the affected accounts so their queue
        // counters stay consistent with the streams. Reads happen
        // first (under the lock), then everything is committed in a
        // single batch.
        let recv_account_key = to_did_hash.as_bytes().to_vec();
        let mut recv_account: StoredAccount = match self
            .accounts
            .get(&recv_account_key)
            .map_err(|e| Self::db_err("store_message:accounts.get", e))?
        {
            Some(v) => Self::decode(&v)?,
            None => StoredAccount::default(),
        };
        recv_account.receive_queue_count = recv_account.receive_queue_count.saturating_add(1);
        recv_account.receive_queue_bytes = recv_account
            .receive_queue_bytes
            .saturating_add(bytes as u64);

        let mut sender_account_pair: Option<(Vec<u8>, StoredAccount)> = None;
        if from != "ANONYMOUS" {
            let key = from.as_bytes().to_vec();
            let mut acc: StoredAccount = match self
                .accounts
                .get(&key)
                .map_err(|e| Self::db_err("store_message:accounts.get", e))?
            {
                Some(v) => Self::decode(&v)?,
                None => StoredAccount::default(),
            };
            acc.send_queue_count = acc.send_queue_count.saturating_add(1);
            acc.send_queue_bytes = acc.send_queue_bytes.saturating_add(bytes as u64);
            sender_account_pair = Some((key, acc));
        }

        // Build the atomic batch.
        let mut batch = self.db.batch();
        batch.insert(&self.messages, msg_id.as_bytes(), Self::encode(&stored)?);
        batch.insert(
            &self.inbox,
            stream_key_from_id(to_did_hash, receive_id),
            Self::encode(&StoredStreamEntry {
                msg_id: msg_id.clone(),
                bytes,
                peer_did: from.clone(),
            })?,
        );
        if let Some(sid) = send_id {
            batch.insert(
                &self.outbox,
                stream_key_from_id(&from, sid),
                Self::encode(&StoredStreamEntry {
                    msg_id: msg_id.clone(),
                    bytes,
                    peer_did: to_did_hash.to_string(),
                })?,
            );
        }
        batch.insert(
            &self.accounts,
            recv_account_key,
            Self::encode(&recv_account)?,
        );
        if let Some((key, acc)) = sender_account_pair {
            batch.insert(&self.accounts, key, Self::encode(&acc)?);
        }
        if expires_at > 0 {
            batch.insert(
                &self.expiry,
                expiry_key(expires_at, &msg_id),
                Vec::<u8>::new(),
            );
        }

        batch
            .commit()
            .map_err(|e| Self::db_err("store_message:commit", e))?;

        // Update global counters separately (best-effort — losing a
        // counter increment on crash is acceptable and matches Redis
        // `HINCRBY` behaviour where counters live outside the Lua
        // function's atomic scope).
        let _ = self.bump_global("RECEIVED_BYTES", bytes as i64);
        let _ = self.bump_global("RECEIVED_COUNT", 1);

        Ok(msg_id)
    }

    async fn delete_message(
        &self,
        message_hash: &str,
        by: DeletionAuthority,
    ) -> Result<(), MediatorError> {
        let _guard = self.write_lock.lock().await;

        let stored: StoredMessage = match self
            .messages
            .get(message_hash.as_bytes())
            .map_err(|e| Self::db_err("delete_message:messages.get", e))?
        {
            Some(v) => Self::decode(&v)?,
            None => {
                return Err(MediatorError::InternalError(
                    404,
                    "fjall".into(),
                    format!("NOT_FOUND: message_hash ({message_hash})"),
                ));
            }
        };

        let permitted = match &by {
            DeletionAuthority::Admin { .. } => true,
            DeletionAuthority::Owner { did_hash } => {
                did_hash == &stored.to_did_hash
                    || stored
                        .from_did_hash
                        .as_deref()
                        .map(|f| f == did_hash)
                        .unwrap_or(false)
            }
        };
        if !permitted {
            return Err(MediatorError::InternalError(
                403,
                "fjall".into(),
                "PERMISSION_DENIED: requesting DID does not own this message".into(),
            ));
        }

        // Read-modify-write the recipient and (if non-anonymous) the
        // sender accounts. Decrement queue counters for each.
        let recv_key = stored.to_did_hash.as_bytes().to_vec();
        let recv_account: Option<StoredAccount> = match self
            .accounts
            .get(&recv_key)
            .map_err(|e| Self::db_err("delete_message:accounts.get", e))?
        {
            Some(v) => Some(Self::decode(&v)?),
            None => None,
        };

        let mut sender_pair: Option<(Vec<u8>, StoredAccount)> = None;
        if let Some(from) = &stored.from_did_hash {
            let key = from.as_bytes().to_vec();
            if let Some(v) = self
                .accounts
                .get(&key)
                .map_err(|e| Self::db_err("delete_message:accounts.get", e))?
            {
                let mut acc: StoredAccount = Self::decode(&v)?;
                acc.send_queue_count = acc.send_queue_count.saturating_sub(1);
                acc.send_queue_bytes = acc.send_queue_bytes.saturating_sub(stored.bytes as u64);
                sender_pair = Some((key, acc));
            }
        }

        let mut batch = self.db.batch();
        batch.remove(&self.messages, message_hash.as_bytes());
        batch.remove(
            &self.inbox,
            stream_key_from_id(&stored.to_did_hash, stored.receive_id),
        );
        if let (Some(from), Some(sid)) = (&stored.from_did_hash, stored.send_id) {
            batch.remove(&self.outbox, stream_key_from_id(from, sid));
        }
        if let Some(mut recv) = recv_account {
            recv.receive_queue_count = recv.receive_queue_count.saturating_sub(1);
            recv.receive_queue_bytes = recv.receive_queue_bytes.saturating_sub(stored.bytes as u64);
            batch.insert(&self.accounts, recv_key, Self::encode(&recv)?);
        }
        if let Some((key, acc)) = sender_pair {
            batch.insert(&self.accounts, key, Self::encode(&acc)?);
        }
        if stored.expires_at > 0 {
            batch.remove(&self.expiry, expiry_key(stored.expires_at, message_hash));
        }

        batch
            .commit()
            .map_err(|e| Self::db_err("delete_message:commit", e))?;

        let _ = self.bump_global("DELETED_BYTES", stored.bytes as i64);
        let _ = self.bump_global("DELETED_COUNT", 1);
        Ok(())
    }

    async fn get_message(
        &self,
        did_hash: &str,
        msg_id: &str,
    ) -> Result<Option<MessageListElement>, MediatorError> {
        let stored: StoredMessage = match self
            .messages
            .get(msg_id.as_bytes())
            .map_err(|e| Self::db_err("get_message:messages.get", e))?
        {
            Some(v) => Self::decode(&v)?,
            None => return Ok(None),
        };

        let is_to = did_hash == stored.to_did_hash;
        let is_from = stored
            .from_did_hash
            .as_deref()
            .map(|f| f == did_hash)
            .unwrap_or(false);
        if !is_to && !is_from {
            // Don't leak existence to non-owners.
            return Ok(None);
        }

        Ok(Some(MessageListElement {
            msg_id: msg_id.to_string(),
            send_id: stored.send_id.map(|s| format_stream_id(s.0, s.1)),
            receive_id: Some(format_stream_id(stored.receive_id.0, stored.receive_id.1)),
            size: stored.bytes as u64,
            timestamp: stored.timestamp_ms as u64,
            to_address: Some(stored.to_did_hash.clone()),
            from_address: stored.from_did_hash.clone(),
            msg: Some(stored.body.clone()),
        }))
    }

    async fn get_message_metadata(
        &self,
        session_id: &str,
        message_hash: &str,
    ) -> Result<MessageMetaData, MediatorError> {
        let stored: StoredMessage = match self
            .messages
            .get(message_hash.as_bytes())
            .map_err(|e| Self::db_err("get_message_metadata:messages.get", e))?
        {
            Some(v) => Self::decode(&v)?,
            None => {
                return Err(MediatorError::DatabaseError(
                    14,
                    session_id.into(),
                    format!("Message metadata not found for {message_hash}"),
                ));
            }
        };
        Ok(MessageMetaData {
            bytes: stored.bytes,
            to_did_hash: stored.to_did_hash,
            from_did_hash: stored.from_did_hash,
            timestamp: stored.timestamp_ms,
        })
    }

    // ─── Inbox & outbox ─────────────────────────────────────────────────────

    async fn list_messages(
        &self,
        did_hash: &str,
        folder: Folder,
        range: Option<(&str, &str)>,
        limit: u32,
    ) -> Result<MessageList, MediatorError> {
        let partition = match folder {
            Folder::Inbox => &self.inbox,
            Folder::Outbox => &self.outbox,
        };

        // Compute (start, end) sub-keys within the DID's prefix.
        let (start_id, end_id) = range
            .map(|(s, e)| {
                let s_id = if s == "-" {
                    (0, 0)
                } else {
                    parse_stream_id_string(s).unwrap_or((0, 0))
                };
                let e_id = if e == "+" {
                    (u64::MAX, u64::MAX)
                } else {
                    parse_stream_id_string(e).unwrap_or((u64::MAX, u64::MAX))
                };
                (s_id, e_id)
            })
            .unwrap_or(((0, 0), (u64::MAX, u64::MAX)));

        let start_key = stream_key_from_id(did_hash, start_id);
        let end_key = stream_key_from_id(did_hash, end_id);
        let did_len = did_hash.len();

        let mut out = Vec::new();
        for guard in partition.range(start_key..=end_key).take(limit as usize) {
            let (key, value) = guard
                .into_inner()
                .map_err(|e| Self::db_err("list_messages:range", e))?;
            // Defensive: skip anything that escaped our did_hash prefix.
            if key.len() < did_len + 16 || &key[..did_len] != did_hash.as_bytes() {
                continue;
            }
            let Some(sid) = decode_stream_id(&key[did_len..did_len + 16]) else {
                continue;
            };
            let entry: StoredStreamEntry = Self::decode(&value)?;

            let mut element = MessageListElement {
                msg_id: entry.msg_id.clone(),
                size: entry.bytes as u64,
                timestamp: sid.0,
                ..Default::default()
            };
            match folder {
                Folder::Inbox => {
                    element.receive_id = Some(format_stream_id(sid.0, sid.1));
                    element.from_address = Some(entry.peer_did);
                }
                Folder::Outbox => {
                    element.send_id = Some(format_stream_id(sid.0, sid.1));
                    element.to_address = Some(entry.peer_did);
                }
            }
            out.push(element);
        }
        Ok(out)
    }

    async fn fetch_messages(
        &self,
        _session_id: &str,
        did_hash: &str,
        options: &FetchOptions,
    ) -> Result<GetMessagesResponse, MediatorError> {
        let start = options.start_id.as_deref().and_then(parse_stream_id_string);
        let limit = options.limit;
        let optimistic_delete = matches!(options.delete_policy, FetchDeletePolicy::Optimistic);

        let mut response = GetMessagesResponse::default();

        // Snapshot relevant entries. Use exclusive lower bound when
        // start is provided (matches Redis `(start_id` semantics).
        let did_bytes = did_hash.as_bytes();
        let did_len = did_bytes.len();

        // Build start key. If `start` is None, scan from the
        // beginning of this DID's prefix.
        let start_key = match start {
            Some((ms, seq)) => stream_key(did_hash, ms, seq),
            None => {
                let mut k = did_bytes.to_vec();
                k.extend_from_slice(&[0u8; 16]);
                k
            }
        };
        // End at the highest stream ID for this DID.
        let end_key = stream_key(did_hash, u64::MAX, u64::MAX);

        let entries: Vec<((u64, u64), StoredStreamEntry)> = {
            let mut buf = Vec::new();
            for guard in self.inbox.range(start_key..=end_key).take(limit as usize) {
                let (key, value) = guard
                    .into_inner()
                    .map_err(|e| Self::db_err("fetch_messages:range", e))?;
                if key.len() < did_len + 16 || &key[..did_len] != did_bytes {
                    continue;
                }
                let Some(sid) = decode_stream_id(&key[did_len..did_len + 16]) else {
                    continue;
                };
                // Skip the start_id itself when start is provided
                // (exclusive lower bound).
                if let Some(s) = start {
                    if sid == s {
                        continue;
                    }
                }
                let entry: StoredStreamEntry = Self::decode(&value)?;
                buf.push((sid, entry));
            }
            buf
        };

        for (sid, entry) in &entries {
            let body = self
                .messages
                .get(entry.msg_id.as_bytes())
                .map_err(|e| Self::db_err("fetch_messages:messages.get", e))?
                .map(|v| Self::decode::<StoredMessage>(&v).ok().map(|s| s.body))
                .flatten();

            let mut element = MessageListElement {
                msg_id: entry.msg_id.clone(),
                receive_id: Some(format_stream_id(sid.0, sid.1)),
                size: entry.bytes as u64,
                timestamp: sid.0,
                from_address: Some(entry.peer_did.clone()),
                to_address: Some(did_hash.to_string()),
                msg: body,
                ..Default::default()
            };

            if optimistic_delete {
                let result = self
                    .delete_message(
                        &entry.msg_id,
                        DeletionAuthority::Owner {
                            did_hash: did_hash.to_string(),
                        },
                    )
                    .await;
                if let Err(e) = result {
                    response
                        .delete_errors
                        .push((entry.msg_id.clone(), e.to_string()));
                    element.msg = None;
                }
            }
            response.success.push(element);
        }
        Ok(response)
    }

    async fn purge_folder(
        &self,
        session_id: &str,
        did_hash: &str,
        folder: Folder,
    ) -> Result<(usize, usize), MediatorError> {
        // Snapshot all msg_ids in this folder, then delete each via
        // the trait method (which handles cross-partition cleanup).
        let partition = match folder {
            Folder::Inbox => &self.inbox,
            Folder::Outbox => &self.outbox,
        };
        let did_bytes = did_hash.as_bytes();
        let did_len = did_bytes.len();
        let start = stream_key(did_hash, 0, 0);
        let end = stream_key(did_hash, u64::MAX, u64::MAX);

        let mut msg_ids = Vec::new();
        for guard in partition.range(start..=end) {
            let (key, value) = guard
                .into_inner()
                .map_err(|e| Self::db_err("purge_folder:range", e))?;
            if key.len() < did_len + 16 || &key[..did_len] != did_bytes {
                continue;
            }
            let entry: StoredStreamEntry = Self::decode(&value)?;
            msg_ids.push(entry.msg_id);
        }

        let mut count = 0;
        let mut bytes = 0;
        for msg_id in msg_ids {
            // Look up bytes before delete (delete_message removes the
            // record).
            let bytes_before = self
                .messages
                .get(msg_id.as_bytes())
                .ok()
                .flatten()
                .and_then(|v| Self::decode::<StoredMessage>(&v).ok())
                .map(|s| s.bytes)
                .unwrap_or(0);
            if self
                .delete_message(
                    &msg_id,
                    DeletionAuthority::Owner {
                        did_hash: did_hash.to_string(),
                    },
                )
                .await
                .is_ok()
            {
                count += 1;
                bytes += bytes_before;
            }
        }

        self.delete_folder_stream(session_id, did_hash, folder)
            .await?;
        Ok((count, bytes))
    }

    async fn delete_folder_stream(
        &self,
        _session_id: &str,
        did_hash: &str,
        folder: Folder,
    ) -> Result<(), MediatorError> {
        let partition = match folder {
            Folder::Inbox => &self.inbox,
            Folder::Outbox => &self.outbox,
        };
        let did_bytes = did_hash.as_bytes();
        let did_len = did_bytes.len();
        let start = stream_key(did_hash, 0, 0);
        let end = stream_key(did_hash, u64::MAX, u64::MAX);

        let _guard = self.write_lock.lock().await;
        let mut to_remove = Vec::new();
        for guard in partition.range(start..=end) {
            let (key, _value) = guard
                .into_inner()
                .map_err(|e| Self::db_err("delete_folder_stream:range", e))?;
            if key.len() < did_len + 16 || &key[..did_len] != did_bytes {
                continue;
            }
            to_remove.push(key);
        }
        let mut batch = self.db.batch();
        for k in to_remove {
            batch.remove(partition, k.as_ref());
        }
        batch
            .commit()
            .map_err(|e| Self::db_err("delete_folder_stream:commit", e))?;
        Ok(())
    }

    async fn inbox_status(&self, did_hash: &str) -> Result<InboxStatusReply, MediatorError> {
        let mut reply = InboxStatusReply {
            recipient_did: did_hash.to_string(),
            ..Default::default()
        };

        // Pull queue count + total bytes from the account record (cheaper
        // than scanning the inbox).
        if let Some(v) = self
            .accounts
            .get(did_hash.as_bytes())
            .map_err(|e| Self::db_err("inbox_status:accounts.get", e))?
        {
            let acc: StoredAccount = Self::decode(&v)?;
            reply.message_count = acc.receive_queue_count as u64;
            reply.total_bytes = acc.receive_queue_bytes;
        }

        // First and last stream IDs come from a forward + reverse
        // range scan limited to one entry each.
        let did_bytes = did_hash.as_bytes();
        let did_len = did_bytes.len();
        let start = stream_key(did_hash, 0, 0);
        let end = stream_key(did_hash, u64::MAX, u64::MAX);

        let mut count: u64 = 0;
        let mut first: Option<(u64, u64)> = None;
        let mut last: Option<(u64, u64)> = None;
        for guard in self.inbox.range(start.clone()..=end.clone()) {
            let (key, _v) = guard
                .into_inner()
                .map_err(|e| Self::db_err("inbox_status:range", e))?;
            if key.len() < did_len + 16 || &key[..did_len] != did_bytes {
                continue;
            }
            let Some(sid) = decode_stream_id(&key[did_len..did_len + 16]) else {
                continue;
            };
            count += 1;
            if first.is_none() {
                first = Some(sid);
            }
            last = Some(sid);
        }
        reply.queue_count = count;
        if let Some((ms, seq)) = first {
            reply.oldest_received = format_stream_id(ms, seq);
        }
        if let Some((ms, seq)) = last {
            reply.newest_received = format_stream_id(ms, seq);
        }

        // Live-delivery flag: streaming_clients lookup (key prefix is
        // mediator_uuid; we don't have it here, so any matching state
        // counts as live).
        for guard in self.streaming_clients.iter() {
            let (key, _v) = guard
                .into_inner()
                .map_err(|e| Self::db_err("inbox_status:streaming.iter", e))?;
            if key.ends_with(did_bytes) {
                reply.live_delivery = true;
                break;
            }
        }

        Ok(reply)
    }

    // ─── Sessions ───────────────────────────────────────────────────────────

    async fn put_session(&self, session: &Session, ttl: Duration) -> Result<(), MediatorError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let stored = StoredSession {
            session: session.clone(),
            expires_at_unix: now.saturating_add(ttl.as_secs()),
        };
        self.sessions
            .insert(session.session_id.as_bytes(), Self::encode(&stored)?)
            .map_err(|e| Self::db_err("put_session:insert", e))?;
        Ok(())
    }

    async fn get_session(&self, session_id: &str, did: &str) -> Result<Session, MediatorError> {
        let raw = self
            .sessions
            .get(session_id.as_bytes())
            .map_err(|e| Self::db_err("get_session:get", e))?
            .ok_or_else(|| {
                MediatorError::SessionError(
                    14,
                    session_id.into(),
                    format!("Session not found: {session_id}"),
                )
            })?;
        let stored: StoredSession = Self::decode(&raw)?;

        // Lazy expiry — drop the session if it's past TTL and report
        // "not found" to match the Redis path's behaviour.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if stored.expires_at_unix > 0 && stored.expires_at_unix <= now {
            let _ = self.sessions.remove(session_id.as_bytes());
            return Err(MediatorError::SessionError(
                14,
                session_id.into(),
                format!("Session expired: {session_id}"),
            ));
        }

        // `Session::session_id` is `#[serde(skip)]`; restore it from
        // the lookup key so the returned struct is fully populated.
        let mut session = stored.session;
        session.session_id = session_id.to_string();

        // Join with account record for ACLs + role (matches the
        // Redis path's "session HMGET + DID HMGET" pipeline).
        if !did.is_empty() {
            let did_hash = digest(did);
            if let Some(v) = self
                .accounts
                .get(did_hash.as_bytes())
                .map_err(|e| Self::db_err("get_session:accounts.get", e))?
            {
                let acc: StoredAccount = Self::decode(&v)?;
                session.acls = MediatorACLSet::from_u64(acc.acls);
                session.account_type = acc.role;
            }
        }
        Ok(session)
    }

    async fn delete_session(&self, session_id: &str) -> Result<(), MediatorError> {
        self.sessions
            .remove(session_id.as_bytes())
            .map_err(|e| Self::db_err("delete_session:remove", e))?;
        Ok(())
    }

    // ─── Accounts ───────────────────────────────────────────────────────────

    async fn account_exists(&self, did_hash: &str) -> Result<bool, MediatorError> {
        self.accounts
            .contains_key(did_hash.as_bytes())
            .map_err(|e| Self::db_err("account_exists:contains_key", e))
    }

    async fn account_get(&self, did_hash: &str) -> Result<Option<Account>, MediatorError> {
        let Some(raw) = self
            .accounts
            .get(did_hash.as_bytes())
            .map_err(|e| Self::db_err("account_get:get", e))?
        else {
            return Ok(None);
        };
        let acc: StoredAccount = Self::decode(&raw)?;
        let count = self.access_list_count_inner(did_hash)?;
        Ok(Some(acc.into_account(did_hash.to_string(), count as u32)))
    }

    async fn account_add(
        &self,
        did_hash: &str,
        acls: &MediatorACLSet,
        queue_limit: Option<u32>,
    ) -> Result<Account, MediatorError> {
        let mut record = StoredAccount {
            acls: acls.to_u64(),
            ..Default::default()
        };
        if let Some(limit) = queue_limit {
            record.queue_send_limit = Some(limit as i32);
            record.queue_receive_limit = Some(limit as i32);
        }
        self.accounts
            .insert(did_hash.as_bytes(), Self::encode(&record)?)
            .map_err(|e| Self::db_err("account_add:insert", e))?;
        Ok(record.into_account(did_hash.to_string(), 0))
    }

    async fn account_remove(
        &self,
        _session: &Session,
        did_hash: &str,
    ) -> Result<bool, MediatorError> {
        // Refuse to remove protected accounts up-front.
        if let Some(raw) = self
            .accounts
            .get(did_hash.as_bytes())
            .map_err(|e| Self::db_err("account_remove:accounts.get", e))?
        {
            let acc: StoredAccount = Self::decode(&raw)?;
            if acc.role == AccountType::Mediator || acc.role == AccountType::RootAdmin {
                return Err(MediatorError::InternalError(
                    18,
                    "fjall".into(),
                    "Cannot remove the mediator or root admin account".into(),
                ));
            }
        }

        // Block ACL.
        let mut blocked = MediatorACLSet::default();
        blocked.set_blocked(true);
        self.set_did_acl(did_hash, &blocked).await?;

        // Drop the outbox stream key (without purging downstream copies
        // already delivered) and purge the inbox.
        self.delete_folder_stream("", did_hash, Folder::Outbox)
            .await?;
        self.purge_folder("", did_hash, Folder::Inbox).await?;

        // Drop account, admin entry, and access list.
        let _guard = self.write_lock.lock().await;
        let mut batch = self.db.batch();
        batch.remove(&self.accounts, did_hash.as_bytes());
        batch.remove(&self.admins, did_hash.as_bytes());
        // Delete all access-list entries for this DID.
        let prefix = did_hash.as_bytes();
        for guard in self.access_lists.prefix(prefix) {
            let (key, _) = guard
                .into_inner()
                .map_err(|e| Self::db_err("account_remove:al.iter", e))?;
            batch.remove(&self.access_lists, key.as_ref());
        }
        batch
            .commit()
            .map_err(|e| Self::db_err("account_remove:commit", e))?;
        Ok(true)
    }

    async fn account_list(
        &self,
        cursor: u32,
        limit: u32,
    ) -> Result<MediatorAccountList, MediatorError> {
        let limit = limit.min(100) as usize;
        let mut accounts = Vec::with_capacity(limit);
        let mut total_seen: u32 = 0;
        let mut returned: u32 = 0;
        let mut more_after = false;

        for guard in self.accounts.iter() {
            let (key, value) = guard
                .into_inner()
                .map_err(|e| Self::db_err("account_list:iter", e))?;
            if total_seen < cursor {
                total_seen += 1;
                continue;
            }
            if returned as usize >= limit {
                more_after = true;
                break;
            }
            let did_hash = String::from_utf8(key.as_ref().to_vec()).unwrap_or_default();
            let acc: StoredAccount = Self::decode(&value)?;
            let count = self.access_list_count_inner(&did_hash)? as u32;
            accounts.push(acc.into_account(did_hash, count));
            total_seen += 1;
            returned += 1;
        }

        let next_cursor = if more_after { cursor + returned } else { 0 };
        Ok(MediatorAccountList {
            accounts,
            cursor: next_cursor,
        })
    }

    async fn account_set_role(
        &self,
        did_hash: &str,
        account_type: &AccountType,
    ) -> Result<(), MediatorError> {
        let _guard = self.write_lock.lock().await;
        let mut record: StoredAccount = match self
            .accounts
            .get(did_hash.as_bytes())
            .map_err(|e| Self::db_err("account_set_role:get", e))?
        {
            Some(v) => Self::decode(&v)?,
            None => StoredAccount::default(),
        };
        record.role = account_type.clone();

        let mut batch = self.db.batch();
        batch.insert(&self.accounts, did_hash.as_bytes(), Self::encode(&record)?);
        if account_type.is_admin() {
            batch.insert(&self.admins, did_hash.as_bytes(), Vec::<u8>::new());
        } else {
            batch.remove(&self.admins, did_hash.as_bytes());
        }
        batch
            .commit()
            .map_err(|e| Self::db_err("account_set_role:commit", e))?;
        Ok(())
    }

    async fn account_change_queue_limits(
        &self,
        did_hash: &str,
        send_queue_limit: Option<i32>,
        receive_queue_limit: Option<i32>,
    ) -> Result<(), MediatorError> {
        let _guard = self.write_lock.lock().await;
        let mut record: StoredAccount = match self
            .accounts
            .get(did_hash.as_bytes())
            .map_err(|e| Self::db_err("account_change_queue_limits:get", e))?
        {
            Some(v) => Self::decode(&v)?,
            None => StoredAccount::default(),
        };
        match send_queue_limit {
            Some(-2) => record.queue_send_limit = None,
            Some(n) => record.queue_send_limit = Some(n),
            None => {}
        }
        match receive_queue_limit {
            Some(-2) => record.queue_receive_limit = None,
            Some(n) => record.queue_receive_limit = Some(n),
            None => {}
        }
        self.accounts
            .insert(did_hash.as_bytes(), Self::encode(&record)?)
            .map_err(|e| Self::db_err("account_change_queue_limits:insert", e))?;
        Ok(())
    }

    // ─── ACLs ───────────────────────────────────────────────────────────────

    async fn set_did_acl(
        &self,
        did_hash: &str,
        acls: &MediatorACLSet,
    ) -> Result<MediatorACLSet, MediatorError> {
        let _guard = self.write_lock.lock().await;
        let mut record: StoredAccount = match self
            .accounts
            .get(did_hash.as_bytes())
            .map_err(|e| Self::db_err("set_did_acl:get", e))?
        {
            Some(v) => Self::decode(&v)?,
            None => StoredAccount::default(),
        };
        record.acls = acls.to_u64();
        self.accounts
            .insert(did_hash.as_bytes(), Self::encode(&record)?)
            .map_err(|e| Self::db_err("set_did_acl:insert", e))?;
        Ok(acls.clone())
    }

    async fn get_did_acl(&self, did_hash: &str) -> Result<Option<MediatorACLSet>, MediatorError> {
        let Some(raw) = self
            .accounts
            .get(did_hash.as_bytes())
            .map_err(|e| Self::db_err("get_did_acl:get", e))?
        else {
            return Ok(None);
        };
        let acc: StoredAccount = Self::decode(&raw)?;
        Ok(Some(MediatorACLSet::from_u64(acc.acls)))
    }

    async fn get_did_acls(
        &self,
        dids: &[String],
        mediator_acl_mode: AccessListModeType,
    ) -> Result<MediatorACLGetResponse, MediatorError> {
        if dids.len() > 100 {
            return Err(MediatorError::DatabaseError(
                27,
                "fjall".into(),
                "# of DIDs cannot exceed 100".into(),
            ));
        }
        let mut response = MediatorACLGetResponse {
            acl_response: Vec::with_capacity(dids.len()),
            mediator_acl_mode,
        };
        for did in dids {
            if let Some(raw) = self
                .accounts
                .get(did.as_bytes())
                .map_err(|e| Self::db_err("get_did_acls:get", e))?
            {
                let acc: StoredAccount = Self::decode(&raw)?;
                let acls = MediatorACLSet::from_u64(acc.acls);
                response.acl_response.push(
                    affinidi_messaging_sdk::protocols::mediator::acls_handler::MediatorACLExpanded {
                        did_hash: did.clone(),
                        acl_value: acls.to_hex_string(),
                        acls,
                    },
                );
            }
        }
        Ok(response)
    }

    async fn access_list_allowed(&self, to_hash: &str, from_hash: Option<&str>) -> bool {
        let Ok(Some(raw)) = self.accounts.get(to_hash.as_bytes()) else {
            return false;
        };
        let acc: StoredAccount = match Self::decode(&raw) {
            Ok(a) => a,
            Err(_) => return false,
        };
        let acls = MediatorACLSet::from_u64(acc.acls);
        match from_hash {
            Some(from) => {
                let in_list = self.access_list_contains(to_hash, from).unwrap_or(false);
                match acls.get_access_list_mode().0 {
                    AccessListModeType::ExplicitAllow => in_list,
                    AccessListModeType::ExplicitDeny => !in_list,
                }
            }
            None => acls.get_anon_receive().0,
        }
    }

    async fn access_list_list(
        &self,
        did_hash: &str,
        cursor: u64,
    ) -> Result<MediatorAccessListListResponse, MediatorError> {
        let prefix = did_hash.as_bytes();
        let prefix_len = prefix.len();
        let mut entries = Vec::new();
        let mut seen: u64 = 0;
        let mut more_after = false;

        for guard in self.access_lists.prefix(prefix) {
            let (key, _v) = guard
                .into_inner()
                .map_err(|e| Self::db_err("access_list_list:prefix", e))?;
            if seen < cursor {
                seen += 1;
                continue;
            }
            if entries.len() >= 100 {
                more_after = true;
                break;
            }
            // Strip the did_hash prefix to get the member DID hash.
            if key.len() <= prefix_len {
                continue;
            }
            let member = String::from_utf8(key[prefix_len..].to_vec()).unwrap_or_default();
            entries.push(member);
            seen += 1;
        }

        let next = if more_after {
            Some(cursor + entries.len() as u64)
        } else {
            None
        };
        Ok(MediatorAccessListListResponse {
            cursor: next,
            did_hashes: entries,
        })
    }

    async fn access_list_count(&self, did_hash: &str) -> Result<usize, MediatorError> {
        self.access_list_count_inner(did_hash)
    }

    async fn access_list_add(
        &self,
        access_list_limit: usize,
        did_hash: &str,
        hashes: &Vec<String>,
    ) -> Result<MediatorAccessListAddResponse, MediatorError> {
        let _guard = self.write_lock.lock().await;
        let current = self.access_list_count_inner(did_hash)?;
        let mut truncated = false;
        let to_add: Vec<String> = if current + hashes.len() > access_list_limit {
            truncated = true;
            let allowed = access_list_limit.saturating_sub(current);
            hashes.iter().take(allowed).cloned().collect()
        } else {
            hashes.clone()
        };
        let mut batch = self.db.batch();
        for h in &to_add {
            let mut k = did_hash.as_bytes().to_vec();
            k.extend_from_slice(h.as_bytes());
            batch.insert(&self.access_lists, k, Vec::<u8>::new());
        }
        batch
            .commit()
            .map_err(|e| Self::db_err("access_list_add:commit", e))?;
        Ok(MediatorAccessListAddResponse {
            did_hashes: to_add,
            truncated,
        })
    }

    async fn access_list_remove(
        &self,
        did_hash: &str,
        hashes: &Vec<String>,
    ) -> Result<usize, MediatorError> {
        let _guard = self.write_lock.lock().await;
        let mut batch = self.db.batch();
        let mut removed = 0;
        for h in hashes {
            let mut k = did_hash.as_bytes().to_vec();
            k.extend_from_slice(h.as_bytes());
            // Only count actually-present entries.
            if self
                .access_lists
                .contains_key(&k)
                .map_err(|e| Self::db_err("access_list_remove:contains", e))?
            {
                batch.remove(&self.access_lists, k);
                removed += 1;
            }
        }
        batch
            .commit()
            .map_err(|e| Self::db_err("access_list_remove:commit", e))?;
        Ok(removed)
    }

    async fn access_list_clear(&self, did_hash: &str) -> Result<(), MediatorError> {
        let _guard = self.write_lock.lock().await;
        let mut batch = self.db.batch();
        for guard in self.access_lists.prefix(did_hash.as_bytes()) {
            let (key, _) = guard
                .into_inner()
                .map_err(|e| Self::db_err("access_list_clear:prefix", e))?;
            batch.remove(&self.access_lists, key.as_ref());
        }
        batch
            .commit()
            .map_err(|e| Self::db_err("access_list_clear:commit", e))?;
        Ok(())
    }

    async fn access_list_get(
        &self,
        did_hash: &str,
        hashes: &Vec<String>,
    ) -> Result<MediatorAccessListGetResponse, MediatorError> {
        let mut found = Vec::new();
        for h in hashes {
            if self.access_list_contains(did_hash, h)? {
                found.push(h.clone());
            }
        }
        Ok(MediatorAccessListGetResponse { did_hashes: found })
    }

    // ─── Admin accounts ─────────────────────────────────────────────────────

    async fn setup_admin_account(
        &self,
        admin_did_hash: &str,
        admin_type: AccountType,
        acls: &MediatorACLSet,
    ) -> Result<(), MediatorError> {
        let exists = self.account_exists(admin_did_hash).await?;
        if !exists {
            self.account_add(admin_did_hash, acls, None).await?;
        }
        let _guard = self.write_lock.lock().await;
        let mut record: StoredAccount = self
            .accounts
            .get(admin_did_hash.as_bytes())
            .map_err(|e| Self::db_err("setup_admin_account:get", e))?
            .map(|v| Self::decode(&v))
            .transpose()?
            .unwrap_or_default();
        record.role = admin_type;
        let mut batch = self.db.batch();
        batch.insert(
            &self.accounts,
            admin_did_hash.as_bytes(),
            Self::encode(&record)?,
        );
        batch.insert(&self.admins, admin_did_hash.as_bytes(), Vec::<u8>::new());
        batch
            .commit()
            .map_err(|e| Self::db_err("setup_admin_account:commit", e))?;
        Ok(())
    }

    async fn check_admin_account(&self, did_hash: &str) -> Result<bool, MediatorError> {
        let in_admins = self
            .admins
            .contains_key(did_hash.as_bytes())
            .map_err(|e| Self::db_err("check_admin_account:contains", e))?;
        if !in_admins {
            return Ok(false);
        }
        let role = self
            .accounts
            .get(did_hash.as_bytes())
            .map_err(|e| Self::db_err("check_admin_account:get", e))?
            .map(|v| Self::decode::<StoredAccount>(&v).map(|a| a.role))
            .transpose()?;
        Ok(matches!(
            role,
            Some(AccountType::Admin) | Some(AccountType::RootAdmin)
        ))
    }

    async fn list_admin_accounts(
        &self,
        cursor: u32,
        limit: u32,
    ) -> Result<MediatorAdminList, MediatorError> {
        let limit = limit.min(100) as usize;
        let mut accounts: Vec<
            affinidi_messaging_sdk::protocols::mediator::administration::AdminAccount,
        > = Vec::with_capacity(limit);
        let mut seen: u32 = 0;
        let mut more = false;
        for guard in self.admins.iter() {
            let (key, _) = guard
                .into_inner()
                .map_err(|e| Self::db_err("list_admin_accounts:iter", e))?;
            if seen < cursor {
                seen += 1;
                continue;
            }
            if accounts.len() >= limit {
                more = true;
                break;
            }
            let did = String::from_utf8(key.as_ref().to_vec()).unwrap_or_default();
            let role = self
                .accounts
                .get(did.as_bytes())
                .map_err(|e| Self::db_err("list_admin_accounts:role.get", e))?
                .map(|v| Self::decode::<StoredAccount>(&v).map(|a| a.role))
                .transpose()?
                .unwrap_or(AccountType::Unknown);
            accounts.push(
                affinidi_messaging_sdk::protocols::mediator::administration::AdminAccount {
                    did_hash: did,
                    _type: role,
                },
            );
            seen += 1;
        }
        let next = if more {
            cursor + accounts.len() as u32
        } else {
            0
        };
        Ok(MediatorAdminList {
            accounts,
            cursor: next,
        })
    }

    // ─── OOB Discovery invitations ──────────────────────────────────────────

    async fn oob_discovery_store(
        &self,
        did_hash: &str,
        invite_b64: &str,
        expires_at: u64,
    ) -> Result<String, MediatorError> {
        let invite_hash = digest(invite_b64);
        let stored = StoredOobInvite {
            invite_b64: invite_b64.to_string(),
            did_hash: did_hash.to_string(),
            expires_at_unix: expires_at,
        };
        self.oob_invites
            .insert(invite_hash.as_bytes(), Self::encode(&stored)?)
            .map_err(|e| Self::db_err("oob_discovery_store:insert", e))?;
        let _ = self.bump_global("OOB_INVITES_CREATED", 1);
        Ok(invite_hash)
    }

    async fn oob_discovery_get(
        &self,
        oob_id: &str,
    ) -> Result<Option<(String, String)>, MediatorError> {
        let Some(raw) = self
            .oob_invites
            .get(oob_id.as_bytes())
            .map_err(|e| Self::db_err("oob_discovery_get:get", e))?
        else {
            return Ok(None);
        };
        let stored: StoredOobInvite = Self::decode(&raw)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if stored.expires_at_unix > 0 && stored.expires_at_unix <= now {
            // Expired — remove and report missing.
            let _ = self.oob_invites.remove(oob_id.as_bytes());
            return Ok(None);
        }
        let _ = self.bump_global("OOB_INVITES_CLAIMED", 1);
        Ok(Some((stored.invite_b64, stored.did_hash)))
    }

    async fn oob_discovery_delete(&self, oob_id: &str) -> Result<bool, MediatorError> {
        let existed = self
            .oob_invites
            .contains_key(oob_id.as_bytes())
            .map_err(|e| Self::db_err("oob_discovery_delete:contains", e))?;
        if existed {
            self.oob_invites
                .remove(oob_id.as_bytes())
                .map_err(|e| Self::db_err("oob_discovery_delete:remove", e))?;
        }
        Ok(existed)
    }

    // ─── Stats / counters ───────────────────────────────────────────────────

    async fn get_global_stats(&self) -> Result<MetadataStats, MediatorError> {
        // Pulls all counters in one snapshot. The reads are independent
        // (no atomic guarantee across counters), which matches Redis
        // `HGETALL GLOBAL` semantics — counters are updated by separate
        // `HINCRBY`s and a snapshot can split mid-update there too.
        Ok(MetadataStats {
            received_bytes: self.read_global("RECEIVED_BYTES"),
            sent_bytes: self.read_global("SENT_BYTES"),
            deleted_bytes: self.read_global("DELETED_BYTES"),
            received_count: self.read_global("RECEIVED_COUNT"),
            sent_count: self.read_global("SENT_COUNT"),
            deleted_count: self.read_global("DELETED_COUNT"),
            websocket_open: self.read_global("WEBSOCKET_OPEN"),
            websocket_close: self.read_global("WEBSOCKET_CLOSE"),
            sessions_created: self.read_global("SESSIONS_CREATED"),
            sessions_success: self.read_global("SESSIONS_SUCCESS"),
            oob_invites_created: self.read_global("OOB_INVITES_CREATED"),
            oob_invites_claimed: self.read_global("OOB_INVITES_CLAIMED"),
        })
    }

    async fn stats_increment(&self, counter: StatCounter, by: i64) -> Result<(), MediatorError> {
        let _guard = self.write_lock.lock().await;
        let key = match counter {
            StatCounter::SentBytes => "SENT_BYTES",
            StatCounter::SentCount => "SENT_COUNT",
            StatCounter::WebsocketOpen => "WEBSOCKET_OPEN",
            StatCounter::WebsocketClose => "WEBSOCKET_CLOSE",
            StatCounter::SessionsCreated => "SESSIONS_CREATED",
            StatCounter::SessionsSuccess => "SESSIONS_SUCCESS",
            StatCounter::OobInvitesCreated => "OOB_INVITES_CREATED",
            StatCounter::OobInvitesClaimed => "OOB_INVITES_CLAIMED",
        };
        self.bump_global(key, by)
    }

    // ─── Forwarding queue ───────────────────────────────────────────────────

    async fn forward_queue_enqueue(
        &self,
        entry: &ForwardQueueEntry,
        max_len: usize,
    ) -> Result<String, MediatorError> {
        let _guard = self.write_lock.lock().await;
        let id = self.alloc_stream_id();
        let mut entry = entry.clone();
        entry.stream_id = format_stream_id(id.0, id.1);
        let stream_id = entry.stream_id.clone();

        let mut batch = self.db.batch();
        batch.insert(
            &self.forward_queue,
            encode_stream_id(id.0, id.1).to_vec(),
            Self::encode(&entry)?,
        );

        // Approximate `max_len` trim: drop oldest entries when over.
        if max_len > 0 {
            let mut to_remove = Vec::new();
            let current = self.forward_queue_count_inner()?;
            if current >= max_len {
                let over = current - max_len + 1; // +1 because we're adding one
                for guard in self.forward_queue.iter().take(over) {
                    let (key, _) = guard
                        .into_inner()
                        .map_err(|e| Self::db_err("forward_queue_enqueue:trim", e))?;
                    to_remove.push(key);
                }
            }
            for k in to_remove {
                batch.remove(&self.forward_queue, k.as_ref());
            }
        }
        batch
            .commit()
            .map_err(|e| Self::db_err("forward_queue_enqueue:commit", e))?;
        drop(_guard);
        self.forward_notify.notify_waiters();
        Ok(stream_id)
    }

    async fn forward_queue_len(&self) -> Result<usize, MediatorError> {
        self.forward_queue_count_inner()
    }

    async fn forward_queue_read(
        &self,
        group_name: &str,
        consumer_name: &str,
        count: usize,
        block: Duration,
    ) -> Result<Vec<ForwardQueueEntry>, MediatorError> {
        // Inner closure: read up to `count` entries strictly past the
        // group's `last_delivered` cursor, claim them, and update the
        // cursor — all under the write lock so two consumers don't
        // double-deliver.
        let try_read = |store: &Self| -> Result<Vec<ForwardQueueEntry>, MediatorError> {
            let last = store.read_group_cursor(group_name);
            let lower = match last {
                Some(sid) => std::ops::Bound::Excluded(encode_stream_id(sid.0, sid.1).to_vec()),
                None => std::ops::Bound::Unbounded,
            };
            let mut entries = Vec::new();
            let mut new_last: Option<(u64, u64)> = last;
            for guard in store
                .forward_queue
                .range::<Vec<u8>, _>((lower, std::ops::Bound::Unbounded))
                .take(count)
            {
                let (key, value) = guard
                    .into_inner()
                    .map_err(|e| Self::db_err("forward_queue_read:range", e))?;
                let Some(sid) = decode_stream_id(key.as_ref()) else {
                    continue;
                };
                let entry: ForwardQueueEntry = Self::decode(&value)?;
                entries.push((sid, entry));
                new_last = Some(sid);
            }

            // Persist the claims and the new cursor in one batch.
            let mut batch = store.db.batch();
            let now = now_ms_u64();
            for (sid, _entry) in &entries {
                let claim = StoredPendingClaim {
                    consumer: consumer_name.to_string(),
                    claimed_at_ms: now,
                    delivery_count: 1,
                };
                batch.insert(
                    &store.forward_pending,
                    pending_key(group_name, *sid),
                    Self::encode(&claim)?,
                );
            }
            if let Some(sid) = new_last {
                batch.insert(
                    &store.globals,
                    group_cursor_key(group_name),
                    encode_stream_id(sid.0, sid.1).to_vec(),
                );
            }
            batch
                .commit()
                .map_err(|e| Self::db_err("forward_queue_read:commit", e))?;

            Ok(entries.into_iter().map(|(_, e)| e).collect())
        };

        let initial = {
            let _guard = self.write_lock.lock().await;
            try_read(self)?
        };
        if !initial.is_empty() || block.is_zero() {
            return Ok(initial);
        }
        // Empty + caller asked to block — wait for an enqueue or
        // timeout, then try once more.
        let _ = tokio::time::timeout(block, self.forward_notify.notified()).await;
        let _guard = self.write_lock.lock().await;
        try_read(self)
    }

    async fn forward_queue_ack(
        &self,
        group_name: &str,
        stream_ids: &[&str],
    ) -> Result<(), MediatorError> {
        let _guard = self.write_lock.lock().await;
        let mut batch = self.db.batch();
        for id in stream_ids {
            if let Some(sid) = parse_stream_id_string(id) {
                batch.remove(&self.forward_pending, pending_key(group_name, sid));
            }
        }
        batch
            .commit()
            .map_err(|e| Self::db_err("forward_queue_ack:commit", e))?;
        Ok(())
    }

    async fn forward_queue_delete(&self, stream_ids: &[&str]) -> Result<(), MediatorError> {
        let _guard = self.write_lock.lock().await;
        let mut batch = self.db.batch();
        for id in stream_ids {
            if let Some(sid) = parse_stream_id_string(id) {
                batch.remove(&self.forward_queue, encode_stream_id(sid.0, sid.1).to_vec());
            }
        }
        batch
            .commit()
            .map_err(|e| Self::db_err("forward_queue_delete:commit", e))?;
        Ok(())
    }

    async fn forward_queue_autoclaim(
        &self,
        group_name: &str,
        consumer_name: &str,
        min_idle: Duration,
        count: usize,
    ) -> Result<Vec<ForwardQueueEntry>, MediatorError> {
        let now = now_ms_u64();
        let min_idle_ms = min_idle.as_millis() as u64;

        let _guard = self.write_lock.lock().await;
        let group_prefix_len = group_name.len() + 1; // +1 for the null byte

        // Snapshot pending entries for this group whose claim is older
        // than `min_idle`.
        let mut stale: Vec<((u64, u64), StoredPendingClaim)> = Vec::new();
        for guard in self.forward_pending.prefix(group_name.as_bytes()) {
            if stale.len() >= count {
                break;
            }
            let (key, value) = guard
                .into_inner()
                .map_err(|e| Self::db_err("forward_queue_autoclaim:prefix", e))?;
            // Defensive: only consider keys that are actually for our
            // group (the prefix iter is conservative).
            if key.len() < group_prefix_len + 16
                || &key[..group_name.len()] != group_name.as_bytes()
                || key[group_name.len()] != 0x00
            {
                continue;
            }
            let Some(sid) = decode_stream_id(&key[group_prefix_len..]) else {
                continue;
            };
            let claim: StoredPendingClaim = Self::decode(&value)?;
            if now.saturating_sub(claim.claimed_at_ms) >= min_idle_ms {
                stale.push((sid, claim));
            }
        }

        // Re-claim each stale entry under the new consumer and bump
        // delivery count. Persist updated claims + collect the
        // associated queue entries to return.
        let mut batch = self.db.batch();
        let mut out = Vec::with_capacity(stale.len());
        for (sid, claim) in stale {
            let new_claim = StoredPendingClaim {
                consumer: consumer_name.to_string(),
                claimed_at_ms: now,
                delivery_count: claim.delivery_count.saturating_add(1),
            };
            batch.insert(
                &self.forward_pending,
                pending_key(group_name, sid),
                Self::encode(&new_claim)?,
            );
            if let Some(raw) = self
                .forward_queue
                .get(encode_stream_id(sid.0, sid.1).to_vec())
                .map_err(|e| Self::db_err("forward_queue_autoclaim:fetch", e))?
            {
                let entry: ForwardQueueEntry = Self::decode(&raw)?;
                out.push(entry);
            }
        }
        batch
            .commit()
            .map_err(|e| Self::db_err("forward_queue_autoclaim:commit", e))?;
        Ok(out)
    }

    // ─── Live streaming (WebSocket pub/sub) ─────────────────────────────────

    async fn streaming_clean_start(&self, mediator_uuid: &str) -> Result<(), MediatorError> {
        // Drop every streaming-client entry that points at this
        // mediator UUID. On startup the mediator calls this to clear
        // stale registrations from a previous run.
        let _guard = self.write_lock.lock().await;
        let mut to_remove = Vec::new();
        for guard in self.streaming_clients.iter() {
            let (key, value) = guard
                .into_inner()
                .map_err(|e| Self::db_err("streaming_clean_start:iter", e))?;
            let stored: StoredStreamingClient = match Self::decode(&value) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if stored.mediator_uuid == mediator_uuid {
                to_remove.push(key);
            }
        }
        let mut batch = self.db.batch();
        for k in to_remove {
            batch.remove(&self.streaming_clients, k.as_ref());
        }
        batch
            .commit()
            .map_err(|e| Self::db_err("streaming_clean_start:commit", e))?;
        Ok(())
    }

    async fn streaming_set_state(
        &self,
        did_hash: &str,
        mediator_uuid: &str,
        state: StreamingClientState,
    ) -> Result<(), MediatorError> {
        match state {
            StreamingClientState::Deregistered => {
                self.streaming_clients
                    .remove(did_hash.as_bytes())
                    .map_err(|e| Self::db_err("streaming_set_state:remove", e))?;
            }
            other => {
                let stored = StoredStreamingClient {
                    mediator_uuid: mediator_uuid.to_string(),
                    state: other,
                };
                self.streaming_clients
                    .insert(did_hash.as_bytes(), Self::encode(&stored)?)
                    .map_err(|e| Self::db_err("streaming_set_state:insert", e))?;
            }
        }
        Ok(())
    }

    async fn streaming_is_client_live(
        &self,
        did_hash: &str,
        force_delivery: bool,
    ) -> Option<String> {
        let raw = self.streaming_clients.get(did_hash.as_bytes()).ok()??;
        let stored: StoredStreamingClient = Self::decode(&raw).ok()?;
        match stored.state {
            StreamingClientState::Live => Some(stored.mediator_uuid),
            StreamingClientState::Registered if force_delivery => Some(stored.mediator_uuid),
            _ => None,
        }
    }

    async fn streaming_publish_message(
        &self,
        did_hash: &str,
        mediator_uuid: &str,
        message: &str,
        force_delivery: bool,
    ) -> Result<(), MediatorError> {
        // Even before `streaming_set_state` lands, publishing into
        // the broadcast channel works — it lets in-process subscribers
        // receive notifications. The cross-process aspect (which Fjall
        // can't do) stays unsupported.
        let channels = self.broadcast_channels.lock().await;
        if let Some(sender) = channels.get(mediator_uuid) {
            let _ = sender.send(PubSubRecord {
                did_hash: did_hash.to_string(),
                message: message.to_string(),
                force_delivery,
            });
        }
        Ok(())
    }

    async fn streaming_subscribe(
        &self,
        mediator_uuid: &str,
    ) -> Result<broadcast::Receiver<PubSubRecord>, MediatorError> {
        let mut channels = self.broadcast_channels.lock().await;
        if let Some(sender) = channels.get(mediator_uuid) {
            return Ok(sender.subscribe());
        }
        let (sender, receiver) = broadcast::channel(PUBSUB_BROADCAST_CAPACITY);
        channels.insert(mediator_uuid.to_string(), sender);
        Ok(receiver)
    }

    // ─── Message expiry processor ───────────────────────────────────────────

    async fn sweep_expired_messages(
        &self,
        now_secs: u64,
        admin_did_hash: &str,
    ) -> Result<ExpiryReport, MediatorError> {
        // Range-scan the expiry partition with `expires_at <=
        // now_secs`. Keys are `expires_at_be_8 || msg_id`, so we
        // bound from `0u64` up to (and including) `now_secs`'s
        // 8-byte big-endian + a max-byte msg_id suffix.
        let mut start = [0u8; 8].to_vec();
        start.extend_from_slice(&[0u8; 64]); // arbitrary low msg_id
        let mut end = now_secs.to_be_bytes().to_vec();
        end.extend_from_slice(&[0xFFu8; 64]);

        let mut report = ExpiryReport::default();
        let mut to_delete = Vec::new();
        let mut last_ts: Option<u64> = None;
        for guard in self.expiry.range(start..=end) {
            let (key, _v) = guard
                .into_inner()
                .map_err(|e| Self::db_err("sweep_expired_messages:range", e))?;
            if key.len() < 8 {
                continue;
            }
            let ts: [u8; 8] = key[..8].try_into().unwrap_or([0u8; 8]);
            let ts = u64::from_be_bytes(ts);
            if last_ts.map(|prev| ts != prev).unwrap_or(true) {
                report.timeslots_swept += 1;
                last_ts = Some(ts);
            }
            let msg_id = String::from_utf8(key[8..].to_vec()).unwrap_or_default();
            if !msg_id.is_empty() {
                to_delete.push(msg_id);
            }
        }

        for msg_id in to_delete {
            match self
                .delete_message(
                    &msg_id,
                    DeletionAuthority::Admin {
                        admin_did_hash: admin_did_hash.to_string(),
                    },
                )
                .await
            {
                Ok(_) => report.expired += 1,
                Err(_) => report.already_deleted += 1,
            }
        }
        Ok(report)
    }
}

// ─── Smoke tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn open_and_close_round_trip() {
        let dir = TempDir::new().expect("tempdir");
        let store = FjallStore::open(dir.path()).expect("open");
        assert_eq!(store.path(), dir.path());
        store.initialize().await.expect("initialize");
        assert!(matches!(store.health().await, StoreHealth::Healthy));
        store.shutdown().await.expect("shutdown");
    }

    #[tokio::test]
    async fn streaming_subscribe_returns_receiver_without_storage() {
        let dir = TempDir::new().expect("tempdir");
        let store = FjallStore::open(dir.path()).expect("open");

        let mut rx = store
            .streaming_subscribe("test-uuid")
            .await
            .expect("subscribe");
        store
            .streaming_publish_message("did_hash", "test-uuid", "payload", false)
            .await
            .expect("publish");

        let msg = tokio::time::timeout(Duration::from_millis(500), rx.recv())
            .await
            .expect("recv timed out")
            .expect("recv error");
        assert_eq!(msg.did_hash, "did_hash");
        assert_eq!(msg.message, "payload");
        assert!(!msg.force_delivery);
    }

    /// Use 64-char SHA-256-hex DID hashes so the inbox/outbox key
    /// encoding (`did_hash || stream_id_be`) exercises the same
    /// fixed-width prefix the production handlers feed in.
    fn hash(s: &str) -> String {
        digest(s)
    }

    #[tokio::test]
    async fn store_and_fetch_message_round_trip() {
        let dir = TempDir::new().expect("tempdir");
        let store = FjallStore::open(dir.path()).expect("open");
        let to = hash("alice");
        let from = hash("bob");

        let msg_id = store
            .store_message("session-1", "hello", &to, Some(&from), 0, 0)
            .await
            .expect("store");

        let got = store
            .get_message(&to, &msg_id)
            .await
            .expect("get")
            .expect("message present");
        assert_eq!(got.msg.as_deref(), Some("hello"));
        assert_eq!(got.to_address.as_deref(), Some(to.as_str()));
        assert_eq!(got.from_address.as_deref(), Some(from.as_str()));

        // Non-owner sees None.
        let none = store
            .get_message(&hash("eve"), &msg_id)
            .await
            .expect("get for non-owner");
        assert!(none.is_none());

        let list = store
            .list_messages(&to, Folder::Inbox, None, 100)
            .await
            .expect("list");
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].msg_id, msg_id);

        store
            .delete_message(
                &msg_id,
                DeletionAuthority::Owner {
                    did_hash: to.clone(),
                },
            )
            .await
            .expect("delete");
        let after = store
            .list_messages(&to, Folder::Inbox, None, 100)
            .await
            .expect("list after delete");
        assert!(after.is_empty());
    }

    #[tokio::test]
    async fn delete_rejects_non_owner_non_admin() {
        let dir = TempDir::new().expect("tempdir");
        let store = FjallStore::open(dir.path()).expect("open");
        let msg_id = store
            .store_message("s", "hi", &hash("alice"), Some(&hash("bob")), 0, 0)
            .await
            .expect("store");
        let err = store
            .delete_message(
                &msg_id,
                DeletionAuthority::Owner {
                    did_hash: hash("eve"),
                },
            )
            .await
            .expect_err("non-owner delete must fail");
        assert!(format!("{err}").contains("PERMISSION_DENIED"));
    }

    #[tokio::test]
    async fn admin_authority_bypasses_ownership() {
        let dir = TempDir::new().expect("tempdir");
        let store = FjallStore::open(dir.path()).expect("open");
        let msg_id = store
            .store_message("s", "hi", &hash("alice"), Some(&hash("bob")), 0, 0)
            .await
            .expect("store");
        store
            .delete_message(
                &msg_id,
                DeletionAuthority::Admin {
                    admin_did_hash: hash("admin"),
                },
            )
            .await
            .expect("admin delete");
    }

    #[tokio::test]
    async fn fetch_messages_optimistic_delete_drains_inbox() {
        let dir = TempDir::new().expect("tempdir");
        let store = FjallStore::open(dir.path()).expect("open");
        let alice = hash("alice");
        let bob = hash("bob");
        for i in 0..5 {
            store
                .store_message("s", &format!("msg-{i}"), &alice, Some(&bob), 0, 0)
                .await
                .expect("store");
        }
        let resp = store
            .fetch_messages(
                "s",
                &alice,
                &FetchOptions {
                    limit: 100,
                    delete_policy: FetchDeletePolicy::Optimistic,
                    ..Default::default()
                },
            )
            .await
            .expect("fetch");
        assert_eq!(resp.success.len(), 5);
        let after = store
            .list_messages(&alice, Folder::Inbox, None, 100)
            .await
            .expect("list");
        assert!(after.is_empty());
    }

    #[tokio::test]
    async fn list_messages_returns_in_stream_order() {
        let dir = TempDir::new().expect("tempdir");
        let store = FjallStore::open(dir.path()).expect("open");
        let alice = hash("alice");
        let bob = hash("bob");
        let mut ids = Vec::new();
        for i in 0..3 {
            ids.push(
                store
                    .store_message("s", &format!("msg-{i}"), &alice, Some(&bob), 0, 0)
                    .await
                    .expect("store"),
            );
        }
        let list = store
            .list_messages(&alice, Folder::Inbox, None, 100)
            .await
            .expect("list");
        let returned: Vec<&str> = list.iter().map(|m| m.msg_id.as_str()).collect();
        let expected: Vec<&str> = ids.iter().map(|s| s.as_str()).collect();
        assert_eq!(returned, expected);
    }

    #[tokio::test]
    async fn sweep_expired_messages_drains_index() {
        let dir = TempDir::new().expect("tempdir");
        let store = FjallStore::open(dir.path()).expect("open");
        let alice = hash("alice");
        let bob = hash("bob");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        store
            .store_message("s", "old", &alice, Some(&bob), now - 10, 0)
            .await
            .expect("store");
        store
            .store_message("s", "expiring", &alice, Some(&bob), now, 0)
            .await
            .expect("store");
        store
            .store_message("s", "future", &alice, Some(&bob), now + 1000, 0)
            .await
            .expect("store");

        let report = store
            .sweep_expired_messages(now, &hash("admin"))
            .await
            .expect("sweep");
        assert_eq!(report.expired, 2, "two messages should expire at <= now");

        let list = store
            .list_messages(&alice, Folder::Inbox, None, 100)
            .await
            .expect("list");
        assert_eq!(list.len(), 1);
    }

    #[tokio::test]
    async fn data_persists_across_open() {
        let dir = TempDir::new().expect("tempdir");
        let alice = hash("alice");
        let bob = hash("bob");

        let msg_id = {
            let store = FjallStore::open(dir.path()).expect("open");
            let id = store
                .store_message("s", "persistent", &alice, Some(&bob), 0, 0)
                .await
                .expect("store");
            store.shutdown().await.expect("shutdown");
            drop(store);
            id
        };

        // Re-open the same directory; previously written data must
        // still be readable.
        let store = FjallStore::open(dir.path()).expect("reopen");
        let got = store
            .get_message(&alice, &msg_id)
            .await
            .expect("get")
            .expect("message must persist across open");
        assert_eq!(got.msg.as_deref(), Some("persistent"));
    }

    #[tokio::test]
    async fn inbox_status_reflects_queue_state() {
        let dir = TempDir::new().expect("tempdir");
        let store = FjallStore::open(dir.path()).expect("open");
        let alice = hash("alice");
        let bob = hash("bob");

        for i in 0..3 {
            store
                .store_message("s", &format!("m-{i}"), &alice, Some(&bob), 0, 0)
                .await
                .expect("store");
        }
        let status = store.inbox_status(&alice).await.expect("status");
        assert_eq!(status.message_count, 3);
        assert_eq!(status.queue_count, 3);
        assert!(!status.oldest_received.is_empty());
        assert!(!status.newest_received.is_empty());
    }

    // ─── Identity-primitive tests (task #15) ──────────────────────────────

    #[tokio::test]
    async fn session_lifecycle() {
        let dir = TempDir::new().expect("tempdir");
        let store = FjallStore::open(dir.path()).expect("open");

        let session = Session {
            session_id: "sid-1".into(),
            challenge: "abc".into(),
            did: "did:peer:test".into(),
            did_hash: hash("did:peer:test"),
            ..Default::default()
        };
        store
            .put_session(&session, Duration::from_secs(60))
            .await
            .expect("put");

        let got = store
            .get_session("sid-1", "did:peer:test")
            .await
            .expect("get");
        assert_eq!(got.session_id, "sid-1");
        assert_eq!(got.challenge, "abc");

        store.delete_session("sid-1").await.expect("delete");
        let missing = store.get_session("sid-1", "did:peer:test").await;
        assert!(missing.is_err(), "deleted session must error");
    }

    #[tokio::test]
    async fn session_expires_lazily() {
        let dir = TempDir::new().expect("tempdir");
        let store = FjallStore::open(dir.path()).expect("open");

        let session = Session {
            session_id: "sid-2".into(),
            ..Default::default()
        };
        // Use a 0s TTL so the entry's expires_at_unix == now and the
        // <= comparison evicts it on the next read.
        store
            .put_session(&session, Duration::from_secs(0))
            .await
            .expect("put");
        // Brief sleep so the wall-clock advances past the stored
        // `expires_at_unix`.
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let result = store.get_session("sid-2", "").await;
        assert!(result.is_err(), "expired session must not return");
    }

    #[tokio::test]
    async fn account_crud_and_persistence() {
        let dir = TempDir::new().expect("tempdir");
        let did = hash("did_hash_1");
        {
            let store = FjallStore::open(dir.path()).expect("open");
            store
                .account_add(&did, &MediatorACLSet::default(), Some(50))
                .await
                .expect("add");
            assert!(store.account_exists(&did).await.unwrap());
            store
                .account_set_role(&did, &AccountType::Admin)
                .await
                .expect("set_role");
            store.shutdown().await.expect("shutdown");
        }
        // Reopen and confirm both the account and admin status.
        let store = FjallStore::open(dir.path()).expect("reopen");
        let got = store
            .account_get(&did)
            .await
            .expect("get")
            .expect("present");
        assert_eq!(got.did_hash, did);
        assert!(store.check_admin_account(&did).await.unwrap());
        let list = store.list_admin_accounts(0, 10).await.expect("list");
        assert!(list.accounts.iter().any(|a| a.did_hash == did));
    }

    #[tokio::test]
    async fn account_list_paginates() {
        let dir = TempDir::new().expect("tempdir");
        let store = FjallStore::open(dir.path()).expect("open");
        for i in 0..5 {
            store
                .account_add(&hash(&format!("d{i}")), &MediatorACLSet::default(), None)
                .await
                .expect("add");
        }

        let page1 = store.account_list(0, 2).await.expect("page1");
        assert_eq!(page1.accounts.len(), 2);
        assert!(page1.cursor > 0, "cursor should advance");

        let page2 = store.account_list(page1.cursor, 2).await.expect("page2");
        assert_eq!(page2.accounts.len(), 2);
        assert!(page2.cursor > 0);

        let page3 = store.account_list(page2.cursor, 2).await.expect("page3");
        assert_eq!(page3.accounts.len(), 1);
        assert_eq!(page3.cursor, 0, "final page returns cursor=0");
    }

    #[tokio::test]
    async fn access_list_round_trip() {
        let dir = TempDir::new().expect("tempdir");
        let store = FjallStore::open(dir.path()).expect("open");
        let alice = hash("alice");
        let bob = hash("bob");
        let charlie = hash("charlie");

        store
            .account_add(&alice, &MediatorACLSet::default(), None)
            .await
            .expect("add");

        let resp = store
            .access_list_add(100, &alice, &vec![bob.clone(), charlie.clone()])
            .await
            .expect("add");
        assert_eq!(resp.did_hashes.len(), 2);
        assert!(!resp.truncated);
        assert_eq!(store.access_list_count(&alice).await.unwrap(), 2);

        let got = store
            .access_list_get(&alice, &vec![bob.clone(), hash("eve")])
            .await
            .expect("get");
        assert_eq!(got.did_hashes, vec![bob.clone()]);

        let removed = store
            .access_list_remove(&alice, &vec![bob.clone()])
            .await
            .expect("remove");
        assert_eq!(removed, 1);
        assert_eq!(store.access_list_count(&alice).await.unwrap(), 1);

        // Clear leaves the list empty.
        store.access_list_clear(&alice).await.expect("clear");
        assert_eq!(store.access_list_count(&alice).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn access_list_allowed_honors_acl_mode() {
        let dir = TempDir::new().expect("tempdir");
        let store = FjallStore::open(dir.path()).expect("open");
        let alice = hash("alice");
        let bob = hash("bob");

        // ExplicitAllow → only entries in the access list pass.
        let mut allow_set = MediatorACLSet::default();
        let _ = allow_set.set_access_list_mode(AccessListModeType::ExplicitAllow, true, true);
        store
            .account_add(&alice, &allow_set, None)
            .await
            .expect("add alice");
        store
            .access_list_add(100, &alice, &vec![bob.clone()])
            .await
            .expect("add bob to list");
        assert!(store.access_list_allowed(&alice, Some(&bob)).await);
        assert!(!store.access_list_allowed(&alice, Some(&hash("eve"))).await);

        // Switching to ExplicitDeny inverts the meaning of the list.
        let mut deny_set = MediatorACLSet::default();
        let _ = deny_set.set_access_list_mode(AccessListModeType::ExplicitDeny, true, true);
        store.set_did_acl(&alice, &deny_set).await.expect("set");
        assert!(!store.access_list_allowed(&alice, Some(&bob)).await);
        assert!(store.access_list_allowed(&alice, Some(&hash("eve"))).await);
    }

    // ─── Stats + forward-queue tests (task #16) ────────────────────────────

    #[tokio::test]
    async fn stats_counters_accumulate_and_persist() {
        let dir = TempDir::new().expect("tempdir");
        {
            let store = FjallStore::open(dir.path()).expect("open");
            store
                .stats_increment(StatCounter::WebsocketOpen, 1)
                .await
                .expect("incr");
            store
                .stats_increment(StatCounter::WebsocketOpen, 2)
                .await
                .expect("incr");
            store
                .stats_increment(StatCounter::SentBytes, 100)
                .await
                .expect("incr");
            store.shutdown().await.expect("shutdown");
        }
        // Reopen — counters should round-trip from disk.
        let store = FjallStore::open(dir.path()).expect("reopen");
        let stats = store.get_global_stats().await.expect("stats");
        assert_eq!(stats.websocket_open, 3);
        assert_eq!(stats.sent_bytes, 100);
    }

    #[tokio::test]
    async fn forward_queue_enqueue_read_ack() {
        let dir = TempDir::new().expect("tempdir");
        let store = FjallStore::open(dir.path()).expect("open");
        let entry = ForwardQueueEntry {
            stream_id: String::new(),
            message: "encrypted".into(),
            to_did_hash: hash("to"),
            from_did_hash: hash("from"),
            from_did: "did:from".into(),
            to_did: "did:to".into(),
            endpoint_url: "http://example".into(),
            received_at_ms: 0,
            delay_milli: 0,
            expires_at: 0,
            retry_count: 0,
            hop_count: 0,
        };
        let id = store
            .forward_queue_enqueue(&entry, 0)
            .await
            .expect("enqueue");
        assert_eq!(store.forward_queue_len().await.unwrap(), 1);

        let read = store
            .forward_queue_read("g", "c", 10, Duration::from_millis(0))
            .await
            .expect("read");
        assert_eq!(read.len(), 1);
        assert_eq!(read[0].stream_id, id);

        store.forward_queue_ack("g", &[&id]).await.expect("ack");
        // After ack, the consumer group's cursor is past this entry,
        // so a subsequent read returns nothing.
        let again = store
            .forward_queue_read("g", "c", 10, Duration::from_millis(0))
            .await
            .expect("read after ack");
        assert!(again.is_empty());
    }

    #[tokio::test]
    async fn forward_queue_blocks_then_returns_on_enqueue() {
        let dir = TempDir::new().expect("tempdir");
        let store = Arc::new(FjallStore::open(dir.path()).expect("open"));

        // Spawn a reader that blocks for up to 2s.
        let reader = {
            let store = Arc::clone(&store);
            tokio::spawn(async move {
                store
                    .forward_queue_read("g", "c", 10, Duration::from_secs(2))
                    .await
                    .expect("read")
            })
        };

        // Give the reader a moment to actually start blocking.
        tokio::time::sleep(Duration::from_millis(50)).await;

        let entry = ForwardQueueEntry {
            stream_id: String::new(),
            message: "delayed".into(),
            to_did_hash: hash("to"),
            from_did_hash: hash("from"),
            from_did: "did:from".into(),
            to_did: "did:to".into(),
            endpoint_url: "http://example".into(),
            received_at_ms: 0,
            delay_milli: 0,
            expires_at: 0,
            retry_count: 0,
            hop_count: 0,
        };
        store
            .forward_queue_enqueue(&entry, 0)
            .await
            .expect("enqueue");

        let read = reader.await.expect("reader join");
        assert_eq!(read.len(), 1);
        assert_eq!(read[0].message, "delayed");
    }

    // ─── Streaming-state tests (task #17) ──────────────────────────────────

    #[tokio::test]
    async fn streaming_set_state_round_trip() {
        let dir = TempDir::new().expect("tempdir");
        let store = FjallStore::open(dir.path()).expect("open");
        let alice = hash("alice");

        // Registered (not yet live) — `is_client_live` only returns
        // a UUID when force_delivery is set.
        store
            .streaming_set_state(&alice, "uuid-1", StreamingClientState::Registered)
            .await
            .expect("register");
        assert!(
            store
                .streaming_is_client_live(&alice, false)
                .await
                .is_none()
        );
        assert_eq!(
            store.streaming_is_client_live(&alice, true).await,
            Some("uuid-1".to_string())
        );

        // Live — both branches return the UUID.
        store
            .streaming_set_state(&alice, "uuid-1", StreamingClientState::Live)
            .await
            .expect("live");
        assert_eq!(
            store.streaming_is_client_live(&alice, false).await,
            Some("uuid-1".to_string())
        );

        // Deregistered — entry is removed entirely.
        store
            .streaming_set_state(&alice, "uuid-1", StreamingClientState::Deregistered)
            .await
            .expect("deregister");
        assert!(store.streaming_is_client_live(&alice, true).await.is_none());
    }

    #[tokio::test]
    async fn streaming_clean_start_drops_only_matching_uuid() {
        let dir = TempDir::new().expect("tempdir");
        let store = FjallStore::open(dir.path()).expect("open");

        store
            .streaming_set_state(&hash("alice"), "uuid-1", StreamingClientState::Live)
            .await
            .expect("alice");
        store
            .streaming_set_state(&hash("bob"), "uuid-2", StreamingClientState::Live)
            .await
            .expect("bob");

        store.streaming_clean_start("uuid-1").await.expect("clean");

        // Alice's entry (uuid-1) is gone; Bob's (uuid-2) remains.
        assert!(
            store
                .streaming_is_client_live(&hash("alice"), true)
                .await
                .is_none()
        );
        assert_eq!(
            store.streaming_is_client_live(&hash("bob"), false).await,
            Some("uuid-2".to_string())
        );
    }

    #[tokio::test]
    async fn forward_queue_autoclaim_recovers_idle_entries() {
        let dir = TempDir::new().expect("tempdir");
        let store = FjallStore::open(dir.path()).expect("open");
        let entry = ForwardQueueEntry {
            stream_id: String::new(),
            message: "msg".into(),
            to_did_hash: hash("to"),
            from_did_hash: hash("from"),
            from_did: "did:from".into(),
            to_did: "did:to".into(),
            endpoint_url: "http://example".into(),
            received_at_ms: 0,
            delay_milli: 0,
            expires_at: 0,
            retry_count: 0,
            hop_count: 0,
        };
        let id = store
            .forward_queue_enqueue(&entry, 0)
            .await
            .expect("enqueue");

        // First consumer claims the entry but never acks.
        let read = store
            .forward_queue_read("g", "consumer-a", 10, Duration::from_millis(0))
            .await
            .expect("read");
        assert_eq!(read.len(), 1);

        // Wait long enough for the claim to look idle.
        tokio::time::sleep(Duration::from_millis(50)).await;

        let reclaimed = store
            .forward_queue_autoclaim("g", "consumer-b", Duration::from_millis(10), 10)
            .await
            .expect("autoclaim");
        assert_eq!(reclaimed.len(), 1);
        assert_eq!(reclaimed[0].stream_id, id);
    }

    #[tokio::test]
    async fn oob_invite_lifecycle() {
        let dir = TempDir::new().expect("tempdir");
        let store = FjallStore::open(dir.path()).expect("open");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let id = store
            .oob_discovery_store(&hash("alice"), "invite-data-base64", now + 60)
            .await
            .expect("store");
        let got = store
            .oob_discovery_get(&id)
            .await
            .expect("get")
            .expect("present");
        assert_eq!(got.0, "invite-data-base64");
        assert_eq!(got.1, hash("alice"));

        // Expired invites read as None and are auto-cleaned.
        let expired = store
            .oob_discovery_store(&hash("alice"), "old-data", now - 5)
            .await
            .expect("store-expired");
        assert!(store.oob_discovery_get(&expired).await.unwrap().is_none());

        // Explicit delete returns true once, false thereafter.
        assert!(store.oob_discovery_delete(&id).await.unwrap());
        assert!(!store.oob_discovery_delete(&id).await.unwrap());
    }
}
