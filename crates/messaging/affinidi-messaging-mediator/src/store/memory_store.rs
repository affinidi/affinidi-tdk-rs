//! In-memory [`MediatorStore`] implementation.
//!
//! All state lives behind a single `Arc<Mutex<MemoryState>>`. No disk
//! I/O. Sub-millisecond startup makes this the default backend for
//! `affinidi-messaging-test-mediator`.
//!
//! # Semantics matched against `RedisStore`
//!
//! - **Stream IDs**: `(timestamp_ms, sequence)` tuples internally,
//!   formatted as `{ms}-{seq}` on the wire (matches Redis stream IDs
//!   so SDK cursor handling is identical).
//! - **TTL**: native (Redis) and lazy (here). Sessions and OOB invites
//!   have an `expires_at` field; reads return `None` (or an error) for
//!   expired entries and remove them on access. A periodic external
//!   sweep is unnecessary — the store stays correct without one.
//! - **Atomicity**: every public method holds the inner mutex for the
//!   whole call, so composite ops (`store_message`, `delete_message`,
//!   `account_remove`) are atomic by construction.
//! - **Pub/sub**: in-process only via [`broadcast::channel`].
//!   `streaming_publish_message` calls succeed even with no
//!   subscribers — matching Redis' fire-and-forget `PUBLISH`.
//! - **Forward queue consumer groups**: each group tracks pending
//!   entries with claim timestamps so `forward_queue_autoclaim`
//!   re-delivers messages whose owning consumer has gone idle.

use crate::common::time::unix_timestamp_secs;
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
            MediatorACLExpanded, MediatorACLGetResponse, MediatorAccessListAddResponse,
            MediatorAccessListGetResponse, MediatorAccessListListResponse,
        },
        administration::{AdminAccount, MediatorAdminList},
    },
};
use async_trait::async_trait;
use sha256::digest;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{Mutex, Notify, broadcast};

const PUBSUB_BROADCAST_CAPACITY: usize = 1024;

// ─── Internal types ─────────────────────────────────────────────────────────

type StreamId = (u64, u64); // (timestamp_ms, sequence)

fn format_stream_id(id: StreamId) -> String {
    format!("{}-{}", id.0, id.1)
}

fn parse_stream_id(s: &str) -> Option<StreamId> {
    let (ms, seq) = s.split_once('-')?;
    Some((ms.parse().ok()?, seq.parse().ok()?))
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[derive(Clone, Debug)]
struct MessageRecord {
    body: String,
    bytes: usize,
    to_did_hash: String,
    from_did_hash: Option<String>,
    timestamp_ms: u128,
    /// Stream ID assigned to the inbox entry. Always present after
    /// `store_message`.
    receive_id: StreamId,
    /// Stream ID assigned to the sender's outbox, if non-anonymous.
    send_id: Option<StreamId>,
    /// Unix-seconds expiry; `0` means no expiry.
    expires_at: u64,
}

#[derive(Clone, Debug)]
struct StreamEntry {
    msg_id: String,
    bytes: usize,
    /// For inbox entries: the sender DID hash (or "ANONYMOUS").
    /// For outbox entries: the recipient DID hash.
    peer_did: String,
}

#[derive(Clone, Debug)]
struct AccountRecord {
    role: AccountType,
    acls: MediatorACLSet,
    send_queue_count: u32,
    send_queue_bytes: u64,
    receive_queue_count: u32,
    receive_queue_bytes: u64,
    queue_send_limit: Option<i32>,
    queue_receive_limit: Option<i32>,
}

impl Default for AccountRecord {
    fn default() -> Self {
        Self {
            role: AccountType::Standard,
            acls: MediatorACLSet::default(),
            send_queue_count: 0,
            send_queue_bytes: 0,
            receive_queue_count: 0,
            receive_queue_bytes: 0,
            queue_send_limit: None,
            queue_receive_limit: None,
        }
    }
}

impl AccountRecord {
    fn into_account(self, did_hash: String, access_list_count: u32) -> Account {
        Account {
            did_hash,
            acls: self.acls.to_u64(),
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

#[derive(Clone, Debug)]
struct SessionRecord {
    session: Session,
    /// Wall-clock instant when the session expires. Compared on every
    /// access; expired sessions are removed lazily.
    expires_at: Instant,
}

#[derive(Clone, Debug)]
struct OobInvite {
    invite_b64: String,
    did_hash: String,
    /// Unix-seconds expiry. Reads compare against `unix_timestamp_secs`
    /// and remove on expiry.
    expires_at: u64,
}

#[derive(Clone, Debug)]
struct PendingClaim {
    consumer: String,
    claimed_at: Instant,
    delivery_count: u32,
}

#[derive(Default, Debug)]
struct ConsumerGroupState {
    pending: BTreeMap<StreamId, PendingClaim>,
    /// Last stream ID delivered via `XREADGROUP >`. Reads with `>`
    /// return entries strictly greater than this.
    last_delivered: StreamId,
}

/// Internal state — guarded by [`MemoryStore`]'s outer `Mutex`.
#[derive(Default)]
struct MemoryState {
    // ─── Messages ───────────────────────────────────────────────────
    messages: HashMap<String, MessageRecord>,

    // ─── Streams (inbox/outbox) ─────────────────────────────────────
    inbox: HashMap<String, BTreeMap<StreamId, StreamEntry>>, // did_hash -> stream
    outbox: HashMap<String, BTreeMap<StreamId, StreamEntry>>,

    // ─── Expiry index ───────────────────────────────────────────────
    /// `expires_at_secs -> set of msg_ids`. Drained by
    /// `sweep_expired_messages`.
    expiry: BTreeMap<u64, HashSet<String>>,

    // ─── Sessions ───────────────────────────────────────────────────
    sessions: HashMap<String, SessionRecord>,

    // ─── Accounts / ACLs / Admins / Access lists ────────────────────
    accounts: HashMap<String, AccountRecord>,
    known_dids: Vec<String>, // ordered for cursor pagination
    access_lists: HashMap<String, Vec<String>>, // ordered for cursor pagination
    admins: HashSet<String>,

    // ─── OOB invitations ────────────────────────────────────────────
    oob_invites: HashMap<String, OobInvite>,

    // ─── Forward queue ──────────────────────────────────────────────
    forward_queue: BTreeMap<StreamId, ForwardQueueEntry>,
    forward_groups: HashMap<String, ConsumerGroupState>,

    // ─── Stats ──────────────────────────────────────────────────────
    counters: HashMap<&'static str, i64>,

    // ─── Live streaming client state ───────────────────────────────
    /// `did_hash -> (mediator_uuid, state)` — only one streaming
    /// session per DID is tracked.
    streaming_clients: HashMap<String, (String, StreamingClientState)>,

    // ─── Stream ID generation ──────────────────────────────────────
    last_stream_ms: u64,
    next_stream_seq: u64,
}

impl MemoryState {
    /// Allocate a fresh stream ID. Monotonic across calls; sequence
    /// resets when the millisecond advances.
    fn alloc_stream_id(&mut self) -> StreamId {
        let now = now_ms();
        if now > self.last_stream_ms {
            self.last_stream_ms = now;
            self.next_stream_seq = 0;
        } else {
            self.next_stream_seq += 1;
        }
        (self.last_stream_ms, self.next_stream_seq)
    }

    /// Record a message-id under its expiry timeslot. `expires_at = 0`
    /// is a no-op (messages without TTL aren't tracked).
    fn index_expiry(&mut self, expires_at: u64, msg_id: &str) {
        if expires_at == 0 {
            return;
        }
        self.expiry
            .entry(expires_at)
            .or_default()
            .insert(msg_id.to_string());
    }

    /// Remove a message-id from its expiry timeslot. Drops the
    /// timeslot entry once empty.
    fn unindex_expiry(&mut self, expires_at: u64, msg_id: &str) {
        if expires_at == 0 {
            return;
        }
        if let Some(set) = self.expiry.get_mut(&expires_at) {
            set.remove(msg_id);
            if set.is_empty() {
                self.expiry.remove(&expires_at);
            }
        }
    }

    /// Lazy session expiry — call before reading a session record.
    /// Returns `None` and removes the session if it's expired.
    fn get_session_record(&mut self, session_id: &str) -> Option<&mut SessionRecord> {
        let expired = self
            .sessions
            .get(session_id)
            .map(|r| r.expires_at <= Instant::now())
            .unwrap_or(false);
        if expired {
            self.sessions.remove(session_id);
            return None;
        }
        self.sessions.get_mut(session_id)
    }

    fn incr_counter(&mut self, key: &'static str, by: i64) {
        *self.counters.entry(key).or_insert(0) += by;
    }
}

// ─── Public type ────────────────────────────────────────────────────────────

/// In-memory [`MediatorStore`]. Cheap to clone (`Arc` internally).
pub struct MemoryStore {
    state: Arc<Mutex<MemoryState>>,
    broadcast_channels: Arc<Mutex<HashMap<String, broadcast::Sender<PubSubRecord>>>>,
    forward_notify: Arc<Notify>,
}

impl MemoryStore {
    /// Construct an empty in-memory store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self {
            state: Arc::new(Mutex::new(MemoryState::default())),
            broadcast_channels: Arc::new(Mutex::new(HashMap::new())),
            forward_notify: Arc::new(Notify::new()),
        }
    }
}

impl Clone for MemoryStore {
    fn clone(&self) -> Self {
        Self {
            state: Arc::clone(&self.state),
            broadcast_channels: Arc::clone(&self.broadcast_channels),
            forward_notify: Arc::clone(&self.forward_notify),
        }
    }
}

impl std::fmt::Debug for MemoryStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryStore").finish_non_exhaustive()
    }
}

// ─── Counter name mapping (matches Redis GLOBAL field names) ────────────────

fn counter_key(c: StatCounter) -> &'static str {
    match c {
        StatCounter::SentBytes => "SENT_BYTES",
        StatCounter::SentCount => "SENT_COUNT",
        StatCounter::WebsocketOpen => "WEBSOCKET_OPEN",
        StatCounter::WebsocketClose => "WEBSOCKET_CLOSE",
        StatCounter::SessionsCreated => "SESSIONS_CREATED",
        StatCounter::SessionsSuccess => "SESSIONS_SUCCESS",
        StatCounter::OobInvitesCreated => "OOB_INVITES_CREATED",
        StatCounter::OobInvitesClaimed => "OOB_INVITES_CLAIMED",
    }
}

// ─── MediatorStore impl ─────────────────────────────────────────────────────

#[async_trait]
impl MediatorStore for MemoryStore {
    // ─── Bootstrap & health ─────────────────────────────────────────────────

    async fn initialize(&self) -> Result<(), MediatorError> {
        Ok(())
    }

    async fn health(&self) -> StoreHealth {
        StoreHealth::Healthy
    }

    async fn shutdown(&self) -> Result<(), MediatorError> {
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
        let ts_ms = now_ms() as u128;
        let from = from_hash.unwrap_or("ANONYMOUS").to_string();

        let mut state = self.state.lock().await;

        // Allocate stream IDs first so we can record them on the
        // MessageRecord below.
        let receive_id = state.alloc_stream_id();
        let send_id = if from != "ANONYMOUS" {
            Some(state.alloc_stream_id())
        } else {
            None
        };

        // Inbox entry for the recipient.
        state
            .inbox
            .entry(to_did_hash.to_string())
            .or_default()
            .insert(
                receive_id,
                StreamEntry {
                    msg_id: msg_id.clone(),
                    bytes,
                    peer_did: from.clone(),
                },
            );

        // Outbox entry for the sender (if non-anonymous).
        if let Some(sid) = send_id {
            state.outbox.entry(from.clone()).or_default().insert(
                sid,
                StreamEntry {
                    msg_id: msg_id.clone(),
                    bytes,
                    peer_did: to_did_hash.to_string(),
                },
            );
            // Sender's account counter
            let sender = state.accounts.entry(from.clone()).or_default();
            sender.send_queue_count = sender.send_queue_count.saturating_add(1);
            sender.send_queue_bytes = sender.send_queue_bytes.saturating_add(bytes as u64);
        }

        // Recipient's account counter
        let recv = state.accounts.entry(to_did_hash.to_string()).or_default();
        recv.receive_queue_count = recv.receive_queue_count.saturating_add(1);
        recv.receive_queue_bytes = recv.receive_queue_bytes.saturating_add(bytes as u64);

        // Global received counters
        state.incr_counter("RECEIVED_BYTES", bytes as i64);
        state.incr_counter("RECEIVED_COUNT", 1);

        // Expiry index
        state.index_expiry(expires_at, &msg_id);

        // Body + metadata
        state.messages.insert(
            msg_id.clone(),
            MessageRecord {
                body: message.to_string(),
                bytes,
                to_did_hash: to_did_hash.to_string(),
                from_did_hash: if from == "ANONYMOUS" {
                    None
                } else {
                    Some(from)
                },
                timestamp_ms: ts_ms,
                receive_id,
                send_id,
                expires_at,
            },
        );

        Ok(msg_id)
    }

    async fn delete_message(
        &self,
        message_hash: &str,
        by: DeletionAuthority,
    ) -> Result<(), MediatorError> {
        let mut state = self.state.lock().await;

        let record = state.messages.get(message_hash).cloned().ok_or_else(|| {
            MediatorError::InternalError(
                404,
                "memory".into(),
                format!("NOT_FOUND: message_hash ({message_hash})"),
            )
        })?;

        // Authorisation. Owner must be TO or FROM. Admin bypasses.
        let permitted = match &by {
            DeletionAuthority::Admin { .. } => true,
            DeletionAuthority::Owner { did_hash } => {
                did_hash == &record.to_did_hash
                    || record
                        .from_did_hash
                        .as_deref()
                        .map(|f| f == did_hash)
                        .unwrap_or(false)
            }
        };
        if !permitted {
            return Err(MediatorError::InternalError(
                403,
                "memory".into(),
                "PERMISSION_DENIED: requesting DID does not own this message".into(),
            ));
        }

        // Stream entries
        if let Some(stream) = state.inbox.get_mut(&record.to_did_hash) {
            stream.remove(&record.receive_id);
        }
        if let (Some(from), Some(sid)) = (record.from_did_hash.as_ref(), record.send_id) {
            if let Some(stream) = state.outbox.get_mut(from) {
                stream.remove(&sid);
            }
            // Sender account counters
            if let Some(sender) = state.accounts.get_mut(from) {
                sender.send_queue_count = sender.send_queue_count.saturating_sub(1);
                sender.send_queue_bytes =
                    sender.send_queue_bytes.saturating_sub(record.bytes as u64);
            }
        }

        // Recipient account counters
        if let Some(recv) = state.accounts.get_mut(&record.to_did_hash) {
            recv.receive_queue_count = recv.receive_queue_count.saturating_sub(1);
            recv.receive_queue_bytes = recv.receive_queue_bytes.saturating_sub(record.bytes as u64);
        }

        // Expiry index
        state.unindex_expiry(record.expires_at, message_hash);

        // Counters + body
        state.incr_counter("DELETED_BYTES", record.bytes as i64);
        state.incr_counter("DELETED_COUNT", 1);
        state.messages.remove(message_hash);

        Ok(())
    }

    async fn get_message(
        &self,
        did_hash: &str,
        msg_id: &str,
    ) -> Result<Option<MessageListElement>, MediatorError> {
        let state = self.state.lock().await;
        let Some(record) = state.messages.get(msg_id) else {
            return Ok(None);
        };

        // Owner check (timing-safe enough for in-memory).
        let is_to = did_hash == record.to_did_hash;
        let is_from = record
            .from_did_hash
            .as_deref()
            .map(|f| f == did_hash)
            .unwrap_or(false);
        if !is_to && !is_from {
            return Ok(None);
        }

        Ok(Some(MessageListElement {
            msg_id: msg_id.to_string(),
            send_id: record.send_id.map(format_stream_id),
            receive_id: Some(format_stream_id(record.receive_id)),
            size: record.bytes as u64,
            timestamp: record.timestamp_ms as u64,
            to_address: Some(record.to_did_hash.clone()),
            from_address: record.from_did_hash.clone(),
            msg: Some(record.body.clone()),
        }))
    }

    async fn get_message_metadata(
        &self,
        session_id: &str,
        message_hash: &str,
    ) -> Result<MessageMetaData, MediatorError> {
        let state = self.state.lock().await;
        let record = state.messages.get(message_hash).ok_or_else(|| {
            MediatorError::DatabaseError(
                14,
                session_id.into(),
                format!("Message metadata not found for {message_hash}"),
            )
        })?;
        Ok(MessageMetaData {
            bytes: record.bytes,
            to_did_hash: record.to_did_hash.clone(),
            from_did_hash: record.from_did_hash.clone(),
            timestamp: record.timestamp_ms,
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
        let state = self.state.lock().await;
        let stream = match folder {
            Folder::Inbox => state.inbox.get(did_hash),
            Folder::Outbox => state.outbox.get(did_hash),
        };
        let Some(stream) = stream else {
            return Ok(Vec::new());
        };

        let (start, end) = range.unwrap_or(("-", "+"));
        let start_id = if start == "-" {
            (0, 0)
        } else {
            parse_stream_id(start).unwrap_or((0, 0))
        };
        let end_id = if end == "+" {
            (u64::MAX, u64::MAX)
        } else {
            parse_stream_id(end).unwrap_or((u64::MAX, u64::MAX))
        };

        let mut out = Vec::new();
        for (sid, entry) in stream.range(start_id..=end_id).take(limit as usize) {
            let mut element = MessageListElement {
                msg_id: entry.msg_id.clone(),
                size: entry.bytes as u64,
                timestamp: sid.0,
                ..Default::default()
            };
            match folder {
                Folder::Inbox => {
                    element.receive_id = Some(format_stream_id(*sid));
                    element.from_address = Some(entry.peer_did.clone());
                }
                Folder::Outbox => {
                    element.send_id = Some(format_stream_id(*sid));
                    element.to_address = Some(entry.peer_did.clone());
                }
            }
            out.push(element);
        }
        Ok(out)
    }

    async fn fetch_messages(
        &self,
        session_id: &str,
        did_hash: &str,
        options: &FetchOptions,
    ) -> Result<GetMessagesResponse, MediatorError> {
        // List inbox entries past the cursor, then fetch bodies and
        // (optionally) delete. Mirrors RedisStore + the `fetch_messages`
        // Lua function.
        let start = options
            .start_id
            .as_deref()
            .and_then(|s| parse_stream_id(s).map(|id| (id.0, id.1)));
        let limit = options.limit;
        let optimistic_delete = matches!(options.delete_policy, FetchDeletePolicy::Optimistic);

        let mut response = GetMessagesResponse::default();

        // Snapshot the relevant entries under the lock, then operate
        // outside it for the optional delete loop.
        let entries: Vec<(StreamId, StreamEntry)> = {
            let state = self.state.lock().await;
            let Some(stream) = state.inbox.get(did_hash) else {
                return Ok(response);
            };
            let lower = match start {
                // Exclusive of start_id: skip entries equal to it.
                Some(id) => std::ops::Bound::Excluded(id),
                None => std::ops::Bound::Unbounded,
            };
            stream
                .range((lower, std::ops::Bound::Unbounded))
                .take(limit)
                .map(|(k, v)| (*k, v.clone()))
                .collect()
        };

        for (sid, entry) in &entries {
            let body = {
                let state = self.state.lock().await;
                state.messages.get(&entry.msg_id).map(|r| r.body.clone())
            };
            let mut element = MessageListElement {
                msg_id: entry.msg_id.clone(),
                receive_id: Some(format_stream_id(*sid)),
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
        let _ = session_id;
        Ok(response)
    }

    async fn purge_folder(
        &self,
        _session_id: &str,
        did_hash: &str,
        folder: Folder,
    ) -> Result<(usize, usize), MediatorError> {
        // Snapshot the message IDs in the folder under the lock, then
        // call delete_message on each (which re-acquires the lock).
        let msg_ids: Vec<String> = {
            let state = self.state.lock().await;
            let stream = match folder {
                Folder::Inbox => state.inbox.get(did_hash),
                Folder::Outbox => state.outbox.get(did_hash),
            };
            stream
                .map(|s| s.values().map(|e| e.msg_id.clone()).collect())
                .unwrap_or_default()
        };

        let mut count = 0;
        let mut bytes = 0;
        for msg_id in msg_ids {
            // Owner-authority delete; respects ownership semantics.
            let bytes_before = {
                let state = self.state.lock().await;
                state.messages.get(&msg_id).map(|r| r.bytes).unwrap_or(0)
            };
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

        // Drop the (now-empty) stream key.
        self.delete_folder_stream(_session_id, did_hash, folder)
            .await?;
        Ok((count, bytes))
    }

    async fn delete_folder_stream(
        &self,
        _session_id: &str,
        did_hash: &str,
        folder: Folder,
    ) -> Result<(), MediatorError> {
        let mut state = self.state.lock().await;
        match folder {
            Folder::Inbox => {
                state.inbox.remove(did_hash);
            }
            Folder::Outbox => {
                state.outbox.remove(did_hash);
            }
        }
        Ok(())
    }

    async fn inbox_status(&self, did_hash: &str) -> Result<InboxStatusReply, MediatorError> {
        let state = self.state.lock().await;
        let mut reply = InboxStatusReply {
            recipient_did: did_hash.to_string(),
            ..Default::default()
        };
        if let Some(stream) = state.inbox.get(did_hash) {
            reply.queue_count = stream.len() as u64;
            if let Some((first, _)) = stream.iter().next() {
                reply.oldest_received = format_stream_id(*first);
            }
            if let Some((last, _)) = stream.iter().next_back() {
                reply.newest_received = format_stream_id(*last);
            }
        }
        if let Some(account) = state.accounts.get(did_hash) {
            reply.message_count = account.receive_queue_count as u64;
            reply.total_bytes = account.receive_queue_bytes;
        }
        if let Some((_, st)) = state.streaming_clients.get(did_hash) {
            reply.live_delivery = matches!(st, StreamingClientState::Live);
        }
        Ok(reply)
    }

    // ─── Sessions ───────────────────────────────────────────────────────────

    async fn put_session(&self, session: &Session, ttl: Duration) -> Result<(), MediatorError> {
        let mut state = self.state.lock().await;
        state.sessions.insert(
            session.session_id.clone(),
            SessionRecord {
                session: session.clone(),
                expires_at: Instant::now() + ttl,
            },
        );
        Ok(())
    }

    async fn get_session(&self, session_id: &str, did: &str) -> Result<Session, MediatorError> {
        let mut state = self.state.lock().await;
        let record = state.get_session_record(session_id).ok_or_else(|| {
            MediatorError::SessionError(
                14,
                session_id.into(),
                format!("Session not found: {session_id}"),
            )
        })?;
        let mut session = record.session.clone();

        // Join with account for ACLs/role (matches Redis path).
        if !did.is_empty() {
            let did_hash = digest(did);
            if let Some(account) = state.accounts.get(&did_hash) {
                session.acls = account.acls.clone();
                session.account_type = account.role;
            }
        }
        Ok(session)
    }

    async fn delete_session(&self, session_id: &str) -> Result<(), MediatorError> {
        let mut state = self.state.lock().await;
        state.sessions.remove(session_id);
        Ok(())
    }

    // ─── Accounts ───────────────────────────────────────────────────────────

    async fn account_exists(&self, did_hash: &str) -> Result<bool, MediatorError> {
        Ok(self.state.lock().await.accounts.contains_key(did_hash))
    }

    async fn account_get(&self, did_hash: &str) -> Result<Option<Account>, MediatorError> {
        let state = self.state.lock().await;
        let Some(record) = state.accounts.get(did_hash).cloned() else {
            return Ok(None);
        };
        let access_list_count = state
            .access_lists
            .get(did_hash)
            .map(|v| v.len() as u32)
            .unwrap_or(0);
        Ok(Some(
            record.into_account(did_hash.to_string(), access_list_count),
        ))
    }

    async fn account_add(
        &self,
        did_hash: &str,
        acls: &MediatorACLSet,
        queue_limit: Option<u32>,
    ) -> Result<Account, MediatorError> {
        let mut state = self.state.lock().await;
        if !state.known_dids.iter().any(|d| d == did_hash) {
            state.known_dids.push(did_hash.to_string());
        }
        let mut record = AccountRecord::default();
        record.acls = acls.clone();
        if let Some(limit) = queue_limit {
            record.queue_send_limit = Some(limit as i32);
            record.queue_receive_limit = Some(limit as i32);
        }
        state.accounts.insert(did_hash.to_string(), record.clone());
        Ok(record.into_account(did_hash.to_string(), 0))
    }

    async fn account_remove(
        &self,
        _session: &Session,
        did_hash: &str,
    ) -> Result<bool, MediatorError> {
        // Block protected accounts up-front.
        {
            let state = self.state.lock().await;
            if let Some(record) = state.accounts.get(did_hash)
                && (record.role == AccountType::Mediator || record.role == AccountType::RootAdmin)
            {
                return Err(MediatorError::InternalError(
                    18,
                    "memory".into(),
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

        // Drop the account, admin set membership, and known-DIDs entry.
        let mut state = self.state.lock().await;
        state.accounts.remove(did_hash);
        state.access_lists.remove(did_hash);
        state.admins.remove(did_hash);
        state.known_dids.retain(|d| d != did_hash);
        Ok(true)
    }

    async fn account_list(
        &self,
        cursor: u32,
        limit: u32,
    ) -> Result<MediatorAccountList, MediatorError> {
        let limit = limit.min(100) as usize;
        let state = self.state.lock().await;
        let dids: Vec<String> = state
            .known_dids
            .iter()
            .skip(cursor as usize)
            .take(limit)
            .cloned()
            .collect();
        let next_cursor = if cursor as usize + dids.len() >= state.known_dids.len() {
            0
        } else {
            cursor + dids.len() as u32
        };
        let mut accounts = Vec::with_capacity(dids.len());
        for did in &dids {
            if let Some(record) = state.accounts.get(did) {
                let count = state
                    .access_lists
                    .get(did)
                    .map(|v| v.len() as u32)
                    .unwrap_or(0);
                accounts.push(record.clone().into_account(did.clone(), count));
            }
        }
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
        let mut state = self.state.lock().await;
        let record = state.accounts.entry(did_hash.to_string()).or_default();
        record.role = *account_type;
        if account_type.is_admin() {
            state.admins.insert(did_hash.to_string());
        } else {
            state.admins.remove(did_hash);
        }
        Ok(())
    }

    async fn account_change_queue_limits(
        &self,
        did_hash: &str,
        send_queue_limit: Option<i32>,
        receive_queue_limit: Option<i32>,
    ) -> Result<(), MediatorError> {
        let mut state = self.state.lock().await;
        let record = state.accounts.entry(did_hash.to_string()).or_default();
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
        Ok(())
    }

    // ─── ACLs ───────────────────────────────────────────────────────────────

    async fn set_did_acl(
        &self,
        did_hash: &str,
        acls: &MediatorACLSet,
    ) -> Result<MediatorACLSet, MediatorError> {
        let mut state = self.state.lock().await;
        let record = state.accounts.entry(did_hash.to_string()).or_default();
        record.acls = acls.clone();
        Ok(acls.clone())
    }

    async fn get_did_acl(&self, did_hash: &str) -> Result<Option<MediatorACLSet>, MediatorError> {
        let state = self.state.lock().await;
        Ok(state.accounts.get(did_hash).map(|r| r.acls.clone()))
    }

    async fn get_did_acls(
        &self,
        dids: &[String],
        mediator_acl_mode: AccessListModeType,
    ) -> Result<MediatorACLGetResponse, MediatorError> {
        if dids.len() > 100 {
            return Err(MediatorError::DatabaseError(
                27,
                "memory".into(),
                "# of DIDs cannot exceed 100".into(),
            ));
        }
        let state = self.state.lock().await;
        let mut response = MediatorACLGetResponse {
            acl_response: Vec::with_capacity(dids.len()),
            mediator_acl_mode,
        };
        for did in dids {
            if let Some(record) = state.accounts.get(did) {
                response.acl_response.push(MediatorACLExpanded {
                    did_hash: did.clone(),
                    acl_value: record.acls.to_hex_string(),
                    acls: record.acls.clone(),
                });
            }
        }
        Ok(response)
    }

    async fn access_list_allowed(&self, to_hash: &str, from_hash: Option<&str>) -> bool {
        let state = self.state.lock().await;
        let Some(account) = state.accounts.get(to_hash) else {
            return false;
        };
        match from_hash {
            Some(from) => {
                let in_list = state
                    .access_lists
                    .get(to_hash)
                    .map(|v| v.iter().any(|d| d == from))
                    .unwrap_or(false);
                match account.acls.get_access_list_mode().0 {
                    AccessListModeType::ExplicitAllow => in_list,
                    AccessListModeType::ExplicitDeny => !in_list,
                }
            }
            None => account.acls.get_anon_receive().0,
        }
    }

    async fn access_list_list(
        &self,
        did_hash: &str,
        cursor: u64,
    ) -> Result<MediatorAccessListListResponse, MediatorError> {
        let state = self.state.lock().await;
        let list = state.access_lists.get(did_hash);
        let entries: Vec<String> = list
            .map(|v| v.iter().skip(cursor as usize).take(100).cloned().collect())
            .unwrap_or_default();
        let next = list
            .map(|v| {
                if (cursor as usize) + entries.len() >= v.len() {
                    None
                } else {
                    Some(cursor + entries.len() as u64)
                }
            })
            .unwrap_or(None);
        Ok(MediatorAccessListListResponse {
            cursor: next,
            did_hashes: entries,
        })
    }

    async fn access_list_count(&self, did_hash: &str) -> Result<usize, MediatorError> {
        Ok(self
            .state
            .lock()
            .await
            .access_lists
            .get(did_hash)
            .map(|v| v.len())
            .unwrap_or(0))
    }

    async fn access_list_add(
        &self,
        access_list_limit: usize,
        did_hash: &str,
        hashes: &Vec<String>,
    ) -> Result<MediatorAccessListAddResponse, MediatorError> {
        let mut state = self.state.lock().await;
        let list = state.access_lists.entry(did_hash.to_string()).or_default();
        let current = list.len();
        let mut truncated = false;
        let to_add: Vec<String> = if current + hashes.len() > access_list_limit {
            truncated = true;
            let allowed = access_list_limit.saturating_sub(current);
            hashes.iter().take(allowed).cloned().collect()
        } else {
            hashes.clone()
        };
        for h in &to_add {
            if !list.iter().any(|d| d == h) {
                list.push(h.clone());
            }
        }
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
        let mut state = self.state.lock().await;
        let Some(list) = state.access_lists.get_mut(did_hash) else {
            return Ok(0);
        };
        let before = list.len();
        list.retain(|d| !hashes.contains(d));
        Ok(before - list.len())
    }

    async fn access_list_clear(&self, did_hash: &str) -> Result<(), MediatorError> {
        self.state.lock().await.access_lists.remove(did_hash);
        Ok(())
    }

    async fn access_list_get(
        &self,
        did_hash: &str,
        hashes: &Vec<String>,
    ) -> Result<MediatorAccessListGetResponse, MediatorError> {
        let state = self.state.lock().await;
        let list = state.access_lists.get(did_hash);
        let did_hashes = match list {
            Some(v) => hashes
                .iter()
                .filter(|h| v.iter().any(|d| &d == h))
                .cloned()
                .collect(),
            None => Vec::new(),
        };
        Ok(MediatorAccessListGetResponse { did_hashes })
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
        let mut state = self.state.lock().await;
        if let Some(record) = state.accounts.get_mut(admin_did_hash) {
            record.role = admin_type;
        }
        state.admins.insert(admin_did_hash.to_string());
        Ok(())
    }

    async fn check_admin_account(&self, did_hash: &str) -> Result<bool, MediatorError> {
        let state = self.state.lock().await;
        if !state.admins.contains(did_hash) {
            return Ok(false);
        }
        let role = state.accounts.get(did_hash).map(|r| r.role);
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
        let state = self.state.lock().await;
        let mut admin_dids: Vec<String> = state.admins.iter().cloned().collect();
        admin_dids.sort();
        let page: Vec<String> = admin_dids
            .iter()
            .skip(cursor as usize)
            .take(limit)
            .cloned()
            .collect();
        let next = if cursor as usize + page.len() >= admin_dids.len() {
            0
        } else {
            cursor + page.len() as u32
        };
        let mut accounts = Vec::with_capacity(page.len());
        for did in &page {
            let role = state
                .accounts
                .get(did)
                .map(|r| r.role)
                .unwrap_or(AccountType::Unknown);
            accounts.push(AdminAccount {
                did_hash: did.clone(),
                _type: role,
            });
        }
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
        let mut state = self.state.lock().await;
        state.oob_invites.insert(
            invite_hash.clone(),
            OobInvite {
                invite_b64: invite_b64.to_string(),
                did_hash: did_hash.to_string(),
                expires_at,
            },
        );
        state.incr_counter("OOB_INVITES_CREATED", 1);
        Ok(invite_hash)
    }

    async fn oob_discovery_get(
        &self,
        oob_id: &str,
    ) -> Result<Option<(String, String)>, MediatorError> {
        let now = unix_timestamp_secs();
        let mut state = self.state.lock().await;
        let invite = match state.oob_invites.get(oob_id) {
            Some(i) if i.expires_at == 0 || i.expires_at > now => {
                Some((i.invite_b64.clone(), i.did_hash.clone()))
            }
            Some(_) => {
                // Expired — remove and return None.
                state.oob_invites.remove(oob_id);
                None
            }
            None => None,
        };
        if invite.is_some() {
            state.incr_counter("OOB_INVITES_CLAIMED", 1);
        }
        Ok(invite)
    }

    async fn oob_discovery_delete(&self, oob_id: &str) -> Result<bool, MediatorError> {
        Ok(self.state.lock().await.oob_invites.remove(oob_id).is_some())
    }

    // ─── Stats / counters ───────────────────────────────────────────────────

    async fn get_global_stats(&self) -> Result<MetadataStats, MediatorError> {
        let state = self.state.lock().await;
        let read = |key: &str| state.counters.get(key).copied().unwrap_or(0);
        Ok(MetadataStats {
            received_bytes: read("RECEIVED_BYTES"),
            sent_bytes: read("SENT_BYTES"),
            deleted_bytes: read("DELETED_BYTES"),
            received_count: read("RECEIVED_COUNT"),
            sent_count: read("SENT_COUNT"),
            deleted_count: read("DELETED_COUNT"),
            websocket_open: read("WEBSOCKET_OPEN"),
            websocket_close: read("WEBSOCKET_CLOSE"),
            sessions_created: read("SESSIONS_CREATED"),
            sessions_success: read("SESSIONS_SUCCESS"),
            oob_invites_created: read("OOB_INVITES_CREATED"),
            oob_invites_claimed: read("OOB_INVITES_CLAIMED"),
        })
    }

    async fn stats_increment(&self, counter: StatCounter, by: i64) -> Result<(), MediatorError> {
        self.state
            .lock()
            .await
            .incr_counter(counter_key(counter), by);
        Ok(())
    }

    // ─── Forwarding queue ───────────────────────────────────────────────────

    async fn forward_queue_enqueue(
        &self,
        entry: &ForwardQueueEntry,
        max_len: usize,
    ) -> Result<String, MediatorError> {
        let mut state = self.state.lock().await;
        let id = state.alloc_stream_id();
        let mut entry = entry.clone();
        entry.stream_id = format_stream_id(id);
        state.forward_queue.insert(id, entry);

        // Approximate max_len trim: drop oldest entries if over.
        if max_len > 0 {
            while state.forward_queue.len() > max_len {
                let Some((&first, _)) = state.forward_queue.iter().next() else {
                    break;
                };
                state.forward_queue.remove(&first);
            }
        }
        let stream_id = format_stream_id(id);
        drop(state);
        self.forward_notify.notify_waiters();
        Ok(stream_id)
    }

    async fn forward_queue_len(&self) -> Result<usize, MediatorError> {
        Ok(self.state.lock().await.forward_queue.len())
    }

    async fn forward_queue_read(
        &self,
        group_name: &str,
        consumer_name: &str,
        count: usize,
        block: Duration,
    ) -> Result<Vec<ForwardQueueEntry>, MediatorError> {
        // Inline read attempt: returns entries strictly greater than
        // the group's `last_delivered`. If empty and `block > 0`, wait
        // on `forward_notify` for a single notification (or timeout)
        // and try again.
        let try_read = || async {
            let mut state = self.state.lock().await;
            let group = state
                .forward_groups
                .entry(group_name.to_string())
                .or_default();
            let after = group.last_delivered;
            let candidates: Vec<(StreamId, ForwardQueueEntry)> = state
                .forward_queue
                .range((std::ops::Bound::Excluded(after), std::ops::Bound::Unbounded))
                .take(count)
                .map(|(k, v)| (*k, v.clone()))
                .collect();
            let claimed_at = Instant::now();
            for (id, _entry) in &candidates {
                let group = state
                    .forward_groups
                    .entry(group_name.to_string())
                    .or_default();
                group.pending.insert(
                    *id,
                    PendingClaim {
                        consumer: consumer_name.to_string(),
                        claimed_at,
                        delivery_count: 1,
                    },
                );
                if *id > group.last_delivered {
                    group.last_delivered = *id;
                }
            }
            candidates
                .into_iter()
                .map(|(_, entry)| entry)
                .collect::<Vec<_>>()
        };

        let initial = try_read().await;
        if !initial.is_empty() || block.is_zero() {
            return Ok(initial);
        }

        // Block for new entries (or timeout).
        let _ = tokio::time::timeout(block, self.forward_notify.notified()).await;
        Ok(try_read().await)
    }

    async fn forward_queue_ack(
        &self,
        group_name: &str,
        stream_ids: &[&str],
    ) -> Result<(), MediatorError> {
        let mut state = self.state.lock().await;
        let Some(group) = state.forward_groups.get_mut(group_name) else {
            return Ok(());
        };
        for id in stream_ids {
            if let Some(parsed) = parse_stream_id(id) {
                group.pending.remove(&parsed);
            }
        }
        Ok(())
    }

    async fn forward_queue_delete(&self, stream_ids: &[&str]) -> Result<(), MediatorError> {
        let mut state = self.state.lock().await;
        for id in stream_ids {
            if let Some(parsed) = parse_stream_id(id) {
                state.forward_queue.remove(&parsed);
            }
        }
        Ok(())
    }

    async fn forward_queue_autoclaim(
        &self,
        group_name: &str,
        consumer_name: &str,
        min_idle: Duration,
        count: usize,
    ) -> Result<Vec<ForwardQueueEntry>, MediatorError> {
        let now = Instant::now();
        let mut state = self.state.lock().await;
        // Snapshot stale entries first to avoid borrow conflicts.
        let stale_ids: Vec<StreamId> = state
            .forward_groups
            .get(group_name)
            .map(|g| {
                g.pending
                    .iter()
                    .filter(|(_, claim)| now.duration_since(claim.claimed_at) >= min_idle)
                    .map(|(id, _)| *id)
                    .take(count)
                    .collect()
            })
            .unwrap_or_default();
        let mut out = Vec::with_capacity(stale_ids.len());
        for id in stale_ids {
            if let Some(group) = state.forward_groups.get_mut(group_name)
                && let Some(claim) = group.pending.get_mut(&id)
            {
                claim.consumer = consumer_name.to_string();
                claim.claimed_at = now;
                claim.delivery_count += 1;
            }
            if let Some(entry) = state.forward_queue.get(&id) {
                out.push(entry.clone());
            }
        }
        Ok(out)
    }

    // ─── Live streaming (WebSocket pub/sub) ─────────────────────────────────

    async fn streaming_clean_start(&self, mediator_uuid: &str) -> Result<(), MediatorError> {
        let mut state = self.state.lock().await;
        state
            .streaming_clients
            .retain(|_, (uuid, _)| uuid != mediator_uuid);
        Ok(())
    }

    async fn streaming_set_state(
        &self,
        did_hash: &str,
        mediator_uuid: &str,
        state: StreamingClientState,
    ) -> Result<(), MediatorError> {
        let mut s = self.state.lock().await;
        match state {
            StreamingClientState::Deregistered => {
                s.streaming_clients.remove(did_hash);
            }
            other => {
                s.streaming_clients
                    .insert(did_hash.to_string(), (mediator_uuid.to_string(), other));
            }
        }
        Ok(())
    }

    async fn streaming_is_client_live(
        &self,
        did_hash: &str,
        force_delivery: bool,
    ) -> Option<String> {
        let state = self.state.lock().await;
        let (uuid, current) = state.streaming_clients.get(did_hash)?;
        match current {
            StreamingClientState::Live => Some(uuid.clone()),
            StreamingClientState::Registered if force_delivery => Some(uuid.clone()),
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
        // Snapshot due timeslot keys + their message ids under the
        // lock, then call delete_message for each.
        let due: Vec<(u64, Vec<String>)> = {
            let state = self.state.lock().await;
            state
                .expiry
                .range(..=now_secs)
                .map(|(ts, ids)| (*ts, ids.iter().cloned().collect()))
                .collect()
        };

        let mut report = ExpiryReport {
            timeslots_swept: due.len() as u32,
            ..Default::default()
        };
        for (ts, ids) in due {
            for msg_id in ids {
                let result = self
                    .delete_message(
                        &msg_id,
                        DeletionAuthority::Admin {
                            admin_did_hash: admin_did_hash.to_string(),
                        },
                    )
                    .await;
                match result {
                    Ok(_) => report.expired += 1,
                    Err(_) => report.already_deleted += 1,
                }
            }
            // Drop the (now-empty) timeslot.
            let mut state = self.state.lock().await;
            state.expiry.remove(&ts);
        }
        Ok(report)
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_messaging_mediator_common::store::SessionState;

    #[tokio::test]
    async fn lifecycle_round_trip() {
        let store = MemoryStore::new();
        store.initialize().await.expect("initialize");
        assert!(matches!(store.health().await, StoreHealth::Healthy));
        store.shutdown().await.expect("shutdown");
    }

    #[tokio::test]
    async fn store_and_fetch_message_round_trip() {
        let store = MemoryStore::new();
        let to = "alice_hash";
        let from = "bob_hash";

        let msg_id = store
            .store_message("session-1", "hello", to, Some(from), 0, 0)
            .await
            .expect("store");

        // Owner can fetch.
        let got = store
            .get_message(to, &msg_id)
            .await
            .expect("get")
            .expect("message present");
        assert_eq!(got.msg.as_deref(), Some("hello"));
        assert_eq!(got.to_address.as_deref(), Some(to));
        assert_eq!(got.from_address.as_deref(), Some(from));

        // Non-owner sees None (security).
        let none = store
            .get_message("eve_hash", &msg_id)
            .await
            .expect("get for non-owner");
        assert!(none.is_none());

        // Inbox listing returns the entry.
        let list = store
            .list_messages(to, Folder::Inbox, None, 100)
            .await
            .expect("list");
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].msg_id, msg_id);
        assert_eq!(list[0].from_address.as_deref(), Some(from));

        // Delete by owner clears stream + body.
        store
            .delete_message(
                &msg_id,
                DeletionAuthority::Owner {
                    did_hash: to.to_string(),
                },
            )
            .await
            .expect("delete");
        let after_list = store
            .list_messages(to, Folder::Inbox, None, 100)
            .await
            .expect("list after delete");
        assert!(after_list.is_empty());
    }

    #[tokio::test]
    async fn delete_rejects_non_owner_non_admin() {
        let store = MemoryStore::new();
        let msg_id = store
            .store_message("s", "hi", "alice", Some("bob"), 0, 0)
            .await
            .expect("store");
        let err = store
            .delete_message(
                &msg_id,
                DeletionAuthority::Owner {
                    did_hash: "eve".into(),
                },
            )
            .await
            .expect_err("non-owner delete must fail");
        assert!(format!("{err}").contains("PERMISSION_DENIED"));
    }

    #[tokio::test]
    async fn admin_authority_bypasses_ownership() {
        let store = MemoryStore::new();
        let msg_id = store
            .store_message("s", "hi", "alice", Some("bob"), 0, 0)
            .await
            .expect("store");
        store
            .delete_message(
                &msg_id,
                DeletionAuthority::Admin {
                    admin_did_hash: "admin".into(),
                },
            )
            .await
            .expect("admin delete");
    }

    #[tokio::test]
    async fn fetch_messages_with_optimistic_delete() {
        let store = MemoryStore::new();
        for i in 0..5 {
            store
                .store_message("s", &format!("msg-{i}"), "alice", Some("bob"), 0, 0)
                .await
                .expect("store");
        }
        let resp = store
            .fetch_messages(
                "s",
                "alice",
                &FetchOptions {
                    limit: 100,
                    delete_policy: FetchDeletePolicy::Optimistic,
                    ..Default::default()
                },
            )
            .await
            .expect("fetch");
        assert_eq!(resp.success.len(), 5);
        // Inbox should be empty after optimistic delete.
        let after = store
            .list_messages("alice", Folder::Inbox, None, 100)
            .await
            .expect("list");
        assert!(after.is_empty());
    }

    #[tokio::test]
    async fn session_lifecycle() {
        let store = MemoryStore::new();
        let did = "did:peer:test";
        let did_hash = digest(did);
        let session = Session {
            session_id: "sid-1".into(),
            challenge: "abc".into(),
            state: SessionState::ChallengeSent,
            did: did.into(),
            did_hash: did_hash.clone(),
            ..Default::default()
        };
        store
            .put_session(&session, Duration::from_secs(60))
            .await
            .expect("put");

        let got = store.get_session("sid-1", did).await.expect("get");
        assert_eq!(got.session_id, "sid-1");
        assert_eq!(got.challenge, "abc");
        // Regression guard: did/did_hash must round-trip. A backend that
        // loses these fields silently misroutes WebSocket messages and
        // breaks the JWT auth → handler hand-off.
        assert_eq!(got.did, did, "did must round-trip through put/get");
        assert_eq!(
            got.did_hash, did_hash,
            "did_hash must round-trip through put/get"
        );

        store.delete_session("sid-1").await.expect("delete");
        let missing = store.get_session("sid-1", did).await;
        assert!(missing.is_err(), "deleted session must error");
    }

    #[tokio::test]
    async fn session_auth_rename_preserves_did() {
        // Full challenge → authenticated rename flow. Catches the bug
        // where `update_session_authenticated` rewrites the session
        // with an empty `did` because the trait default passed
        // did_hash to get_session (which expects raw did) and the
        // resulting "not found" error was swallowed by `unwrap_or_else`.
        let store = MemoryStore::new();
        let did = "did:peer:test-auth-rename";
        let challenge_id = "challenge-sid";
        let new_id = "authed-sid";

        // Pre-create the account so get_session can join successfully.
        store
            .account_add("dummy", &MediatorACLSet::default(), None)
            .await
            .expect("account_add");

        // Step 1: challenge — write a ChallengeSent session with did set.
        let challenge_session = Session {
            session_id: challenge_id.into(),
            challenge: "abc".into(),
            state: SessionState::ChallengeSent,
            did: did.into(),
            did_hash: digest(did),
            ..Default::default()
        };
        store
            .put_session(&challenge_session, Duration::from_secs(900))
            .await
            .expect("put challenge session");

        // Step 2: promote to Authenticated under a new session_id.
        store
            .update_session_authenticated(challenge_id, new_id, did, "refresh-hash-xyz")
            .await
            .expect("update_session_authenticated");

        // Step 3: read the new session and assert did is preserved.
        let got = store
            .get_session(new_id, did)
            .await
            .expect("get authenticated session");
        assert_eq!(got.session_id, new_id);
        assert_eq!(
            got.did, did,
            "did must survive update_session_authenticated"
        );
        assert_eq!(
            got.did_hash,
            digest(did),
            "did_hash must survive update_session_authenticated"
        );
        assert_eq!(got.state, SessionState::Authenticated);
        assert_eq!(got.refresh_token_hash.as_deref(), Some("refresh-hash-xyz"));
    }

    #[tokio::test]
    async fn refresh_token_rotation_preserves_did_and_state() {
        // Catches the bug where `update_refresh_token_hash`'s trait
        // default did `get_session(session_id, "")` (empty did →
        // ROLE_TYPE missing on `DID:<sha256("")>`), the resulting
        // Err was caught by `unwrap_or_else`, a default Session was
        // substituted (state=Unknown, did=""), and `put_session`
        // wrote that corrupt default back.
        let store = MemoryStore::new();
        let did = "did:peer:refresh-test";
        let sid = "auth-sid-1";

        let session = Session {
            session_id: sid.into(),
            challenge: "abc".into(),
            state: SessionState::Authenticated,
            did: did.into(),
            did_hash: digest(did),
            authenticated: true,
            refresh_token_hash: Some("hash-1".into()),
            ..Default::default()
        };
        store
            .put_session(&session, Duration::from_secs(86_400))
            .await
            .expect("put");

        // Rotate the refresh-token hash. Must NOT corrupt did/state.
        store
            .update_refresh_token_hash(sid, "hash-2")
            .await
            .expect("update_refresh_token_hash");

        let got = store.get_session(sid, did).await.expect("get");
        assert_eq!(got.did, did, "did must survive refresh-hash rotation");
        assert_eq!(
            got.state,
            SessionState::Authenticated,
            "state must stay Authenticated"
        );
        assert_eq!(got.refresh_token_hash.as_deref(), Some("hash-2"));

        // Reading the field directly must also work without spurious errors.
        let read = store
            .get_refresh_token_hash(sid)
            .await
            .expect("get_refresh_token_hash");
        assert_eq!(read.as_deref(), Some("hash-2"));
    }

    #[tokio::test]
    async fn session_expires_lazily() {
        let store = MemoryStore::new();
        let session = Session {
            session_id: "sid-2".into(),
            ..Default::default()
        };
        // Tiny TTL — already expired by the time we read.
        store
            .put_session(&session, Duration::from_millis(1))
            .await
            .expect("put");
        tokio::time::sleep(Duration::from_millis(10)).await;
        let result = store.get_session("sid-2", "").await;
        assert!(result.is_err(), "expired session must not return");
    }

    #[tokio::test]
    async fn account_crud() {
        let store = MemoryStore::new();
        let acls = MediatorACLSet::default();
        store
            .account_add("did_hash_1", &acls, Some(50))
            .await
            .expect("add");
        assert!(store.account_exists("did_hash_1").await.unwrap());
        let got = store
            .account_get("did_hash_1")
            .await
            .expect("get")
            .expect("present");
        assert_eq!(got.did_hash, "did_hash_1");

        store
            .account_set_role("did_hash_1", &AccountType::Admin)
            .await
            .expect("set_role");
        assert!(store.check_admin_account("did_hash_1").await.unwrap());

        let list = store.account_list(0, 10).await.expect("list");
        assert_eq!(list.accounts.len(), 1);
    }

    #[tokio::test]
    async fn access_list_round_trip() {
        let store = MemoryStore::new();
        store
            .account_add("alice", &MediatorACLSet::default(), None)
            .await
            .expect("add");

        let resp = store
            .access_list_add(100, "alice", &vec!["bob".into(), "charlie".into()])
            .await
            .expect("add");
        assert_eq!(resp.did_hashes.len(), 2);
        assert!(!resp.truncated);
        assert_eq!(store.access_list_count("alice").await.unwrap(), 2);

        let got = store
            .access_list_get("alice", &vec!["bob".into(), "eve".into()])
            .await
            .expect("get");
        assert_eq!(got.did_hashes, vec!["bob"]);

        let removed = store
            .access_list_remove("alice", &vec!["bob".into()])
            .await
            .expect("remove");
        assert_eq!(removed, 1);
        assert_eq!(store.access_list_count("alice").await.unwrap(), 1);
    }

    #[tokio::test]
    async fn forward_queue_enqueue_read_ack() {
        let store = MemoryStore::new();
        let entry = ForwardQueueEntry {
            stream_id: String::new(),
            message: "encrypted".into(),
            to_did_hash: "to".into(),
            from_did_hash: "from".into(),
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

        let entries = store
            .forward_queue_read("g", "c", 10, Duration::from_millis(0))
            .await
            .expect("read");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].stream_id, id);

        store.forward_queue_ack("g", &[&id]).await.expect("ack");
        // After ack, the consumer group's `last_delivered` is past
        // this entry, so a re-read returns nothing.
        let again = store
            .forward_queue_read("g", "c", 10, Duration::from_millis(0))
            .await
            .expect("read after ack");
        assert!(again.is_empty());
    }

    #[tokio::test]
    async fn streaming_publish_subscribe_round_trip() {
        let store = MemoryStore::new();
        let mut rx = store.streaming_subscribe("uuid").await.expect("subscribe");
        store
            .streaming_publish_message("did", "uuid", "payload", false)
            .await
            .expect("publish");
        let msg = tokio::time::timeout(Duration::from_millis(500), rx.recv())
            .await
            .expect("recv timeout")
            .expect("recv error");
        assert_eq!(msg.message, "payload");
    }

    #[tokio::test]
    async fn sweep_expired_messages_drains_index() {
        let store = MemoryStore::new();
        let now = unix_timestamp_secs();
        // Three messages, one expired, one current, one future.
        store
            .store_message("s", "old", "alice", Some("bob"), now - 10, 0)
            .await
            .expect("store");
        store
            .store_message("s", "expiring-now", "alice", Some("bob"), now, 0)
            .await
            .expect("store");
        store
            .store_message("s", "future", "alice", Some("bob"), now + 1000, 0)
            .await
            .expect("store");

        let report = store
            .sweep_expired_messages(now, "admin")
            .await
            .expect("sweep");
        assert_eq!(report.expired, 2, "two messages should expire at <= now");
        assert!(report.timeslots_swept >= 1);

        // The remaining message is still fetchable.
        let list = store
            .list_messages("alice", Folder::Inbox, None, 100)
            .await
            .expect("list");
        assert_eq!(list.len(), 1);
    }

    #[tokio::test]
    async fn stats_increment_round_trip() {
        let store = MemoryStore::new();
        store
            .stats_increment(StatCounter::WebsocketOpen, 1)
            .await
            .expect("incr");
        store
            .stats_increment(StatCounter::WebsocketOpen, 2)
            .await
            .expect("incr");
        let stats = store.get_global_stats().await.expect("stats");
        assert_eq!(stats.websocket_open, 3);
    }

    #[tokio::test]
    async fn oob_invite_round_trip() {
        let store = MemoryStore::new();
        let now = unix_timestamp_secs();
        let id = store
            .oob_discovery_store("alice", "invite-data-base64", now + 60)
            .await
            .expect("store");
        let got = store
            .oob_discovery_get(&id)
            .await
            .expect("get")
            .expect("present");
        assert_eq!(got.0, "invite-data-base64");
        assert_eq!(got.1, "alice");
    }
}
