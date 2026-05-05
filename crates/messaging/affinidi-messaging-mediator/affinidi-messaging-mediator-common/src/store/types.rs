//! Shared types referenced by the [`MediatorStore`](super::MediatorStore) trait.
//!
//! These are the storage-layer types every backend must produce or accept.
//! Public protocol types (`Account`, `MediatorACLSet`, `Folder`, `MessageList`,
//! …) come from `affinidi-messaging-sdk` and are imported at use sites — not
//! re-exported here, to keep the dependency direction one-way (sdk → store).
//!
//! Some types here intentionally duplicate definitions still living in
//! `affinidi-messaging-mediator/src/database/*.rs` and `…/tasks/*`. The
//! duplicates are removed in the call-site refactor commit; carrying them
//! both during the transition keeps each commit small and reviewable.

use crate::errors::MediatorError;
use crate::types::{accounts::AccountType, acls::MediatorACLSet};
use ahash::AHashMap as HashMap;
use num_format::{Locale, ToFormattedString};
use serde::{Deserialize, Serialize};
use sha256::digest;
use std::fmt::{self, Display, Formatter};

// ─── Sessions ────────────────────────────────────────────────────────────────

/// Lifecycle state of an authentication session.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum SessionState {
    #[default]
    Unknown,
    ChallengeSent,
    Authenticated,
    Blocked,
}

impl std::fmt::Display for SessionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl TryFrom<&String> for SessionState {
    type Error = MediatorError;

    fn try_from(value: &String) -> Result<Self, Self::Error> {
        match value.as_str() {
            "ChallengeSent" => Ok(Self::ChallengeSent),
            "Authenticated" => Ok(Self::Authenticated),
            "Blocked" => Ok(Self::Blocked),
            _ => Err(MediatorError::SessionError(
                20,
                "NA".into(),
                format!("Unknown session state: ({value})"),
            )),
        }
    }
}

/// JWT claims embedded in session tokens.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionClaims {
    pub aud: String,
    pub sub: String,
    pub session_id: String,
    pub exp: u64,
}

/// An authentication session as stored by a backend.
///
/// The `session_id` is the storage key — backends must accept it on input
/// and round-trip it on output. ACLs and account type are populated from
/// the corresponding `DID:` record when the session is read; they are not
/// persisted on the session record itself.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Session {
    #[serde(skip)]
    pub session_id: String,
    pub challenge: String,
    pub state: SessionState,
    pub did: String,
    pub did_hash: String,
    pub authenticated: bool,
    pub acls: MediatorACLSet,
    pub account_type: AccountType,
    /// Unix timestamp (seconds) when this session expires. Backends with
    /// native TTL (Redis EXPIRE) honour this directly; backends without
    /// (Fjall, memory) sweep expired sessions in a background task.
    pub expires_at: u64,
    /// Hash of the most recently issued refresh token. Used to enforce
    /// one-time-use semantics on refresh — the handler reads the session,
    /// compares the presented refresh token to this hash, and on match
    /// rotates by writing back a new hash. `None` until the first refresh
    /// token is issued (i.e., for `ChallengeSent` sessions pre-auth).
    pub refresh_token_hash: Option<String>,
}

impl Session {
    /// Construct a session from a flat key-value map. Used by the Redis
    /// backend (HGETALL → `Session`) and by the memory/fjall backends to
    /// keep on-disk shape uniform.
    pub fn from_fields(session_id: &str, fields: &HashMap<String, String>) -> Option<Self> {
        let challenge = fields.get("challenge")?.clone();
        let state = match fields.get("state")?.as_str() {
            "ChallengeSent" => SessionState::ChallengeSent,
            "Authenticated" => SessionState::Authenticated,
            "Blocked" => SessionState::Blocked,
            _ => return None,
        };
        let did = fields.get("did")?.clone();
        let did_hash = digest(did.as_str());

        Some(Session {
            session_id: session_id.to_string(),
            challenge,
            state,
            did,
            did_hash,
            authenticated: matches!(state, SessionState::Authenticated),
            ..Default::default()
        })
    }
}

// ─── Messages ────────────────────────────────────────────────────────────────

/// Metadata associated with a stored message. Backends index this so
/// `delete_message` can do its ownership check without deserialising the
/// message body.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageMetaData {
    pub bytes: usize,
    pub to_did_hash: String,
    pub from_did_hash: Option<String>,
    /// Unix timestamp in milliseconds when the message was received.
    pub timestamp: u128,
}

/// Reply to a Message Pickup 3.0 status query for one DID.
///
/// Currently produced by the `get_status_reply` Lua function on Redis;
/// non-Redis backends compute this in Rust against their own indices.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct InboxStatusReply {
    pub recipient_did: String,
    pub message_count: u64,
    pub total_bytes: u64,
    /// Stream ID of the oldest message in the inbox, or `0` if empty.
    pub oldest_received: String,
    /// Stream ID of the newest message in the inbox, or `0` if empty.
    pub newest_received: String,
    /// Reported queue length from the storage backend.
    pub queue_count: u64,
    /// Whether the recipient has an active live-streaming subscription.
    pub live_delivery: bool,
}

// ─── Forwarding queue ────────────────────────────────────────────────────────

/// A message queued for forwarding to a remote mediator.
///
/// On Redis this maps 1:1 onto a `FORWARD_Q` stream entry. On Fjall it's a
/// row in the `forward_queue` partition keyed by monotonic stream ID. On
/// memory it's an entry in a `BTreeMap<StreamId, ForwardQueueEntry>`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ForwardQueueEntry {
    /// Backend-assigned stream ID (e.g., Redis "1700000000000-0"). Empty
    /// when the entry is being constructed for enqueue; populated on read.
    pub stream_id: String,
    pub message: String,
    pub to_did_hash: String,
    pub from_did_hash: String,
    pub from_did: String,
    pub to_did: String,
    pub endpoint_url: String,
    pub received_at_ms: u128,
    pub delay_milli: i64,
    pub expires_at: u64,
    pub retry_count: u32,
    /// Hop counter for loop detection. The mediator increments on each
    /// forward and rejects messages exceeding `max_hops`.
    pub hop_count: u32,
}

// ─── Live streaming pub/sub ─────────────────────────────────────────────────

/// Payload published when a new message is delivered to a live-streaming
/// recipient. Subscribers (the WebSocket task) decode this and forward to
/// the connected client.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PubSubRecord {
    pub did_hash: String,
    pub message: String,
    /// When `true`, deliver even if the client is not in the live-delivery
    /// state (used to push status messages on live-delivery transitions).
    pub force_delivery: bool,
}

// ─── Stats ───────────────────────────────────────────────────────────────────

/// Snapshot of the mediator's global counters.
///
/// Backends maintain these counters in whatever shape suits them (Redis
/// `GLOBAL` hash with `HINCRBY`, Fjall partition with atomic counters, etc.)
/// and produce a snapshot on demand.
#[derive(Clone, Debug, Default)]
pub struct MetadataStats {
    pub received_bytes: i64,
    pub sent_bytes: i64,
    pub deleted_bytes: i64,
    pub received_count: i64,
    pub sent_count: i64,
    pub deleted_count: i64,
    pub websocket_open: i64,
    pub websocket_close: i64,
    pub sessions_created: i64,
    pub sessions_success: i64,
    pub oob_invites_created: i64,
    pub oob_invites_claimed: i64,
}

impl Display for MetadataStats {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            r#"
    Message counts: recv({}) sent({}) deleted({}) queued({})
    Storage: received({}), sent({}), deleted({}), current_queued({})
    Connections: ws_open({}) ws_close({}) ws_current({}) :: sessions_created({}), sessions_authenticated({})
    OOB Invites: created({}) claimed({})
            "#,
            self.received_count.to_formatted_string(&Locale::en),
            self.sent_count.to_formatted_string(&Locale::en),
            self.deleted_count.to_formatted_string(&Locale::en),
            (self.received_count - self.deleted_count).to_formatted_string(&Locale::en),
            self.received_bytes.to_formatted_string(&Locale::en),
            self.sent_bytes.to_formatted_string(&Locale::en),
            self.deleted_bytes.to_formatted_string(&Locale::en),
            (self.received_bytes - self.deleted_bytes).to_formatted_string(&Locale::en),
            self.websocket_open.to_formatted_string(&Locale::en),
            self.websocket_close.to_formatted_string(&Locale::en),
            (self.websocket_open - self.websocket_close).to_formatted_string(&Locale::en),
            self.sessions_created.to_formatted_string(&Locale::en),
            self.sessions_success.to_formatted_string(&Locale::en),
            self.oob_invites_created.to_formatted_string(&Locale::en),
            self.oob_invites_claimed.to_formatted_string(&Locale::en)
        )
    }
}

impl MetadataStats {
    /// Per-tick delta vs a previously-captured snapshot. Used by the
    /// statistics task to log "messages this period" rates without
    /// interfering with the absolute counters in the backend.
    pub fn delta(&self, previous: &MetadataStats) -> MetadataStats {
        MetadataStats {
            received_bytes: self.received_bytes - previous.received_bytes,
            sent_bytes: self.sent_bytes - previous.sent_bytes,
            deleted_bytes: self.deleted_bytes - previous.deleted_bytes,
            received_count: self.received_count - previous.received_count,
            sent_count: self.sent_count - previous.sent_count,
            deleted_count: self.deleted_count - previous.deleted_count,
            websocket_open: self.websocket_open - previous.websocket_open,
            websocket_close: self.websocket_close - previous.websocket_close,
            sessions_created: self.sessions_created - previous.sessions_created,
            sessions_success: self.sessions_success - previous.sessions_success,
            oob_invites_created: self.oob_invites_created - previous.oob_invites_created,
            oob_invites_claimed: self.oob_invites_claimed - previous.oob_invites_claimed,
        }
    }
}

/// Counter that [`MediatorStore::stats_increment`] understands. Adding a
/// variant requires teaching every backend to recognise it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StatCounter {
    SentBytes,
    SentCount,
    WebsocketOpen,
    WebsocketClose,
    SessionsCreated,
    SessionsSuccess,
    OobInvitesCreated,
    OobInvitesClaimed,
}

// ─── Authorisation context for destructive ops ─────────────────────────────

/// Who is authorising a message deletion.
///
/// Replaces the prior `(did_hash, admin_did_hash)` parameter pair with a
/// typed enum that makes the policy explicit at the call site.
#[derive(Clone, Debug)]
pub enum DeletionAuthority {
    /// The requesting DID claims ownership (must be the message's TO or
    /// FROM). Backends reject with `permission_denied` when the DID
    /// doesn't match either side.
    Owner { did_hash: String },
    /// The requester is acting as the mediator admin. Bypasses ownership.
    /// Used by the message expiry processor and account removal.
    Admin { admin_did_hash: String },
}

impl DeletionAuthority {
    pub fn principal_did_hash(&self) -> &str {
        match self {
            DeletionAuthority::Owner { did_hash } => did_hash,
            DeletionAuthority::Admin { admin_did_hash } => admin_did_hash,
        }
    }
}

// ─── Live streaming state ───────────────────────────────────────────────────

/// State of a live-streaming subscriber, set by the WebSocket task as
/// clients connect, transition to live delivery, and disconnect.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum StreamingClientState {
    /// Client has a WebSocket connection but has not yet enabled live
    /// delivery. Messages still queue normally.
    Registered,
    /// Client has enabled live delivery; new messages are pushed instead
    /// of (or in addition to) being queued.
    Live,
    /// Client has disconnected; remove all streaming state.
    Deregistered,
}

// ─── Account roles ──────────────────────────────────────────────────────────

// `AccountType` is re-exported from `affinidi-messaging-sdk`; the trait
// uses it directly via `account_set_role` and the admin-account methods.

// ─── Message expiry sweep ───────────────────────────────────────────────────

/// Outcome of one full pass of the message expiry sweep.
#[derive(Clone, Copy, Debug, Default)]
pub struct ExpiryReport {
    /// Number of expiry timeslots inspected.
    pub timeslots_swept: u32,
    /// Number of messages successfully deleted.
    pub expired: u32,
    /// Number of messages found in expiry indices but already gone (the
    /// normal-delete path beat the sweep). Difference between this and
    /// `expired` is informational, not an error.
    pub already_deleted: u32,
}

// ─── Health ──────────────────────────────────────────────────────────────────

/// Reported health of the storage backend, surfaced via `/readyz`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreHealth {
    /// Backend is operational and accepting requests.
    Healthy,
    /// Backend is degraded but still serving requests (e.g., circuit
    /// breaker in half-open state).
    Degraded,
    /// Backend is unavailable and short-circuiting requests.
    Unavailable,
}

impl StoreHealth {
    pub fn as_str(&self) -> &'static str {
        match self {
            StoreHealth::Healthy => "healthy",
            StoreHealth::Degraded => "degraded",
            StoreHealth::Unavailable => "unavailable",
        }
    }
}
