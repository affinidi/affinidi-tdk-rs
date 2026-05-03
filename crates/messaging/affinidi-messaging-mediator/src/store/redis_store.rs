//! Redis-backed [`MediatorStore`] implementation.
//!
//! This is the multi-mediator backend: cross-process pub/sub via Redis
//! `PUBLISH`/`SUBSCRIBE`, atomic composite operations via the bundled
//! Lua functions in `conf/atm-functions.lua`. It wraps the existing
//! [`Database`] type — until the call-site refactor (commit 6) lands,
//! the original code paths in `crate::database::*` continue to work
//! and `RedisStore` is a parallel implementation that satisfies the
//! trait. Commit 6 swaps call sites onto the trait and the legacy
//! wrappers can be retired.
//!
//! The store maintains a per-mediator-UUID broadcast channel for live
//! streaming so multiple in-process subscribers can share one Redis
//! pubsub bridge.

use crate::common::session::{Session as InnerSession, SessionState as InnerSessionState};
use crate::database::{
    Database, forwarding::ForwardQueueEntry as InnerForwardEntry,
    stats::MetadataStats as InnerMetadataStats, store::MessageMetaData as InnerMessageMetaData,
};
use affinidi_messaging_mediator_common::{
    errors::MediatorError,
    store::{
        DeletionAuthority, ExpiryReport, ForwardQueueEntry, InboxStatusReply, MediatorStore,
        MessageMetaData, MetadataStats, PubSubRecord, Session, SessionState, StatCounter,
        StoreHealth, StreamingClientState,
    },
};
use affinidi_messaging_sdk::{
    messages::{Folder, GetMessagesResponse, MessageList, MessageListElement, fetch::FetchOptions},
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
use futures_util::StreamExt;
use redis::{Value, from_redis_value};
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::sync::{Mutex, broadcast};
use tracing::{debug, warn};

const PUBSUB_BROADCAST_CAPACITY: usize = 1024;
const STATIC_TIMESLOT_BATCH: u32 = 100;

/// Redis-backed [`MediatorStore`].
///
/// Wraps the existing [`Database`] (which itself wraps
/// `DatabaseHandler` + a circuit breaker). All composite atomic ops
/// (store/delete/fetch/expire) go through Lua functions registered on
/// the Redis server.
#[derive(Clone)]
pub struct RedisStore {
    db: Database,
    lua_scripts_path: Option<String>,
    broadcast_channels: Arc<Mutex<HashMap<String, broadcast::Sender<PubSubRecord>>>>,
}

impl RedisStore {
    /// Construct a new `RedisStore` wrapping the given [`Database`].
    ///
    /// `lua_scripts_path` should match `config.database.functions_file`
    /// from the mediator config. When `None`, [`MediatorStore::initialize`]
    /// returns an error — the Redis backend cannot operate without its
    /// Lua functions loaded.
    pub fn new(db: Database, lua_scripts_path: Option<String>) -> Self {
        Self {
            db,
            lua_scripts_path,
            broadcast_channels: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Access the wrapped [`Database`]. Used by the call-site refactor
    /// in commit 6 while we shim trait methods into the existing code
    /// paths. Will be removed once those paths are retired.
    pub fn inner(&self) -> &Database {
        &self.db
    }
}

impl std::fmt::Debug for RedisStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisStore")
            .field("circuit_breaker", &self.db.circuit_breaker_state())
            .finish()
    }
}

// ─── Type conversions ───────────────────────────────────────────────────────
//
// The `mediator-common::store::types` module defines a fresh set of
// types that mirror the legacy ones in `crate::database::*`. The
// duplication is intentional during the migration: legacy call sites
// still use the legacy types, the trait uses the new types, and the
// store impl converts at the boundary. Commit 6 unifies them.

fn session_state_into_new(s: InnerSessionState) -> SessionState {
    match s {
        InnerSessionState::Unknown => SessionState::Unknown,
        InnerSessionState::ChallengeSent => SessionState::ChallengeSent,
        InnerSessionState::Authenticated => SessionState::Authenticated,
        InnerSessionState::Blocked => SessionState::Blocked,
    }
}

fn session_state_into_old(s: SessionState) -> InnerSessionState {
    match s {
        SessionState::Unknown => InnerSessionState::Unknown,
        SessionState::ChallengeSent => InnerSessionState::ChallengeSent,
        SessionState::Authenticated => InnerSessionState::Authenticated,
        SessionState::Blocked => InnerSessionState::Blocked,
    }
}

fn session_into_new(inner: InnerSession, refresh_token_hash: Option<String>) -> Session {
    Session {
        session_id: inner.session_id,
        challenge: inner.challenge,
        state: session_state_into_new(inner.state),
        did: inner.did,
        did_hash: inner.did_hash,
        authenticated: inner.authenticated,
        acls: inner.acls,
        account_type: inner.account_type,
        expires_at: inner.expires_at,
        refresh_token_hash,
    }
}

fn fwd_entry_into_new(inner: InnerForwardEntry) -> ForwardQueueEntry {
    ForwardQueueEntry {
        stream_id: inner.stream_id,
        message: inner.message,
        to_did_hash: inner.to_did_hash,
        from_did_hash: inner.from_did_hash,
        from_did: inner.from_did,
        to_did: inner.to_did,
        endpoint_url: inner.endpoint_url,
        received_at_ms: inner.received_at_ms,
        delay_milli: inner.delay_milli,
        expires_at: inner.expires_at,
        retry_count: inner.retry_count,
        hop_count: inner.hop_count,
    }
}

fn fwd_entry_into_old(new: &ForwardQueueEntry) -> InnerForwardEntry {
    InnerForwardEntry {
        stream_id: new.stream_id.clone(),
        message: new.message.clone(),
        to_did_hash: new.to_did_hash.clone(),
        from_did_hash: new.from_did_hash.clone(),
        from_did: new.from_did.clone(),
        to_did: new.to_did.clone(),
        endpoint_url: new.endpoint_url.clone(),
        received_at_ms: new.received_at_ms,
        delay_milli: new.delay_milli,
        expires_at: new.expires_at,
        retry_count: new.retry_count,
        hop_count: new.hop_count,
    }
}

fn message_meta_into_new(inner: InnerMessageMetaData) -> MessageMetaData {
    MessageMetaData {
        bytes: inner.bytes,
        to_did_hash: inner.to_did_hash,
        from_did_hash: inner.from_did_hash,
        timestamp: inner.timestamp,
    }
}

fn stats_into_new(inner: InnerMetadataStats) -> MetadataStats {
    MetadataStats {
        received_bytes: inner.received_bytes,
        sent_bytes: inner.sent_bytes,
        deleted_bytes: inner.deleted_bytes,
        received_count: inner.received_count,
        sent_count: inner.sent_count,
        deleted_count: inner.deleted_count,
        websocket_open: inner.websocket_open,
        websocket_close: inner.websocket_close,
        sessions_created: inner.sessions_created,
        sessions_success: inner.sessions_success,
        oob_invites_created: inner.oob_invites_created,
        oob_invites_claimed: inner.oob_invites_claimed,
    }
}

fn stat_counter_redis_field(counter: StatCounter) -> &'static str {
    match counter {
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

#[async_trait]
impl MediatorStore for RedisStore {
    // ─── Bootstrap & health ─────────────────────────────────────────────────

    async fn initialize(&self) -> Result<(), MediatorError> {
        let path = self.lua_scripts_path.as_ref().ok_or_else(|| {
            MediatorError::ConfigError(
                12,
                "RedisStore".into(),
                "lua_scripts_path is required for the Redis backend".into(),
            )
        })?;
        self.db.load_scripts(path).await
    }

    async fn health(&self) -> StoreHealth {
        match self.db.circuit_breaker_state() {
            "closed" => StoreHealth::Healthy,
            "half_open" => StoreHealth::Degraded,
            "open" => StoreHealth::Unavailable,
            _ => StoreHealth::Healthy,
        }
    }

    async fn shutdown(&self) -> Result<(), MediatorError> {
        // Drop all broadcast channels — subscribers see Closed and the
        // bridge tasks exit. The underlying Database's connection
        // manager drops with the store.
        self.broadcast_channels.lock().await.clear();
        Ok(())
    }

    // ─── Messages ───────────────────────────────────────────────────────────

    async fn store_message(
        &self,
        session_id: &str,
        message: &str,
        to_did_hash: &str,
        from_hash: Option<&str>,
        expires_at: u64,
        queue_maxlen: usize,
    ) -> Result<String, MediatorError> {
        self.db
            .store_message(
                session_id,
                message,
                to_did_hash,
                from_hash,
                expires_at,
                queue_maxlen,
            )
            .await
    }

    async fn delete_message(
        &self,
        message_hash: &str,
        by: DeletionAuthority,
    ) -> Result<(), MediatorError> {
        let (did_hash, admin) = match &by {
            DeletionAuthority::Owner { did_hash } => (did_hash.as_str(), None),
            DeletionAuthority::Admin { admin_did_hash } => {
                // Pass the admin DID as both requester and admin so the
                // Lua permission check accepts the system delete.
                (admin_did_hash.as_str(), Some(admin_did_hash.as_str()))
            }
        };
        self.db
            .handler
            .delete_message(None, did_hash, message_hash, None, admin)
            .await
    }

    async fn get_message(
        &self,
        did_hash: &str,
        msg_id: &str,
    ) -> Result<Option<MessageListElement>, MediatorError> {
        self.db.get_message(did_hash, msg_id).await
    }

    async fn get_message_metadata(
        &self,
        session_id: &str,
        message_hash: &str,
    ) -> Result<MessageMetaData, MediatorError> {
        let inner = self
            .db
            .get_message_metadata(session_id, message_hash)
            .await?;
        Ok(message_meta_into_new(inner))
    }

    // ─── Inbox & outbox ────────────────────────────────────────────────────

    async fn list_messages(
        &self,
        did_hash: &str,
        folder: Folder,
        range: Option<(&str, &str)>,
        limit: u32,
    ) -> Result<MessageList, MediatorError> {
        self.db.list_messages(did_hash, folder, range, limit).await
    }

    async fn fetch_messages(
        &self,
        session_id: &str,
        did_hash: &str,
        options: &FetchOptions,
    ) -> Result<GetMessagesResponse, MediatorError> {
        self.db.fetch_messages(session_id, did_hash, options).await
    }

    async fn purge_folder(
        &self,
        session_id: &str,
        did_hash: &str,
        folder: Folder,
    ) -> Result<(usize, usize), MediatorError> {
        // Synthesize a minimal Session for the legacy `purge_messages`
        // signature — it only reads `session_id` for log context and
        // doesn't touch the other fields.
        let session = InnerSession {
            session_id: session_id.to_string(),
            ..Default::default()
        };
        self.db.purge_messages(&session, did_hash, folder).await
    }

    async fn delete_folder_stream(
        &self,
        session_id: &str,
        did_hash: &str,
        folder: Folder,
    ) -> Result<(), MediatorError> {
        let session = InnerSession {
            session_id: session_id.to_string(),
            ..Default::default()
        };
        self.db
            .delete_folder_stream(&session, did_hash, &folder)
            .await
    }

    async fn inbox_status(&self, did_hash: &str) -> Result<InboxStatusReply, MediatorError> {
        // Calls the `get_status_reply` Lua function and parses the
        // response into an `InboxStatusReply`. The legacy code path
        // builds a Message Pickup 3.0 reply directly in the handler;
        // here we expose the underlying data so the trait stays
        // protocol-agnostic.
        let mut conn = self.db.get_connection().await?;
        let result: Value = redis::cmd("FCALL")
            .arg("get_status_reply")
            .arg(1)
            .arg(did_hash)
            .query_async(&mut conn)
            .await
            .map_err(|err| {
                MediatorError::DatabaseError(
                    14,
                    did_hash.into(),
                    format!("inbox_status Lua call failed: {err}"),
                )
            })?;

        // The Lua function returns a map with: recipient_did,
        // message_count, total_bytes, oldest_received, newest_received,
        // queue_count, live_delivery.
        let fields: HashMap<String, Value> = from_redis_value(result).map_err(|err| {
            MediatorError::DatabaseError(
                21,
                did_hash.into(),
                format!("inbox_status response parse failed: {err}"),
            )
        })?;

        let read_str = |k: &str| -> String {
            fields
                .get(k)
                .and_then(|v| from_redis_value::<String>(v.clone()).ok())
                .unwrap_or_default()
        };
        let read_u64 = |k: &str| -> u64 {
            fields
                .get(k)
                .and_then(|v| from_redis_value::<i64>(v.clone()).ok())
                .map(|i| i.max(0) as u64)
                .unwrap_or(0)
        };
        let read_bool = |k: &str| -> bool {
            fields
                .get(k)
                .and_then(|v| from_redis_value::<bool>(v.clone()).ok())
                .unwrap_or(false)
        };

        Ok(InboxStatusReply {
            recipient_did: read_str("recipient_did"),
            message_count: read_u64("message_count"),
            total_bytes: read_u64("total_bytes"),
            oldest_received: read_str("oldest_received"),
            newest_received: read_str("newest_received"),
            queue_count: read_u64("queue_count"),
            live_delivery: read_bool("live_delivery"),
        })
    }

    // ─── Sessions ───────────────────────────────────────────────────────────

    async fn put_session(&self, session: &Session, ttl: Duration) -> Result<(), MediatorError> {
        let mut conn = self.db.get_connection().await?;
        let sid = format!("SESSION:{}", session.session_id);
        let mut pipe = redis::pipe();
        pipe.atomic()
            .cmd("HSET")
            .arg(&sid)
            .arg("challenge")
            .arg(&session.challenge)
            .arg("state")
            .arg(session_state_into_old(session.state).to_string())
            .arg("did")
            .arg(&session.did);
        if let Some(hash) = &session.refresh_token_hash {
            pipe.cmd("HSET")
                .arg(&sid)
                .arg("refresh_token_hash")
                .arg(hash);
        }
        pipe.expire(&sid, ttl.as_secs() as i64)
            .exec_async(&mut conn)
            .await
            .map_err(|err| {
                MediatorError::SessionError(
                    14,
                    session.session_id.clone(),
                    format!("put_session failed: {err}"),
                )
            })?;
        Ok(())
    }

    async fn get_session(&self, session_id: &str, did: &str) -> Result<Session, MediatorError> {
        let inner = self.db.get_session(session_id, did).await?;
        let refresh = self.db.get_refresh_token_hash(session_id).await?;
        Ok(session_into_new(inner, refresh))
    }

    async fn delete_session(&self, session_id: &str) -> Result<(), MediatorError> {
        let mut conn = self.db.get_connection().await?;
        let sid = format!("SESSION:{session_id}");
        redis::cmd("DEL")
            .arg(&sid)
            .exec_async(&mut conn)
            .await
            .map_err(|err| {
                MediatorError::SessionError(
                    14,
                    session_id.into(),
                    format!("delete_session failed: {err}"),
                )
            })?;
        Ok(())
    }

    // ─── Accounts ───────────────────────────────────────────────────────────

    async fn account_exists(&self, did_hash: &str) -> Result<bool, MediatorError> {
        self.db.account_exists(did_hash).await
    }

    async fn account_get(&self, did_hash: &str) -> Result<Option<Account>, MediatorError> {
        self.db.account_get(did_hash).await
    }

    async fn account_add(
        &self,
        did_hash: &str,
        acls: &MediatorACLSet,
        queue_limit: Option<u32>,
    ) -> Result<Account, MediatorError> {
        self.db.account_add(did_hash, acls, queue_limit).await
    }

    async fn account_remove(
        &self,
        session: &Session,
        did_hash: &str,
    ) -> Result<bool, MediatorError> {
        // Synthesize a legacy session — `account_remove` only reads
        // session_id from it for tracing context.
        let inner_session = InnerSession {
            session_id: session.session_id.clone(),
            ..Default::default()
        };
        self.db.account_remove(&inner_session, did_hash).await
    }

    async fn account_list(
        &self,
        cursor: u32,
        limit: u32,
    ) -> Result<MediatorAccountList, MediatorError> {
        self.db.account_list(cursor, limit).await
    }

    async fn account_set_role(
        &self,
        did_hash: &str,
        account_type: &AccountType,
    ) -> Result<(), MediatorError> {
        // Update the role field. For admin-tier roles, ensure the DID
        // is in the ADMINS set; for Standard, remove it. This wraps
        // the legacy `account_change_type` + admin-set membership in
        // one atomic operation.
        let mut conn = self.db.get_connection().await?;
        let key = format!("DID:{did_hash}");
        let role_str: String = account_type.to_owned().into();

        let mut pipe = redis::pipe();
        pipe.atomic()
            .cmd("HSET")
            .arg(&key)
            .arg("ROLE_TYPE")
            .arg(&role_str);
        if account_type.is_admin() {
            pipe.cmd("SADD").arg("ADMINS").arg(did_hash);
        } else {
            pipe.cmd("SREM").arg("ADMINS").arg(did_hash);
        }
        pipe.exec_async(&mut conn).await.map_err(|err| {
            MediatorError::DatabaseError(
                14,
                did_hash.into(),
                format!("account_set_role failed: {err}"),
            )
        })?;
        Ok(())
    }

    async fn account_change_queue_limits(
        &self,
        did_hash: &str,
        send_queue_limit: Option<i32>,
        receive_queue_limit: Option<i32>,
    ) -> Result<(), MediatorError> {
        self.db
            .account_change_queue_limits(did_hash, send_queue_limit, receive_queue_limit)
            .await
    }

    // ─── ACLs ───────────────────────────────────────────────────────────────

    async fn set_did_acl(
        &self,
        did_hash: &str,
        acls: &MediatorACLSet,
    ) -> Result<MediatorACLSet, MediatorError> {
        self.db.set_did_acl(did_hash, acls).await
    }

    async fn get_did_acl(&self, did_hash: &str) -> Result<Option<MediatorACLSet>, MediatorError> {
        self.db.get_did_acl(did_hash).await
    }

    async fn get_did_acls(
        &self,
        dids: &[String],
        mediator_acl_mode: AccessListModeType,
    ) -> Result<MediatorACLGetResponse, MediatorError> {
        self.db.get_did_acls(dids, mediator_acl_mode).await
    }

    async fn access_list_allowed(&self, to_hash: &str, from_hash: Option<&str>) -> bool {
        self.db.access_list_allowed(to_hash, from_hash).await
    }

    async fn access_list_list(
        &self,
        did_hash: &str,
        cursor: u64,
    ) -> Result<MediatorAccessListListResponse, MediatorError> {
        self.db.access_list_list(did_hash, cursor).await
    }

    async fn access_list_count(&self, did_hash: &str) -> Result<usize, MediatorError> {
        self.db.access_list_count(did_hash).await
    }

    async fn access_list_add(
        &self,
        access_list_limit: usize,
        did_hash: &str,
        hashes: &Vec<String>,
    ) -> Result<MediatorAccessListAddResponse, MediatorError> {
        self.db
            .access_list_add(access_list_limit, did_hash, hashes)
            .await
    }

    async fn access_list_remove(
        &self,
        did_hash: &str,
        hashes: &Vec<String>,
    ) -> Result<usize, MediatorError> {
        self.db.access_list_remove(did_hash, hashes).await
    }

    async fn access_list_clear(&self, did_hash: &str) -> Result<(), MediatorError> {
        self.db.access_list_clear(did_hash).await
    }

    async fn access_list_get(
        &self,
        did_hash: &str,
        hashes: &Vec<String>,
    ) -> Result<MediatorAccessListGetResponse, MediatorError> {
        self.db.access_list_get(did_hash, hashes).await
    }

    // ─── Admin accounts ─────────────────────────────────────────────────────

    async fn setup_admin_account(
        &self,
        admin_did_hash: &str,
        admin_type: AccountType,
        acls: &MediatorACLSet,
    ) -> Result<(), MediatorError> {
        self.db
            .setup_admin_account(admin_did_hash, admin_type, acls)
            .await
    }

    async fn check_admin_account(&self, did_hash: &str) -> Result<bool, MediatorError> {
        self.db.check_admin_account(did_hash).await
    }

    async fn list_admin_accounts(
        &self,
        cursor: u32,
        limit: u32,
    ) -> Result<MediatorAdminList, MediatorError> {
        self.db.list_admin_accounts(cursor, limit).await
    }

    // ─── OOB Discovery invitations ──────────────────────────────────────────

    async fn oob_discovery_store(
        &self,
        did_hash: &str,
        invite_b64: &str,
        expires_at: u64,
    ) -> Result<String, MediatorError> {
        // The legacy `oob_discovery_store` takes a `Message` and an
        // `oob_invite_ttl`, then computes the absolute expiry inside.
        // The trait already takes the absolute `expires_at`, so we
        // call the underlying Redis ops directly here.
        use sha256::digest;

        let invite_hash = digest(invite_b64);
        let key = format!("OOB_INVITES:{invite_hash}");
        let mut conn = self.db.get_connection().await?;

        redis::pipe()
            .atomic()
            .cmd("HMSET")
            .arg(&key)
            .arg("INVITE")
            .arg(invite_b64)
            .arg("DID")
            .arg(did_hash)
            .cmd("EXPIREAT")
            .arg(&key)
            .arg(expires_at)
            .cmd("HINCRBY")
            .arg("GLOBAL")
            .arg("OOB_INVITES_CREATED")
            .arg(1)
            .exec_async(&mut conn)
            .await
            .map_err(|err| {
                MediatorError::DatabaseError(
                    14,
                    did_hash.into(),
                    format!("oob_discovery_store failed: {err}"),
                )
            })?;

        Ok(invite_hash)
    }

    async fn oob_discovery_get(
        &self,
        oob_id: &str,
    ) -> Result<Option<(String, String)>, MediatorError> {
        self.db.oob_discovery_get(oob_id).await
    }

    async fn oob_discovery_delete(&self, oob_id: &str) -> Result<bool, MediatorError> {
        self.db.oob_discovery_delete(oob_id).await
    }

    // ─── Stats / counters ───────────────────────────────────────────────────

    async fn get_global_stats(&self) -> Result<MetadataStats, MediatorError> {
        let inner = self.db.get_db_metadata().await?;
        Ok(stats_into_new(inner))
    }

    async fn stats_increment(&self, counter: StatCounter, by: i64) -> Result<(), MediatorError> {
        let field = stat_counter_redis_field(counter);
        let mut conn = self.db.get_connection().await?;
        redis::cmd("HINCRBY")
            .arg("GLOBAL")
            .arg(field)
            .arg(by)
            .exec_async(&mut conn)
            .await
            .map_err(|err| {
                MediatorError::DatabaseError(
                    14,
                    "stats".into(),
                    format!("stats_increment({field}) failed: {err}"),
                )
            })?;
        Ok(())
    }

    // ─── Forwarding queue ───────────────────────────────────────────────────

    async fn forward_queue_enqueue(
        &self,
        entry: &ForwardQueueEntry,
        max_len: usize,
    ) -> Result<String, MediatorError> {
        let inner = fwd_entry_into_old(entry);
        self.db
            .forward_queue_enqueue_with_limit(&inner, max_len)
            .await
    }

    async fn forward_queue_len(&self) -> Result<usize, MediatorError> {
        self.db.get_forward_tasks_len().await
    }

    async fn forward_queue_read(
        &self,
        group_name: &str,
        consumer_name: &str,
        count: usize,
        block: Duration,
    ) -> Result<Vec<ForwardQueueEntry>, MediatorError> {
        // Auto-create the consumer group on first read. Idempotent —
        // the legacy ensure_group ignores BUSYGROUP errors.
        self.db.forward_queue_ensure_group(group_name).await?;
        let inner = self
            .db
            .forward_queue_read(group_name, consumer_name, count, block.as_millis() as usize)
            .await?;
        Ok(inner.into_iter().map(fwd_entry_into_new).collect())
    }

    async fn forward_queue_ack(
        &self,
        group_name: &str,
        stream_ids: &[&str],
    ) -> Result<(), MediatorError> {
        self.db.forward_queue_ack(group_name, stream_ids).await
    }

    async fn forward_queue_delete(&self, stream_ids: &[&str]) -> Result<(), MediatorError> {
        self.db.forward_queue_delete(stream_ids).await
    }

    async fn forward_queue_autoclaim(
        &self,
        group_name: &str,
        consumer_name: &str,
        min_idle: Duration,
        count: usize,
    ) -> Result<Vec<ForwardQueueEntry>, MediatorError> {
        let inner = self
            .db
            .forward_queue_autoclaim(
                group_name,
                consumer_name,
                min_idle.as_millis() as u64,
                count,
            )
            .await?;
        Ok(inner.into_iter().map(fwd_entry_into_new).collect())
    }

    // ─── Live streaming (WebSocket pub/sub) ─────────────────────────────────

    async fn streaming_clean_start(&self, mediator_uuid: &str) -> Result<(), MediatorError> {
        self.db.streaming_clean_start(mediator_uuid).await
    }

    async fn streaming_set_state(
        &self,
        did_hash: &str,
        mediator_uuid: &str,
        state: StreamingClientState,
    ) -> Result<(), MediatorError> {
        match state {
            StreamingClientState::Registered => {
                self.db
                    .streaming_register_client(did_hash, mediator_uuid)
                    .await
            }
            StreamingClientState::Live => {
                self.db.streaming_start_live(did_hash, mediator_uuid).await
            }
            StreamingClientState::Deregistered => {
                self.db
                    .streaming_deregister_client(did_hash, mediator_uuid)
                    .await
            }
        }
    }

    async fn streaming_is_client_live(
        &self,
        did_hash: &str,
        force_delivery: bool,
    ) -> Option<String> {
        self.db
            .streaming_is_client_live(did_hash, force_delivery)
            .await
    }

    async fn streaming_publish_message(
        &self,
        did_hash: &str,
        mediator_uuid: &str,
        message: &str,
        force_delivery: bool,
    ) -> Result<(), MediatorError> {
        self.db
            .streaming_publish_message(did_hash, mediator_uuid, message, force_delivery)
            .await
    }

    async fn streaming_subscribe(
        &self,
        mediator_uuid: &str,
    ) -> Result<broadcast::Receiver<PubSubRecord>, MediatorError> {
        let mut channels = self.broadcast_channels.lock().await;
        if let Some(sender) = channels.get(mediator_uuid) {
            return Ok(sender.subscribe());
        }

        // First subscriber for this UUID — open a Redis pubsub
        // connection and bridge incoming messages into a broadcast
        // channel. The bridge task lives until the underlying pubsub
        // connection drops or the broadcast Sender is removed.
        let (sender, receiver) = broadcast::channel(PUBSUB_BROADCAST_CAPACITY);
        let mut pubsub = self.db.handler.get_pubsub_connection().await?;
        let channel_name = format!("CHANNEL:{mediator_uuid}");
        pubsub.subscribe(&channel_name).await.map_err(|err| {
            MediatorError::DatabaseError(
                14,
                mediator_uuid.into(),
                format!("streaming_subscribe SUBSCRIBE failed: {err}"),
            )
        })?;
        debug!(
            "RedisStore: opened pubsub bridge for channel {}",
            channel_name
        );

        let inner_sender = sender.clone();
        let task_uuid = mediator_uuid.to_string();
        tokio::spawn(async move {
            let mut stream = pubsub.on_message();
            while let Some(msg) = stream.next().await {
                match msg.get_payload::<String>() {
                    Ok(payload) => match serde_json::from_str::<PubSubRecord>(&payload) {
                        Ok(record) => {
                            // Ignore send errors — no current
                            // subscribers is acceptable.
                            let _ = inner_sender.send(record);
                        }
                        Err(e) => warn!(
                            "RedisStore pubsub bridge ({}): malformed payload: {}",
                            task_uuid, e
                        ),
                    },
                    Err(e) => warn!(
                        "RedisStore pubsub bridge ({}): payload decode failed: {}",
                        task_uuid, e
                    ),
                }
            }
            debug!("RedisStore pubsub bridge ({}) exited", task_uuid);
        });

        channels.insert(mediator_uuid.to_string(), sender);
        Ok(receiver)
    }

    // ─── Message expiry processor ───────────────────────────────────────────

    async fn sweep_expired_messages(
        &self,
        now_secs: u64,
        admin_did_hash: &str,
    ) -> Result<ExpiryReport, MediatorError> {
        // Replicates the legacy two-step `timeslot_scan` +
        // `expire_messages_from_timeslot` flow inline so the trait
        // doesn't have to expose the timeslot abstraction.
        let mut conn = self.db.get_connection().await?;
        let timeslot_keys: Vec<String> = redis::cmd("ZRANGE")
            .arg("MSG_EXPIRY")
            .arg("-inf")
            .arg(now_secs)
            .arg("BYSCORE")
            .arg("LIMIT")
            .arg(0)
            .arg(STATIC_TIMESLOT_BATCH)
            .query_async(&mut conn)
            .await
            .map_err(|err| {
                MediatorError::DatabaseError(
                    14,
                    "expiry".into(),
                    format!("sweep_expired_messages timeslot_scan failed: {err}"),
                )
            })?;

        let mut report = ExpiryReport {
            timeslots_swept: timeslot_keys.len() as u32,
            ..Default::default()
        };

        for key in &timeslot_keys {
            let mut conn = self.db.get_connection().await?;
            loop {
                let msg_id: Option<String> = redis::cmd("SPOP")
                    .arg(key)
                    .query_async(&mut conn)
                    .await
                    .map_err(|err| {
                        MediatorError::DatabaseError(
                            14,
                            "expiry".into(),
                            format!("sweep_expired_messages SPOP failed: {err}"),
                        )
                    })?;

                if let Some(msg_id) = msg_id {
                    match self
                        .db
                        .handler
                        .delete_message(None, admin_did_hash, &msg_id, None, Some(admin_did_hash))
                        .await
                    {
                        Ok(_) => report.expired += 1,
                        Err(_) => report.already_deleted += 1,
                    }
                } else {
                    redis::cmd("ZREM")
                        .arg("MSG_EXPIRY")
                        .arg(key)
                        .exec_async(&mut conn)
                        .await
                        .map_err(|err| {
                            MediatorError::DatabaseError(
                                14,
                                "expiry".into(),
                                format!("sweep_expired_messages ZREM failed: {err}"),
                            )
                        })?;
                    break;
                }
            }
        }

        Ok(report)
    }
}

// `oob_expires_at` / `encode_oob_invite` moved up to `crate::store`
// so non-Redis builds can call them too.
