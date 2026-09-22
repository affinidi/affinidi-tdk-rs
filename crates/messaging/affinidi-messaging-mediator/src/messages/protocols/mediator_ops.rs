//! Handlers for the mediator-operations Trust Tasks — the `messaging/stats/*`,
//! `messaging/queue/*`, `messaging/message/*` and `messaging/monitor/*`
//! families (trustoverip/dtgwg-trust-tasks-tf#549).
//!
//! These are what an operator console runs on: mediator-wide telemetry and
//! queue rankings for an administrator, and an account's own queues and
//! messages for its controller. Dispatch, acceptance checks and response
//! signing are shared with the account/ACL tasks in [`super::trust_tasks`].

use std::cmp::Ordering;
use std::collections::HashMap;

use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_messaging_mediator_common::store::types::{DeletionAuthority, DeliveryState};
use affinidi_messaging_mediator_common::store::{PurgeFilter, PurgeReport};
use affinidi_messaging_mediator_common::types::accounts::AccountType;
use affinidi_messaging_mediator_common::types::audit::AuditAction;
use affinidi_messaging_mediator_common::types::messages::{Folder, MessageProtocol};
use chrono::{DateTime, Utc};
use http::StatusCode;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use trust_tasks_rs::TrustTask;
use trust_tasks_rs::specs::messaging::{message, monitor, queue, stats};
use uuid::Uuid;

use crate::SharedData;
use crate::common::authz::{self, Capability};
use crate::common::session::Session;
use crate::messages::protocols::mediator::acls::check_permissions;
use crate::messages::protocols::mediator::record_audit;
use crate::messages::protocols::trust_tasks::{
    require_admin, serialize_err, tt_problem, validate_tt_basic,
};
use crate::tasks::queue_survey::{AccountQueues, FolderStats, QueueSnapshot};

/// How many messages of one queue `queue/status` reads to break it down by
/// counterparty. The breakdown covers the oldest this-many messages; a deeper
/// queue is reported on that prefix, which is where a stall shows first.
const PEER_SCAN_LIMIT: u32 = 2_000;

/// Default and maximum page size for `messaging/queue/list`.
const QUEUE_LIST_DEFAULT_LIMIT: usize = 50;
const QUEUE_LIST_MAX_LIMIT: usize = 500;

/// Handle `messaging/stats/show`: admin-only mediator-wide telemetry.
///
/// Lifetime counters come from the store, connection and forwarding state from
/// the running process, and the queue aggregate from the latest survey (absent
/// until the first one completes, a minute after start).
pub(crate) async fn consume_stats_show(
    typed: TrustTask<stats::show::v0_1::Payload>,
    state: &SharedData,
    session: &Session,
    mediator_did: &str,
    now: DateTime<Utc>,
) -> Result<Value, MediatorError> {
    validate_tt_basic(&typed, session, mediator_did, now)?;
    require_admin(session, "messaging/stats/show")?;

    let totals = state.database.get_global_stats().await?;
    let forward_queue_length = state.database.forward_queue_len().await?;
    let non_negative = |v: i64| v.max(0) as u64;

    let mut response = json!({
        "version": env!("CARGO_PKG_VERSION"),
        "startedAt": state.service_start_timestamp,
        "uptimeSeconds": non_negative(now.signed_duration_since(state.service_start_timestamp).num_seconds()),
        "connections": {
            "websocketActive": state
                .active_websocket_count
                .load(std::sync::atomic::Ordering::Relaxed),
        },
        "totals": {
            "receivedCount": non_negative(totals.received_count),
            "receivedBytes": non_negative(totals.received_bytes),
            "sentCount": non_negative(totals.sent_count),
            "sentBytes": non_negative(totals.sent_bytes),
            "deletedCount": non_negative(totals.deleted_count),
            "deletedBytes": non_negative(totals.deleted_bytes),
            "websocketOpened": non_negative(totals.websocket_open),
            "websocketClosed": non_negative(totals.websocket_close),
            "sessionsCreated": non_negative(totals.sessions_created),
            "sessionsAuthenticated": non_negative(totals.sessions_success),
            "invitationsCreated": non_negative(totals.oob_invites_created),
            "invitationsClaimed": non_negative(totals.oob_invites_claimed),
        },
        "forwarding": {
            "queueLength": forward_queue_length,
            "queueLimit": state.limits().forward_task_queue,
            "circuitBreaker": match state.database.circuit_breaker_state() {
                "open" => "open",
                "half_open" => "halfOpen",
                _ => "closed",
            },
        },
    });
    // 0 means "no ceiling configured"; the spec says to omit it then.
    if state.config.limits.max_websocket_connections > 0 {
        response["connections"]["websocketMax"] =
            json!(state.config.limits.max_websocket_connections);
    }
    if let Some(snapshot) = state.queue_snapshot.latest() {
        response["queues"] = json!({
            "surveyedAt": snapshot.taken_at,
            "accounts": snapshot.survey.accounts_surveyed,
            "truncated": snapshot.survey.truncated,
            "receive": aggregate_depth(&snapshot.survey.inbox),
            "send": aggregate_depth(&snapshot.survey.outbox),
        });
    }

    let response: stats::show::v0_1::Response = from_json(response)?;
    serde_json::to_value(typed.respond_with(Uuid::new_v4().to_string(), response))
        .map_err(serialize_err)
}

/// A folder's totals as a `QueueDepth`. `saturation` is the highest single
/// queue's and `oldestAgeSeconds` the oldest probed message's; `limit` and
/// `deliveredUnacked` have no aggregate meaning (the latter is a sample) and
/// are omitted.
fn aggregate_depth(folder: &FolderStats) -> Value {
    let mut depth = json!({ "count": folder.messages, "bytes": folder.bytes });
    if let Some(saturation) = folder.max_saturation {
        depth["saturation"] = json!(saturation);
    }
    if let Some(oldest) = &folder.oldest {
        depth["oldestAgeSeconds"] = json!(oldest.age_secs);
    }
    depth
}

/// Handle `messaging/queue/list`: admin-only ranking of accounts by queue
/// depth, bytes, oldest message or saturation.
///
/// Served from the latest survey, not a live walk: `snapshotAt` says how old
/// it is (at most about a minute), and `truncated` whether it covered every
/// account. A cursor pins the snapshot its first page came from, so paging
/// never mixes two rankings; one whose snapshot has since been replaced is
/// refused and the client starts again.
pub(crate) async fn consume_queue_list(
    typed: TrustTask<queue::list::v0_1::Payload>,
    state: &SharedData,
    session: &Session,
    mediator_did: &str,
    now: DateTime<Utc>,
) -> Result<Value, MediatorError> {
    use queue::list::v0_1::{PayloadSort, Queue};

    validate_tt_basic(&typed, session, mediator_did, now)?;
    require_admin(session, "messaging/queue/list")?;

    let Some(snapshot) = state.queue_snapshot.latest() else {
        return Err(tt_problem(
            session,
            "message.trust_task.unavailable",
            "no queue survey has completed yet; the first runs a minute after start".into(),
            StatusCode::SERVICE_UNAVAILABLE,
        ));
    };

    let payload = &typed.payload;
    let receive = !matches!(payload.queue, Some(Queue::Send));
    let sort = payload.sort.unwrap_or(PayloadSort::Count);
    let min_count = payload.min_count.unwrap_or(1);
    let limit = payload
        .limit
        .map_or(QUEUE_LIST_DEFAULT_LIMIT, |n| n.get() as usize)
        .min(QUEUE_LIST_MAX_LIMIT);

    let offset = match &payload.cursor {
        None => 0,
        Some(cursor) => parse_cursor(cursor, &snapshot).ok_or_else(|| {
            tt_problem(
                session,
                "message.trust_task.malformed",
                "the cursor belongs to a queue survey that has since been replaced; \
                 start again without a cursor"
                    .into(),
                StatusCode::BAD_REQUEST,
            )
        })?,
    };

    let response = ranked_page(&snapshot, receive, sort, min_count, offset, limit);
    let response: queue::list::v0_1::Response = from_json(response)?;
    serde_json::to_value(typed.respond_with(Uuid::new_v4().to_string(), response))
        .map_err(serialize_err)
}

/// Handle `messaging/queue/status`: one account's two queues, live.
///
/// Self or admin — an omitted `did` is the requester's own account. Depth
/// comes from the account record, limits are the effective ones (the account's
/// own, else the mediator default), and each queue's oldest message is one
/// range read. With `includePeers`, each queue is also broken down by
/// counterparty: in the send queue that is *who has not collected* — a message
/// is held against its sender until the recipient deletes it, so a stalled
/// recipient shows up as the top entry in its senders' send queues.
pub(crate) async fn consume_queue_status(
    typed: TrustTask<queue::status::v0_1::Payload>,
    state: &SharedData,
    session: &Session,
    sender_kid: &Option<String>,
    mediator_did: &str,
    now: DateTime<Utc>,
) -> Result<Value, MediatorError> {
    validate_tt_basic(&typed, session, mediator_did, now)?;

    let target = typed
        .payload
        .did
        .as_ref()
        .map_or_else(|| session.did_hash.clone(), |d| d.to_string());
    if !check_permissions(
        session,
        std::slice::from_ref(&target),
        state.config.security.block_remote_admin_msgs,
        sender_kid,
    ) {
        return Err(tt_problem(
            session,
            "authorization.account.denied",
            format!("not permitted to read the queues of account {target}"),
            StatusCode::FORBIDDEN,
        ));
    }
    let account = state.database.account_get(&target).await?.ok_or_else(|| {
        tt_problem(
            session,
            "account.not_found",
            format!("account {target} not found"),
            StatusCode::NOT_FOUND,
        )
    })?;

    let limits = state.limits();
    let receive_limit = account
        .queue_receive_limit
        .unwrap_or(limits.queued_receive_messages_soft);
    let send_limit = account
        .queue_send_limit
        .unwrap_or(limits.queued_send_messages_soft);
    let now_secs = state.clock.unix_secs();

    let receive = live_depth(
        state,
        &target,
        Folder::Inbox,
        account.receive_queue_count,
        account.receive_queue_bytes,
        receive_limit,
        now_secs,
    )
    .await;
    let send = live_depth(
        state,
        &target,
        Folder::Outbox,
        account.send_queue_count,
        account.send_queue_bytes,
        send_limit,
        now_secs,
    )
    .await;

    let mut summary = json!({ "did": target, "receive": receive, "send": send });
    if let Some(role) = account_type_name(&account._type) {
        summary["accountType"] = json!(role);
    }
    let mut response = json!({ "queues": summary });

    if let Some(top) = typed.payload.include_peers {
        let top = top.get() as usize;
        response["receivePeers"] =
            json!(peer_breakdown(state, &target, Folder::Inbox, top, now_secs).await?);
        response["sendPeers"] =
            json!(peer_breakdown(state, &target, Folder::Outbox, top, now_secs).await?);
    }

    let response: queue::status::v0_1::Response = from_json(response)?;
    serde_json::to_value(typed.respond_with(Uuid::new_v4().to_string(), response))
        .map_err(serialize_err)
}

/// One queue's live `QueueDepth`. The oldest-message read is best-effort: a
/// queue whose age cannot be read still reports its depth.
async fn live_depth(
    state: &SharedData,
    did_hash: &str,
    folder: Folder,
    count: u32,
    bytes: u64,
    limit: i32,
    now_secs: u64,
) -> Value {
    let mut depth = json!({ "count": count, "bytes": bytes, "limit": limit.max(-1) });
    if limit > 0 {
        depth["saturation"] = json!(f64::from(count) / f64::from(limit));
    }
    if let Ok(oldest) = state
        .database
        .list_messages(did_hash, folder, Some(("-", "+")), 1)
        .await
        && let Some(first) = oldest.first()
    {
        depth["oldestAgeSeconds"] = json!(now_secs.saturating_sub(first.timestamp / 1_000));
    }
    depth
}

/// The top `top` counterparties of one queue by message count, over its oldest
/// [`PEER_SCAN_LIMIT`] messages. In an inbox the counterparty is the sender
/// (anonymous messages have none and are left out); in an outbox, the
/// recipient.
async fn peer_breakdown(
    state: &SharedData,
    did_hash: &str,
    folder: Folder,
    top: usize,
    now_secs: u64,
) -> Result<Vec<Value>, MediatorError> {
    let inbox = matches!(folder, Folder::Inbox);
    let messages = state
        .database
        .list_messages(did_hash, folder, Some(("-", "+")), PEER_SCAN_LIMIT)
        .await?;

    // peer → (count, bytes, oldest arrival ms)
    let mut peers: HashMap<String, (u64, u64, u64)> = HashMap::new();
    for m in &messages {
        let peer = if inbox {
            &m.from_address
        } else {
            &m.to_address
        };
        let Some(peer) = peer else { continue };
        let entry = peers.entry(peer.clone()).or_insert((0, 0, u64::MAX));
        entry.0 += 1;
        entry.1 += m.size;
        entry.2 = entry.2.min(m.timestamp);
    }
    let mut ranked: Vec<(String, (u64, u64, u64))> = peers.into_iter().collect();
    ranked.sort_by(|a, b| b.1.0.cmp(&a.1.0).then_with(|| a.0.cmp(&b.0)));
    Ok(ranked
        .into_iter()
        .take(top)
        .map(|(peer, (count, bytes, oldest_ms))| {
            json!({
                "peer": peer,
                "count": count,
                "bytes": bytes,
                "oldestAgeSeconds": now_secs.saturating_sub(oldest_ms / 1_000),
            })
        })
        .collect())
}

/// Default and maximum page size for `messaging/message/list`, and how many
/// entries one call may examine when a `peer` filter skips most of them.
const MESSAGE_LIST_DEFAULT_LIMIT: u32 = 100;
const MESSAGE_LIST_MAX_LIMIT: u32 = 500;
const MESSAGE_LIST_MAX_SCAN: u32 = 5_000;

/// The largest stored message `messaging/message/get` returns (10 MiB, the
/// spec's `message` bound).
const MESSAGE_GET_MAX_BYTES: u64 = 10 * 1024 * 1024;

/// Resolve the account a self-or-admin message task targets, and authorise it.
///
/// An omitted `did` is the requester's own account, which additionally needs
/// the `local` capability — the same gate as the REST `/list`, `/delete` and
/// `/purge` routes, since only a locally served account has queues here.
/// Another account needs admin standing.
fn message_target(
    did: Option<String>,
    state: &SharedData,
    session: &Session,
    sender_kid: &Option<String>,
) -> Result<String, MediatorError> {
    let target = did.unwrap_or_else(|| session.did_hash.clone());
    if target == session.did_hash {
        if authz::require_capability(&session.acls, Capability::Local).is_err() {
            return Err(tt_problem(
                session,
                "authorization.local",
                "the account is not local to this mediator".into(),
                StatusCode::FORBIDDEN,
            ));
        }
    } else if !check_permissions(
        session,
        std::slice::from_ref(&target),
        state.config.security.block_remote_admin_msgs,
        sender_kid,
    ) {
        return Err(tt_problem(
            session,
            "authorization.account.denied",
            format!("not permitted to act on the messages of account {target}"),
            StatusCode::FORBIDDEN,
        ));
    }
    Ok(target)
}

/// The next stream id strictly after `id` (`"<ms>-<seq>"` in every backend).
fn stream_successor(id: &str) -> Option<String> {
    let (ms, seq) = id.split_once('-')?;
    let ms: u64 = ms.parse().ok()?;
    let seq: u64 = seq.parse().ok()?;
    Some(format!("{ms}-{}", seq.checked_add(1)?))
}

/// Handle `messaging/message/list`: stored-message metadata for one queue,
/// oldest first. Never a body. Self (with `local`) or admin.
///
/// `peer` narrows to one counterparty — the sender in a receive queue, the
/// recipient in a send queue. The filter is applied while paging, so a page
/// may come back short with a `nextCursor`; one call examines at most
/// [`MESSAGE_LIST_MAX_SCAN`] entries.
pub(crate) async fn consume_message_list(
    typed: TrustTask<message::list::v0_1::Payload>,
    state: &SharedData,
    session: &Session,
    sender_kid: &Option<String>,
    mediator_did: &str,
    now: DateTime<Utc>,
) -> Result<Value, MediatorError> {
    use message::list::v0_1::Queue;

    validate_tt_basic(&typed, session, mediator_did, now)?;
    let payload = &typed.payload;
    let target = message_target(
        payload.did.as_ref().map(|d| d.to_string()),
        state,
        session,
        sender_kid,
    )?;
    if state.database.account_get(&target).await?.is_none() {
        return Err(tt_problem(
            session,
            "account.not_found",
            format!("account {target} not found"),
            StatusCode::NOT_FOUND,
        ));
    }

    let receive = !matches!(payload.queue, Queue::Send);
    let folder = if receive {
        Folder::Inbox
    } else {
        Folder::Outbox
    };
    let limit = payload.limit.map_or(MESSAGE_LIST_DEFAULT_LIMIT, |n| {
        n.get().min(u64::from(MESSAGE_LIST_MAX_LIMIT)) as u32
    });
    let peer = payload.peer.as_ref().map(|p| p.to_string());

    let mut start = match &payload.cursor {
        Some(c) => stream_successor(c).ok_or_else(|| {
            tt_problem(
                session,
                "message.trust_task.malformed",
                "invalid cursor".into(),
                StatusCode::BAD_REQUEST,
            )
        })?,
        None => "-".to_string(),
    };
    let mut kept = Vec::new();
    let mut scanned = 0u32;
    let mut last_seen: Option<String> = None;
    let mut exhausted = false;
    while (kept.len() as u32) < limit && scanned < MESSAGE_LIST_MAX_SCAN {
        let batch = limit.min(MESSAGE_LIST_MAX_SCAN - scanned);
        let page = state
            .database
            .list_messages(&target, folder.clone(), Some((&start, "+")), batch)
            .await?;
        let got = page.len() as u32;
        for m in page {
            scanned += 1;
            let stream_id = if receive {
                m.receive_id.clone()
            } else {
                m.send_id.clone()
            };
            let counterparty = if receive {
                &m.from_address
            } else {
                &m.to_address
            };
            let wanted = peer
                .as_ref()
                .is_none_or(|p| counterparty.as_deref() == Some(p));
            if let Some(id) = &stream_id {
                last_seen = Some(id.clone());
            }
            if wanted {
                kept.push(m);
                if kept.len() as u32 == limit {
                    break;
                }
            }
        }
        if got < batch {
            exhausted = true;
            break;
        }
        match last_seen.as_deref().and_then(stream_successor) {
            Some(next) => start = next,
            None => {
                exhausted = true;
                break;
            }
        }
    }

    let ids: Vec<String> = kept.iter().map(|m| m.msg_id.clone()).collect();
    let states = state
        .database
        .delivery_states(&ids)
        .await
        .unwrap_or_default();
    let queue_name = if receive { "receive" } else { "send" };
    let messages: Vec<Value> = kept
        .iter()
        .enumerate()
        .map(|(i, m)| {
            let mut meta = json!({
                "msgId": m.msg_id,
                "queue": queue_name,
                "size": m.size,
                "receivedAt": millis_to_datetime(m.timestamp),
            });
            if let Some(from) = &m.from_address {
                meta["from"] = json!(from);
            }
            if let Some(to) = &m.to_address {
                meta["to"] = json!(to);
            }
            apply_delivery_state(&mut meta, states.get(i).cloned().flatten());
            meta
        })
        .collect();

    let mut response = json!({ "messages": messages });
    if !exhausted && let Some(last) = last_seen {
        response["nextCursor"] = json!(last);
    }
    let response: message::list::v0_1::Response = from_json(response)?;
    serde_json::to_value(typed.respond_with(Uuid::new_v4().to_string(), response))
        .map_err(serialize_err)
}

/// Handle `messaging/message/get`: one stored message, verbatim and
/// undecrypted, with its metadata.
///
/// An account's own message (with `local`); another account's only for a
/// **rootAdmin** — it is the one read here that can expose content a plain
/// admin should not see (a signed-only or plaintext DIDComm message is
/// readable without the recipient's key) — and such a read is audited. This
/// is not a pickup: the message's delivery state is unchanged. The response is
/// signed, as the spec requires, by the shared response path.
pub(crate) async fn consume_message_get(
    typed: TrustTask<message::get::v0_1::Payload>,
    state: &SharedData,
    session: &Session,
    sender_kid: &Option<String>,
    mediator_did: &str,
    now: DateTime<Utc>,
) -> Result<Value, MediatorError> {
    validate_tt_basic(&typed, session, mediator_did, now)?;
    let payload = &typed.payload;
    let requested = payload.did.as_ref().map(|d| d.to_string());
    let cross_account = requested.as_ref().is_some_and(|d| *d != session.did_hash);
    if cross_account && session.account_type != AccountType::RootAdmin {
        return Err(tt_problem(
            session,
            "messaging/message/get:rootAdminRequired",
            "reading another account's stored message requires a rootAdmin".into(),
            StatusCode::FORBIDDEN,
        ));
    }
    let target = message_target(requested, state, session, sender_kid)?;
    if state.database.account_get(&target).await?.is_none() {
        return Err(tt_problem(
            session,
            "messaging/message/get:unknownAccount",
            format!("account {target} not found"),
            StatusCode::NOT_FOUND,
        ));
    }

    let msg_id = payload.msg_id.to_string();
    // `get_message` answers `None` unless `target` is the message's sender or
    // recipient — so an id from someone else's queue is indistinguishable
    // from one that does not exist.
    let Some(stored) = state.database.get_message(&target, &msg_id).await? else {
        return Err(tt_problem(
            session,
            "messaging/message/get:unknownMessage",
            format!("no message {msg_id} in the queues of account {target}"),
            StatusCode::NOT_FOUND,
        ));
    };
    if stored.size > MESSAGE_GET_MAX_BYTES {
        return Err(tt_problem(
            session,
            "messaging/message/get:messageTooLarge",
            format!(
                "message {msg_id} is {} bytes; the limit is {MESSAGE_GET_MAX_BYTES}",
                stored.size
            ),
            StatusCode::PAYLOAD_TOO_LARGE,
        ));
    }
    let Some(body) = stored.msg.clone() else {
        return Err(tt_problem(
            session,
            "messaging/message/get:unknownMessage",
            format!("message {msg_id} has no stored body"),
            StatusCode::NOT_FOUND,
        ));
    };

    let receive = stored.to_address.as_deref() == Some(target.as_str());
    let mut meta = json!({
        "msgId": stored.msg_id,
        "queue": if receive { "receive" } else { "send" },
        "size": stored.size,
        "receivedAt": millis_to_datetime(stored.timestamp),
        "protocol": wire_protocol(&body),
    });
    if let Some(from) = &stored.from_address {
        meta["from"] = json!(from);
    }
    if let Some(to) = &stored.to_address {
        meta["to"] = json!(to);
    }
    let delivery = state.database.delivery_state(&msg_id).await.ok().flatten();
    apply_delivery_state(&mut meta, delivery);

    if cross_account {
        record_audit(
            state,
            session,
            &target,
            AuditAction::MessageRead,
            format!("read message {msg_id} ({} bytes)", stored.size),
        )
        .await;
    }

    let response: message::get::v0_1::Response =
        from_json(json!({ "meta": meta, "message": body }))?;
    serde_json::to_value(typed.respond_with(Uuid::new_v4().to_string(), response))
        .map_err(serialize_err)
}

/// Handle `messaging/monitor/subscribe`: open or renew a leased, filtered live
/// tap on the mediator's traffic metadata (see [`crate::monitor`]).
///
/// An administrator may watch anything. Anyone else sees only traffic to or
/// from their own account: an omitted `dids` is narrowed to it, and naming any
/// other account is refused rather than silently narrowed. The response
/// carries the filter actually in force.
pub(crate) async fn consume_monitor_subscribe(
    typed: TrustTask<monitor::subscribe::v0_1::Payload>,
    state: &SharedData,
    session: &Session,
    mediator_did: &str,
    now: DateTime<Utc>,
    transport: super::trust_tasks::TaskTransport,
) -> Result<Value, MediatorError> {
    use crate::monitor::{
        DEFAULT_LEASE_SECONDS, DEFAULT_MAX_EVENTS_PER_SECOND, Delivery, Filter,
        MAX_EVENTS_PER_SECOND, MAX_LEASE_SECONDS, MonitorError,
    };

    validate_tt_basic(&typed, session, mediator_did, now)?;
    let payload = &typed.payload;
    let is_admin = matches!(
        session.account_type,
        AccountType::Admin | AccountType::RootAdmin
    );

    let mut filter: Filter = match &payload.filter {
        Some(f) => serde_json::to_value(f)
            .and_then(serde_json::from_value)
            .map_err(serialize_err)?,
        None => Filter::default(),
    };
    if !is_admin {
        match &filter.dids {
            None => filter.dids = Some(vec![session.did_hash.clone()]),
            Some(dids) if dids.iter().all(|d| *d == session.did_hash) => {}
            Some(_) => {
                return Err(tt_problem(
                    session,
                    "permissionDenied",
                    "only an administrator may monitor another account's traffic".into(),
                    StatusCode::FORBIDDEN,
                ));
            }
        }
    }

    let lease = payload.lease_seconds.map_or(DEFAULT_LEASE_SECONDS, |s| {
        s.clamp(10, MAX_LEASE_SECONDS as i64) as u64
    });
    let max_eps = payload
        .max_events_per_second
        .map_or(DEFAULT_MAX_EVENTS_PER_SECOND, |n| {
            n.get().min(MAX_EVENTS_PER_SECOND)
        });
    let renew = payload.subscription_id.as_ref().map(|s| s.to_string());

    // Served over the transport it was opened on: a TSP subscriber's batches
    // are sealed to its VID, which needs its encryption key. Resolving it here
    // rather than per batch also means a VID the mediator cannot resolve is
    // refused at subscribe time instead of quietly dropping every batch.
    let delivery = match transport {
        super::trust_tasks::TaskTransport::DidComm => Delivery::DidComm,
        #[cfg(feature = "tsp")]
        super::trust_tasks::TaskTransport::Tsp => {
            let resolved =
                crate::messages::inbound::resolve_tsp_vid(state, &session.did, &session.session_id)
                    .await?;
            Delivery::Tsp {
                encryption_key: resolved.encryption_key,
            }
        }
    };

    let granted = state
        .monitor
        .subscribe(
            state,
            &session.did,
            &session.did_hash,
            renew.as_deref(),
            filter,
            lease,
            max_eps,
            delivery,
        )
        .await
        .map_err(|e| match e {
            MonitorError::UnknownSubscription => tt_problem(
                session,
                "messaging/monitor/subscribe:unknownSubscription",
                "no such subscription held by this account".into(),
                StatusCode::NOT_FOUND,
            ),
            MonitorError::TooManySubscriptions => tt_problem(
                session,
                "messaging/monitor/subscribe:tooManySubscriptions",
                format!(
                    "this account already holds {} monitor subscriptions",
                    crate::monitor::MAX_SUBSCRIPTIONS_PER_OWNER
                ),
                StatusCode::TOO_MANY_REQUESTS,
            ),
        })?;

    // An administrator's tap can see other accounts' traffic metadata, so it
    // is on the record: who watched which accounts, and for how long. (A
    // non-admin's subscription is confined to its own traffic.)
    if is_admin {
        let scope = granted
            .filter
            .dids
            .as_ref()
            .map_or_else(|| "all accounts".to_string(), |d| abbreviate(d));
        record_audit(
            state,
            session,
            granted
                .filter
                .dids
                .as_ref()
                .and_then(|d| (d.len() == 1).then(|| d[0].as_str()))
                .unwrap_or("*"),
            AuditAction::MonitorSubscribe,
            format!(
                "{} monitor {} watching {scope} for {lease}s (filter: {})",
                if renew.is_some() { "renewed" } else { "opened" },
                granted.subscription_id,
                granted.filter.to_json(),
            ),
        )
        .await;
    }

    let response: monitor::subscribe::v0_1::Response = from_json(json!({
        "subscriptionId": granted.subscription_id,
        "expiresAt": granted.expires_at,
        "filter": granted.filter.to_json(),
        "maxEventsPerSecond": granted.max_eps,
    }))?;
    serde_json::to_value(typed.respond_with(Uuid::new_v4().to_string(), response))
        .map_err(serialize_err)
}

/// Handle `messaging/monitor/unsubscribe`: end a subscription — the owner's
/// own, or any for a rootAdmin. Another account's id answers exactly as an
/// unknown one does.
pub(crate) async fn consume_monitor_unsubscribe(
    typed: TrustTask<monitor::unsubscribe::v0_1::Payload>,
    state: &SharedData,
    session: &Session,
    mediator_did: &str,
    now: DateTime<Utc>,
) -> Result<Value, MediatorError> {
    validate_tt_basic(&typed, session, mediator_did, now)?;
    let subscription_id = typed.payload.subscription_id.to_string();
    let (sent, dropped) = state
        .monitor
        .unsubscribe(
            &subscription_id,
            &session.did_hash,
            session.account_type == AccountType::RootAdmin,
        )
        .map_err(|_| {
            tt_problem(
                session,
                "messaging/monitor/unsubscribe:unknownSubscription",
                "no such subscription held by this account".into(),
                StatusCode::NOT_FOUND,
            )
        })?;
    if matches!(
        session.account_type,
        AccountType::Admin | AccountType::RootAdmin
    ) {
        record_audit(
            state,
            session,
            "*",
            AuditAction::MonitorUnsubscribe,
            format!("ended monitor {subscription_id} ({sent} events sent, {dropped} dropped)"),
        )
        .await;
    }
    let response: monitor::unsubscribe::v0_1::Response =
        from_json(json!({ "eventsSent": sent, "eventsDropped": dropped }))?;
    serde_json::to_value(typed.respond_with(Uuid::new_v4().to_string(), response))
        .map_err(serialize_err)
}

/// Refuse a destructive operation on a privileged account's queue unless the
/// requester is a rootAdmin. An account acting on its own queue is exempt: the
/// guard protects administrators' queues from *other* administrators.
fn guard_privileged_target(
    target: &str,
    target_type: AccountType,
    session: &Session,
    code: &str,
) -> Result<(), MediatorError> {
    let privileged = matches!(
        target_type,
        AccountType::Admin | AccountType::RootAdmin | AccountType::Mediator
    );
    if privileged && target != session.did_hash && session.account_type != AccountType::RootAdmin {
        return Err(tt_problem(
            session,
            code,
            format!("acting on the queues of privileged account {target} requires a rootAdmin"),
            StatusCode::FORBIDDEN,
        ));
    }
    Ok(())
}

/// Handle `messaging/message/delete`: remove up to 100 stored messages from
/// one account's queues, reporting each id's outcome in request order.
///
/// Self (with `local`) or admin; an admin, admin/rootAdmin or mediator account
/// needs a rootAdmin. An id not in the target account's queues is a per-item
/// `notFound` — never a whole-task failure, and never reported deleted unless
/// the store removed it. Deleting another account's messages is audited.
pub(crate) async fn consume_message_delete(
    typed: TrustTask<message::delete::v0_1::Payload>,
    state: &SharedData,
    session: &Session,
    sender_kid: &Option<String>,
    mediator_did: &str,
    now: DateTime<Utc>,
) -> Result<Value, MediatorError> {
    validate_tt_basic(&typed, session, mediator_did, now)?;
    let payload = &typed.payload;
    let target = message_target(
        payload.did.as_ref().map(|d| d.to_string()),
        state,
        session,
        sender_kid,
    )?;
    let Some(account) = state.database.account_get(&target).await? else {
        return Err(tt_problem(
            session,
            "messaging/message/delete:unknownAccount",
            format!("account {target} not found"),
            StatusCode::NOT_FOUND,
        ));
    };
    guard_privileged_target(
        &target,
        account._type,
        session,
        "messaging/message/delete:rootAdminRequired",
    )?;

    let own = target == session.did_hash;
    let authority = if own {
        DeletionAuthority::Owner {
            did_hash: target.clone(),
        }
    } else {
        DeletionAuthority::Admin {
            admin_did_hash: session.did_hash.clone(),
        }
    };

    let mut results = Vec::with_capacity(payload.msg_ids.len());
    let mut deleted_ids = Vec::new();
    for id in &payload.msg_ids {
        let id = id.to_string();
        // Only messages the target account sends or receives are in scope;
        // `get_message` answers `None` for anything else.
        let Some(stored) = state.database.get_message(&target, &id).await? else {
            results.push(json!({ "msgId": id, "deleted": false, "reason": "notFound" }));
            continue;
        };
        match state.database.delete_message(&id, authority.clone()).await {
            Ok(()) => {
                state.monitor.deleted(
                    &id,
                    &target,
                    stored.from_address.as_deref(),
                    stored.to_address.as_deref(),
                    crate::monitor::Channel::Internal,
                );
                results.push(json!({ "msgId": id, "deleted": true }));
                deleted_ids.push(id);
            }
            // Gone between the lookup and the delete (a concurrent pickup or
            // expiry): not deleted by us, so not reported as deleted.
            Err(e) if is_not_found(&e) => {
                results.push(json!({ "msgId": id, "deleted": false, "reason": "notFound" }));
            }
            Err(e) => return Err(e),
        }
    }

    if !own && !deleted_ids.is_empty() {
        record_audit(
            state,
            session,
            &target,
            AuditAction::MessageDelete,
            format!(
                "deleted {} message(s): {}",
                deleted_ids.len(),
                abbreviate(&deleted_ids)
            ),
        )
        .await;
    }

    let response: message::delete::v0_1::Response = from_json(json!({ "results": results }))?;
    serde_json::to_value(typed.respond_with(Uuid::new_v4().to_string(), response))
        .map_err(serialize_err)
}

/// Handle `messaging/queue/purge`: remove every message in one account queue,
/// optionally only those exchanged with one counterparty or older than an
/// age — or, with `dryRun`, report what would go and remove nothing.
///
/// Self (with `local`) or admin; a privileged account's queue needs a
/// rootAdmin. Undelivered messages are gone, not returned to their senders.
/// Every real purge is audited, including one that removed nothing. What the
/// spec's response has no member for — messages examined, messages that
/// matched but could not be removed, and whether the walk hit its scan
/// ceiling — is reported under `ext["com.affinidi.mediator"]` rather than
/// dropped: a recovery tool must not imply a queue is emptier than it is.
pub(crate) async fn consume_queue_purge(
    typed: TrustTask<queue::purge::v0_1::Payload>,
    state: &SharedData,
    session: &Session,
    sender_kid: &Option<String>,
    mediator_did: &str,
    now: DateTime<Utc>,
) -> Result<Value, MediatorError> {
    use queue::purge::v0_1::Queue;

    validate_tt_basic(&typed, session, mediator_did, now)?;
    let payload = &typed.payload;
    let target = message_target(
        payload.did.as_ref().map(|d| d.to_string()),
        state,
        session,
        sender_kid,
    )?;
    let Some(account) = state.database.account_get(&target).await? else {
        return Err(tt_problem(
            session,
            "messaging/queue/purge:unknownAccount",
            format!("account {target} not found"),
            StatusCode::NOT_FOUND,
        ));
    };
    guard_privileged_target(
        &target,
        account._type,
        session,
        "messaging/queue/purge:rootAdminRequired",
    )?;

    let folder = if matches!(payload.queue, Queue::Send) {
        Folder::Outbox
    } else {
        Folder::Inbox
    };
    let dry_run = payload.dry_run.unwrap_or(false);
    let peer = payload.peer.as_ref().map(|p| p.to_string());
    let older_than = payload.older_than_seconds;

    let report = if peer.is_some() || older_than.is_some() || dry_run {
        let filter = PurgeFilter {
            peer: peer.clone(),
            arrived_before_ms: older_than.map(|secs| {
                state
                    .clock
                    .unix_millis()
                    .saturating_sub(u128::from(secs) * 1_000) as u64
            }),
            dry_run,
        };
        state
            .database
            .purge_folder_filtered(&target, folder.clone(), &filter)
            .await?
    } else {
        let (count, bytes) = state
            .database
            .purge_folder(&session.session_id, &target, folder.clone())
            .await?;
        PurgeReport {
            count,
            bytes,
            scanned: count,
            failed: 0,
            truncated: false,
        }
    };

    let queue_name = if matches!(folder, Folder::Outbox) {
        "send"
    } else {
        "receive"
    };
    if !dry_run {
        state.monitor.purged(
            &target,
            report.count,
            report.bytes,
            crate::monitor::Channel::Internal,
        );
        record_audit(
            state,
            session,
            &target,
            AuditAction::QueuePurge,
            format!(
                "purged {} message(s), {} bytes from the {queue_name} queue (peer: {}, older than: {}s){}",
                report.count,
                report.bytes,
                peer.as_deref().unwrap_or("any"),
                older_than.map_or_else(|| "any".to_string(), |s| s.to_string()),
                if report.failed > 0 || report.truncated {
                    format!("; {} failed, truncated: {}", report.failed, report.truncated)
                } else {
                    String::new()
                },
            ),
        )
        .await;
    }

    let response: queue::purge::v0_1::Response = from_json(json!({
        "matched": report.count + report.failed,
        "matchedBytes": report.bytes,
        "purged": if dry_run { 0 } else { report.count },
        "dryRun": dry_run,
        "ext": {
            "com.affinidi.mediator": {
                "scanned": report.scanned,
                "failed": report.failed,
                "truncated": report.truncated,
            }
        },
    }))?;
    serde_json::to_value(typed.respond_with(Uuid::new_v4().to_string(), response))
        .map_err(serialize_err)
}

/// Whether a store error means "no such message". The backends report it as
/// an internal error with code 404 and a `NOT_FOUND` marker.
fn is_not_found(e: &MediatorError) -> bool {
    matches!(e, MediatorError::InternalError(404, ..)) || e.to_string().contains("NOT_FOUND")
}

/// The first few ids for an audit line, with a count of the rest.
fn abbreviate(ids: &[String]) -> String {
    const SHOWN: usize = 5;
    let head = ids
        .iter()
        .take(SHOWN)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    match ids.len().saturating_sub(SHOWN) {
        0 => head,
        more => format!("{head} and {more} more"),
    }
}

/// Set `deliveryState` / `deliveredAt` on a `MessageMeta` from the store's
/// record. Absent when the backend keeps no record.
fn apply_delivery_state(meta: &mut Value, state: Option<DeliveryState>) {
    let Some(state) = state else { return };
    match state.first_delivered_at_ms {
        Some(ms) => {
            meta["deliveryState"] = json!("delivered");
            meta["deliveredAt"] = json!(millis_to_datetime(ms));
        }
        None => meta["deliveryState"] = json!("queued"),
    }
}

/// The spec's `WireProtocol` for a stored message body.
fn wire_protocol(body: &str) -> &'static str {
    match MessageProtocol::detect(body) {
        MessageProtocol::DidComm => "didcomm",
        MessageProtocol::Tsp => "tsp",
        _ => "other",
    }
}

fn millis_to_datetime(ms: u64) -> DateTime<Utc> {
    DateTime::from_timestamp_millis(ms as i64).unwrap_or_default()
}

/// One page of the ranking, as a `queue/list` response body.
fn ranked_page(
    snapshot: &QueueSnapshot,
    receive: bool,
    sort: queue::list::v0_1::PayloadSort,
    min_count: u64,
    offset: usize,
    limit: usize,
) -> Value {
    let mut ranked: Vec<&AccountQueues> = snapshot
        .survey
        .accounts
        .iter()
        .filter(|a| {
            u64::from(if receive {
                a.receive_count
            } else {
                a.send_count
            }) >= min_count
        })
        .collect();
    ranked.sort_by(|a, b| rank(b, a, sort, receive));

    let page: Vec<Value> = ranked
        .iter()
        .skip(offset)
        .take(limit)
        .map(|a| queue_summary(a))
        .collect();
    let next = offset + page.len();

    let mut response = json!({
        "queues": page,
        "snapshotAt": snapshot.taken_at,
        "truncated": snapshot.survey.truncated,
    });
    if next < ranked.len() {
        response["nextCursor"] = json!(format!("{}:{next}", snapshot.taken_at.timestamp()));
    }
    response
}

/// Order two accounts by the requested key on the chosen queue. Called as
/// `rank(b, a)` for a descending sort. A queue with no reading for the key
/// (unmeasured age, unlimited saturation) sorts after every one that has one;
/// ties fall back to depth, then DID hash, so pages are stable.
fn rank(
    a: &AccountQueues,
    b: &AccountQueues,
    sort: queue::list::v0_1::PayloadSort,
    receive: bool,
) -> Ordering {
    use queue::list::v0_1::PayloadSort;
    let key = |x: &AccountQueues| -> (u32, u64, Option<u64>, Option<f64>) {
        if receive {
            (
                x.receive_count,
                x.receive_bytes,
                x.receive_oldest_secs,
                x.receive_saturation(),
            )
        } else {
            (
                x.send_count,
                x.send_bytes,
                x.send_oldest_secs,
                x.send_saturation(),
            )
        }
    };
    let (ac, ab, ao, asat) = key(a);
    let (bc, bb, bo, bsat) = key(b);
    let primary = match sort {
        PayloadSort::Bytes => ab.cmp(&bb),
        PayloadSort::Oldest => ao.cmp(&bo),
        PayloadSort::Saturation => match (asat, bsat) {
            (Some(x), Some(y)) => x.partial_cmp(&y).unwrap_or(Ordering::Equal),
            (Some(_), None) => Ordering::Greater,
            (None, Some(_)) => Ordering::Less,
            (None, None) => Ordering::Equal,
        },
        // `Count`, and any sort key a later spec version adds.
        _ => ac.cmp(&bc),
    };
    primary
        .then(ac.cmp(&bc))
        .then_with(|| b.did_hash.cmp(&a.did_hash))
}

/// One account's `QueueSummary`.
fn queue_summary(a: &AccountQueues) -> Value {
    let depth = |count: u32, bytes: u64, limit: i32, oldest: Option<u64>, sat: Option<f64>| {
        let mut d = json!({ "count": count, "bytes": bytes, "limit": limit.max(-1) });
        if let Some(s) = sat {
            d["saturation"] = json!(s);
        }
        if let Some(o) = oldest {
            d["oldestAgeSeconds"] = json!(o);
        }
        d
    };
    let mut summary = json!({
        "did": a.did_hash,
        "receive": depth(a.receive_count, a.receive_bytes, a.receive_limit, a.receive_oldest_secs, a.receive_saturation()),
        "send": depth(a.send_count, a.send_bytes, a.send_limit, a.send_oldest_secs, a.send_saturation()),
    });
    if let Some(role) = account_type_name(&a.account_type) {
        summary["accountType"] = json!(role);
    }
    summary
}

/// The spec's `AccountType` name, or `None` for a role it does not define.
fn account_type_name(role: &AccountType) -> Option<&'static str> {
    match role {
        AccountType::Standard => Some("standard"),
        AccountType::Admin => Some("admin"),
        AccountType::RootAdmin => Some("rootAdmin"),
        AccountType::Mediator => Some("mediator"),
        AccountType::Unknown => None,
    }
}

/// A `queue/list` cursor is `"<snapshot unix secs>:<offset>"`; it is valid only
/// against the snapshot it was issued from.
fn parse_cursor(cursor: &str, snapshot: &QueueSnapshot) -> Option<usize> {
    let (taken, offset) = cursor.split_once(':')?;
    (taken.parse::<i64>().ok()? == snapshot.taken_at.timestamp()).then_some(())?;
    offset.parse().ok()
}

/// Build a generated response type from JSON. Deserialisation (rather than the
/// builders) keeps these handlers compiling when the spec gains an optional
/// member, and checks the shape against the generated types.
fn from_json<T: DeserializeOwned>(value: Value) -> Result<T, MediatorError> {
    serde_json::from_value(value).map_err(|e| {
        MediatorError::InternalError(
            14,
            "NA".into(),
            format!("couldn't build Trust Task response: {e}"),
        )
    })
}

/// `config/patch` — change mediator limits at runtime. rootAdmin only.
///
/// Each key is checked on its own (see
/// [`overrides::with_override`](crate::common::config::overrides::with_override));
/// a bad one is reported under `rejected` and does not stop the rest. The
/// accepted keys are stored as overrides, so they survive a restart, and then:
///
/// - a **live** key takes effect now and is reported `applied`;
/// - a **restart** key applies from the next start and is reported
///   `pendingRestart`.
///
/// A `null` value removes a key's override, returning it to the file/env value.
/// Nothing is applied unless the store kept the overrides.
pub(crate) async fn consume_config_patch(
    typed: TrustTask<trust_tasks_rs::specs::config::patch::v0_1::Payload>,
    state: &SharedData,
    session: &Session,
    mediator_did: &str,
    now: DateTime<Utc>,
) -> Result<Value, MediatorError> {
    use crate::common::config::overrides::{
        self, KeyClass, class_of, parse_stored, with_fields_from, with_override,
    };

    validate_tt_basic(&typed, session, mediator_did, now)?;
    if session.account_type != AccountType::RootAdmin {
        return Err(tt_problem(
            session,
            "authorization.root_admin_required",
            "config/patch changes the mediator for every account and requires a rootAdmin".into(),
            StatusCode::FORBIDDEN,
        ));
    }

    // One change at a time: this reads the stored overrides, adds to them and
    // writes them back, and interleaved patches would lose each other's keys.
    let _one_at_a_time = state.live_limits.lock_for_patch().await;
    let storage_err = |e: MediatorError| {
        tt_problem(
            session,
            "config.storage",
            format!("the mediator could not keep configuration overrides: {e}"),
            StatusCode::SERVICE_UNAVAILABLE,
        )
    };
    let stored = state
        .database
        .config_overrides_get()
        .await
        .map_err(storage_err)?;
    let mut stored = parse_stored(stored.as_deref());

    // What the configuration should become: the baseline with every stored
    // override, then this patch's keys in turn.
    let baseline = (*state.live_limits.baseline()).clone();
    let desired_from = |stored: &serde_json::Map<String, Value>| {
        let mut limits = baseline.clone();
        overrides::overlay(&mut limits, stored);
        limits
    };
    let mut desired = desired_from(&stored);

    let mut accepted: Vec<(String, KeyClass, Value)> = Vec::new();
    let mut rejected: Vec<Value> = Vec::new();
    for (key, value) in &typed.payload.overrides {
        let Some(class) = class_of(key) else {
            rejected.push(json!({ "key": key, "reason": "not a patchable configuration key" }));
            continue;
        };
        if value.is_null() {
            let mut without = stored.clone();
            without.remove(key);
            desired = desired_from(&without);
            stored = without;
            accepted.push((key.clone(), class, Value::Null));
            continue;
        }
        match with_override(&desired, &baseline, key, value) {
            Ok(next) => {
                desired = next;
                stored.insert(key.clone(), value.clone());
                accepted.push((key.clone(), class, value.clone()));
            }
            Err(reason) => rejected.push(json!({ "key": key, "reason": reason })),
        }
    }

    if !accepted.is_empty() {
        state
            .database
            .config_overrides_set(&Value::Object(stored).to_string())
            .await
            .map_err(storage_err)?;
    }

    let keys_of = |wanted: KeyClass| -> Vec<String> {
        accepted
            .iter()
            .filter(|(_, class, _)| *class == wanted)
            .map(|(key, ..)| key.clone())
            .collect()
    };
    let applied = keys_of(KeyClass::Live);
    let pending_restart = keys_of(KeyClass::Restart);
    if !applied.is_empty() {
        let live = state.limits();
        state
            .live_limits
            .set(with_fields_from(&live, &desired, &applied));
    }

    if !accepted.is_empty() {
        let detail = accepted
            .iter()
            .map(|(key, class, value)| {
                let when = if *class == KeyClass::Live {
                    "now"
                } else {
                    "at restart"
                };
                if value.is_null() {
                    format!("{key} reset ({when})")
                } else {
                    format!("{key}={value} ({when})")
                }
            })
            .collect::<Vec<_>>()
            .join(", ");
        record_audit(
            state,
            session,
            &state.config.mediator_did_hash,
            AuditAction::ConfigPatch,
            detail,
        )
        .await;
    }

    let response: trust_tasks_rs::specs::config::patch::v0_1::Response =
        serde_json::from_value(json!({
            "applied": applied,
            "pendingRestart": pending_restart,
            "rejected": rejected,
        }))
        .map_err(serialize_err)?;
    serde_json::to_value(typed.respond_with(Uuid::new_v4().to_string(), response))
        .map_err(serialize_err)
}

/// `config/reload` — re-read the limits from the configuration file (and the
/// environment) the mediator was started from, without a restart. rootAdmin.
///
/// The file/env limits become the new baseline; the stored `config/patch`
/// overrides are laid over it again, held to the same bounds (so an override
/// looser than a newly lowered configured value no longer applies). Live keys
/// whose value changed take effect now and are reported in `keysReloaded`;
/// restart-gated keys that changed apply from the next start and are logged.
pub(crate) async fn consume_config_reload(
    typed: TrustTask<trust_tasks_rs::specs::config::reload::v0_1::Payload>,
    state: &SharedData,
    session: &Session,
    mediator_did: &str,
    now: DateTime<Utc>,
) -> Result<Value, MediatorError> {
    use crate::common::config::limits::LimitsConfig;
    use crate::common::config::overrides::{config_path, parse_stored, reload_plan};

    validate_tt_basic(&typed, session, mediator_did, now)?;
    if session.account_type != AccountType::RootAdmin {
        return Err(tt_problem(
            session,
            "authorization.root_admin_required",
            "config/reload changes the mediator for every account and requires a rootAdmin".into(),
            StatusCode::FORBIDDEN,
        ));
    }
    let Some(path) = config_path() else {
        return Err(tt_problem(
            session,
            "config.reload.unavailable",
            "this mediator was not started from a configuration file, so there is nothing to \
             reload"
                .into(),
            StatusCode::CONFLICT,
        ));
    };

    let config_err = |e: String| {
        tt_problem(
            session,
            "config.reload.invalid",
            format!("the configuration could not be re-read, and nothing changed: {e}"),
            StatusCode::UNPROCESSABLE_ENTITY,
        )
    };
    let raw = affinidi_messaging_mediator_config::env::read_config_file(path)
        .map_err(|e| config_err(e.to_string()))?;
    let baseline: LimitsConfig = raw
        .limits
        .try_into()
        .map_err(|e: MediatorError| config_err(e.to_string()))?;

    let _one_at_a_time = state.live_limits.lock_for_patch().await;
    let stored = state
        .database
        .config_overrides_get()
        .await
        .map_err(|e| config_err(e.to_string()))?;
    let plan = reload_plan(&state.limits(), &baseline, &parse_stored(stored.as_deref()));
    for (key, reason) in &plan.skipped {
        tracing::warn!("config/reload: stored override {key} no longer applies: {reason}");
    }
    if !plan.pending_restart.is_empty() {
        tracing::info!(
            "config/reload: {} changed in the configuration and apply from the next start",
            plan.pending_restart.join(", ")
        );
    }
    state.live_limits.set_baseline(baseline);
    state.live_limits.set(plan.live);

    record_audit(
        state,
        session,
        &state.config.mediator_did_hash,
        AuditAction::ConfigReload,
        format!(
            "reloaded {path}: now {}; at restart {}",
            if plan.reloaded.is_empty() {
                "nothing".to_string()
            } else {
                plan.reloaded.join(", ")
            },
            if plan.pending_restart.is_empty() {
                "nothing".to_string()
            } else {
                plan.pending_restart.join(", ")
            },
        ),
    )
    .await;

    let response: trust_tasks_rs::specs::config::reload::v0_1::Response =
        serde_json::from_value(json!({ "keysReloaded": plan.reloaded })).map_err(serialize_err)?;
    serde_json::to_value(typed.respond_with(Uuid::new_v4().to_string(), response))
        .map_err(serialize_err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tasks::queue_survey::QueueSurvey;
    use queue::list::v0_1::PayloadSort;

    fn account(did: &str, recv: u32, recv_limit: i32, oldest: Option<u64>) -> AccountQueues {
        AccountQueues {
            did_hash: did.into(),
            account_type: AccountType::Standard,
            receive_count: recv,
            receive_bytes: u64::from(recv) * 100,
            receive_limit: recv_limit,
            send_count: 0,
            send_bytes: 0,
            send_limit: 1000,
            receive_oldest_secs: oldest,
            send_oldest_secs: None,
        }
    }

    fn snapshot(accounts: Vec<AccountQueues>) -> QueueSnapshot {
        QueueSnapshot {
            taken_at: DateTime::from_timestamp(1_800_000_000, 0).unwrap(),
            survey: QueueSurvey {
                accounts,
                ..QueueSurvey::default()
            },
        }
    }

    fn dids(page: &Value) -> Vec<&str> {
        page["queues"]
            .as_array()
            .unwrap()
            .iter()
            .map(|q| q["did"].as_str().unwrap())
            .collect()
    }

    #[test]
    fn ranks_by_depth_and_pages_with_a_snapshot_cursor() {
        let snap = snapshot(vec![
            account("a", 5, 100, None),
            account("b", 50, 100, None),
            account("c", 20, 100, None),
        ]);
        let first = ranked_page(&snap, true, PayloadSort::Count, 1, 0, 2);
        assert_eq!(dids(&first), ["b", "c"]);
        let cursor = first["nextCursor"].as_str().unwrap();
        let offset = parse_cursor(cursor, &snap).expect("cursor is valid for its snapshot");
        let second = ranked_page(&snap, true, PayloadSort::Count, 1, offset, 2);
        assert_eq!(dids(&second), ["a"]);
        assert!(
            second.get("nextCursor").is_none(),
            "last page has no cursor"
        );
        // The page shape is exactly the generated response type.
        let _: queue::list::v0_1::Response = from_json(first).unwrap();
    }

    #[test]
    fn a_cursor_from_an_older_snapshot_is_refused() {
        let snap = snapshot(vec![account("a", 1, 10, None)]);
        assert!(parse_cursor("1799999940:1", &snap).is_none());
        assert!(parse_cursor("garbage", &snap).is_none());
    }

    #[test]
    fn saturation_ranks_unlimited_queues_last() {
        // "b" is deeper but unlimited: it has no saturation and must not
        // outrank a queue that is actually close to its limit.
        let snap = snapshot(vec![
            account("a", 90, 100, None),
            account("b", 500, -1, None),
            account("c", 10, 100, None),
        ]);
        let page = ranked_page(&snap, true, PayloadSort::Saturation, 1, 0, 10);
        assert_eq!(dids(&page), ["a", "c", "b"]);
    }

    #[test]
    fn oldest_ranks_unmeasured_queues_last_and_min_count_filters() {
        let snap = snapshot(vec![
            account("a", 3, 100, Some(60)),
            account("b", 9, 100, None),
            account("c", 4, 100, Some(3600)),
            account("d", 1, 100, Some(99999)),
        ]);
        let page = ranked_page(&snap, true, PayloadSort::Oldest, 2, 0, 10);
        assert_eq!(dids(&page), ["c", "a", "b"], "d is below minCount");
    }
}
