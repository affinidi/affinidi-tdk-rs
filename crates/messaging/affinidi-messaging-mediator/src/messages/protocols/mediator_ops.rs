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
use affinidi_messaging_mediator_common::types::accounts::AccountType;
use affinidi_messaging_mediator_common::types::messages::Folder;
use chrono::{DateTime, Utc};
use http::StatusCode;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use trust_tasks_rs::TrustTask;
use trust_tasks_rs::specs::messaging::{queue, stats};
use uuid::Uuid;

use crate::SharedData;
use crate::common::session::Session;
use crate::messages::protocols::mediator::acls::check_permissions;
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
            "queueLimit": state.config.limits.forward_task_queue,
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

    let limits = &state.config.limits;
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
