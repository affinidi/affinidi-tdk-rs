//! `GET /queue/status` — a DID's own queue depth, limits and age.
//!
//! # Why this exists
//!
//! A sender learned its queue was full by being refused. By then it is already
//! failing, and the messages it was refused are the ones it most wanted to
//! send. Everything needed to see it coming was in the account record and
//! unreachable: a DID could read neither its own depth nor the limit it was
//! being measured against, so "back off at 80%" was not expressible.
//!
//! The depth counters come from the account record, which already holds them —
//! this adds no accounting. The ages come from the inbox and outbox streams,
//! which are arrival-ordered, so the oldest entry is a single range read.
//!
//! # Scope
//!
//! Strictly the caller's own queue: the DID comes from the authenticated
//! session, never from the request. The limits reported are the **effective**
//! ones for that account — its own override, or the mediator's default where it
//! has none — and not the mediator's configuration at large. A caller learns
//! what applies to it, which it can already discover by hitting the wall, and
//! nothing about anyone else.

use affinidi_messaging_mediator_common::errors::{AppError, MediatorError, SuccessResponse};
use affinidi_messaging_sdk::messages::{Folder, QueueSideStatus, QueueStatusResponse};
use axum::{Json, extract::State};
use http::StatusCode;
use tracing::{Instrument, Level, span};

use crate::{SharedData, common::session::Session};

/// Saturation of `used` against `limit`, or `None` when the limit is unlimited.
///
/// Matches the mediator's own queue-survey metric: an unlimited account has no
/// ratio, and reporting `0.0` would read as "empty" for the one account that
/// can never be full.
fn saturation(used: u32, limit: i32) -> Option<f64> {
    (limit > 0).then(|| f64::from(used) / f64::from(limit))
}

/// Age in seconds of the oldest message in `folder`, or `None` when empty.
///
/// `("-", "+")` with a limit of 1 is a range-min read: inbox and outbox are
/// arrival-ordered streams in every backend, so the first entry in a DID's
/// range is its genuine oldest message, with the arrival millisecond already
/// in the stream id.
async fn oldest_age_secs(
    state: &SharedData,
    did_hash: &str,
    folder: Folder,
) -> Result<Option<u64>, MediatorError> {
    let oldest = state
        .database
        .list_messages(did_hash, folder, Some(("-", "+")), 1)
        .await?;
    Ok(oldest
        .first()
        .map(|m| state.clock.unix_secs().saturating_sub(m.timestamp / 1_000)))
}

pub async fn queue_status_handler(
    session: Session,
    State(state): State<SharedData>,
) -> Result<(StatusCode, Json<SuccessResponse<QueueStatusResponse>>), AppError> {
    let _span = span!(
        Level::DEBUG,
        "queue_status_handler",
        session = session.session_id,
        did = session.did,
    );
    async move {
        // An account the mediator has never seen reports zeroes against the
        // configured defaults, which is accurate: that is exactly the state it
        // would start from.
        let account = state
            .database
            .account_get(&session.did_hash)
            .await?
            .unwrap_or_default();

        let send_limit = account
            .queue_send_limit
            .unwrap_or(state.limits().queued_send_messages_soft);
        let receive_limit = account
            .queue_receive_limit
            .unwrap_or(state.limits().queued_receive_messages_soft);

        // Best-effort: a queue whose age cannot be read still reports its
        // depth. A status endpoint that fails outright because one range read
        // failed is worse than one that reports what it has.
        let send_age = oldest_age_secs(&state, &session.did_hash, Folder::Outbox)
            .await
            .unwrap_or(None);
        let receive_age = oldest_age_secs(&state, &session.did_hash, Folder::Inbox)
            .await
            .unwrap_or(None);

        let data = QueueStatusResponse {
            send: QueueSideStatus {
                messages: account.send_queue_count,
                bytes: account.send_queue_bytes,
                limit: send_limit,
                saturation: saturation(account.send_queue_count, send_limit),
                oldest_age_secs: send_age,
            },
            receive: QueueSideStatus {
                messages: account.receive_queue_count,
                bytes: account.receive_queue_bytes,
                limit: receive_limit,
                saturation: saturation(account.receive_queue_count, receive_limit),
                oldest_age_secs: receive_age,
            },
            send_per_peer_limit: state.limits().queued_send_messages_per_peer,
        };

        Ok((
            StatusCode::OK,
            Json(SuccessResponse {
                session_id: session.session_id,
                http_code: StatusCode::OK.as_u16(),
                error_code: 0,
                error_code_str: "NA".to_string(),
                message: "Success".to_string(),
                data: Some(data),
            }),
        ))
    }
    .instrument(_span)
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saturation_reports_the_distance_to_the_wall() {
        // 1.0 is the depth at which the mediator starts refusing, so an alert
        // at 0.8 fires before anything breaks.
        assert_eq!(saturation(200, 200), Some(1.0));
        assert_eq!(saturation(160, 200), Some(0.8));
        assert_eq!(saturation(0, 200), Some(0.0));
    }

    #[test]
    fn an_unlimited_queue_has_no_saturation() {
        // Not `Some(0.0)`: an unlimited account would then read as the emptiest
        // in the fleet, which is the opposite of what a caller should conclude.
        assert_eq!(saturation(10_000, -1), None);
        assert_eq!(saturation(5, 0), None);
    }
}
