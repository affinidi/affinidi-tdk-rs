use crate::{
    SharedData,
    common::authz::{self, Capability},
    common::session::Session,
};
use affinidi_messaging_mediator_common::errors::{AppError, MediatorError, SuccessResponse};
use affinidi_messaging_sdk::messages::problem_report::{ProblemReportScope, ProblemReportSorter};
use affinidi_messaging_sdk::messages::{Folder, PurgeQueueResponse};
use axum::{
    Json,
    extract::{Path, State},
};
use http::StatusCode;
use tracing::{Instrument, Level, info, span};

/// Empty one of the calling DID's own queues.
///
/// # Why this exists
///
/// Until now the only way to clear a queue was to page it with `/list` (capped
/// at 100, no cursor) or `/fetch`, and delete by id 100 at a time — every batch
/// separately authenticated. That is the recovery path a node needs precisely
/// when it is already being rate-limited, which is to say precisely when it
/// cannot use it. `purge_folder` had existed in every store implementation the
/// whole time, reachable only as a side effect of deleting the account.
///
/// The queue that strands a deployment is usually not the one on the node that
/// is failing: a message is held against the **sender's** account until the
/// **recipient** deletes it, so a receiver whose deletes are failing fills the
/// send queue of every peer talking to it. The peer cannot fix that by fixing
/// itself, and with `queued_send_messages_hard` at 1000 it stops being able to
/// send anything at all. This gives it a way back without an operator deleting
/// and rebuilding the account.
///
/// # Scope
///
/// Strictly the caller's own queue: the DID comes from the authenticated
/// session, never from the request. There is deliberately no way to purge
/// another DID's queue — that would be a denial-of-service primitive handed to
/// anyone with `Local` access, and the recovery case does not need it. Same
/// `Capability::Local` gate as `/delete`, for the same reason.
///
/// Purging is destructive and unrecoverable: undelivered messages are gone, not
/// returned to their senders. It is logged at `info` with the count and bytes
/// so the loss is on the record.
pub async fn message_purge_handler(
    session: Session,
    State(state): State<SharedData>,
    Path(folder): Path<Folder>,
) -> Result<(StatusCode, Json<SuccessResponse<PurgeQueueResponse>>), AppError> {
    let _span = span!(
        Level::DEBUG,
        "message_purge_handler",
        session = session.session_id,
        did = session.did,
        ?folder,
    );
    async move {
        // Same gate as `/delete`: emptying a queue is a superset of deleting
        // from it, so it cannot be the easier of the two to reach.
        if authz::require_capability(&session.acls, Capability::Local).is_err() {
            return Err(MediatorError::problem(
                40,
                session.session_id,
                None,
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "authorization.local",
                "DID isn't local to the mediator",
                vec![],
                StatusCode::FORBIDDEN,
            )
            .into());
        }

        let (count, bytes) = state
            .database
            .purge_folder(&session.session_id, &session.did_hash, folder.clone())
            .await?;

        // `info`, not `debug`: this destroys undelivered messages, and the
        // count is the only record that they existed.
        info!(?folder, count, bytes, "purged queue on the owner's request");

        Ok((
            StatusCode::OK,
            Json(SuccessResponse {
                session_id: session.session_id,
                http_code: StatusCode::OK.as_u16(),
                error_code: 0,
                error_code_str: "NA".to_string(),
                message: format!("{count} message(s) purged"),
                data: Some(PurgeQueueResponse { count, bytes }),
            }),
        ))
    }
    .instrument(_span)
    .await
}
