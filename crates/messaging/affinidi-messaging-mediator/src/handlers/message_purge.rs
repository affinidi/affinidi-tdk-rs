use crate::{
    SharedData,
    common::authz::{self, Capability},
    common::session::Session,
};
use affinidi_messaging_mediator_common::errors::{AppError, MediatorError, SuccessResponse};
use affinidi_messaging_mediator_common::store::PurgeFilter;
use affinidi_messaging_sdk::messages::problem_report::{ProblemReportScope, ProblemReportSorter};
use affinidi_messaging_sdk::messages::{Folder, PurgeQueueResponse};
use axum::{
    Json,
    extract::{Path, Query, State},
};
use http::StatusCode;
use serde::Deserialize;
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
/// Narrowing for a purge, from the query string.
///
/// All optional, and all absent is the historical whole-folder purge — so an
/// existing caller is unaffected and keeps the faster path.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PurgeParams {
    /// Only messages exchanged with this counterparty DID hash. In an outbox
    /// that is who the message was sent to; in an inbox, who sent it.
    pub peer: Option<String>,
    /// Only messages that have been queued at least this long.
    pub older_than_secs: Option<u64>,
    /// Report what would be purged and purge nothing.
    #[serde(default)]
    pub dry_run: bool,
}

impl PurgeParams {
    /// Whether anything actually narrows the purge. A dry run counts: it must
    /// take the filtered path even with no filter, or it would purge.
    fn narrows(&self) -> bool {
        self.peer.is_some() || self.older_than_secs.is_some() || self.dry_run
    }
}

pub async fn message_purge_handler(
    session: Session,
    State(state): State<SharedData>,
    Path(folder): Path<Folder>,
    Query(params): Query<PurgeParams>,
) -> Result<(StatusCode, Json<SuccessResponse<PurgeQueueResponse>>), AppError> {
    crate::common::legacy_admin::admit(
        &state,
        &session,
        "DELETE /purge",
        "the messaging/queue/purge Trust Task",
    )?;
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

        let report = if params.narrows() {
            let filter = PurgeFilter {
                peer: params.peer.clone(),
                // Seconds of age from the caller become an absolute arrival
                // cut-off here, so the whole walk is measured against one
                // instant rather than drifting as it pages.
                arrived_before_ms: params.older_than_secs.map(|secs| {
                    state
                        .clock
                        .unix_millis()
                        .saturating_sub(u128::from(secs) * 1_000) as u64
                }),
                dry_run: params.dry_run,
            };
            state
                .database
                .purge_folder_filtered(&session.did_hash, folder.clone(), &filter)
                .await?
        } else {
            // Nothing to narrow by: keep the whole-folder path, which drops
            // the stream key in one go rather than walking it.
            let (count, bytes) = state
                .database
                .purge_folder(&session.session_id, &session.did_hash, folder.clone())
                .await?;
            affinidi_messaging_mediator_common::store::PurgeReport {
                count,
                bytes,
                scanned: count,
                failed: 0,
                truncated: false,
            }
        };

        let (count, bytes, scanned) = (report.count, report.bytes, report.scanned);
        if !params.dry_run {
            state.monitor.purged(
                &session.did_hash,
                count,
                bytes,
                crate::monitor::Channel::Rest,
            );
        }
        let (failed, truncated) = (report.failed, report.truncated);

        // `info`, not `debug`: this destroys undelivered messages, and the
        // count is the only record that they existed. A dry run says so, so a
        // log reader is never left inferring whether anything was destroyed.
        if params.dry_run {
            info!(
                ?folder,
                count,
                bytes,
                scanned,
                peer = ?params.peer,
                older_than_secs = ?params.older_than_secs,
                "dry run: reported what a purge would remove, removed nothing"
            );
        } else {
            info!(
                ?folder,
                count,
                bytes,
                scanned,
                failed,
                truncated,
                peer = ?params.peer,
                older_than_secs = ?params.older_than_secs,
                "purged queue on the owner's request"
            );
        }

        let message = if params.dry_run {
            format!("{count} message(s) would be purged")
        } else {
            format!("{count} message(s) purged")
        };

        Ok((
            StatusCode::OK,
            Json(SuccessResponse {
                session_id: session.session_id,
                http_code: StatusCode::OK.as_u16(),
                error_code: 0,
                error_code_str: "NA".to_string(),
                message,
                data: Some(PurgeQueueResponse {
                    count,
                    bytes,
                    scanned,
                    dry_run: params.dry_run,
                    failed,
                    truncated,
                }),
            }),
        ))
    }
    .instrument(_span)
    .await
}
