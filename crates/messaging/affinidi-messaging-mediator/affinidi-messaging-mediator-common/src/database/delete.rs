/*!
 * The message delete database function sits in common so that it can be used by
 * both the mediator and the processors (message_expiry for example)
 */
use super::DatabaseHandler;
use crate::errors::MediatorError;
use affinidi_messaging_sdk::messages::problem_report::{ProblemReportScope, ProblemReportSorter};
use axum::http::StatusCode;
use tracing::{Instrument, Level, debug, info, span};

impl DatabaseHandler {
    /// Deletes a message in the database
    /// - session_id: Some(authentication session ID)
    /// - did_hash: DID hash of the delete requestor
    /// - message_hash: sha256 hash of the message to delete
    /// - request_msg_id: ID of the requesting message (if applicable)
    /// - admin_did_hash: If provided, `did_hash` matching this value gets admin-level delete
    ///   permission (used by message expiry and system operations)
    pub async fn delete_message(
        &self,
        session_id: Option<&str>,
        did_hash: &str,
        message_hash: &str,
        request_msg_id: Option<&str>,
        admin_did_hash: Option<&str>,
    ) -> Result<(), MediatorError> {
        let _span = span!(
            Level::INFO,
            "database_delete",
            session = session_id,
            did_hash = did_hash,
            message_hash = message_hash,
        );
        async move {
            let mut conn = self.get_async_connection().await?;
            let mut cmd = redis::cmd("FCALL");
            cmd.arg("delete_message")
                .arg(1)
                .arg(message_hash)
                .arg(did_hash);
            if let Some(admin_hash) = admin_did_hash {
                cmd.arg(admin_hash);
            }
            let response: String = cmd.query_async(&mut conn).await.map_err(|err| {
                // TODO: Should check the response from the function and have better error handling
                MediatorError::problem_with_log(
                    10,
                    "NA",
                    request_msg_id.map(|s| s.to_string()),
                    ProblemReportSorter::Warning,
                    ProblemReportScope::Message,
                    "database.message.delete.error",
                    "Couldn't delete message_hash ({1}). Reason: {2}",
                    vec![message_hash.to_string(), err.to_string()],
                    StatusCode::SERVICE_UNAVAILABLE,
                    format!("Couldn't delete message_hash ({message_hash}). Reason: {err}"),
                )
            })?;

            debug!(
                "{}did_hash({}) message_id({}). database response: ({})",
                if let Some(session_id) = session_id {
                    format!("{session_id}: ")
                } else {
                    "".to_string()
                },
                did_hash,
                message_hash,
                response
            );

            if response != "OK" {
                // TODO: As above - better handling of error response from the function
                Err(MediatorError::problem_with_log(
                    11,
                    "NA",
                    request_msg_id.map(|s| s.to_string()),
                    ProblemReportSorter::Warning,
                    ProblemReportScope::Message,
                    "database.message.delete.status",
                    "delete function returned not being OK. Status: {1}",
                    vec![response.to_string()],
                    StatusCode::SERVICE_UNAVAILABLE,
                    format!("delete function returned not being OK. Status: {response}"),
                ))
            } else {
                info!("Successfully deleted",);
                Ok(())
            }
        }
        .instrument(_span)
        .await
    }
}
