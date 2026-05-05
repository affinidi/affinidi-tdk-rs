/*!
 * The message delete database function sits in common so that it can be used by
 * both the mediator and the processors (message_expiry for example)
 */
use super::DatabaseHandler;
use crate::errors::MediatorError;
use crate::types::problem_report::{ProblemReportScope, ProblemReportSorter};
use axum::http::StatusCode;
use tracing::{Instrument, Level, debug, info, span, warn};

impl DatabaseHandler {
    /// Deletes a message in the database.
    ///
    /// The Lua `delete_message` function performs an ownership check:
    /// the requesting DID must be the message's TO, FROM, or match
    /// the `admin_did_hash` (for system operations like expiry cleanup).
    ///
    /// Returns specific errors for not-found and permission-denied cases.
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
            let result: Result<String, redis::RedisError> = cmd.query_async(&mut conn).await;

            match result {
                Ok(response) if response == "OK" => {
                    info!("Successfully deleted message_hash({})", message_hash);
                    Ok(())
                }
                Ok(response) => {
                    // Lua returned a non-OK status (shouldn't happen with current script)
                    warn!(
                        "delete_message returned unexpected status: {} for message_hash({})",
                        response, message_hash
                    );
                    Err(MediatorError::problem_with_log(
                        11,
                        "NA",
                        request_msg_id.map(|s| s.to_string()),
                        ProblemReportSorter::Warning,
                        ProblemReportScope::Message,
                        "database.message.delete.status",
                        "delete returned unexpected status ({1}) for message ({2})",
                        vec![response.to_string(), message_hash.to_string()],
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("delete returned unexpected status ({response}) for message ({message_hash})"),
                    ))
                }
                Err(err) => {
                    let err_str = err.to_string();

                    // Parse Lua error responses for specific handling
                    if err_str.contains("NOT_FOUND") {
                        debug!(
                            "Message not found for deletion: message_hash({})",
                            message_hash
                        );
                        Err(MediatorError::problem(
                            10,
                            "NA",
                            request_msg_id.map(|s| s.to_string()),
                            ProblemReportSorter::Warning,
                            ProblemReportScope::Message,
                            "database.message.delete.not_found",
                            "Message ({1}) not found",
                            vec![message_hash.to_string()],
                            StatusCode::NOT_FOUND,
                        ))
                    } else if err_str.contains("PERMISSION_DENIED") {
                        warn!(
                            "Permission denied deleting message_hash({}) by did_hash({})",
                            message_hash, did_hash
                        );
                        Err(MediatorError::problem(
                            10,
                            "NA",
                            request_msg_id.map(|s| s.to_string()),
                            ProblemReportSorter::Warning,
                            ProblemReportScope::Message,
                            "database.message.delete.permission_denied",
                            "Not authorized to delete message ({1})",
                            vec![message_hash.to_string()],
                            StatusCode::FORBIDDEN,
                        ))
                    } else {
                        // Generic database error
                        Err(MediatorError::problem_with_log(
                            10,
                            "NA",
                            request_msg_id.map(|s| s.to_string()),
                            ProblemReportSorter::Warning,
                            ProblemReportScope::Message,
                            "database.message.delete.error",
                            "Couldn't delete message_hash ({1}). Reason: {2}",
                            vec![message_hash.to_string(), err_str],
                            StatusCode::SERVICE_UNAVAILABLE,
                            format!("Couldn't delete message_hash ({message_hash}). Reason: {err}"),
                        ))
                    }
                }
            }
        }
        .instrument(_span)
        .await
    }
}
