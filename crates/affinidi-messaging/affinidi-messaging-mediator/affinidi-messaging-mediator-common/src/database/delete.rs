/*!
 * The message delete database function sits in common so that it can be used by
 * both the mediator and the processors (message_expiry for example)
 */
use super::DatabaseHandler;
use crate::errors::MediatorError;
use affinidi_messaging_sdk::messages::problem_report::{
    ProblemReport, ProblemReportScope, ProblemReportSorter,
};
use axum::http::StatusCode;
use tracing::{Instrument, Level, debug, info, span};

impl DatabaseHandler {
    /// Deletes a message in the database
    /// - session_id: Some(authentication session ID)
    /// - did_hash: DID of the delete requestor (can be `ADMIN` if the mediator is deleting the message, i.e. Expired Message cleanup)
    /// - message_hash: sha256 hash of the message to delete
    /// - request_msg_id: ID of the requesting message (if applicable)
    pub async fn delete_message(
        &self,
        session_id: Option<&str>,
        did_hash: &str,
        message_hash: &str,
        request_msg_id: Option<&str>,
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
            let response: String = deadpool_redis::redis::cmd("FCALL")
                .arg("delete_message")
                .arg(1)
                .arg(message_hash)
                .arg(did_hash)
                .query_async(&mut conn)
                .await
                .map_err(|err| {
                    // TODO: Should check the response from the function and have better error handling
                    MediatorError::MediatorError(
                        10,
                        "NA".to_string(),
                        request_msg_id.map(|s| s.to_string()),
                        Box::new(ProblemReport::new(
                            ProblemReportSorter::Warning,
                            ProblemReportScope::Message,
                            "database.message.delete.error".into(),
                            "Couldn't delete message_hash ({1}). Reason: {2}".into(),
                            vec![message_hash.to_string(), err.to_string()],
                            None,
                        )),
                        StatusCode::SERVICE_UNAVAILABLE.as_u16(),
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
                Err(MediatorError::MediatorError(
                    11,
                    "NA".to_string(),
                    request_msg_id.map(|s| s.to_string()),
                    Box::new(ProblemReport::new(
                        ProblemReportSorter::Warning,
                        ProblemReportScope::Message,
                        "database.message.delete.status".into(),
                        "delete function returned not being OK. Status: {1}".into(),
                        vec![response.to_string()],
                        None,
                    )),
                    StatusCode::SERVICE_UNAVAILABLE.as_u16(),
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
