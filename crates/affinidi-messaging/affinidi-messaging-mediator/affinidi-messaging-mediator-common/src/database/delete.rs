use tracing::{Instrument, Level, debug, info, span};

use crate::errors::MediatorError;

use super::DatabaseHandler;

impl DatabaseHandler {
    /// Deletes a message in the database
    /// - session_id: Some(authentication session ID)
    /// - did_hash: DID of the delete requestor (can be `ADMIN` if the mediator is deleting the message, i.e. Expired Message cleanup)
    /// - message_hash: sha256 hash of the message to delete
    pub async fn delete_message(
        &self,
        session_id: Option<&str>,
        did_hash: &str,
        message_hash: &str,
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
                    MediatorError::DatabaseError(
                        did_hash.into(),
                        format!(
                            "Couldn't delete message_id({}) from database for DID {}: {}",
                            message_hash, did_hash, err
                        ),
                    )
                })?;

            debug!(
                "{}did_hash({}) message_id({}). database response: ({})",
                if let Some(session_id) = session_id {
                    format!("{}: ", session_id)
                } else {
                    "".to_string()
                },
                did_hash,
                message_hash,
                response
            );

            if response != "OK" {
                Err(MediatorError::DatabaseError(
                    session_id.unwrap_or("NA").into(),
                    response,
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
