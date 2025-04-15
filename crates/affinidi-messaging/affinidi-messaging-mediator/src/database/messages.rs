/*!
 * Database related routines that deal with the management of raw messages in the database.
 *
 */

use super::{Database, session::Session};
use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_messaging_sdk::messages::Folder;
use ahash::AHashMap as HashMap;
use tracing::{Instrument, Level, debug, span, warn};

impl Database {
    /// Will purge/delete all messages from the database for the given DID and folder
    /// Returns the number of messages purged and the total bytes purged
    pub(crate) async fn purge_messages(
        &self,
        session: &Session,
        did_hash: &str,
        folder: Folder,
    ) -> Result<(usize, usize), MediatorError> {
        let mut purge_count: usize = 0;
        let mut purge_bytes: usize = 0;

        loop {
            let (count, bytes) = self._purge_messages(session, did_hash, &folder).await?;
            purge_count += count;
            purge_bytes += bytes;

            if count == 0 {
                break;
            }
        }

        // Remove the stream key
        self.delete_folder_stream(session, did_hash, &folder)
            .await?;

        Ok((purge_count, purge_bytes))
    }

    // Helper function that does the actual work of purging messages
    async fn _purge_messages(
        &self,
        session: &Session,
        did_hash: &str,
        folder: &Folder,
    ) -> Result<(usize, usize), MediatorError> {
        let _span = span!(Level::DEBUG, "purge_messages", did_hash = did_hash, folder = ?folder);

        async move {
            let mut con = self.0.get_async_connection().await?;

            // Grab a message from the Stream
            let key = if folder == &Folder::Inbox {
                ["RECEIVE_Q:", did_hash].concat()
            } else {
                ["SEND_Q:", did_hash].concat()
            };
            let message: Vec<(String, HashMap<String, String>)> =
                deadpool_redis::redis::Cmd::xrange_count(&key, "-", "+", 1)
                    .query_async(&mut con)
                    .await
                    .map_err(|e| {
                        MediatorError::DatabaseError(14, session.session_id.clone(), e.to_string())
                    })?;

            let (stream_id, message) = if message.is_empty() {
                debug!("No messages to purge...");
                return Ok((0, 0));
            } else {
                message.first().unwrap()
            };

            // Extract the message details
            let message_hash = if let Some(message_id) = message.get("MSG_ID") {
                message_id
            } else {
                warn!("Couldn't find MSG_ID");
                return Ok((0, 0));
            };

            let bytes = if let Some(bytes) = message.get("BYTES") {
                match bytes.parse::<usize>() {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        warn!(
                            "Invalid BYTES value ({}) in message ({}): {}",
                            bytes, message_hash, e
                        );
                        0_usize
                    }
                }
            } else {
                warn!("BYTES value missing in message ({})", message_hash);
                0_usize
            };

            // Delete the message
            self.0
                .delete_message(Some(&session.session_id), did_hash, message_hash, None)
                .await?;

            // Delete the stream entry
            self._delete_msg_stream_record(session, &key, stream_id)
                .await?;

            Ok((1, bytes))
        }
        .instrument(_span)
        .await
    }

    // Deletes a stream record
    async fn _delete_msg_stream_record(
        &self,
        session: &Session,
        key: &str,
        id: &str,
    ) -> Result<(), MediatorError> {
        let mut con = self.0.get_async_connection().await?;

        deadpool_redis::redis::Cmd::xdel(key, &[id])
            .exec_async(&mut con)
            .await
            .map_err(|e| {
                MediatorError::DatabaseError(14, session.session_id.clone(), e.to_string())
            })
    }

    // Deletes a stream record
    pub async fn delete_folder_stream(
        &self,
        session: &Session,
        did_hash: &str,
        folder: &Folder,
    ) -> Result<(), MediatorError> {
        let mut con = self.0.get_async_connection().await?;

        let key = if folder == &Folder::Inbox {
            ["RECEIVE_Q:", did_hash].concat()
        } else {
            ["SEND_Q:", did_hash].concat()
        };

        deadpool_redis::redis::Cmd::del(key)
            .exec_async(&mut con)
            .await
            .map_err(|e| {
                MediatorError::DatabaseError(14, session.session_id.clone(), e.to_string())
            })
    }
}
