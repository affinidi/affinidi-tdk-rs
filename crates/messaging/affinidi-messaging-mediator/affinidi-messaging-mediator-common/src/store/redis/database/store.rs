use std::time::Instant;

use super::Database;
use crate::errors::MediatorError;

// Mirror of the metric names declared in the mediator's
// `common::metrics::names` module — kept as raw strings here so this
// `database/` impl can live in mediator-common without depending on
// the mediator's metrics registry.
mod names {
    pub const MESSAGE_STORE_DURATION_SECONDS: &str = "message_store_duration_seconds";
    pub const MESSAGES_STORED_TOTAL: &str = "messages_stored_total";
}
use serde::{Deserialize, Serialize};
use sha256::digest;
use tracing::{Instrument, Level, debug, event, info, span};

#[derive(Serialize, Deserialize, Debug)]
pub struct MessageMetaData {
    pub bytes: usize,
    pub to_did_hash: String,
    pub from_did_hash: Option<String>,
    pub timestamp: u128,
}

impl Database {
    /// Stores a message in the database
    /// Returns the message_id (hash of the message)
    /// - expires_at: The timestamp at which the message expires (since epoch in seconds)
    /// - `from_hash`: The hash of the DID of the sender
    /// - `queue_maxlen`: Max entries per RECEIVE_Q/SEND_Q stream (0 = unlimited)
    pub async fn store_message(
        &self,
        session_id: &str,
        message: &str,
        to_did_hash: &str,
        from_hash: Option<&str>,
        expires_at: u64,
        queue_maxlen: usize,
    ) -> Result<String, MediatorError> {
        let _span = span!(Level::DEBUG, "store_message", session_id = session_id);
        async move {
            let message_hash = digest(message.as_bytes());

            let from_hash = from_hash.filter(|s| !s.is_empty()).unwrap_or("ANONYMOUS");
            debug!(
                "trying to store msg_id({}), from_hash({:?}) to_hash({}), bytes({})",
                message_hash,
                from_hash,
                to_did_hash,
                message.len()
            );

            let start = Instant::now();
            let mut conn = self.get_connection().await?;
            let mut cmd = redis::cmd("FCALL");
            cmd.arg("store_message")
                .arg(1)
                .arg(&message_hash)
                .arg(message)
                .arg(expires_at)
                .arg(message.len())
                .arg(to_did_hash)
                .arg(from_hash);
            if queue_maxlen > 0 {
                cmd.arg(queue_maxlen);
            }
            cmd.exec_async(&mut conn).await.map_err(|err| {
                event!(Level::ERROR, "Couldn't store message in database: {}", err);
                MediatorError::DatabaseError(
                    14,
                    session_id.into(),
                    format!("Couldn't store message in database: {err}"),
                )
            })?;

            metrics::histogram!(names::MESSAGE_STORE_DURATION_SECONDS)
                .record(start.elapsed().as_secs_f64());
            metrics::counter!(names::MESSAGES_STORED_TOTAL).increment(1);

            info!(
                "Message hash({}) from({}) to({}) stored in database",
                message_hash, from_hash, to_did_hash
            );

            Ok(message_hash)
        }
        .instrument(_span)
        .await
    }

    /// Retrieves the message MetaData for a given message hash
    /// - session_id: The session_id for the request
    /// - message_hash: The hash of the message to retrieve
    pub async fn get_message_metadata(
        &self,
        session_id: &str,
        message_hash: &str,
    ) -> Result<MessageMetaData, MediatorError> {
        let _span = span!(
            Level::DEBUG,
            "get_message_metadata",
            session_id = session_id,
            message_hash = message_hash
        );
        async move {
            // The `store_message` Lua function keeps a message's metadata in
            // the hash `MSG:META:{id}`: BYTES, TO, TIMESTAMP (unix ms), and
            // FROM when the sender is known. (This read used to look for a
            // `MESSAGE_STORE` hash field that nothing writes, so it could
            // never succeed.)
            let mut conn = self.get_connection().await?;
            let fields: std::collections::HashMap<String, String> = redis::cmd("HGETALL")
                .arg(["MSG:META:", message_hash].concat())
                .query_async(&mut conn)
                .await
                .map_err(|err| {
                    event!(
                        Level::ERROR,
                        "Couldn't get message metadata from database: {}",
                        err
                    );
                    MediatorError::DatabaseError(
                        14,
                        session_id.into(),
                        format!("Couldn't get message metadata from database: {err}"),
                    )
                })?;
            let metadata = metadata_from_fields(&fields).ok_or_else(|| {
                MediatorError::DatabaseError(
                    22,
                    session_id.into(),
                    format!("No usable metadata for message {message_hash}"),
                )
            })?;

            Ok(metadata)
        }
        .instrument(_span)
        .await
    }
}

/// A `MSG:META:{id}` hash as [`MessageMetaData`]; `None` when the message is
/// gone (an empty hash) or a required field is missing or malformed.
fn metadata_from_fields(
    fields: &std::collections::HashMap<String, String>,
) -> Option<MessageMetaData> {
    Some(MessageMetaData {
        bytes: fields.get("BYTES")?.parse().ok()?,
        to_did_hash: fields.get("TO")?.clone(),
        from_did_hash: fields.get("FROM").cloned(),
        timestamp: fields.get("TIMESTAMP")?.parse().ok()?,
    })
}

#[cfg(test)]
mod metadata_tests {
    use super::*;

    #[test]
    fn a_message_meta_hash_parses_and_an_empty_one_is_absent() {
        let fields: std::collections::HashMap<String, String> = [
            ("BYTES", "42"),
            ("TO", "bob"),
            ("FROM", "alice"),
            ("TIMESTAMP", "1700000000123"),
            ("RECEIVE_ID", "1-0"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        let meta = metadata_from_fields(&fields).unwrap();
        assert_eq!(meta.bytes, 42);
        assert_eq!(meta.to_did_hash, "bob");
        assert_eq!(meta.from_did_hash.as_deref(), Some("alice"));
        assert_eq!(meta.timestamp, 1_700_000_000_123);

        assert!(metadata_from_fields(&Default::default()).is_none());
    }
}
