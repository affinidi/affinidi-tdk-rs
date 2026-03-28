//! Database operations for the FORWARD_Q Redis stream (standalone processor version)
//! Uses DatabaseHandler directly instead of the mediator's Database wrapper.

use affinidi_messaging_mediator_common::errors::ProcessorError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, warn};

use super::processor::ForwardingProcessor;

/// Represents a message queued for forwarding to a remote mediator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForwardQueueEntry {
    /// Redis stream entry ID (set after reading from stream)
    pub stream_id: String,
    /// The packed message to forward
    pub message: String,
    /// DID hash of the recipient
    pub to_did_hash: String,
    /// DID hash of the sender
    pub from_did_hash: String,
    /// The sender DID (not hashed, needed for problem reports)
    pub from_did: String,
    /// The recipient DID (not hashed, needed for routing)
    pub to_did: String,
    /// The service endpoint URL of the remote mediator
    pub endpoint_url: String,
    /// Unix timestamp (millis) when the message was received by this mediator
    pub received_at_ms: u128,
    /// Optional delay in milliseconds requested by the sender
    pub delay_milli: i64,
    /// Unix timestamp (seconds) when the message expires
    pub expires_at: u64,
    /// Number of retry attempts so far
    pub retry_count: u32,
    /// Hop counter for loop detection. Incremented each time a mediator forwards the message.
    pub hop_count: u32,
}

impl ForwardingProcessor {
    /// Ensure the consumer group exists for FORWARD_Q.
    pub(crate) async fn ensure_group(&self) -> Result<(), ProcessorError> {
        let mut conn =
            self.database.get_async_connection().await.map_err(|e| {
                ProcessorError::ForwardingError(format!("DB connection error: {e}"))
            })?;

        let result: Result<String, _> = redis::cmd("XGROUP")
            .arg("CREATE")
            .arg("FORWARD_Q")
            .arg(&self.config.consumer_group)
            .arg("0")
            .arg("MKSTREAM")
            .query_async(&mut conn)
            .await;

        match result {
            Ok(_) => {
                debug!(
                    "Created consumer group '{}' for FORWARD_Q",
                    self.config.consumer_group
                );
                Ok(())
            }
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("BUSYGROUP") {
                    debug!(
                        "Consumer group '{}' already exists",
                        self.config.consumer_group
                    );
                    Ok(())
                } else {
                    Err(ProcessorError::ForwardingError(format!(
                        "Couldn't create consumer group: {e}"
                    )))
                }
            }
        }
    }

    /// Blocking read from FORWARD_Q using consumer groups.
    /// Uses a dedicated connection with no response timeout since the redis crate 1.x
    /// defaults to 500ms which is shorter than the BLOCK duration.
    pub(crate) async fn read_entries(
        &self,
        block_ms: usize,
    ) -> Result<Vec<ForwardQueueEntry>, ProcessorError> {
        let mut conn = self.database.get_blocking_connection().await.map_err(|e| {
            ProcessorError::ForwardingError(format!("DB blocking connection error: {e}"))
        })?;

        let result: Option<Vec<(String, Vec<(String, HashMap<String, String>)>)>> =
            redis::cmd("XREADGROUP")
                .arg("GROUP")
                .arg(&self.config.consumer_group)
                .arg(&self.consumer_name)
                .arg("BLOCK")
                .arg(block_ms)
                .arg("COUNT")
                .arg(self.config.batch_size)
                .arg("STREAMS")
                .arg("FORWARD_Q")
                .arg(">")
                .query_async(&mut conn)
                .await
                .map_err(|err| {
                    ProcessorError::ForwardingError(format!("XREADGROUP error: {err}"))
                })?;

        let Some(streams) = result else {
            return Ok(vec![]);
        };

        let mut entries = Vec::new();
        for (_stream_name, messages) in streams {
            for (stream_id, fields) in messages {
                match parse_forward_entry(stream_id, fields) {
                    Ok(entry) => entries.push(entry),
                    Err(e) => {
                        warn!("Skipping malformed FORWARD_Q entry: {}", e);
                    }
                }
            }
        }

        Ok(entries)
    }

    /// Acknowledge successfully processed messages
    pub(crate) async fn ack_entries(&self, stream_ids: &[&str]) -> Result<(), ProcessorError> {
        if stream_ids.is_empty() {
            return Ok(());
        }

        let mut conn =
            self.database.get_async_connection().await.map_err(|e| {
                ProcessorError::ForwardingError(format!("DB connection error: {e}"))
            })?;

        let mut cmd = redis::cmd("XACK");
        cmd.arg("FORWARD_Q").arg(&self.config.consumer_group);
        for id in stream_ids {
            cmd.arg(*id);
        }
        cmd.exec_async(&mut conn)
            .await
            .map_err(|err| ProcessorError::ForwardingError(format!("XACK error: {err}")))?;

        Ok(())
    }

    /// Delete acknowledged messages from the stream
    pub(crate) async fn delete_entries(&self, stream_ids: &[&str]) -> Result<(), ProcessorError> {
        if stream_ids.is_empty() {
            return Ok(());
        }

        let mut conn =
            self.database.get_async_connection().await.map_err(|e| {
                ProcessorError::ForwardingError(format!("DB connection error: {e}"))
            })?;

        let mut cmd = redis::cmd("XDEL");
        cmd.arg("FORWARD_Q");
        for id in stream_ids {
            cmd.arg(*id);
        }
        cmd.exec_async(&mut conn)
            .await
            .map_err(|err| ProcessorError::ForwardingError(format!("XDEL error: {err}")))?;

        Ok(())
    }

    /// Claim stale messages from crashed/timed-out consumers
    pub(crate) async fn _autoclaim_entries(
        &self,
        min_idle_ms: u64,
    ) -> Result<Vec<ForwardQueueEntry>, ProcessorError> {
        let mut conn =
            self.database.get_async_connection().await.map_err(|e| {
                ProcessorError::ForwardingError(format!("DB connection error: {e}"))
            })?;

        let result: (String, Vec<(String, HashMap<String, String>)>, Vec<String>) =
            redis::cmd("XAUTOCLAIM")
                .arg("FORWARD_Q")
                .arg(&self.config.consumer_group)
                .arg(&self.consumer_name)
                .arg(min_idle_ms)
                .arg("0-0")
                .arg("COUNT")
                .arg(self.config.batch_size)
                .query_async(&mut conn)
                .await
                .map_err(|err| {
                    ProcessorError::ForwardingError(format!("XAUTOCLAIM error: {err}"))
                })?;

        let mut entries = Vec::new();
        for (stream_id, fields) in result.1 {
            match parse_forward_entry(stream_id, fields) {
                Ok(entry) => entries.push(entry),
                Err(e) => {
                    warn!("Skipping malformed autoclaimed entry: {}", e);
                }
            }
        }

        Ok(entries)
    }

    /// Re-enqueue a message with updated retry count
    pub(crate) async fn enqueue_entry(
        &self,
        entry: &ForwardQueueEntry,
    ) -> Result<String, ProcessorError> {
        let mut conn =
            self.database.get_async_connection().await.map_err(|e| {
                ProcessorError::ForwardingError(format!("DB connection error: {e}"))
            })?;

        let stream_id: String = redis::cmd("XADD")
            .arg("FORWARD_Q")
            .arg("*")
            .arg("MESSAGE")
            .arg(&entry.message)
            .arg("TO_DID_HASH")
            .arg(&entry.to_did_hash)
            .arg("FROM_DID_HASH")
            .arg(&entry.from_did_hash)
            .arg("FROM_DID")
            .arg(&entry.from_did)
            .arg("TO_DID")
            .arg(&entry.to_did)
            .arg("ENDPOINT_URL")
            .arg(&entry.endpoint_url)
            .arg("RECEIVED_AT_MS")
            .arg(entry.received_at_ms.to_string())
            .arg("DELAY_MILLI")
            .arg(entry.delay_milli.to_string())
            .arg("EXPIRES_AT")
            .arg(entry.expires_at.to_string())
            .arg("RETRY_COUNT")
            .arg(entry.retry_count.to_string())
            .arg("HOP_COUNT")
            .arg(entry.hop_count.to_string())
            .query_async(&mut conn)
            .await
            .map_err(|err| ProcessorError::ForwardingError(format!("XADD error: {err}")))?;

        debug!("Re-enqueued forward message: stream_id={}", stream_id);
        Ok(stream_id)
    }

    /// Store a message in the sender's receive queue (for problem reports)
    pub(crate) async fn store_problem_report(
        &self,
        message: &str,
        to_did_hash: &str,
        expires_at: u64,
    ) -> Result<(), ProcessorError> {
        let mut conn =
            self.database.get_async_connection().await.map_err(|e| {
                ProcessorError::ForwardingError(format!("DB connection error: {e}"))
            })?;

        let message_hash = sha256::digest(message.as_bytes());

        redis::cmd("FCALL")
            .arg("store_message")
            .arg(1)
            .arg(&message_hash)
            .arg(message)
            .arg(expires_at)
            .arg(message.len())
            .arg(to_did_hash)
            .arg("SYSTEM")
            .exec_async(&mut conn)
            .await
            .map_err(|err| {
                ProcessorError::ForwardingError(format!("Couldn't store problem report: {err}"))
            })?;

        debug!(
            "Stored problem report hash({}) for did_hash({})",
            message_hash, to_did_hash
        );
        Ok(())
    }
}

fn parse_forward_entry(
    stream_id: String,
    fields: HashMap<String, String>,
) -> Result<ForwardQueueEntry, String> {
    Ok(ForwardQueueEntry {
        stream_id,
        message: fields.get("MESSAGE").ok_or("missing MESSAGE")?.clone(),
        to_did_hash: fields
            .get("TO_DID_HASH")
            .ok_or("missing TO_DID_HASH")?
            .clone(),
        from_did_hash: fields
            .get("FROM_DID_HASH")
            .ok_or("missing FROM_DID_HASH")?
            .clone(),
        from_did: fields.get("FROM_DID").unwrap_or(&String::new()).clone(),
        to_did: fields.get("TO_DID").ok_or("missing TO_DID")?.clone(),
        endpoint_url: fields
            .get("ENDPOINT_URL")
            .ok_or("missing ENDPOINT_URL")?
            .clone(),
        received_at_ms: fields
            .get("RECEIVED_AT_MS")
            .ok_or("missing RECEIVED_AT_MS")?
            .parse()
            .map_err(|_| "invalid RECEIVED_AT_MS")?,
        delay_milli: fields
            .get("DELAY_MILLI")
            .ok_or("missing DELAY_MILLI")?
            .parse()
            .map_err(|_| "invalid DELAY_MILLI")?,
        expires_at: fields
            .get("EXPIRES_AT")
            .ok_or("missing EXPIRES_AT")?
            .parse()
            .map_err(|_| "invalid EXPIRES_AT")?,
        retry_count: fields
            .get("RETRY_COUNT")
            .ok_or("missing RETRY_COUNT")?
            .parse()
            .map_err(|_| "invalid RETRY_COUNT")?,
        hop_count: fields
            .get("HOP_COUNT")
            .unwrap_or(&"0".to_string())
            .parse()
            .unwrap_or(0),
    })
}
