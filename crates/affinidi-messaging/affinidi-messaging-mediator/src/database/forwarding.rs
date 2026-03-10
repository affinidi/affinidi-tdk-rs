//! Database operations for the FORWARD_Q Redis stream
//! Used by the forwarding processor to enqueue, read, and acknowledge
//! messages that need to be forwarded to remote mediators.

use super::Database;
use affinidi_messaging_mediator_common::errors::MediatorError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{Level, debug, event, warn};

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
}

impl Database {
    /// Enqueue a message for forwarding to a remote mediator
    pub async fn forward_queue_enqueue(
        &self,
        entry: &ForwardQueueEntry,
    ) -> Result<String, MediatorError> {
        let mut conn = self.0.get_async_connection().await?;

        let stream_id: String = deadpool_redis::redis::cmd("XADD")
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
            .query_async(&mut conn)
            .await
            .map_err(|err| {
                event!(Level::ERROR, "Couldn't enqueue forward message: {}", err);
                MediatorError::DatabaseError(
                    90,
                    "forwarding".into(),
                    format!("Couldn't enqueue forward message: {err}"),
                )
            })?;

        debug!("Enqueued forward message: stream_id={}", stream_id);
        Ok(stream_id)
    }

    /// Ensure the consumer group exists for FORWARD_Q.
    /// Creates the group if it doesn't exist; ignores "BUSYGROUP" errors.
    pub async fn forward_queue_ensure_group(
        &self,
        group_name: &str,
    ) -> Result<(), MediatorError> {
        let mut conn = self.0.get_async_connection().await?;

        // XGROUP CREATE FORWARD_Q <group> 0 MKSTREAM
        let result: Result<String, _> = deadpool_redis::redis::cmd("XGROUP")
            .arg("CREATE")
            .arg("FORWARD_Q")
            .arg(group_name)
            .arg("0")
            .arg("MKSTREAM")
            .query_async(&mut conn)
            .await;

        match result {
            Ok(_) => {
                debug!("Created consumer group '{}' for FORWARD_Q", group_name);
                Ok(())
            }
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("BUSYGROUP") {
                    debug!("Consumer group '{}' already exists", group_name);
                    Ok(())
                } else {
                    event!(Level::ERROR, "Couldn't create consumer group: {}", e);
                    Err(MediatorError::DatabaseError(
                        91,
                        "forwarding".into(),
                        format!("Couldn't create consumer group: {e}"),
                    ))
                }
            }
        }
    }

    /// Blocking read from FORWARD_Q using consumer groups.
    /// Returns up to `count` new messages, blocking for `block_ms` milliseconds.
    /// Use block_ms=0 for indefinite blocking.
    pub async fn forward_queue_read(
        &self,
        group_name: &str,
        consumer_name: &str,
        count: usize,
        block_ms: usize,
    ) -> Result<Vec<ForwardQueueEntry>, MediatorError> {
        let mut conn = self.0.get_async_connection().await?;

        // XREADGROUP GROUP <group> <consumer> BLOCK <ms> COUNT <n> STREAMS FORWARD_Q >
        let result: Option<Vec<(String, Vec<(String, HashMap<String, String>)>)>> =
            deadpool_redis::redis::cmd("XREADGROUP")
                .arg("GROUP")
                .arg(group_name)
                .arg(consumer_name)
                .arg("BLOCK")
                .arg(block_ms)
                .arg("COUNT")
                .arg(count)
                .arg("STREAMS")
                .arg("FORWARD_Q")
                .arg(">")
                .query_async(&mut conn)
                .await
                .map_err(|err| {
                    // Timeout returns nil, which is Ok(None)
                    event!(Level::ERROR, "XREADGROUP error: {}", err);
                    MediatorError::DatabaseError(
                        92,
                        "forwarding".into(),
                        format!("XREADGROUP error: {err}"),
                    )
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
    pub async fn forward_queue_ack(
        &self,
        group_name: &str,
        stream_ids: &[&str],
    ) -> Result<(), MediatorError> {
        if stream_ids.is_empty() {
            return Ok(());
        }

        let mut conn = self.0.get_async_connection().await?;

        let mut cmd = deadpool_redis::redis::cmd("XACK");
        cmd.arg("FORWARD_Q").arg(group_name);
        for id in stream_ids {
            cmd.arg(*id);
        }
        cmd.exec_async(&mut conn).await.map_err(|err| {
            event!(Level::ERROR, "XACK error: {}", err);
            MediatorError::DatabaseError(
                93,
                "forwarding".into(),
                format!("XACK error: {err}"),
            )
        })?;

        Ok(())
    }

    /// Delete acknowledged messages from the stream to free memory
    pub async fn forward_queue_delete(
        &self,
        stream_ids: &[&str],
    ) -> Result<(), MediatorError> {
        if stream_ids.is_empty() {
            return Ok(());
        }

        let mut conn = self.0.get_async_connection().await?;

        let mut cmd = deadpool_redis::redis::cmd("XDEL");
        cmd.arg("FORWARD_Q");
        for id in stream_ids {
            cmd.arg(*id);
        }
        cmd.exec_async(&mut conn).await.map_err(|err| {
            event!(Level::ERROR, "XDEL error: {}", err);
            MediatorError::DatabaseError(
                94,
                "forwarding".into(),
                format!("XDEL error: {err}"),
            )
        })?;

        Ok(())
    }

    /// Claim stale messages from crashed/timed-out consumers.
    /// Messages idle for more than `min_idle_ms` are transferred to this consumer.
    pub async fn forward_queue_autoclaim(
        &self,
        group_name: &str,
        consumer_name: &str,
        min_idle_ms: u64,
        count: usize,
    ) -> Result<Vec<ForwardQueueEntry>, MediatorError> {
        let mut conn = self.0.get_async_connection().await?;

        // XAUTOCLAIM FORWARD_Q <group> <consumer> <min-idle-ms> 0 COUNT <n>
        // Returns: [next-start-id, [[id, [field, value, ...]], ...], [deleted-ids]]
        let result: (String, Vec<(String, HashMap<String, String>)>, Vec<String>) =
            deadpool_redis::redis::cmd("XAUTOCLAIM")
                .arg("FORWARD_Q")
                .arg(group_name)
                .arg(consumer_name)
                .arg(min_idle_ms)
                .arg("0-0")
                .arg("COUNT")
                .arg(count)
                .query_async(&mut conn)
                .await
                .map_err(|err| {
                    event!(Level::ERROR, "XAUTOCLAIM error: {}", err);
                    MediatorError::DatabaseError(
                        95,
                        "forwarding".into(),
                        format!("XAUTOCLAIM error: {err}"),
                    )
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
}

fn parse_forward_entry(
    stream_id: String,
    fields: HashMap<String, String>,
) -> Result<ForwardQueueEntry, String> {
    Ok(ForwardQueueEntry {
        stream_id,
        message: fields
            .get("MESSAGE")
            .ok_or("missing MESSAGE")?
            .clone(),
        to_did_hash: fields
            .get("TO_DID_HASH")
            .ok_or("missing TO_DID_HASH")?
            .clone(),
        from_did_hash: fields
            .get("FROM_DID_HASH")
            .ok_or("missing FROM_DID_HASH")?
            .clone(),
        from_did: fields
            .get("FROM_DID")
            .unwrap_or(&String::new())
            .clone(),
        to_did: fields
            .get("TO_DID")
            .ok_or("missing TO_DID")?
            .clone(),
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
    })
}
