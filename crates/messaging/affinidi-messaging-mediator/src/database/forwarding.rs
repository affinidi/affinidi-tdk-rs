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
    /// Hop counter for loop detection. Incremented each time a mediator forwards the message.
    pub hop_count: u32,
}

impl Database {
    /// Enqueue a message for forwarding to a remote mediator.
    /// Uses MAXLEN with approximate trimming (~) to bound the stream size.
    pub async fn forward_queue_enqueue(
        &self,
        entry: &ForwardQueueEntry,
    ) -> Result<String, MediatorError> {
        self.forward_queue_enqueue_with_limit(entry, 0).await
    }

    /// Enqueue a message with an explicit max stream length.
    /// If `max_len` is 0, no MAXLEN constraint is applied.
    pub async fn forward_queue_enqueue_with_limit(
        &self,
        entry: &ForwardQueueEntry,
        max_len: usize,
    ) -> Result<String, MediatorError> {
        let mut conn = self.get_connection().await?;

        let mut cmd = redis::cmd("XADD");
        cmd.arg("FORWARD_Q");
        if max_len > 0 {
            cmd.arg("MAXLEN").arg("~").arg(max_len);
        }
        let stream_id: String = cmd
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
    pub async fn forward_queue_ensure_group(&self, group_name: &str) -> Result<(), MediatorError> {
        let mut conn = self.get_connection().await?;

        // XGROUP CREATE FORWARD_Q <group> 0 MKSTREAM
        let result: Result<String, _> = redis::cmd("XGROUP")
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
        // Use a dedicated connection with no response timeout for blocking XREADGROUP.
        // The redis crate 1.x defaults to a 500ms response timeout which is shorter
        // than the BLOCK duration, causing spurious timeout errors.
        let mut conn = self.get_blocking_connection().await?;

        // XREADGROUP GROUP <group> <consumer> BLOCK <ms> COUNT <n> STREAMS FORWARD_Q >
        let result: Option<Vec<(String, Vec<(String, HashMap<String, String>)>)>> =
            redis::cmd("XREADGROUP")
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

        let mut conn = self.get_connection().await?;

        let mut cmd = redis::cmd("XACK");
        cmd.arg("FORWARD_Q").arg(group_name);
        for id in stream_ids {
            cmd.arg(*id);
        }
        cmd.exec_async(&mut conn).await.map_err(|err| {
            event!(Level::ERROR, "XACK error: {}", err);
            MediatorError::DatabaseError(93, "forwarding".into(), format!("XACK error: {err}"))
        })?;

        Ok(())
    }

    /// Delete acknowledged messages from the stream to free memory
    pub async fn forward_queue_delete(&self, stream_ids: &[&str]) -> Result<(), MediatorError> {
        if stream_ids.is_empty() {
            return Ok(());
        }

        let mut conn = self.get_connection().await?;

        let mut cmd = redis::cmd("XDEL");
        cmd.arg("FORWARD_Q");
        for id in stream_ids {
            cmd.arg(*id);
        }
        cmd.exec_async(&mut conn).await.map_err(|err| {
            event!(Level::ERROR, "XDEL error: {}", err);
            MediatorError::DatabaseError(94, "forwarding".into(), format!("XDEL error: {err}"))
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
        let mut conn = self.get_connection().await?;

        // XAUTOCLAIM FORWARD_Q <group> <consumer> <min-idle-ms> 0 COUNT <n>
        // Returns: [next-start-id, [[id, [field, value, ...]], ...], [deleted-ids]]
        let result: (String, Vec<(String, HashMap<String, String>)>, Vec<String>) =
            redis::cmd("XAUTOCLAIM")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_forward_queue_entry_defaults() {
        let entry = ForwardQueueEntry {
            stream_id: String::new(),
            message: "test message".to_string(),
            to_did_hash: "hash123".to_string(),
            from_did_hash: "hash456".to_string(),
            from_did: "did:example:sender".to_string(),
            to_did: "did:example:recipient".to_string(),
            endpoint_url: "https://example.com/didcomm".to_string(),
            received_at_ms: 1000000,
            delay_milli: 0,
            expires_at: 2000000,
            retry_count: 0,
            hop_count: 0,
        };
        assert_eq!(entry.retry_count, 0);
        assert_eq!(entry.delay_milli, 0);
        assert_eq!(entry.hop_count, 0);
        assert!(!entry.message.is_empty());
    }

    #[test]
    fn test_forward_queue_entry_clone() {
        let entry = ForwardQueueEntry {
            stream_id: "1234-0".to_string(),
            message: "packed_msg".to_string(),
            to_did_hash: "to_hash".to_string(),
            from_did_hash: "from_hash".to_string(),
            from_did: "did:example:sender".to_string(),
            to_did: "did:example:recipient".to_string(),
            endpoint_url: "https://mediator.example.com".to_string(),
            received_at_ms: 1000,
            delay_milli: 500,
            expires_at: 9999,
            retry_count: 3,
            hop_count: 2,
        };
        let cloned = entry.clone();
        assert_eq!(cloned.stream_id, entry.stream_id);
        assert_eq!(cloned.message, entry.message);
        assert_eq!(cloned.retry_count, entry.retry_count);
        assert_eq!(cloned.delay_milli, entry.delay_milli);
        assert_eq!(cloned.hop_count, entry.hop_count);
    }

    /// Helper to build a complete HashMap for parse_forward_entry
    fn make_fields(overrides: Vec<(&str, &str)>) -> HashMap<String, String> {
        let mut fields = HashMap::new();
        fields.insert("MESSAGE".into(), "test_msg".into());
        fields.insert("TO_DID_HASH".into(), "to_hash".into());
        fields.insert("FROM_DID_HASH".into(), "from_hash".into());
        fields.insert("FROM_DID".into(), "did:example:sender".into());
        fields.insert("TO_DID".into(), "did:example:recipient".into());
        fields.insert("ENDPOINT_URL".into(), "https://example.com".into());
        fields.insert("RECEIVED_AT_MS".into(), "1000000".into());
        fields.insert("DELAY_MILLI".into(), "0".into());
        fields.insert("EXPIRES_AT".into(), "2000000".into());
        fields.insert("RETRY_COUNT".into(), "0".into());
        for (k, v) in overrides {
            fields.insert(k.into(), v.into());
        }
        fields
    }

    #[test]
    fn test_parse_forward_entry_success() {
        let fields = make_fields(vec![]);
        let entry = parse_forward_entry("stream-1".into(), fields).unwrap();
        assert_eq!(entry.stream_id, "stream-1");
        assert_eq!(entry.message, "test_msg");
        assert_eq!(entry.to_did_hash, "to_hash");
        assert_eq!(entry.from_did_hash, "from_hash");
        assert_eq!(entry.from_did, "did:example:sender");
        assert_eq!(entry.to_did, "did:example:recipient");
        assert_eq!(entry.endpoint_url, "https://example.com");
        assert_eq!(entry.received_at_ms, 1000000);
        assert_eq!(entry.delay_milli, 0);
        assert_eq!(entry.expires_at, 2000000);
        assert_eq!(entry.retry_count, 0);
    }

    #[test]
    fn test_parse_forward_entry_with_retry_count() {
        let fields = make_fields(vec![("RETRY_COUNT", "5")]);
        let entry = parse_forward_entry("s-2".into(), fields).unwrap();
        assert_eq!(entry.retry_count, 5);
    }

    #[test]
    fn test_parse_forward_entry_with_negative_delay() {
        let fields = make_fields(vec![("DELAY_MILLI", "-100")]);
        let entry = parse_forward_entry("s-3".into(), fields).unwrap();
        assert_eq!(entry.delay_milli, -100);
    }

    #[test]
    fn test_parse_forward_entry_missing_message() {
        let mut fields = make_fields(vec![]);
        fields.remove("MESSAGE");
        let result = parse_forward_entry("s-4".into(), fields);
        assert_eq!(result.unwrap_err(), "missing MESSAGE");
    }

    #[test]
    fn test_parse_forward_entry_missing_to_did_hash() {
        let mut fields = make_fields(vec![]);
        fields.remove("TO_DID_HASH");
        let result = parse_forward_entry("s-5".into(), fields);
        assert_eq!(result.unwrap_err(), "missing TO_DID_HASH");
    }

    #[test]
    fn test_parse_forward_entry_missing_endpoint_url() {
        let mut fields = make_fields(vec![]);
        fields.remove("ENDPOINT_URL");
        let result = parse_forward_entry("s-6".into(), fields);
        assert_eq!(result.unwrap_err(), "missing ENDPOINT_URL");
    }

    #[test]
    fn test_parse_forward_entry_invalid_received_at_ms() {
        let fields = make_fields(vec![("RECEIVED_AT_MS", "not_a_number")]);
        let result = parse_forward_entry("s-7".into(), fields);
        assert_eq!(result.unwrap_err(), "invalid RECEIVED_AT_MS");
    }

    #[test]
    fn test_parse_forward_entry_invalid_expires_at() {
        let fields = make_fields(vec![("EXPIRES_AT", "abc")]);
        let result = parse_forward_entry("s-8".into(), fields);
        assert_eq!(result.unwrap_err(), "invalid EXPIRES_AT");
    }

    #[test]
    fn test_parse_forward_entry_invalid_retry_count() {
        let fields = make_fields(vec![("RETRY_COUNT", "-1")]);
        let result = parse_forward_entry("s-9".into(), fields);
        assert_eq!(result.unwrap_err(), "invalid RETRY_COUNT");
    }

    #[test]
    fn test_parse_forward_entry_missing_from_did_defaults_empty() {
        let mut fields = make_fields(vec![]);
        fields.remove("FROM_DID");
        let entry = parse_forward_entry("s-10".into(), fields).unwrap();
        assert_eq!(entry.from_did, "");
    }

    #[test]
    fn test_parse_forward_entry_missing_to_did() {
        let mut fields = make_fields(vec![]);
        fields.remove("TO_DID");
        let result = parse_forward_entry("s-11".into(), fields);
        assert_eq!(result.unwrap_err(), "missing TO_DID");
    }

    #[test]
    fn test_parse_forward_entry_missing_delay_milli() {
        let mut fields = make_fields(vec![]);
        fields.remove("DELAY_MILLI");
        let result = parse_forward_entry("s-12".into(), fields);
        assert_eq!(result.unwrap_err(), "missing DELAY_MILLI");
    }

    #[test]
    fn test_forward_queue_entry_serialization_roundtrip() {
        let entry = ForwardQueueEntry {
            stream_id: "1-0".to_string(),
            message: "{\"encrypted\":true}".to_string(),
            to_did_hash: "abc".to_string(),
            from_did_hash: "def".to_string(),
            from_did: "did:example:alice".to_string(),
            to_did: "did:example:bob".to_string(),
            endpoint_url: "https://mediator.example.com".to_string(),
            received_at_ms: 1234567890,
            delay_milli: 5000,
            expires_at: 9999999999,
            retry_count: 2,
            hop_count: 1,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: ForwardQueueEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.stream_id, entry.stream_id);
        assert_eq!(deserialized.message, entry.message);
        assert_eq!(deserialized.delay_milli, entry.delay_milli);
        assert_eq!(deserialized.retry_count, entry.retry_count);
        assert_eq!(deserialized.expires_at, entry.expires_at);
    }
}
