//! Database operations for the FORWARD_Q Redis stream
//! Used by the forwarding processor to enqueue, read, and acknowledge
//! messages that need to be forwarded to remote mediators.

use super::Database;
use crate::errors::MediatorError;
use std::collections::HashMap;
use tracing::{Level, debug, event, warn};

pub use crate::store::types::ForwardQueueEntry;

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
        cmd.arg("*");
        for (field, value) in entry_fields(entry) {
            cmd.arg(field).arg(value);
        }
        let stream_id: String = cmd.query_async(&mut conn).await.map_err(|err| {
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
        #[allow(clippy::type_complexity)]
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
        let mut malformed = Vec::new();
        for (_stream_name, messages) in streams {
            for (stream_id, fields) in messages {
                match parse_forward_entry(stream_id.clone(), fields) {
                    Ok(entry) => entries.push(entry),
                    Err(e) => {
                        warn!("Dropping malformed FORWARD_Q entry {stream_id}: {e}");
                        malformed.push(stream_id);
                    }
                }
            }
        }
        // Claimed by this read, so this consumer drops it; left claimed it
        // would come back through every reclaim sweep.
        for stream_id in malformed {
            if let Err(e) = self
                .forward_queue_finish(group_name, consumer_name, &stream_id, None)
                .await
            {
                warn!("Could not drop malformed FORWARD_Q entry {stream_id}: {e}");
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
    ///
    /// One XAUTOCLAIM, from `start`: Redis examines at most ten times `count`
    /// pending entries per call, so the returned cursor must be followed to
    /// cover the whole list. Returns `(next cursor, entries)`; the cursor is
    /// `0-0` once the scan is complete.
    pub async fn forward_queue_autoclaim(
        &self,
        group_name: &str,
        consumer_name: &str,
        min_idle_ms: u64,
        count: usize,
        start: &str,
    ) -> Result<(String, Vec<ForwardQueueEntry>), MediatorError> {
        let mut conn = self.get_connection().await?;

        // XAUTOCLAIM FORWARD_Q <group> <consumer> <min-idle-ms> <start> COUNT <n>
        // Returns: [next-start-id, [[id, [field, value, ...]], ...], [deleted-ids]]
        #[allow(clippy::type_complexity)]
        let result: (String, Vec<(String, HashMap<String, String>)>, Vec<String>) =
            redis::cmd("XAUTOCLAIM")
                .arg("FORWARD_Q")
                .arg(group_name)
                .arg(consumer_name)
                .arg(min_idle_ms)
                .arg(start)
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
        let mut malformed = Vec::new();
        for (stream_id, fields) in result.1 {
            match parse_forward_entry(stream_id.clone(), fields) {
                Ok(entry) => entries.push(entry),
                Err(e) => {
                    warn!("Dropping malformed FORWARD_Q entry {stream_id}: {e}");
                    malformed.push(stream_id);
                }
            }
        }
        // Just claimed by this consumer, so it is this consumer's to drop;
        // left alone it would be reclaimed, and skipped, on every sweep.
        for stream_id in malformed {
            if let Err(e) = self
                .forward_queue_finish(group_name, consumer_name, &stream_id, None)
                .await
            {
                warn!("Could not drop malformed FORWARD_Q entry {stream_id}: {e}");
            }
        }

        Ok((result.0, entries))
    }

    /// See [`MediatorStore::forward_queue_finish`](crate::store::MediatorStore::forward_queue_finish).
    pub async fn forward_queue_finish(
        &self,
        group_name: &str,
        consumer_name: &str,
        stream_id: &str,
        requeue: Option<&ForwardQueueEntry>,
    ) -> Result<bool, MediatorError> {
        let mut conn = self.get_connection().await?;
        let mut invocation = FINISH.key("FORWARD_Q");
        invocation.arg(group_name).arg(consumer_name).arg(stream_id);
        if let Some(entry) = requeue {
            for (field, value) in entry_fields(entry) {
                invocation.arg(field).arg(value);
            }
        }
        let finished: i64 = invocation.invoke_async(&mut conn).await.map_err(|err| {
            event!(Level::ERROR, "forward queue finish error: {}", err);
            MediatorError::DatabaseError(
                97,
                "forwarding".into(),
                format!("forward queue finish error: {err}"),
            )
        })?;
        Ok(finished == 1)
    }
}

/// Reset the idle time of the entries in ARGV[3..] that consumer ARGV[2] of
/// group ARGV[1] still holds, and return the ids it does not. Ownership is
/// checked and the claim refreshed in one script, so a claim another
/// consumer has taken over is never moved back.
///
/// KEYS: [1] the stream.
static REFRESH_CLAIMS: std::sync::LazyLock<redis::Script> = std::sync::LazyLock::new(|| {
    redis::Script::new(
        r#"
local lost = {}
for i = 3, #ARGV do
  local p = redis.call('XPENDING', KEYS[1], ARGV[1], ARGV[i], ARGV[i], 1)
  if p[1] and p[1][2] == ARGV[2] then
    redis.call('XCLAIM', KEYS[1], ARGV[1], ARGV[2], 0, ARGV[i], 'JUSTID')
  else
    lost[#lost + 1] = ARGV[i]
  end
end
return lost
"#,
    )
});

/// Finish with entry ARGV[3] for consumer ARGV[2] of group ARGV[1], only if
/// that consumer still holds it: XACK and XDEL it, and when field/value pairs
/// follow in ARGV[4..], XADD them as its replacement first. Returns 1 when
/// done, 0 when the entry is not held by that consumer (nothing changed).
///
/// KEYS: [1] the stream.
static FINISH: std::sync::LazyLock<redis::Script> = std::sync::LazyLock::new(|| {
    redis::Script::new(
        r#"
local p = redis.call('XPENDING', KEYS[1], ARGV[1], ARGV[3], ARGV[3], 1)
if not (p[1] and p[1][2] == ARGV[2]) then
  return 0
end
if #ARGV > 3 then
  local fields = {}
  for i = 4, #ARGV do
    fields[#fields + 1] = ARGV[i]
  end
  redis.call('XADD', KEYS[1], '*', unpack(fields))
end
redis.call('XACK', KEYS[1], ARGV[1], ARGV[3])
redis.call('XDEL', KEYS[1], ARGV[3])
return 1
"#,
    )
});

/// The stream fields of a queue entry, as `XADD` writes them.
fn entry_fields(entry: &ForwardQueueEntry) -> [(&'static str, String); 12] {
    [
        ("MESSAGE", entry.message.clone()),
        ("TO_DID_HASH", entry.to_did_hash.clone()),
        ("FROM_DID_HASH", entry.from_did_hash.clone()),
        ("FROM_DID", entry.from_did.clone()),
        ("TO_DID", entry.to_did.clone()),
        ("ENDPOINT_URL", entry.endpoint_url.clone()),
        ("RECEIVED_AT_MS", entry.received_at_ms.to_string()),
        ("DELAY_MILLI", entry.delay_milli.to_string()),
        ("EXPIRES_AT", entry.expires_at.to_string()),
        ("RETRY_COUNT", entry.retry_count.to_string()),
        ("HOP_COUNT", entry.hop_count.to_string()),
        ("NOT_BEFORE_MS", entry.not_before_ms.to_string()),
    ]
}

/// Ids per refresh script call, so one call does not hold Redis for long.
const REFRESH_CHUNK: usize = 256;

impl Database {
    /// See [`MediatorStore::forward_queue_refresh_claims`](crate::store::MediatorStore::forward_queue_refresh_claims).
    pub async fn forward_queue_refresh_claims(
        &self,
        group_name: &str,
        consumer_name: &str,
        stream_ids: &[&str],
    ) -> Result<Vec<String>, MediatorError> {
        let mut lost = Vec::new();
        if stream_ids.is_empty() {
            return Ok(lost);
        }
        let mut conn = self.get_connection().await?;
        for chunk in stream_ids.chunks(REFRESH_CHUNK) {
            let mut invocation = REFRESH_CLAIMS.key("FORWARD_Q");
            invocation.arg(group_name).arg(consumer_name);
            for id in chunk {
                invocation.arg(*id);
            }
            let chunk_lost: Vec<String> =
                invocation.invoke_async(&mut conn).await.map_err(|err| {
                    event!(Level::ERROR, "forward claim refresh error: {}", err);
                    MediatorError::DatabaseError(
                        96,
                        "forwarding".into(),
                        format!("forward claim refresh error: {err}"),
                    )
                })?;
            lost.extend(chunk_lost);
        }
        Ok(lost)
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
        // Absent on entries written before retries carried a not-before.
        not_before_ms: fields
            .get("NOT_BEFORE_MS")
            .and_then(|v| v.parse().ok())
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
            not_before_ms: 0,
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
            not_before_ms: 0,
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
            not_before_ms: 0,
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
