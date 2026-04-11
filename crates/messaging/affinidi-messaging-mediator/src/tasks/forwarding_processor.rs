//! Forwarding Processor
//!
//! Reads messages from the FORWARD_Q Redis stream and delivers them to remote mediators.
//! Uses Redis consumer groups for multi-processor coordination:
//! - XREADGROUP BLOCK 0 for event-driven wake-up (no polling)
//! - XACK on successful delivery
//! - XAUTOCLAIM for recovering stale messages from crashed processors
//!
//! Transport selection:
//! - Tracks message rate per endpoint over a sliding window
//! - If rate exceeds threshold: use WebSocket (kept alive with idle timeout)
//! - Otherwise: use REST POST
//!
//! Error handling:
//! - Connection failures: retry with exponential backoff
//! - Rejection from remote mediator: send problem report to sender, drop message

use crate::common::time::{unix_timestamp_millis, unix_timestamp_secs};
use crate::{
    common::config::ForwardingConfig, database::Database, database::forwarding::ForwardQueueEntry,
};
use futures_util::{SinkExt, StreamExt};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{Mutex, RwLock};
use tokio_tungstenite::tungstenite;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// Tracks message rate to a specific endpoint over a sliding window
struct EndpointRateTracker {
    /// Timestamps of messages sent within the rate window
    timestamps: Vec<Instant>,
    /// Rate window duration
    window: Duration,
}

impl EndpointRateTracker {
    fn new(window_seconds: u64) -> Self {
        Self {
            timestamps: Vec::new(),
            window: Duration::from_secs(window_seconds),
        }
    }

    /// Record a message send and return current rate per 10 seconds
    fn record_and_rate(&mut self) -> f64 {
        let now = Instant::now();
        self.timestamps.push(now);
        self.prune(now);
        let window_secs = self.window.as_secs_f64();
        if window_secs > 0.0 {
            (self.timestamps.len() as f64 / window_secs) * 10.0
        } else {
            0.0
        }
    }

    /// Get current rate per 10 seconds without recording
    fn current_rate(&mut self) -> f64 {
        self.prune(Instant::now());
        let window_secs = self.window.as_secs_f64();
        if window_secs > 0.0 {
            (self.timestamps.len() as f64 / window_secs) * 10.0
        } else {
            0.0
        }
    }

    fn prune(&mut self, now: Instant) {
        let cutoff = now - self.window;
        self.timestamps.retain(|t| *t > cutoff);
    }
}

/// State for a connection to a remote mediator endpoint
struct EndpointState {
    rate_tracker: EndpointRateTracker,
    last_activity: Instant,
    /// Consecutive failure count for backoff calculation
    consecutive_failures: u32,
}

/// Shared HTTP client to avoid creating one per request
struct HttpClientPool {
    client: reqwest::Client,
}

impl HttpClientPool {
    fn new(accept_invalid_certs: bool) -> Result<Self, String> {
        if accept_invalid_certs {
            warn!(
                "HTTP client configured to accept invalid TLS certificates — NOT safe for production"
            );
        }
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .danger_accept_invalid_certs(accept_invalid_certs)
            .pool_max_idle_per_host(10)
            .pool_idle_timeout(Duration::from_secs(90))
            .build()
            .map_err(|e| format!("HTTP client error: {e}"))?;
        Ok(Self { client })
    }
}

/// A pooled WebSocket connection to a remote mediator
struct PooledWebSocket {
    /// Write half of the WebSocket stream
    writer: futures_util::stream::SplitSink<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        tungstenite::Message,
    >,
    /// When this connection was last used
    last_used: Instant,
}

/// The forwarding processor that reads from FORWARD_Q and delivers to remote mediators
pub struct ForwardingProcessor {
    config: ForwardingConfig,
    database: Database,
    consumer_name: String,
    endpoints: Arc<RwLock<HashMap<String, EndpointState>>>,
    http_pool: Arc<HttpClientPool>,
    /// WebSocket connection pool keyed by endpoint URL
    ws_pool: Arc<Mutex<HashMap<String, PooledWebSocket>>>,
}

impl ForwardingProcessor {
    pub fn new(config: ForwardingConfig, database: Database) -> Self {
        let consumer_name = format!("processor_{}", Uuid::new_v4());
        info!(
            "ForwardingProcessor created: consumer={}, group={}",
            consumer_name, config.consumer_group
        );
        let http_pool = Arc::new(
            HttpClientPool::new(config.accept_invalid_certs)
                .expect("Failed to create HTTP client pool"),
        );
        Self {
            config,
            database,
            consumer_name,
            endpoints: Arc::new(RwLock::new(HashMap::new())),
            http_pool,
            ws_pool: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Start the forwarding processor. This runs indefinitely.
    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Ensure consumer group exists
        self.database
            .forward_queue_ensure_group(&self.config.consumer_group)
            .await
            .map_err(|e| format!("Failed to create consumer group: {e}"))?;

        info!(
            "ForwardingProcessor started: consumer={}, group={}, batch_size={}, ws_threshold={} msgs/10s, ws_idle_timeout={}s",
            self.consumer_name,
            self.config.consumer_group,
            self.config.batch_size,
            self.config.ws_threshold_msgs_per_10s,
            self.config.ws_idle_timeout_seconds
        );

        // Spawn a background task to periodically reclaim stale messages
        let db_clone = self.database.clone();
        let group = self.config.consumer_group.clone();
        let consumer = self.consumer_name.clone();
        let batch_size = self.config.batch_size;
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(30)).await;
                match db_clone
                    .forward_queue_autoclaim(&group, &consumer, 60_000, batch_size)
                    .await
                {
                    Ok(entries) if !entries.is_empty() => {
                        info!("Autoclaimed {} stale forwarding messages", entries.len());
                    }
                    Ok(_) => {}
                    Err(e) => {
                        warn!("Autoclaim error: {}", e);
                    }
                }
            }
        });

        // Spawn a background task to clean up idle WebSocket connections
        let ws_pool = self.ws_pool.clone();
        let idle_timeout = Duration::from_secs(self.config.ws_idle_timeout_seconds);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(10)).await;
                let mut pool = ws_pool.lock().await;
                let now = Instant::now();
                let before = pool.len();
                pool.retain(|endpoint, ws| {
                    if now.duration_since(ws.last_used) > idle_timeout {
                        info!(
                            "Closing idle WebSocket to {} (idle {}s)",
                            endpoint,
                            now.duration_since(ws.last_used).as_secs()
                        );
                        // Dropping the writer closes the connection
                        false
                    } else {
                        true
                    }
                });
                let closed = before - pool.len();
                if closed > 0 {
                    debug!(
                        "Closed {} idle WebSocket connections ({} remaining)",
                        closed,
                        pool.len()
                    );
                }
            }
        });

        // Main processing loop
        loop {
            let entries = match self
                .database
                .forward_queue_read(
                    &self.config.consumer_group,
                    &self.consumer_name,
                    self.config.batch_size,
                    5000, // 5 second block timeout, then loop to check for stale messages
                )
                .await
            {
                Ok(entries) => entries,
                Err(e) => {
                    error!("Error reading from FORWARD_Q: {}. Retrying in 1s...", e);
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };

            if entries.is_empty() {
                continue;
            }

            debug!("Read {} entries from FORWARD_Q", entries.len());

            // Group by endpoint URL for batch delivery
            let mut by_endpoint: HashMap<String, Vec<ForwardQueueEntry>> = HashMap::new();
            for entry in entries {
                by_endpoint
                    .entry(entry.endpoint_url.clone())
                    .or_default()
                    .push(entry);
            }

            // Process each endpoint group
            for (endpoint_url, messages) in by_endpoint {
                self.process_endpoint_batch(&endpoint_url, messages).await;
            }
        }
    }

    /// Process a batch of messages all destined for the same endpoint
    async fn process_endpoint_batch(&self, endpoint_url: &str, messages: Vec<ForwardQueueEntry>) {
        let msg_count = messages.len();
        debug!(
            "Processing {} messages for endpoint: {}",
            msg_count, endpoint_url
        );

        // Check if any messages have expired
        let now_secs = unix_timestamp_secs();

        let (active, expired): (Vec<_>, Vec<_>) =
            messages.into_iter().partition(|m| m.expires_at > now_secs);

        // ACK and delete expired messages
        if !expired.is_empty() {
            let expired_ids: Vec<&str> = expired.iter().map(|m| m.stream_id.as_str()).collect();
            warn!(
                "Dropping {} expired forwarding messages for endpoint {}",
                expired.len(),
                endpoint_url
            );
            for msg in &expired {
                info!(
                    "FORWARD_EXPIRED: to_did_hash={} from_did_hash={} endpoint={}",
                    msg.to_did_hash, msg.from_did_hash, endpoint_url
                );
            }
            let _ = self
                .database
                .forward_queue_ack(&self.config.consumer_group, &expired_ids)
                .await;
            let _ = self.database.forward_queue_delete(&expired_ids).await;
        }

        if active.is_empty() {
            return;
        }

        // Check if delay_milli requires us to wait
        let mut ready = Vec::new();
        let mut delayed = Vec::new();
        let now_ms = unix_timestamp_millis();

        for msg in active {
            let deliver_at_ms = if msg.delay_milli > 0 {
                msg.received_at_ms + msg.delay_milli as u128
            } else {
                msg.received_at_ms
            };

            if deliver_at_ms <= now_ms {
                ready.push(msg);
            } else {
                delayed.push(msg);
            }
        }

        if !delayed.is_empty() {
            debug!(
                "{} messages delayed for endpoint {}",
                delayed.len(),
                endpoint_url
            );
            // Don't ACK — they stay in pending and will be autoclaimed/re-read
        }

        if ready.is_empty() {
            return;
        }

        // Update rate tracker and decide transport
        let use_websocket = {
            let mut endpoints = self.endpoints.write().await;
            let state = endpoints
                .entry(endpoint_url.to_string())
                .or_insert_with(|| EndpointState {
                    rate_tracker: EndpointRateTracker::new(self.config.rate_window_seconds),
                    last_activity: Instant::now(),
                    consecutive_failures: 0,
                });

            for _ in 0..ready.len() {
                state.rate_tracker.record_and_rate();
            }
            state.last_activity = Instant::now();

            let rate = state.rate_tracker.current_rate();
            debug!(
                "Endpoint {} rate: {:.2} msgs/10s (threshold: {})",
                endpoint_url, rate, self.config.ws_threshold_msgs_per_10s
            );
            rate >= self.config.ws_threshold_msgs_per_10s as f64
        };

        // Deliver messages
        let transport = if use_websocket { "WebSocket" } else { "REST" };
        debug!(
            "Delivering {} messages to {} via {}",
            ready.len(),
            endpoint_url,
            transport
        );

        let mut succeeded = Vec::new();
        let mut failed = Vec::new();

        for msg in &ready {
            match self.deliver_message(endpoint_url, msg, use_websocket).await {
                Ok(()) => {
                    let forward_time_ms = now_ms.saturating_sub(msg.received_at_ms);
                    let delay_info = if msg.delay_milli > 0 {
                        format!(", delay_requested={}ms", msg.delay_milli)
                    } else {
                        String::new()
                    };

                    info!(
                        "FORWARD_DELIVERED: to_did_hash={} from_did_hash={} endpoint={} transport={} forward_time={}ms{}",
                        msg.to_did_hash,
                        msg.from_did_hash,
                        endpoint_url,
                        transport,
                        forward_time_ms,
                        delay_info,
                    );
                    succeeded.push(msg.stream_id.as_str());
                }
                Err(e) => {
                    warn!(
                        "FORWARD_FAILED: to_did_hash={} from_did_hash={} endpoint={} error={} retry_count={}",
                        msg.to_did_hash, msg.from_did_hash, endpoint_url, e, msg.retry_count
                    );
                    failed.push(msg);
                }
            }
        }

        // ACK and delete succeeded messages
        if !succeeded.is_empty() {
            let count = succeeded.len();
            let _ = self
                .database
                .forward_queue_ack(&self.config.consumer_group, &succeeded)
                .await;
            let _ = self.database.forward_queue_delete(&succeeded).await;
            debug!("ACKed {} forwarded messages for {}", count, endpoint_url);

            // Reset failure counter on success
            let mut endpoints = self.endpoints.write().await;
            if let Some(state) = endpoints.get_mut(endpoint_url) {
                state.consecutive_failures = 0;
            }
        }

        // Handle failures
        if !failed.is_empty() {
            let mut endpoints = self.endpoints.write().await;
            let consecutive_failures = if let Some(state) = endpoints.get_mut(endpoint_url) {
                state.consecutive_failures += 1;
                state.consecutive_failures
            } else {
                1
            };
            drop(endpoints);

            // Remove broken WebSocket connection on failure
            if use_websocket {
                let mut pool = self.ws_pool.lock().await;
                if pool.remove(endpoint_url).is_some() {
                    debug!("Removed failed WebSocket connection for {}", endpoint_url);
                }
            }

            for msg in failed {
                if msg.retry_count >= self.config.max_retries {
                    // Max retries exceeded — ACK and drop, send problem report to sender
                    warn!(
                        "FORWARD_ABANDONED: to_did_hash={} from_did_hash={} endpoint={} retries={}",
                        msg.to_did_hash, msg.from_did_hash, endpoint_url, msg.retry_count
                    );
                    let ids = [msg.stream_id.as_str()];
                    let _ = self
                        .database
                        .forward_queue_ack(&self.config.consumer_group, &ids)
                        .await;
                    let _ = self.database.forward_queue_delete(&ids).await;

                    // Send problem report to the original sender if we know their DID
                    if self.config.report_errors && !msg.from_did.is_empty() {
                        self.send_forwarding_failure_report(msg, endpoint_url).await;
                    }
                } else {
                    // Re-enqueue with incremented retry count
                    let mut retry_entry = msg.clone();
                    retry_entry.retry_count += 1;

                    // ACK the old entry
                    let ids = [msg.stream_id.as_str()];
                    let _ = self
                        .database
                        .forward_queue_ack(&self.config.consumer_group, &ids)
                        .await;
                    let _ = self.database.forward_queue_delete(&ids).await;

                    // Enqueue new entry with incremented retry count
                    let _ = self.database.forward_queue_enqueue(&retry_entry).await;
                }
            }

            // Apply backoff before next attempt to this endpoint
            let backoff = self.calculate_backoff(consecutive_failures);
            debug!(
                "Backing off {}ms for endpoint {} (failures: {})",
                backoff.as_millis(),
                endpoint_url,
                consecutive_failures
            );
            tokio::time::sleep(backoff).await;
        }
    }

    /// Send a problem report to the original sender when forwarding has been abandoned
    async fn send_forwarding_failure_report(&self, msg: &ForwardQueueEntry, endpoint_url: &str) {
        let now = unix_timestamp_secs();

        let problem_body = serde_json::json!({
            "code": "e.p.me.res.forwarding.abandoned",
            "comment": format!(
                "Message forwarding to {} failed after {} retries. Destination endpoint: {}",
                msg.to_did, msg.retry_count, endpoint_url
            ),
            "args": [msg.to_did, msg.retry_count.to_string(), endpoint_url],
        });

        let report_msg = serde_json::json!({
            "type": "https://didcomm.org/report-problem/2.0/problem-report",
            "id": Uuid::new_v4().to_string(),
            "body": problem_body,
            "to": [msg.from_did],
            "created_time": now,
            "expires_time": now + 300,
        });

        let report_str = report_msg.to_string();

        match self
            .database
            .store_message(
                "forwarding-processor",
                &report_str,
                &msg.from_did_hash,
                Some("SYSTEM"),
                now + 300,
            )
            .await
        {
            Ok(hash) => {
                info!(
                    "FORWARD_PROBLEM_REPORT: stored problem report {} for sender {}",
                    hash, msg.from_did_hash
                );
            }
            Err(e) => {
                error!(
                    "Failed to store forwarding problem report for {}: {}",
                    msg.from_did_hash, e
                );
            }
        }
    }

    /// Deliver a single message to a remote mediator endpoint
    async fn deliver_message(
        &self,
        endpoint_url: &str,
        msg: &ForwardQueueEntry,
        use_websocket: bool,
    ) -> Result<(), String> {
        if use_websocket {
            match self.deliver_via_websocket(endpoint_url, msg).await {
                Ok(()) => Ok(()),
                Err(ws_err) => {
                    // WebSocket failed — fall back to REST for this message
                    debug!(
                        "WebSocket delivery failed for {}, falling back to REST: {}",
                        endpoint_url, ws_err
                    );
                    self.deliver_via_rest(endpoint_url, msg).await
                }
            }
        } else {
            self.deliver_via_rest(endpoint_url, msg).await
        }
    }

    /// Deliver a message via REST POST to the remote mediator's inbound endpoint
    async fn deliver_via_rest(
        &self,
        endpoint_url: &str,
        msg: &ForwardQueueEntry,
    ) -> Result<(), String> {
        let inbound_url = if endpoint_url.ends_with('/') {
            format!("{}inbound", endpoint_url)
        } else {
            format!("{}/inbound", endpoint_url)
        };

        let response = self
            .http_pool
            .client
            .post(&inbound_url)
            .header("Content-Type", "application/didcomm-encrypted+json")
            .body(msg.message.clone())
            .send()
            .await
            .map_err(|e| format!("Connection error to {}: {}", inbound_url, e))?;

        let status = response.status();
        if status.is_success() {
            Ok(())
        } else {
            let body = response.text().await.unwrap_or_default();
            Err(format!(
                "Remote mediator {} returned HTTP {}: {}",
                inbound_url, status, body
            ))
        }
    }

    /// Deliver a message via WebSocket to the remote mediator.
    ///
    /// Connections are pooled per endpoint URL and kept alive for the configured
    /// idle timeout. When the rate drops below the threshold, the idle cleanup
    /// task closes the connection.
    ///
    /// If no pooled connection exists, a new one is established.
    /// If sending on a pooled connection fails, the connection is removed from
    /// the pool and an error is returned (caller falls back to REST).
    async fn deliver_via_websocket(
        &self,
        endpoint_url: &str,
        msg: &ForwardQueueEntry,
    ) -> Result<(), String> {
        let ws_url = Self::http_to_ws_url(endpoint_url);

        let mut pool = self.ws_pool.lock().await;

        // Try to send on existing connection
        if let Some(ws) = pool.get_mut(endpoint_url) {
            let ws_msg = tungstenite::Message::Text(msg.message.clone().into());
            match ws.writer.send(ws_msg).await {
                Ok(()) => {
                    ws.last_used = Instant::now();
                    debug!("Sent via pooled WebSocket to {}", endpoint_url);
                    return Ok(());
                }
                Err(e) => {
                    warn!(
                        "Pooled WebSocket send failed for {}: {}. Reconnecting...",
                        endpoint_url, e
                    );
                    pool.remove(endpoint_url);
                }
            }
        }

        // No existing connection or it failed — establish a new one
        drop(pool); // Release the lock while connecting

        let (ws_stream, _response) = tokio_tungstenite::connect_async(&ws_url)
            .await
            .map_err(|e| format!("WebSocket connect to {} failed: {}", ws_url, e))?;

        info!("WebSocket connected to {} (pool)", endpoint_url);

        let (mut writer, _reader) = ws_stream.split();

        // Send the message on the fresh connection
        let ws_msg = tungstenite::Message::Text(msg.message.clone().into());
        writer
            .send(ws_msg)
            .await
            .map_err(|e| format!("WebSocket send to {} failed: {}", ws_url, e))?;

        // Store the connection in the pool for reuse
        // We drop the reader side — we're only using WebSocket for sending.
        // The reader would need a background task to handle pings and detect
        // remote close, but for simplicity we rely on send errors to detect stale connections.
        let mut pool = self.ws_pool.lock().await;
        pool.insert(
            endpoint_url.to_string(),
            PooledWebSocket {
                writer,
                last_used: Instant::now(),
            },
        );

        Ok(())
    }

    /// Convert an HTTP(S) endpoint URL to a WebSocket URL
    fn http_to_ws_url(endpoint_url: &str) -> String {
        let ws_base = endpoint_url
            .replace("https://", "wss://")
            .replace("http://", "ws://");

        if ws_base.ends_with('/') {
            format!("{}ws", ws_base)
        } else {
            format!("{}/ws", ws_base)
        }
    }

    /// Calculate exponential backoff duration
    fn calculate_backoff(&self, consecutive_failures: u32) -> Duration {
        let base = self.config.initial_backoff_ms;
        let max = self.config.max_backoff_ms;
        let backoff = base.saturating_mul(2u64.saturating_pow(consecutive_failures.min(10)));
        Duration::from_millis(backoff.min(max))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- http_to_ws_url tests ---

    #[test]
    fn test_http_to_ws_url_https() {
        assert_eq!(
            ForwardingProcessor::http_to_ws_url("https://example.com/path"),
            "wss://example.com/path/ws"
        );
    }

    #[test]
    fn test_http_to_ws_url_http() {
        assert_eq!(
            ForwardingProcessor::http_to_ws_url("http://example.com/path"),
            "ws://example.com/path/ws"
        );
    }

    #[test]
    fn test_http_to_ws_url_with_trailing_slash() {
        assert_eq!(
            ForwardingProcessor::http_to_ws_url("https://example.com/"),
            "wss://example.com/ws"
        );
    }

    #[test]
    fn test_http_to_ws_url_plain_domain() {
        assert_eq!(
            ForwardingProcessor::http_to_ws_url("https://mediator.example.com"),
            "wss://mediator.example.com/ws"
        );
    }

    #[test]
    fn test_http_to_ws_url_with_port() {
        assert_eq!(
            ForwardingProcessor::http_to_ws_url("http://localhost:8080/didcomm"),
            "ws://localhost:8080/didcomm/ws"
        );
    }

    // --- EndpointRateTracker tests ---

    #[test]
    fn test_rate_tracker_new_has_zero_rate() {
        let mut tracker = EndpointRateTracker::new(60);
        assert_eq!(tracker.current_rate(), 0.0);
    }

    #[test]
    fn test_rate_tracker_record_increases_rate() {
        let mut tracker = EndpointRateTracker::new(60);
        let rate = tracker.record_and_rate();
        // 1 message in 60 seconds = 1/60 * 10 = 0.1667 msgs/10s
        assert!(rate > 0.0);
    }

    #[test]
    fn test_rate_tracker_multiple_records() {
        let mut tracker = EndpointRateTracker::new(60);
        for _ in 0..10 {
            tracker.record_and_rate();
        }
        let rate = tracker.current_rate();
        // 10 messages in 60 second window = 10/60 * 10 = ~1.667 msgs/10s
        assert!(rate > 1.0, "rate should be > 1.0, got {}", rate);
        assert!(rate < 2.0, "rate should be < 2.0, got {}", rate);
    }

    #[test]
    fn test_rate_tracker_zero_window_returns_zero() {
        let mut tracker = EndpointRateTracker::new(0);
        // With a zero-second window, all timestamps get pruned immediately
        let rate = tracker.record_and_rate();
        assert_eq!(rate, 0.0);
    }

    // --- calculate_backoff tests ---

    /// Helper to test calculate_backoff without needing a full ForwardingProcessor.
    /// Replicates the same formula: base * 2^min(failures, 10), capped at max.
    fn compute_backoff(
        initial_backoff_ms: u64,
        max_backoff_ms: u64,
        consecutive_failures: u32,
    ) -> Duration {
        let base = initial_backoff_ms;
        let max = max_backoff_ms;
        let backoff = base.saturating_mul(2u64.saturating_pow(consecutive_failures.min(10)));
        Duration::from_millis(backoff.min(max))
    }

    #[test]
    fn test_backoff_zero_failures() {
        // 2^0 = 1, so backoff = initial_backoff_ms * 1 = 1000ms
        let backoff = compute_backoff(1000, 60000, 0);
        assert_eq!(backoff, Duration::from_millis(1000));
    }

    #[test]
    fn test_backoff_one_failure() {
        // 2^1 = 2, so backoff = 1000 * 2 = 2000ms
        let backoff = compute_backoff(1000, 60000, 1);
        assert_eq!(backoff, Duration::from_millis(2000));
    }

    #[test]
    fn test_backoff_three_failures() {
        // 2^3 = 8, so backoff = 1000 * 8 = 8000ms
        let backoff = compute_backoff(1000, 60000, 3);
        assert_eq!(backoff, Duration::from_millis(8000));
    }

    #[test]
    fn test_backoff_capped_at_max() {
        // 2^6 = 64, so 1000 * 64 = 64000ms, but max is 60000ms
        let backoff = compute_backoff(1000, 60000, 6);
        assert_eq!(backoff, Duration::from_millis(60000));
    }

    #[test]
    fn test_backoff_high_failures_capped_exponent_at_10() {
        // Failures > 10 should be clamped to 10: 2^10 = 1024
        // 1000 * 1024 = 1024000, but max is 60000
        let backoff = compute_backoff(1000, 60000, 20);
        assert_eq!(backoff, Duration::from_millis(60000));
    }

    #[test]
    fn test_backoff_custom_initial_and_max() {
        // initial=500, max=5000, failures=2 => 500 * 4 = 2000
        let backoff = compute_backoff(500, 5000, 2);
        assert_eq!(backoff, Duration::from_millis(2000));

        // failures=4 => 500 * 16 = 8000, capped at 5000
        let backoff = compute_backoff(500, 5000, 4);
        assert_eq!(backoff, Duration::from_millis(5000));
    }

    #[test]
    fn test_backoff_saturating_prevents_overflow() {
        // Very large initial_backoff_ms should not panic
        let backoff = compute_backoff(u64::MAX / 2, 60000, 5);
        // Should be capped at max_backoff_ms
        assert_eq!(backoff, Duration::from_millis(60000));
    }
}
