/*!
 * Standalone forwarding processor that reads from FORWARD_Q
 * and delivers messages to remote mediators via REST POST.
 *
 * This processor can run independently from the mediator, connecting
 * directly to the same Redis instance.
 */

use affinidi_messaging_mediator_common::{database::DatabaseHandler, errors::ProcessorError};
use lru::LruCache;
use std::{
    collections::HashMap,
    num::NonZeroUsize,
    time::{Duration, Instant},
};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use super::config::ForwardingProcessorConfig;
use super::database::ForwardQueueEntry;

/// Tracks message rate to a specific endpoint over a sliding window
struct EndpointRateTracker {
    timestamps: Vec<Instant>,
    window: Duration,
}

impl EndpointRateTracker {
    fn new(window_seconds: u64) -> Self {
        Self {
            timestamps: Vec::new(),
            window: Duration::from_secs(window_seconds),
        }
    }

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

struct EndpointState {
    rate_tracker: EndpointRateTracker,
    last_activity: Instant,
    consecutive_failures: u32,
}

/// The standalone forwarding processor
pub struct ForwardingProcessor {
    pub(crate) config: ForwardingProcessorConfig,
    pub(crate) database: DatabaseHandler,
    pub(crate) consumer_name: String,
    endpoints: LruCache<String, EndpointState>,
    http_client: reqwest::Client,
}

impl ForwardingProcessor {
    pub fn new(config: ForwardingProcessorConfig, database: DatabaseHandler) -> Self {
        let consumer_name = format!("processor_{}", Uuid::new_v4());
        info!(
            "ForwardingProcessor created: consumer={}, group={}",
            consumer_name, config.consumer_group
        );
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .danger_accept_invalid_certs(true)
            .pool_max_idle_per_host(10)
            .pool_idle_timeout(Duration::from_secs(90))
            .build()
            .expect("Failed to create HTTP client");

        let max_endpoints =
            NonZeroUsize::new(config.max_endpoints).unwrap_or(NonZeroUsize::new(1000).unwrap());

        Self {
            config,
            database,
            consumer_name,
            endpoints: LruCache::new(max_endpoints),
            http_client,
        }
    }

    pub async fn start(&mut self) -> Result<(), ProcessorError> {
        self.ensure_group().await?;

        info!(
            "ForwardingProcessor started: consumer={}, group={}, batch_size={}",
            self.consumer_name, self.config.consumer_group, self.config.batch_size
        );

        loop {
            let entries = match self.read_entries(5000).await {
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

    async fn process_endpoint_batch(
        &mut self,
        endpoint_url: &str,
        messages: Vec<ForwardQueueEntry>,
    ) {
        let now_secs = crate::unix_epoch_now().as_secs();

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
            let _ = self.ack_entries(&expired_ids).await;
            let _ = self.delete_entries(&expired_ids).await;
        }

        if active.is_empty() {
            return;
        }

        let now_ms = crate::unix_epoch_now().as_millis();

        let (ready, _delayed): (Vec<_>, Vec<_>) = active.into_iter().partition(|msg| {
            let deliver_at_ms = if msg.delay_milli > 0 {
                msg.received_at_ms + msg.delay_milli as u128
            } else {
                msg.received_at_ms
            };
            deliver_at_ms <= now_ms
        });

        if ready.is_empty() {
            return;
        }

        // Update rate tracker (get_or_insert into LRU cache)
        if self.endpoints.get(endpoint_url).is_none() {
            self.endpoints.put(
                endpoint_url.to_string(),
                EndpointState {
                    rate_tracker: EndpointRateTracker::new(self.config.rate_window_seconds),
                    last_activity: Instant::now(),
                    consecutive_failures: 0,
                },
            );
        }
        let state = self.endpoints.get_mut(endpoint_url).expect("just inserted");
        for _ in 0..ready.len() {
            state.rate_tracker.record_and_rate();
        }
        state.last_activity = Instant::now();
        let _rate = state.current_rate_value();

        // Deliver messages
        let mut succeeded = Vec::new();
        let mut failed = Vec::new();

        for msg in &ready {
            match self.deliver_via_rest(endpoint_url, msg).await {
                Ok(()) => {
                    let forward_time_ms = now_ms.saturating_sub(msg.received_at_ms);
                    info!(
                        "FORWARD_DELIVERED: to_did_hash={} from_did_hash={} endpoint={} forward_time={}ms",
                        msg.to_did_hash, msg.from_did_hash, endpoint_url, forward_time_ms,
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

        // ACK succeeded
        if !succeeded.is_empty() {
            let count = succeeded.len();
            let _ = self.ack_entries(&succeeded).await;
            let _ = self.delete_entries(&succeeded).await;
            debug!("ACKed {} forwarded messages for {}", count, endpoint_url);

            if let Some(state) = self.endpoints.get_mut(endpoint_url) {
                state.consecutive_failures = 0;
            }
        }

        // Handle failures
        if !failed.is_empty() {
            let consecutive_failures = if let Some(state) = self.endpoints.get_mut(endpoint_url) {
                state.consecutive_failures += 1;
                state.consecutive_failures
            } else {
                1
            };

            for msg in failed {
                if msg.retry_count >= self.config.max_retries {
                    warn!(
                        "FORWARD_ABANDONED: to_did_hash={} from_did_hash={} endpoint={} retries={}",
                        msg.to_did_hash, msg.from_did_hash, endpoint_url, msg.retry_count
                    );
                    let ids = [msg.stream_id.as_str()];
                    let _ = self.ack_entries(&ids).await;
                    let _ = self.delete_entries(&ids).await;

                    // Send problem report
                    if self.config.report_errors && !msg.from_did.is_empty() {
                        self.send_problem_report(msg, endpoint_url).await;
                    }
                } else {
                    let mut retry_entry = msg.clone();
                    retry_entry.retry_count += 1;

                    let ids = [msg.stream_id.as_str()];
                    let _ = self.ack_entries(&ids).await;
                    let _ = self.delete_entries(&ids).await;
                    let _ = self.enqueue_entry(&retry_entry).await;
                }
            }

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
            .http_client
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

    async fn send_problem_report(&self, msg: &ForwardQueueEntry, endpoint_url: &str) {
        let now = crate::unix_epoch_now().as_secs();

        let report_msg = serde_json::json!({
            "type": "https://didcomm.org/report-problem/2.0/problem-report",
            "id": Uuid::new_v4().to_string(),
            "body": {
                "code": "e.p.me.res.forwarding.abandoned",
                "comment": format!(
                    "Message forwarding to {} failed after {} retries. Destination endpoint: {}",
                    msg.to_did, msg.retry_count, endpoint_url
                ),
            },
            "to": [msg.from_did],
            "created_time": now,
            "expires_time": now + 300,
        });

        match self
            .store_problem_report(&report_msg.to_string(), &msg.from_did_hash, now + 300)
            .await
        {
            Ok(()) => {
                info!(
                    "FORWARD_PROBLEM_REPORT: stored for sender {}",
                    msg.from_did_hash
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

    fn calculate_backoff(&self, consecutive_failures: u32) -> Duration {
        let base = self.config.initial_backoff_ms as u64;
        let max = self.config.max_backoff_ms;
        let backoff = base.saturating_mul(2u64.saturating_pow(consecutive_failures.min(10)));
        Duration::from_millis(backoff.min(max))
    }
}

impl EndpointState {
    fn current_rate_value(&mut self) -> f64 {
        self.rate_tracker.current_rate()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        // 1 message in 60 seconds = 1/60 * 10 = ~0.167 msgs/10s
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
        let rate = tracker.record_and_rate();
        assert_eq!(rate, 0.0);
    }

    // --- EndpointState tests ---

    #[test]
    fn test_endpoint_state_current_rate_value() {
        let mut state = EndpointState {
            rate_tracker: EndpointRateTracker::new(60),
            last_activity: Instant::now(),
            consecutive_failures: 0,
        };
        assert_eq!(state.current_rate_value(), 0.0);
        state.rate_tracker.record_and_rate();
        assert!(state.current_rate_value() > 0.0);
    }

    // --- calculate_backoff tests ---

    /// Replicates the backoff formula to test without needing a full ForwardingProcessor.
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
        let backoff = compute_backoff(1000, 60000, 0);
        assert_eq!(backoff, Duration::from_millis(1000));
    }

    #[test]
    fn test_backoff_one_failure() {
        let backoff = compute_backoff(1000, 60000, 1);
        assert_eq!(backoff, Duration::from_millis(2000));
    }

    #[test]
    fn test_backoff_three_failures() {
        let backoff = compute_backoff(1000, 60000, 3);
        assert_eq!(backoff, Duration::from_millis(8000));
    }

    #[test]
    fn test_backoff_capped_at_max() {
        // 2^6 = 64, 1000 * 64 = 64000, capped at 60000
        let backoff = compute_backoff(1000, 60000, 6);
        assert_eq!(backoff, Duration::from_millis(60000));
    }

    #[test]
    fn test_backoff_high_failures_capped_exponent_at_10() {
        // failures > 10 clamped to 10: 2^10 = 1024, 1000 * 1024 = 1024000, capped at 60000
        let backoff = compute_backoff(1000, 60000, 20);
        assert_eq!(backoff, Duration::from_millis(60000));
    }

    #[test]
    fn test_backoff_custom_initial_and_max() {
        let backoff = compute_backoff(500, 5000, 2);
        assert_eq!(backoff, Duration::from_millis(2000));

        let backoff = compute_backoff(500, 5000, 4);
        assert_eq!(backoff, Duration::from_millis(5000));
    }

    #[test]
    fn test_backoff_saturating_prevents_overflow() {
        let backoff = compute_backoff(u64::MAX / 2, 60000, 5);
        assert_eq!(backoff, Duration::from_millis(60000));
    }

    // --- ForwardingProcessorConfig default tests ---

    #[test]
    fn test_default_config_values() {
        let config = ForwardingProcessorConfig::default();
        assert!(config.enabled);
        assert_eq!(config.rate_window_seconds, 300);
        assert_eq!(config.ws_threshold_msgs_per_10s, 1);
        assert_eq!(config.ws_idle_timeout_seconds, 60);
        assert_eq!(config.batch_size, 50);
        assert_eq!(config.max_retries, 5);
        assert_eq!(config.initial_backoff_ms, 1000);
        assert_eq!(config.max_backoff_ms, 60000);
        assert_eq!(config.consumer_group, "forwarding");
        assert!(config.report_errors);
        assert_eq!(config.max_endpoints, 1000);
    }
}
