use affinidi_messaging_mediator_common::errors::ProcessorError;
use serde::{Deserialize, Serialize};

/// Configuration for the standalone forwarding processor
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ForwardingProcessorConfig {
    pub enabled: bool,
    /// Sliding window in seconds for tracking message rate per remote endpoint
    #[serde(default = "default_300")]
    pub rate_window_seconds: u64,
    /// If messages per 10 seconds >= this threshold, prefer WebSocket over REST
    #[serde(default = "default_1")]
    pub ws_threshold_msgs_per_10s: u64,
    /// Seconds of idle time before disconnecting a WebSocket to a remote mediator
    #[serde(default = "default_60")]
    pub ws_idle_timeout_seconds: u64,
    /// Number of messages to read per batch from FORWARD_Q
    #[serde(default = "default_50")]
    pub batch_size: usize,
    /// Maximum number of retry attempts for failed forwarding
    #[serde(default = "default_5")]
    pub max_retries: u32,
    /// Initial backoff delay in milliseconds for retry
    #[serde(default = "default_1000")]
    pub initial_backoff_ms: u64,
    /// Maximum backoff delay in milliseconds for retry
    #[serde(default = "default_60000")]
    pub max_backoff_ms: u64,
    /// Redis consumer group name for forwarding processors
    #[serde(default = "default_forwarding_group")]
    pub consumer_group: String,
    /// Whether to send problem reports to senders on forwarding failure
    #[serde(default = "default_true")]
    pub report_errors: bool,
}

fn default_300() -> u64 { 300 }
fn default_1() -> u64 { 1 }
fn default_60() -> u64 { 60 }
fn default_50() -> usize { 50 }
fn default_5() -> u32 { 5 }
fn default_1000() -> u64 { 1000 }
fn default_60000() -> u64 { 60000 }
fn default_forwarding_group() -> String { "forwarding".to_string() }
fn default_true() -> bool { true }

impl Default for ForwardingProcessorConfig {
    fn default() -> Self {
        ForwardingProcessorConfig {
            enabled: true,
            rate_window_seconds: 300,
            ws_threshold_msgs_per_10s: 1,
            ws_idle_timeout_seconds: 60,
            batch_size: 50,
            max_retries: 5,
            initial_backoff_ms: 1000,
            max_backoff_ms: 60000,
            consumer_group: "forwarding".to_string(),
            report_errors: true,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ForwardingProcessorConfigRaw {
    pub enabled: String,
    #[serde(default = "default_300_str")]
    pub rate_window_seconds: String,
    #[serde(default = "default_1_str")]
    pub ws_threshold_msgs_per_10s: String,
    #[serde(default = "default_60_str")]
    pub ws_idle_timeout_seconds: String,
    #[serde(default = "default_50_str")]
    pub batch_size: String,
    #[serde(default = "default_5_str")]
    pub max_retries: String,
    #[serde(default = "default_1000_str")]
    pub initial_backoff_ms: String,
    #[serde(default = "default_60000_str")]
    pub max_backoff_ms: String,
    #[serde(default = "default_forwarding_group")]
    pub consumer_group: String,
    #[serde(default = "default_true_str")]
    pub report_errors: String,
}

fn default_300_str() -> String { "300".to_string() }
fn default_1_str() -> String { "1".to_string() }
fn default_60_str() -> String { "60".to_string() }
fn default_50_str() -> String { "50".to_string() }
fn default_5_str() -> String { "5".to_string() }
fn default_1000_str() -> String { "1000".to_string() }
fn default_60000_str() -> String { "60000".to_string() }
fn default_true_str() -> String { "true".to_string() }

impl std::convert::TryFrom<ForwardingProcessorConfigRaw> for ForwardingProcessorConfig {
    type Error = ProcessorError;

    fn try_from(raw: ForwardingProcessorConfigRaw) -> Result<Self, Self::Error> {
        Ok(ForwardingProcessorConfig {
            enabled: raw.enabled.parse().unwrap_or(true),
            rate_window_seconds: raw.rate_window_seconds.parse().unwrap_or(300),
            ws_threshold_msgs_per_10s: raw.ws_threshold_msgs_per_10s.parse().unwrap_or(1),
            ws_idle_timeout_seconds: raw.ws_idle_timeout_seconds.parse().unwrap_or(60),
            batch_size: raw.batch_size.parse().unwrap_or(50),
            max_retries: raw.max_retries.parse().unwrap_or(5),
            initial_backoff_ms: raw.initial_backoff_ms.parse().unwrap_or(1000),
            max_backoff_ms: raw.max_backoff_ms.parse().unwrap_or(60000),
            consumer_group: raw.consumer_group,
            report_errors: raw.report_errors.parse().unwrap_or(true),
        })
    }
}
