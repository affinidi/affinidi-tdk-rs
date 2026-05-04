//! Forwarding processor configuration — backend-agnostic.
//!
//! Same struct that's serialized into the mediator's
//! `[processors.forwarding]` TOML block. Lives in mediator-common so
//! the standalone forwarding binary in
//! `affinidi-messaging-mediator-processors` can read its config into
//! the same shape without duplicating the type. Mediator's
//! `common::config::processors` keeps the `RawConfig` + `TryFrom`
//! parser layer for backward compatibility with operator-supplied
//! all-strings TOML.

use ahash::AHashSet as HashSet;
use serde::{Deserialize, Serialize};

/// DIDComm routing and forwarding configuration. Consumed by
/// [`ForwardingProcessor`](crate::tasks::forwarding::ForwardingProcessor).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ForwardingConfig {
    pub enabled: bool,
    pub future_time_limit: u64,
    pub external_forwarding: bool,
    pub report_errors: bool,
    pub blocked_forwarding: HashSet<String>,
    /// Sliding window in seconds for tracking message rate per remote endpoint
    pub rate_window_seconds: u64,
    /// If messages per 10 seconds >= this threshold, prefer WebSocket over REST
    pub ws_threshold_msgs_per_10s: u64,
    /// Seconds of idle time before disconnecting a WebSocket to a remote mediator
    pub ws_idle_timeout_seconds: u64,
    /// Number of messages to read per batch from FORWARD_Q
    pub batch_size: usize,
    /// Maximum number of retry attempts for failed forwarding
    pub max_retries: u32,
    /// Initial backoff delay in milliseconds for retry
    pub initial_backoff_ms: u64,
    /// Maximum backoff delay in milliseconds for retry
    pub max_backoff_ms: u64,
    /// Redis consumer group name for forwarding processors
    pub consumer_group: String,
    /// Whether to accept invalid TLS certificates when forwarding to remote mediators.
    /// MUST be false in production. Only set to true for local development/testing.
    pub accept_invalid_certs: bool,
    /// Maximum number of hops a forwarded message can make before being dropped.
    /// Prevents forwarding loops between mediators.
    pub max_hops: u32,
}

impl Default for ForwardingConfig {
    fn default() -> Self {
        ForwardingConfig {
            enabled: true,
            future_time_limit: 86400,
            external_forwarding: true,
            report_errors: true,
            blocked_forwarding: HashSet::new(),
            rate_window_seconds: 300,
            ws_threshold_msgs_per_10s: 1,
            ws_idle_timeout_seconds: 60,
            batch_size: 50,
            max_retries: 5,
            initial_backoff_ms: 1000,
            max_backoff_ms: 60000,
            consumer_group: "forwarding".to_string(),
            accept_invalid_certs: false,
            max_hops: 10,
        }
    }
}
