//! Raw `[processors]` config schema (forwarding + expiry sweeps).
//!
//! The resolved `ProcessorsConfig` / `ForwardingConfig` and all conversions
//! stay in the mediator (`ForwardingConfig` lives in mediator-common alongside
//! the forwarding processor).

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProcessorsConfigRaw {
    pub forwarding: ForwardingConfigRaw,
    pub message_expiry_cleanup: MessageExpiryCleanupConfigRaw,
    // Added after the first release of this struct; default so configs
    // written before the session sweeper existed still parse.
    #[serde(default)]
    pub session_expiry_cleanup: SessionExpiryCleanupConfigRaw,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageExpiryCleanupConfigRaw {
    pub enabled: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionExpiryCleanupConfigRaw {
    #[serde(default = "default_true")]
    pub enabled: String,
}

impl Default for SessionExpiryCleanupConfigRaw {
    fn default() -> Self {
        SessionExpiryCleanupConfigRaw {
            enabled: default_true(),
        }
    }
}

// `ForwardingConfig` (the typed shape) lives in `mediator-common`
// alongside `ForwardingProcessor` so the standalone forwarding binary
// can construct it. `ForwardingConfigRaw` (this struct) is the wizard's
// all-strings TOML format and stays here, in the schema crate.

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ForwardingConfigRaw {
    pub enabled: String,
    pub future_time_limit: String,
    pub external_forwarding: String,
    pub report_errors: String,
    pub blocked_forwarding_dids: String,
    #[serde(default = "default_300")]
    pub rate_window_seconds: String,
    #[serde(default = "default_1")]
    pub ws_threshold_msgs_per_10s: String,
    #[serde(default = "default_60")]
    pub ws_idle_timeout_seconds: String,
    #[serde(default = "default_50")]
    pub batch_size: String,
    #[serde(default = "default_5")]
    pub max_retries: String,
    #[serde(default = "default_1000")]
    pub initial_backoff_ms: String,
    #[serde(default = "default_60000")]
    pub max_backoff_ms: String,
    #[serde(default = "default_forwarding_group")]
    pub consumer_group: String,
    #[serde(default = "default_false")]
    pub accept_invalid_certs: String,
    #[serde(default = "default_10")]
    pub max_hops: String,
    /// Relay mode for remote next-hop forwards: "blind" (default) or "rewrap".
    #[serde(default = "default_blind")]
    pub relay_mode: String,
    /// Comma-separated allowlist of trusted peer-mediator DIDs (rewrap mode).
    #[serde(default)]
    pub relay_trusted_mediators: String,
}

fn default_300() -> String {
    "300".to_string()
}
fn default_1() -> String {
    "1".to_string()
}
fn default_60() -> String {
    "60".to_string()
}
fn default_50() -> String {
    "50".to_string()
}
fn default_5() -> String {
    "5".to_string()
}
fn default_1000() -> String {
    "1000".to_string()
}
fn default_60000() -> String {
    "60000".to_string()
}
fn default_forwarding_group() -> String {
    "forwarding".to_string()
}
fn default_false() -> String {
    "false".to_string()
}
fn default_true() -> String {
    "true".to_string()
}
fn default_10() -> String {
    "10".to_string()
}
fn default_blind() -> String {
    "blind".to_string()
}
