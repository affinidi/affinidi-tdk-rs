use affinidi_messaging_mediator_common::errors::MediatorError;
pub use affinidi_messaging_mediator_common::tasks::forwarding::ForwardingConfig;
use ahash::AHashSet as HashSet;
use serde::{Deserialize, Serialize};

/// Processor configuration for the mediator
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProcessorsConfig {
    pub forwarding: ForwardingConfig,
    pub message_expiry_cleanup: MessageExpiryCleanupConfig,
}

impl Default for ProcessorsConfig {
    fn default() -> Self {
        Self {
            forwarding: ForwardingConfig::default(),
            message_expiry_cleanup: MessageExpiryCleanupConfig::default(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct ProcessorsConfigRaw {
    pub forwarding: ForwardingConfigRaw,
    pub message_expiry_cleanup: MessageExpiryCleanupConfigRaw,
}

/// Configuration for the in-process message expiry sweep. The standalone
/// `message_expiry_cleanup` binary in `affinidi-messaging-mediator-processors`
/// has its own config — they're intentionally not shared because the
/// standalone binary is Redis-only by design and runs in a separate process.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageExpiryCleanupConfig {
    pub enabled: bool,
}

impl Default for MessageExpiryCleanupConfig {
    fn default() -> Self {
        MessageExpiryCleanupConfig { enabled: true }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct MessageExpiryCleanupConfigRaw {
    pub enabled: String,
}

impl std::convert::TryFrom<MessageExpiryCleanupConfigRaw> for MessageExpiryCleanupConfig {
    type Error = MediatorError;

    fn try_from(raw: MessageExpiryCleanupConfigRaw) -> Result<Self, Self::Error> {
        Ok(MessageExpiryCleanupConfig {
            enabled: raw.enabled.parse().unwrap_or(true),
        })
    }
}

// `ForwardingConfig` (the typed shape) lives in `mediator-common`
// alongside `ForwardingProcessor` so the standalone forwarding binary
// can construct it. `ForwardingConfigRaw` (this file) is the wizard's
// all-strings TOML format and stays here.

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct ForwardingConfigRaw {
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
fn default_10() -> String {
    "10".to_string()
}

impl std::convert::TryFrom<ForwardingConfigRaw> for ForwardingConfig {
    type Error = MediatorError;

    fn try_from(raw: ForwardingConfigRaw) -> Result<Self, Self::Error> {
        let warn_default = |field: &str, default: &str| {
            eprintln!(
                "WARN: Could not parse processors.forwarding.{field} config value, using default: {default}"
            );
        };

        Ok(ForwardingConfig {
            enabled: raw.enabled.parse().unwrap_or_else(|_| {
                warn_default("enabled", "true");
                true
            }),
            future_time_limit: raw.future_time_limit.parse().unwrap_or_else(|_| {
                warn_default("future_time_limit", "86400");
                86400
            }),
            external_forwarding: raw.external_forwarding.parse().unwrap_or_else(|_| {
                warn_default("external_forwarding", "true");
                true
            }),
            report_errors: raw.report_errors.parse().unwrap_or_else(|_| {
                warn_default("report_errors", "true");
                true
            }),
            blocked_forwarding: HashSet::new(),
            rate_window_seconds: raw.rate_window_seconds.parse().unwrap_or_else(|_| {
                warn_default("rate_window_seconds", "300");
                300
            }),
            ws_threshold_msgs_per_10s: raw.ws_threshold_msgs_per_10s.parse().unwrap_or_else(|_| {
                warn_default("ws_threshold_msgs_per_10s", "1");
                1
            }),
            ws_idle_timeout_seconds: raw.ws_idle_timeout_seconds.parse().unwrap_or_else(|_| {
                warn_default("ws_idle_timeout_seconds", "60");
                60
            }),
            batch_size: raw.batch_size.parse().unwrap_or_else(|_| {
                warn_default("batch_size", "50");
                50
            }),
            max_retries: raw.max_retries.parse().unwrap_or_else(|_| {
                warn_default("max_retries", "5");
                5
            }),
            initial_backoff_ms: raw.initial_backoff_ms.parse().unwrap_or_else(|_| {
                warn_default("initial_backoff_ms", "1000");
                1000
            }),
            max_backoff_ms: raw.max_backoff_ms.parse().unwrap_or_else(|_| {
                warn_default("max_backoff_ms", "60000");
                60000
            }),
            consumer_group: raw.consumer_group,
            accept_invalid_certs: raw.accept_invalid_certs.parse().unwrap_or_else(|_| {
                warn_default("accept_invalid_certs", "false");
                false
            }),
            max_hops: raw.max_hops.parse().unwrap_or_else(|_| {
                warn_default("max_hops", "10");
                10
            }),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_forwarding_config_default() {
        let config = ForwardingConfig::default();
        assert!(config.enabled);
        assert!(config.external_forwarding);
        assert!(config.report_errors);
        assert_eq!(config.future_time_limit, 86400);
        assert_eq!(config.rate_window_seconds, 300);
        assert_eq!(config.ws_threshold_msgs_per_10s, 1);
        assert_eq!(config.ws_idle_timeout_seconds, 60);
        assert_eq!(config.batch_size, 50);
        assert_eq!(config.max_retries, 5);
        assert_eq!(config.initial_backoff_ms, 1000);
        assert_eq!(config.max_backoff_ms, 60000);
        assert_eq!(config.consumer_group, "forwarding");
        assert!(!config.accept_invalid_certs);
        assert_eq!(config.max_hops, 10);
        assert!(config.blocked_forwarding.is_empty());
    }

    #[test]
    fn test_forwarding_config_try_from() {
        let raw = ForwardingConfigRaw {
            enabled: "true".to_string(),
            external_forwarding: "true".to_string(),
            future_time_limit: "3600".to_string(),
            report_errors: "true".to_string(),
            blocked_forwarding_dids: "did:example:blocked1,did:example:blocked2".to_string(),
            rate_window_seconds: default_300(),
            ws_threshold_msgs_per_10s: default_1(),
            ws_idle_timeout_seconds: default_60(),
            batch_size: default_50(),
            max_retries: default_5(),
            initial_backoff_ms: default_1000(),
            max_backoff_ms: default_60000(),
            consumer_group: default_forwarding_group(),
            accept_invalid_certs: default_false(),
            max_hops: default_10(),
        };
        let config = ForwardingConfig::try_from(raw).unwrap();
        assert!(config.enabled);
        assert!(config.external_forwarding);
        assert!(config.report_errors);
        assert!(!config.accept_invalid_certs);
        assert_eq!(config.max_hops, 10);
        assert_eq!(config.future_time_limit, 3600);
        assert_eq!(config.rate_window_seconds, 300);
        assert_eq!(config.ws_threshold_msgs_per_10s, 1);
        assert_eq!(config.ws_idle_timeout_seconds, 60);
        assert_eq!(config.batch_size, 50);
        assert_eq!(config.max_retries, 5);
        assert_eq!(config.initial_backoff_ms, 1000);
        assert_eq!(config.max_backoff_ms, 60000);
        assert_eq!(config.consumer_group, "forwarding");
        // Note: TryFrom currently ignores blocked_forwarding_dids and always sets empty HashSet
        assert!(config.blocked_forwarding.is_empty());
    }

    #[test]
    fn test_forwarding_config_try_from_disabled() {
        let raw = ForwardingConfigRaw {
            enabled: "false".to_string(),
            external_forwarding: "false".to_string(),
            future_time_limit: "7200".to_string(),
            report_errors: "false".to_string(),
            blocked_forwarding_dids: String::new(),
            rate_window_seconds: "600".to_string(),
            ws_threshold_msgs_per_10s: "10".to_string(),
            ws_idle_timeout_seconds: "120".to_string(),
            batch_size: "100".to_string(),
            max_retries: "3".to_string(),
            initial_backoff_ms: "2000".to_string(),
            max_backoff_ms: "120000".to_string(),
            consumer_group: "custom_group".to_string(),
            accept_invalid_certs: "false".to_string(),
            max_hops: "5".to_string(),
        };
        let config = ForwardingConfig::try_from(raw).unwrap();
        assert!(!config.enabled);
        assert!(!config.external_forwarding);
        assert!(!config.report_errors);
        assert!(!config.accept_invalid_certs);
        assert_eq!(config.max_hops, 5);
        assert_eq!(config.future_time_limit, 7200);
        assert_eq!(config.rate_window_seconds, 600);
        assert_eq!(config.ws_threshold_msgs_per_10s, 10);
        assert_eq!(config.ws_idle_timeout_seconds, 120);
        assert_eq!(config.batch_size, 100);
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.initial_backoff_ms, 2000);
        assert_eq!(config.max_backoff_ms, 120000);
        assert_eq!(config.consumer_group, "custom_group");
    }

    #[test]
    fn test_forwarding_config_try_from_invalid_values_use_defaults() {
        let raw = ForwardingConfigRaw {
            enabled: "not_bool".to_string(),
            external_forwarding: "not_bool".to_string(),
            future_time_limit: "not_a_number".to_string(),
            report_errors: "not_bool".to_string(),
            blocked_forwarding_dids: String::new(),
            rate_window_seconds: "bad".to_string(),
            ws_threshold_msgs_per_10s: "bad".to_string(),
            ws_idle_timeout_seconds: "bad".to_string(),
            batch_size: "bad".to_string(),
            max_retries: "bad".to_string(),
            initial_backoff_ms: "bad".to_string(),
            max_backoff_ms: "bad".to_string(),
            consumer_group: "forwarding".to_string(),
            accept_invalid_certs: "bad".to_string(),
            max_hops: "bad".to_string(),
        };
        let config = ForwardingConfig::try_from(raw).unwrap();
        // All invalid values should fall back to unwrap_or defaults
        assert!(config.enabled); // default true
        assert!(config.external_forwarding); // default true
        assert!(config.report_errors); // default true
        assert_eq!(config.future_time_limit, 86400);
        assert_eq!(config.rate_window_seconds, 300);
        assert_eq!(config.ws_threshold_msgs_per_10s, 1);
        assert_eq!(config.ws_idle_timeout_seconds, 60);
        assert_eq!(config.batch_size, 50);
        assert_eq!(config.max_retries, 5);
        assert_eq!(config.initial_backoff_ms, 1000);
        assert_eq!(config.max_backoff_ms, 60000);
        assert!(!config.accept_invalid_certs); // default false
        assert_eq!(config.max_hops, 10); // default 10
    }
}
