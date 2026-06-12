use affinidi_messaging_mediator_common::errors::MediatorError;
pub use affinidi_messaging_mediator_common::tasks::forwarding::ForwardingConfig;
use affinidi_messaging_mediator_common::tasks::forwarding::RelayMode;
// Raw TOML schema lives in the config crate; the typed configs + conversions
// stay here. `ForwardingConfig` is a mediator-common type, so its conversion is
// a free fn (`forwarding_config_from_raw`) rather than a `TryFrom` (orphan rule).
use affinidi_messaging_mediator_config::{
    ForwardingConfigRaw, MessageExpiryCleanupConfigRaw, SessionExpiryCleanupConfigRaw,
};
use ahash::AHashSet as HashSet;
use serde::{Deserialize, Serialize};

/// Processor configuration for the mediator
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct ProcessorsConfig {
    pub forwarding: ForwardingConfig,
    pub message_expiry_cleanup: MessageExpiryCleanupConfig,
    pub session_expiry_cleanup: SessionExpiryCleanupConfig,
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

impl std::convert::TryFrom<MessageExpiryCleanupConfigRaw> for MessageExpiryCleanupConfig {
    type Error = MediatorError;

    fn try_from(raw: MessageExpiryCleanupConfigRaw) -> Result<Self, Self::Error> {
        Ok(MessageExpiryCleanupConfig {
            enabled: raw.enabled.parse().unwrap_or(true),
        })
    }
}

/// Configuration for the in-process session expiry sweep. Only does work
/// on backends without native TTL (Fjall, memory); on Redis the sweep is
/// a no-op, so leaving it enabled there is harmless.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionExpiryCleanupConfig {
    pub enabled: bool,
}

impl Default for SessionExpiryCleanupConfig {
    fn default() -> Self {
        SessionExpiryCleanupConfig { enabled: true }
    }
}

impl std::convert::TryFrom<SessionExpiryCleanupConfigRaw> for SessionExpiryCleanupConfig {
    type Error = MediatorError;

    fn try_from(raw: SessionExpiryCleanupConfigRaw) -> Result<Self, Self::Error> {
        Ok(SessionExpiryCleanupConfig {
            enabled: raw.enabled.parse().unwrap_or(true),
        })
    }
}

/// Build the typed [`ForwardingConfig`] (a mediator-common type) from the raw
/// [`ForwardingConfigRaw`] schema. A free function rather than a `TryFrom` impl
/// because both types are now foreign to this crate (the raw type moved to
/// `affinidi-messaging-mediator-config`), which the orphan rule forbids.
pub(crate) fn forwarding_config_from_raw(
    raw: ForwardingConfigRaw,
) -> Result<ForwardingConfig, MediatorError> {
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
        relay_mode: match raw.relay_mode.trim().to_ascii_lowercase().as_str() {
            "rewrap" => RelayMode::Rewrap,
            "blind" | "" => RelayMode::Blind,
            other => {
                warn_default(&format!("relay_mode (unrecognised: {other:?})"), "blind");
                RelayMode::Blind
            }
        },
        relay_trusted_mediators: raw
            .relay_trusted_mediators
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect(),
    })
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
            rate_window_seconds: "300".to_string(),
            ws_threshold_msgs_per_10s: "1".to_string(),
            ws_idle_timeout_seconds: "60".to_string(),
            batch_size: "50".to_string(),
            max_retries: "5".to_string(),
            initial_backoff_ms: "1000".to_string(),
            max_backoff_ms: "60000".to_string(),
            consumer_group: "forwarding".to_string(),
            accept_invalid_certs: "false".to_string(),
            max_hops: "10".to_string(),
            relay_mode: "blind".to_string(),
            relay_trusted_mediators: String::new(),
        };
        let config = forwarding_config_from_raw(raw).unwrap();
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
            relay_mode: "rewrap".to_string(),
            relay_trusted_mediators: "did:peer:alice , did:peer:bob".to_string(),
        };
        let config = forwarding_config_from_raw(raw).unwrap();
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
        // relay_mode parses case-insensitively; the trusted-mediator list is
        // comma-split with surrounding whitespace trimmed and blanks dropped.
        assert_eq!(config.relay_mode, RelayMode::Rewrap);
        assert!(config.relay_trusted_mediators.contains("did:peer:alice"));
        assert!(config.relay_trusted_mediators.contains("did:peer:bob"));
        assert_eq!(config.relay_trusted_mediators.len(), 2);
    }

    #[test]
    fn relay_mode_defaults_to_blind_with_empty_allowlist() {
        // The first try_from fixture leaves relay_mode = "blind" and an empty
        // trusted list — the historical, no-regression default.
        let config = ForwardingConfig::default();
        assert_eq!(config.relay_mode, RelayMode::Blind);
        assert!(config.relay_trusted_mediators.is_empty());
    }

    #[test]
    fn unrecognised_relay_mode_falls_back_to_blind() {
        let raw = ForwardingConfigRaw {
            enabled: "true".to_string(),
            external_forwarding: "true".to_string(),
            future_time_limit: "3600".to_string(),
            report_errors: "true".to_string(),
            blocked_forwarding_dids: String::new(),
            rate_window_seconds: "300".to_string(),
            ws_threshold_msgs_per_10s: "1".to_string(),
            ws_idle_timeout_seconds: "60".to_string(),
            batch_size: "50".to_string(),
            max_retries: "5".to_string(),
            initial_backoff_ms: "1000".to_string(),
            max_backoff_ms: "60000".to_string(),
            consumer_group: "forwarding".to_string(),
            accept_invalid_certs: "false".to_string(),
            max_hops: "10".to_string(),
            relay_mode: "bogus".to_string(),
            relay_trusted_mediators: String::new(),
        };
        let config = forwarding_config_from_raw(raw).unwrap();
        assert_eq!(config.relay_mode, RelayMode::Blind);
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
            relay_mode: "bad".to_string(),
            relay_trusted_mediators: String::new(),
        };
        let config = forwarding_config_from_raw(raw).unwrap();
        // All invalid values should fall back to unwrap_or defaults
        assert!(config.enabled); // default true
        assert_eq!(config.relay_mode, RelayMode::Blind); // unrecognised → blind
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
