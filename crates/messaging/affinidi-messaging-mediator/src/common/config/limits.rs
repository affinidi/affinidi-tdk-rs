use affinidi_messaging_mediator_common::errors::MediatorError;
use serde::{Deserialize, Serialize};

/// Resource limits configuration for the mediator
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LimitsConfig {
    pub attachments_max_count: usize,
    pub crypto_operations_per_message: usize,
    pub deleted_messages: usize,
    pub forward_task_queue: usize,
    pub http_size: usize,
    pub listed_messages: usize,
    pub local_max_acl: usize,
    pub message_expiry_seconds: u64,
    pub message_size: usize,
    pub queued_send_messages_soft: i32,
    pub queued_send_messages_hard: i32,
    pub queued_receive_messages_soft: i32,
    pub queued_receive_messages_hard: i32,
    pub to_keys_per_recipient: usize,
    pub to_recipients: usize,
    pub ws_size: usize,
    pub access_list_limit: usize,
    pub oob_invite_ttl: usize,
    /// Maximum requests per second per IP address. 0 = unlimited.
    pub rate_limit_per_ip: u32,
    /// Burst size for rate limiting (additional requests allowed in a burst)
    pub rate_limit_burst: u32,
    /// Maximum number of concurrent WebSocket connections. 0 = unlimited.
    pub max_websocket_connections: usize,
    /// Maximum requests per second per authenticated DID. 0 = unlimited (disabled).
    pub did_rate_limit_per_second: u32,
    /// Burst size for per-DID rate limiting (additional requests allowed in a burst).
    pub did_rate_limit_burst: u32,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        LimitsConfig {
            attachments_max_count: 20,
            crypto_operations_per_message: 1000,
            deleted_messages: 100,
            forward_task_queue: 50_000,
            http_size: 10_485_760,
            listed_messages: 100,
            local_max_acl: 1_000,
            message_expiry_seconds: 604_800,
            message_size: 1_048_576,
            queued_send_messages_soft: 200,
            queued_send_messages_hard: 1_000,
            queued_receive_messages_soft: 200,
            queued_receive_messages_hard: 1_000,
            to_keys_per_recipient: 100,
            to_recipients: 100,
            ws_size: 10_485_760,
            access_list_limit: 1_000,
            oob_invite_ttl: 86_400,
            rate_limit_per_ip: 100,
            rate_limit_burst: 50,
            max_websocket_connections: 10000,
            did_rate_limit_per_second: 0,
            did_rate_limit_burst: 10,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct LimitsConfigRaw {
    pub attachments_max_count: String,
    pub crypto_operations_per_message: String,
    pub deleted_messages: String,
    pub forward_task_queue: String,
    pub http_size: String,
    pub listed_messages: String,
    pub local_max_acl: String,
    pub message_expiry_seconds: String,
    pub message_size: String,
    pub queued_send_messages_soft: String,
    pub queued_send_messages_hard: String,
    pub queued_receive_messages_soft: String,
    pub queued_receive_messages_hard: String,
    pub to_keys_per_recipient: String,
    pub to_recipients: String,
    pub ws_size: String,
    pub access_list_limit: String,
    pub oob_invite_ttl: String,
    #[serde(default = "default_rate_limit_per_ip")]
    pub rate_limit_per_ip: String,
    #[serde(default = "default_rate_limit_burst")]
    pub rate_limit_burst: String,
    #[serde(default = "default_max_websocket_connections")]
    pub max_websocket_connections: String,
    #[serde(default = "default_did_rate_limit_per_second")]
    pub did_rate_limit_per_second: String,
    #[serde(default = "default_did_rate_limit_burst")]
    pub did_rate_limit_burst: String,
}

fn default_rate_limit_per_ip() -> String {
    "100".to_string()
}
fn default_rate_limit_burst() -> String {
    "50".to_string()
}
fn default_max_websocket_connections() -> String {
    "10000".to_string()
}
fn default_did_rate_limit_per_second() -> String {
    "0".to_string()
}
fn default_did_rate_limit_burst() -> String {
    "10".to_string()
}

impl std::convert::TryFrom<LimitsConfigRaw> for LimitsConfig {
    type Error = MediatorError;

    fn try_from(raw: LimitsConfigRaw) -> Result<Self, Self::Error> {
        let warn_default = |field: &str, default: &str| {
            eprintln!(
                "WARN: Could not parse limits.{field} config value, using default: {default}"
            );
        };

        Ok(LimitsConfig {
            attachments_max_count: raw.attachments_max_count.parse().unwrap_or_else(|_| {
                warn_default("attachments_max_count", "20");
                20
            }),
            crypto_operations_per_message: raw
                .crypto_operations_per_message
                .parse()
                .unwrap_or_else(|_| {
                    warn_default("crypto_operations_per_message", "1000");
                    1000
                }),
            deleted_messages: raw.deleted_messages.parse().unwrap_or_else(|_| {
                warn_default("deleted_messages", "100");
                100
            }),
            forward_task_queue: raw.forward_task_queue.parse().unwrap_or_else(|_| {
                warn_default("forward_task_queue", "50000");
                50_000
            }),
            http_size: raw.http_size.parse().unwrap_or_else(|_| {
                warn_default("http_size", "10485760");
                10_485_760
            }),
            listed_messages: raw.listed_messages.parse().unwrap_or_else(|_| {
                warn_default("listed_messages", "100");
                100
            }),
            local_max_acl: raw.local_max_acl.parse().unwrap_or_else(|_| {
                warn_default("local_max_acl", "1000");
                1_000
            }),
            message_expiry_seconds: raw.message_expiry_seconds.parse().unwrap_or_else(|_| {
                warn_default("message_expiry_seconds", "604800");
                604_800
            }),
            message_size: raw.message_size.parse().unwrap_or_else(|_| {
                warn_default("message_size", "1048576");
                1_048_576
            }),
            queued_send_messages_soft: raw.queued_send_messages_soft.parse().unwrap_or_else(|_| {
                warn_default("queued_send_messages_soft", "200");
                200
            }),
            queued_send_messages_hard: raw.queued_send_messages_hard.parse().unwrap_or_else(|_| {
                warn_default("queued_send_messages_hard", "1000");
                1_000
            }),
            queued_receive_messages_soft: raw.queued_receive_messages_soft.parse().unwrap_or_else(
                |_| {
                    warn_default("queued_receive_messages_soft", "200");
                    200
                },
            ),
            queued_receive_messages_hard: raw.queued_receive_messages_hard.parse().unwrap_or_else(
                |_| {
                    warn_default("queued_receive_messages_hard", "1000");
                    1_000
                },
            ),
            to_keys_per_recipient: raw.to_keys_per_recipient.parse().unwrap_or_else(|_| {
                warn_default("to_keys_per_recipient", "100");
                100
            }),
            to_recipients: raw.to_recipients.parse().unwrap_or_else(|_| {
                warn_default("to_recipients", "100");
                100
            }),
            ws_size: raw.ws_size.parse().unwrap_or_else(|_| {
                warn_default("ws_size", "10485760");
                10_485_760
            }),
            access_list_limit: raw.access_list_limit.parse().unwrap_or_else(|_| {
                warn_default("access_list_limit", "1000");
                1_000
            }),
            oob_invite_ttl: raw.oob_invite_ttl.parse().unwrap_or_else(|_| {
                warn_default("oob_invite_ttl", "86400");
                86_400
            }),
            rate_limit_per_ip: raw.rate_limit_per_ip.parse().unwrap_or_else(|_| {
                warn_default("rate_limit_per_ip", "100");
                100
            }),
            rate_limit_burst: raw.rate_limit_burst.parse().unwrap_or_else(|_| {
                warn_default("rate_limit_burst", "50");
                50
            }),
            max_websocket_connections: raw.max_websocket_connections.parse().unwrap_or_else(|_| {
                warn_default("max_websocket_connections", "10000");
                10000
            }),
            did_rate_limit_per_second: raw.did_rate_limit_per_second.parse().unwrap_or_else(|_| {
                warn_default("did_rate_limit_per_second", "0");
                0
            }),
            did_rate_limit_burst: raw.did_rate_limit_burst.parse().unwrap_or_else(|_| {
                warn_default("did_rate_limit_burst", "10");
                10
            }),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_limits_default() {
        let limits = LimitsConfig::default();
        assert_eq!(limits.attachments_max_count, 20);
        assert_eq!(limits.crypto_operations_per_message, 1000);
        assert_eq!(limits.deleted_messages, 100);
        assert_eq!(limits.forward_task_queue, 50_000);
        assert_eq!(limits.http_size, 10_485_760);
        assert_eq!(limits.listed_messages, 100);
        assert_eq!(limits.local_max_acl, 1_000);
        assert_eq!(limits.message_expiry_seconds, 604_800);
        assert_eq!(limits.message_size, 1_048_576);
        assert_eq!(limits.queued_send_messages_soft, 200);
        assert_eq!(limits.queued_send_messages_hard, 1_000);
        assert_eq!(limits.queued_receive_messages_soft, 200);
        assert_eq!(limits.queued_receive_messages_hard, 1_000);
        assert_eq!(limits.to_keys_per_recipient, 100);
        assert_eq!(limits.to_recipients, 100);
        assert_eq!(limits.ws_size, 10_485_760);
        assert_eq!(limits.access_list_limit, 1_000);
        assert_eq!(limits.oob_invite_ttl, 86_400);
        assert_eq!(limits.rate_limit_per_ip, 100);
        assert_eq!(limits.rate_limit_burst, 50);
        assert_eq!(limits.max_websocket_connections, 10000);
        assert_eq!(limits.did_rate_limit_per_second, 0);
        assert_eq!(limits.did_rate_limit_burst, 10);
    }

    #[test]
    fn test_limits_try_from_valid() {
        let raw = LimitsConfigRaw {
            attachments_max_count: "5".to_string(),
            crypto_operations_per_message: "500".to_string(),
            deleted_messages: "75".to_string(),
            forward_task_queue: "2000".to_string(),
            http_size: "8192".to_string(),
            listed_messages: "50".to_string(),
            local_max_acl: "500".to_string(),
            message_expiry_seconds: "3600".to_string(),
            message_size: "2048".to_string(),
            queued_send_messages_soft: "150".to_string(),
            queued_send_messages_hard: "800".to_string(),
            queued_receive_messages_soft: "150".to_string(),
            queued_receive_messages_hard: "800".to_string(),
            to_keys_per_recipient: "50".to_string(),
            to_recipients: "50".to_string(),
            ws_size: "8192".to_string(),
            access_list_limit: "500".to_string(),
            oob_invite_ttl: "7200".to_string(),
            rate_limit_per_ip: "200".to_string(),
            rate_limit_burst: "100".to_string(),
            max_websocket_connections: "5000".to_string(),
            did_rate_limit_per_second: "50".to_string(),
            did_rate_limit_burst: "20".to_string(),
        };
        let limits = LimitsConfig::try_from(raw).unwrap();
        assert_eq!(limits.attachments_max_count, 5);
        assert_eq!(limits.crypto_operations_per_message, 500);
        assert_eq!(limits.deleted_messages, 75);
        assert_eq!(limits.forward_task_queue, 2000);
        assert_eq!(limits.http_size, 8192);
        assert_eq!(limits.listed_messages, 50);
        assert_eq!(limits.local_max_acl, 500);
        assert_eq!(limits.message_expiry_seconds, 3600);
        assert_eq!(limits.message_size, 2048);
        assert_eq!(limits.queued_send_messages_soft, 150);
        assert_eq!(limits.queued_send_messages_hard, 800);
        assert_eq!(limits.queued_receive_messages_soft, 150);
        assert_eq!(limits.queued_receive_messages_hard, 800);
        assert_eq!(limits.to_keys_per_recipient, 50);
        assert_eq!(limits.to_recipients, 50);
        assert_eq!(limits.ws_size, 8192);
        assert_eq!(limits.access_list_limit, 500);
        assert_eq!(limits.oob_invite_ttl, 7200);
        assert_eq!(limits.rate_limit_per_ip, 200);
        assert_eq!(limits.rate_limit_burst, 100);
        assert_eq!(limits.max_websocket_connections, 5000);
        assert_eq!(limits.did_rate_limit_per_second, 50);
        assert_eq!(limits.did_rate_limit_burst, 20);
    }

    #[test]
    fn test_limits_try_from_invalid_number_falls_back_to_default() {
        // TryFrom uses unwrap_or, so invalid values fall back to defaults rather than erroring
        let raw = LimitsConfigRaw {
            attachments_max_count: "not_a_number".to_string(),
            crypto_operations_per_message: "bad".to_string(),
            deleted_messages: "100".to_string(),
            forward_task_queue: "50000".to_string(),
            http_size: "10485760".to_string(),
            listed_messages: "100".to_string(),
            local_max_acl: "1000".to_string(),
            message_expiry_seconds: "10080".to_string(),
            message_size: "1048576".to_string(),
            queued_send_messages_soft: "100".to_string(),
            queued_send_messages_hard: "1000".to_string(),
            queued_receive_messages_soft: "100".to_string(),
            queued_receive_messages_hard: "1000".to_string(),
            to_keys_per_recipient: "100".to_string(),
            to_recipients: "100".to_string(),
            ws_size: "10485760".to_string(),
            access_list_limit: "1000".to_string(),
            oob_invite_ttl: "86400".to_string(),
            rate_limit_per_ip: default_rate_limit_per_ip(),
            rate_limit_burst: default_rate_limit_burst(),
            max_websocket_connections: default_max_websocket_connections(),
            did_rate_limit_per_second: default_did_rate_limit_per_second(),
            did_rate_limit_burst: default_did_rate_limit_burst(),
        };
        let limits = LimitsConfig::try_from(raw).unwrap();
        // Invalid values should fall back to unwrap_or defaults
        assert_eq!(limits.attachments_max_count, 20);
        assert_eq!(limits.crypto_operations_per_message, 1000);
    }
}
