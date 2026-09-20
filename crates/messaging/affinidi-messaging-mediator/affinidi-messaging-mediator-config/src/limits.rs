//! Raw `[limits]` config schema.
//!
//! The resolved `LimitsConfig` (typed numbers) and the
//! `LimitsConfigRaw → LimitsConfig` conversion stay in the mediator.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LimitsConfigRaw {
    pub attachments_max_count: String,
    pub crypto_operations_per_message: String,
    pub deleted_messages: String,
    pub forward_task_queue: String,
    pub http_size: String,
    pub listed_messages: String,
    pub local_max_acl: String,
    pub message_expiry_seconds: String,
    /// How long a message is kept after it has first been handed to its
    /// recipient. `"0"` (the default) means "no different from any other
    /// message" — the historical behaviour.
    #[serde(default = "default_delivered_expiry_seconds")]
    pub delivered_expiry_seconds: String,
    pub message_size: String,
    #[serde(default = "default_queued_send_messages_per_peer")]
    pub queued_send_messages_per_peer: String,
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
    #[serde(default = "default_max_websocket_connections_per_did")]
    pub max_websocket_connections_per_did: String,
    #[serde(default = "default_did_rate_limit_per_second")]
    pub did_rate_limit_per_second: String,
    #[serde(default = "default_did_rate_limit_burst")]
    pub did_rate_limit_burst: String,
    #[serde(default = "default_ws_send_buffer")]
    pub ws_send_buffer: String,
    #[serde(default = "default_pubsub_buffer")]
    pub pubsub_buffer: String,
}

/// 50 — the per-relationship outbound cap. A sender may hold this many
/// messages for any one recipient; beyond that it is flooding that peer, not
/// serving it. Defaulted (rather than required) so an existing `mediator.toml`
/// keeps loading without an edit.
/// Off. Enabling this shortens how long a delivered-but-unacknowledged message
/// survives, which is a reduction in durability, so it is never turned on by an
/// upgrade — only by an operator who has read what it does.
fn default_delivered_expiry_seconds() -> String {
    "0".to_string()
}

fn default_queued_send_messages_per_peer() -> String {
    "50".to_string()
}

fn default_rate_limit_per_ip() -> String {
    "100".to_string()
}

/// 32 MiB — aggregate ceiling across every live WebSocket send queue.
fn default_ws_send_buffer() -> String {
    "33554432".to_string()
}

/// 16 MiB — the live-delivery pub/sub ring. Divided by `message_size` to get
/// the ring's slot count, so this is a true byte ceiling.
fn default_pubsub_buffer() -> String {
    "16777216".to_string()
}
fn default_rate_limit_burst() -> String {
    "50".to_string()
}
fn default_max_websocket_connections() -> String {
    "10000".to_string()
}
fn default_max_websocket_connections_per_did() -> String {
    "100".to_string()
}
fn default_did_rate_limit_per_second() -> String {
    "0".to_string()
}
fn default_did_rate_limit_burst() -> String {
    "10".to_string()
}
