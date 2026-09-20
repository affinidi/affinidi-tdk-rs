use affinidi_messaging_mediator_common::errors::MediatorError;
// `LimitsConfigRaw` (the raw TOML schema) lives in the config crate; the
// conversion to the typed `LimitsConfig` (a mediator-local type) stays here.
use affinidi_messaging_mediator_config::LimitsConfigRaw;
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
    /// Per-relationship outbound cap: how many messages one sender may have
    /// queued for one *specific* recipient. This is the gate that catches
    /// flooding; `queued_send_messages_soft` below is a coarse ceiling that
    /// cannot tell flooding from fan-out. `-1` disables it.
    pub queued_send_messages_per_peer: i32,
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
    /// Maximum concurrent WebSocket connections for a single DID, so one DID
    /// can't exhaust the global `max_websocket_connections` budget.
    /// 0 = unlimited (only the global cap applies).
    pub max_websocket_connections_per_did: usize,
    /// Maximum requests per second per authenticated DID. 0 = unlimited (disabled).
    pub did_rate_limit_per_second: u32,
    /// Burst size for per-DID rate limiting (additional requests allowed in a burst).
    pub did_rate_limit_burst: u32,
    /// Aggregate byte ceiling across every live WebSocket send queue.
    /// Collapses `slots x message_size x connections` into one real number.
    pub ws_send_buffer: usize,
    /// Byte ceiling for the live-delivery pub/sub ring. The ring's slot count is
    /// derived from this — see [`LimitsConfig::pubsub_capacity`].
    pub pubsub_buffer: usize,
}

impl LimitsConfig {
    /// Stream `MAXLEN` for the per-DID inbox and outbox streams.
    ///
    /// One value bounds **both** streams — the `store_message` Lua applies the
    /// single `queue_maxlen` argument to `RECEIVE_Q` and `SEND_Q` alike — so it
    /// has to sit above the larger of the two hard limits, not one of them.
    ///
    /// It previously *was* one of them: the receive hard limit was passed
    /// directly, so the send stream was trimmed at the receive bound. That was
    /// latent while the send soft limit (200) sat far below it, and became
    /// reachable when 0.28.0 raised the send limits past it. A trim removes the
    /// stream entry and nothing decrements `SEND_QUEUE_COUNT` or `PEER_Q` —
    /// only `delete_message` does — so past the trim a sender is refused by
    /// counters for messages it can no longer list or purge, and recovers only
    /// when the message TTL expires.
    ///
    /// Hence `+ 1`, not `max(..)`: strictly above every limit an account can be
    /// *clamped* to, so trimming cannot fire for an account that is being held
    /// to a limit. Trimming is a backstop against state the gates should have
    /// prevented, never a bound on traffic they allow.
    ///
    /// **Residual, stated rather than hidden:** an account may be granted `-1`
    /// or `-2` (unlimited), which `account_update` passes through *without*
    /// clamping to the hard limit. No finite bound can sit above that, so for
    /// such an account the stream is still bounded while its counters are not.
    /// Those accounts have deliberately opted out of limits; the divergence is
    /// a property of that choice, not of this value.
    ///
    /// A global hard limit of `-1` disables trimming outright (`0` = no
    /// `MAXLEN`), which also avoids handing Redis the result of casting `-1`
    /// to `usize`.
    #[must_use]
    pub fn queue_stream_maxlen(&self) -> usize {
        if self.queued_send_messages_hard < 0 || self.queued_receive_messages_hard < 0 {
            return 0;
        }
        let larger = self
            .queued_send_messages_hard
            .max(self.queued_receive_messages_hard);
        larger as usize + 1
    }
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
            queued_send_messages_per_peer: 50,
            queued_send_messages_soft: 2_000,
            queued_send_messages_hard: 10_000,
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
            max_websocket_connections_per_did: 100,
            did_rate_limit_per_second: 0,
            did_rate_limit_burst: 10,
            ws_send_buffer: 33_554_432,
            pubsub_buffer: 16_777_216,
        }
    }
}

impl LimitsConfig {
    /// Slot count for the live-delivery pub/sub ring, derived from the byte
    /// budget: `pubsub_buffer / message_size`.
    ///
    /// A `tokio::sync::broadcast` ring holds all of its `capacity` slots for the
    /// life of the channel — a slot is freed only when it is overwritten
    /// `capacity` sends later, not when a subscriber reads it. So the ring costs
    /// `capacity x message_size` bytes as a *standing reservation*, and picking a
    /// capacity by feel (it was 1024) silently reserves that much memory. Deriving
    /// it from a byte budget makes the ceiling explicit and honest.
    ///
    /// Floored at 8 so a small `pubsub_buffer` cannot collapse the ring to a
    /// single slot, which would make even a momentary hiccup lag the subscriber.
    /// Lag is not message loss (the message is durable in the recipient's inbox
    /// and arrives on the next poll), but it does cost a live push.
    pub fn pubsub_capacity(&self) -> usize {
        let per_slot = self.message_size.max(1);
        (self.pubsub_buffer / per_slot).max(8)
    }
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
            queued_send_messages_per_peer: raw
                .queued_send_messages_per_peer
                .parse()
                .unwrap_or_else(|_| {
                    warn_default("queued_send_messages_per_peer", "50");
                    50
                }),
            queued_send_messages_soft: raw.queued_send_messages_soft.parse().unwrap_or_else(|_| {
                warn_default("queued_send_messages_soft", "2000");
                2_000
            }),
            queued_send_messages_hard: raw.queued_send_messages_hard.parse().unwrap_or_else(|_| {
                warn_default("queued_send_messages_hard", "10000");
                10_000
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
            max_websocket_connections_per_did: raw
                .max_websocket_connections_per_did
                .parse()
                .unwrap_or_else(|_| {
                    warn_default("max_websocket_connections_per_did", "100");
                    100
                }),
            did_rate_limit_per_second: raw.did_rate_limit_per_second.parse().unwrap_or_else(|_| {
                warn_default("did_rate_limit_per_second", "0");
                0
            }),
            did_rate_limit_burst: raw.did_rate_limit_burst.parse().unwrap_or_else(|_| {
                warn_default("did_rate_limit_burst", "10");
                10
            }),
            ws_send_buffer: raw.ws_send_buffer.parse().unwrap_or_else(|_| {
                warn_default("ws_send_buffer", "33554432");
                33_554_432
            }),
            pubsub_buffer: raw.pubsub_buffer.parse().unwrap_or_else(|_| {
                warn_default("pubsub_buffer", "16777216");
                16_777_216
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
        assert_eq!(limits.queued_send_messages_per_peer, 50);
        // Strictly above BOTH hard limits — one value bounds both streams.
        assert!(limits.queue_stream_maxlen() > limits.queued_send_messages_hard as usize);
        assert!(limits.queue_stream_maxlen() > limits.queued_receive_messages_hard as usize);
        // The send total is a coarse ceiling, not the flooding gate — see
        // `validate_peer_queue_limit`. It sits well above realistic fan-out so
        // that a sender is not silenced because its recipients went offline.
        assert_eq!(limits.queued_send_messages_soft, 2_000);
        // `hard` is the maximum an account may set for itself, so it must stay
        // at or above `soft`, which is the default every account starts on.
        assert_eq!(limits.queued_send_messages_hard, 10_000);
        assert!(limits.queued_send_messages_hard >= limits.queued_send_messages_soft);
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
            queued_send_messages_per_peer: "50".to_string(),
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
            max_websocket_connections_per_did: "250".to_string(),
            did_rate_limit_per_second: "50".to_string(),
            did_rate_limit_burst: "20".to_string(),
            ws_send_buffer: "8388608".to_string(),
            pubsub_buffer: "4194304".to_string(),
        };
        let limits = LimitsConfig::try_from(raw).unwrap();
        assert_eq!(limits.ws_send_buffer, 8_388_608);
        assert_eq!(limits.pubsub_buffer, 4_194_304);
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
            queued_send_messages_per_peer: "50".to_string(),
            queued_send_messages_soft: "100".to_string(),
            queued_send_messages_hard: "1000".to_string(),
            queued_receive_messages_soft: "100".to_string(),
            queued_receive_messages_hard: "1000".to_string(),
            to_keys_per_recipient: "100".to_string(),
            to_recipients: "100".to_string(),
            ws_size: "10485760".to_string(),
            access_list_limit: "1000".to_string(),
            oob_invite_ttl: "86400".to_string(),
            rate_limit_per_ip: "100".to_string(),
            rate_limit_burst: "50".to_string(),
            max_websocket_connections: "10000".to_string(),
            max_websocket_connections_per_did: "100".to_string(),
            did_rate_limit_per_second: "0".to_string(),
            did_rate_limit_burst: "10".to_string(),
            ws_send_buffer: "67108864".to_string(),
            pubsub_buffer: "33554432".to_string(),
        };
        let limits = LimitsConfig::try_from(raw).unwrap();
        // Invalid values should fall back to unwrap_or defaults
        assert_eq!(limits.attachments_max_count, 20);
        assert_eq!(limits.crypto_operations_per_message, 1000);
    }
}

#[cfg(test)]
mod queue_stream_maxlen_tests {
    use super::LimitsConfig;

    /// The regression 0.28.0 introduced: the send stream was trimmed at the
    /// *receive* hard limit, so raising the send limits past it made trimming
    /// reachable in ordinary use — and a trim removes the stream entry while
    /// `SEND_QUEUE_COUNT` and `PEER_Q` keep counting it.
    #[test]
    fn maxlen_sits_above_the_larger_hard_limit_not_the_receive_one() {
        let limits = LimitsConfig {
            queued_send_messages_hard: 10_000,
            queued_receive_messages_hard: 1_000,
            ..LimitsConfig::default()
        };
        // The bug was `1_000` here, which is below the send limit it also bounds.
        assert_eq!(limits.queue_stream_maxlen(), 10_001);
    }

    /// Symmetric: whichever side is larger is the one that has to fit.
    #[test]
    fn maxlen_follows_whichever_hard_limit_is_larger() {
        let limits = LimitsConfig {
            queued_send_messages_hard: 500,
            queued_receive_messages_hard: 9_000,
            ..LimitsConfig::default()
        };
        assert_eq!(limits.queue_stream_maxlen(), 9_001);
    }

    /// An unlimited hard limit disables trimming rather than casting `-1` to
    /// `usize` and handing Redis 18446744073709551615 as a `MAXLEN`.
    #[test]
    fn an_unlimited_hard_limit_disables_trimming() {
        let send_unlimited = LimitsConfig {
            queued_send_messages_hard: -1,
            ..LimitsConfig::default()
        };
        assert_eq!(send_unlimited.queue_stream_maxlen(), 0);

        let receive_unlimited = LimitsConfig {
            queued_receive_messages_hard: -1,
            ..LimitsConfig::default()
        };
        assert_eq!(receive_unlimited.queue_stream_maxlen(), 0);
    }

    /// The property the value exists for, over the whole settable range: a
    /// stream is never trimmed at or below a limit an account can be clamped
    /// to, because that is what makes counters and stream diverge.
    #[test]
    fn maxlen_is_never_at_or_below_a_clampable_limit() {
        for (send, receive) in [
            (1, 1),
            (200, 200),
            (1_000, 10_000),
            (10_000, 1_000),
            (i32::MAX, 5),
        ] {
            let limits = LimitsConfig {
                queued_send_messages_hard: send,
                queued_receive_messages_hard: receive,
                ..LimitsConfig::default()
            };
            let maxlen = limits.queue_stream_maxlen();
            assert!(
                maxlen > send as usize,
                "send {send} not below maxlen {maxlen}"
            );
            assert!(
                maxlen > receive as usize,
                "receive {receive} not below maxlen {maxlen}"
            );
        }
    }
}
