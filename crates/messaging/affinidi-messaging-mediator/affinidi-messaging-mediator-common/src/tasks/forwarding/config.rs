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

/// How a mediator relays a forward whose next hop is a *remote* mediator.
///
/// See [`ForwardingConfig::relay_mode`]. Both mediators in a relaying pair must
/// agree on the mode: a `Rewrap` sender produces envelopes only a `Rewrap`
/// receiver knows how to peel.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayMode {
    /// Relay the inner forward attachment to the next mediator **unchanged**
    /// (byte-for-byte). Simple, but the inner envelope — including the original
    /// sender's key id in its JWE protected header — is visible on the wire,
    /// and the receiving mediator cannot identify the relaying peer mediator.
    /// This is the historical behaviour and the default.
    #[default]
    Blind,
    /// **Re-encrypt** the inner forward for the next mediator: wrap it in a new
    /// `forward` authcrypted *from this mediator* to the next hop. The inner
    /// envelope (and the original sender's identity) is hidden from on-wire
    /// observers, and the receiving mediator can authenticate and allowlist the
    /// relaying peer mediator (see [`ForwardingConfig::relay_trusted_mediators`]).
    /// Requires the receiving mediator to also run in `Rewrap` mode.
    Rewrap,
}

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
    /// How to relay a forward to a remote next-hop mediator. See [`RelayMode`].
    /// Defaults to [`RelayMode::Blind`] (historical behaviour, no regression).
    pub relay_mode: RelayMode,
    /// In [`RelayMode::Rewrap`], the allowlist of peer-mediator DIDs whose
    /// re-wrapped relays this mediator will accept on its inbound endpoint.
    /// Empty = accept any peer (capability still gated by ACLs). Ignored in
    /// [`RelayMode::Blind`], where the relaying peer's identity is not visible.
    pub relay_trusted_mediators: HashSet<String>,
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
            relay_mode: RelayMode::Blind,
            relay_trusted_mediators: HashSet::new(),
        }
    }
}
