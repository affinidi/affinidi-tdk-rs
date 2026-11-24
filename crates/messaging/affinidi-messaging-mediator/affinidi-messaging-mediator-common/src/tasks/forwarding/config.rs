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
    /// How many next-hop endpoints are delivered to at once. Messages for one
    /// endpoint go out one at a time; different endpoints proceed in parallel
    /// up to this limit, so a slow endpoint holds one slot rather than the
    /// whole processor.
    #[serde(default = "default_max_concurrent_endpoints")]
    pub max_concurrent_endpoints: usize,
    /// Upper bound, in seconds, on one delivery attempt (connect, send and
    /// the peer's answer, including a WebSocket attempt and its REST
    /// fallback). An attempt that runs over is a retryable failure. Keep it
    /// above 60: a WebSocket attempt (connect, send and the peer's ack) takes
    /// at most 30 s before the REST fallback, which has 30 s of its own.
    /// Below 90 the WebSocket attempt is cut to a third of this, so the
    /// fallback always has time; below 60 a warning is logged at startup.
    #[serde(default = "default_delivery_timeout_seconds")]
    pub delivery_timeout_seconds: u64,
    /// Seconds a claimed queue entry may sit untouched before any processor
    /// in the consumer group takes it over: how soon the entries a stopped or
    /// restarted processor held are delivered by another. A running processor
    /// refreshes its claims four times in this window, so it never loses one
    /// it is still working on. The same sweep picks up a requested delay
    /// longer than `max_backoff_ms` once it is due.
    ///
    /// Keep it at least twice `delivery_timeout_seconds`. A processor stops
    /// starting sends once its claims have gone unconfirmed for half this
    /// window, but a send already under way runs on for up to the delivery
    /// timeout; a shorter window lets another processor take the entry over
    /// and send it too.
    #[serde(default = "default_reclaim_idle_seconds")]
    pub reclaim_idle_seconds: u64,
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
    /// Allowlist of peer-mediator DIDs whose relays this mediator will accept on
    /// its inbound endpoint. Empty = accept any peer (the relay capability is
    /// still gated by ACLs).
    ///
    /// Applies wherever the relaying peer can actually be identified:
    ///
    /// * **DIDComm**, in [`RelayMode::Rewrap`] only — the re-wrap layer is
    ///   addressed to this mediator, so authcrypt names its sender. Ignored in
    ///   [`RelayMode::Blind`], where the peer's identity is not visible.
    /// * **TSP**, on every routed/nested relay hop — no mode to select. Such a
    ///   hop is sealed to this mediator, and unpacking it verifies an Ed25519
    ///   signature over the envelope *and* opens the payload with HPKE-Auth, so
    ///   the peer is authenticated twice over. TSP routed relay is Rewrap-like by
    ///   construction.
    ///
    /// It does **not** apply to TSP opaque pass-through (a message addressed to a
    /// local recipient rather than to this mediator): nothing there is addressed
    /// to us, so there is no peer to identify. That case is governed by
    /// `security.local_direct_delivery_allowed` and
    /// `security.enable_inter_mediator_relay`.
    pub relay_trusted_mediators: HashSet<String>,
}

fn default_max_concurrent_endpoints() -> usize {
    32
}

fn default_delivery_timeout_seconds() -> u64 {
    90
}

fn default_reclaim_idle_seconds() -> u64 {
    180
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
            max_concurrent_endpoints: default_max_concurrent_endpoints(),
            delivery_timeout_seconds: default_delivery_timeout_seconds(),
            reclaim_idle_seconds: default_reclaim_idle_seconds(),
            consumer_group: "forwarding".to_string(),
            accept_invalid_certs: false,
            max_hops: 10,
            relay_mode: RelayMode::Blind,
            relay_trusted_mediators: HashSet::new(),
        }
    }
}
