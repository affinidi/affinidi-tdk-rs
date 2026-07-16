//! Transport-agnostic connection vocabulary shared by messaging transports
//! (DIDComm today, TSP later). Kept here in `affinidi-messaging-core` — the
//! protocol-agnostic base of the messaging stack — so every transport and the
//! delivery layer above them speak the same words.

use serde::{Deserialize, Serialize};

/// Re-falsifiable connection / reachability state of a messaging transport.
///
/// A conforming transport MUST publish a transition on **every** drop and
/// **every** (re)connect for the life of the process — this is not a boot-time
/// latch (rule R6.2). Transports carry it over a [`tokio::sync::watch`] channel
/// they own, so the delivery layer, health endpoints, and retry loops all
/// observe the *same* latest value rather than each inferring connectivity.
///
/// [`tokio::sync::watch`]: https://docs.rs/tokio/latest/tokio/sync/watch/index.html
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ConnState {
    /// Establishing the first connection; no successful connect yet.
    Connecting,
    /// Connected to the next hop (mediator / relay) — sends can be attempted.
    Connected,
    /// The connection has dropped; the transport is retrying or idle. A send
    /// attempted now is not on the wire.
    Disconnected,
}
