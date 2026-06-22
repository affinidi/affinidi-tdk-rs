//! Affinidi Messaging Mediator
//!
//! A DIDComm/TSP messaging mediator that routes, stores, and forwards messages
//! on behalf of connected agents. Requires at least one of the `didcomm` or `tsp`
//! features to be enabled.

#[cfg(not(any(feature = "didcomm", feature = "tsp")))]
compile_error!("At least one of the `didcomm` or `tsp` features must be enabled");

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_messaging_mediator_common::store::MediatorStore;
#[cfg(feature = "didcomm")]
use affinidi_messaging_sdk::protocols::discover_features::DiscoverFeatures;
use axum::extract::{FromRef, FromRequestParts};
use chrono::{DateTime, Utc};
use common::{config::Config, did_rate_limiter::DidRateLimiter, jwt_auth::AuthError};
use dashmap::DashMap;
use http::request::Parts;
use std::{collections::HashSet, fmt::Debug, sync::Arc, sync::atomic::AtomicUsize};
use tasks::supervisor::HealthRegistry;
use tasks::websocket_streaming::StreamingTask;
use tokio_util::sync::CancellationToken;

pub mod builder;
pub mod commands;
pub mod common;
#[cfg(feature = "didcomm")]
pub mod didcomm_compat;
pub mod handlers;
pub mod messages;
pub mod server;
pub mod store;
pub mod tasks;
#[cfg(feature = "tsp")]
pub mod tsp_identity;

/// Shared application state available to all request handlers via Axum's state extraction.
#[derive(Clone)]
pub struct SharedData {
    /// Mediator configuration loaded at startup.
    pub config: Config,
    /// Timestamp when the mediator service was started.
    pub service_start_timestamp: DateTime<Utc>,
    /// Cached DID resolver for resolving DID documents.
    pub did_resolver: DIDCacheClient,
    /// Storage backend for sessions, messages, accounts, and live
    /// streaming. Polymorphic so the mediator can run against Redis,
    /// Fjall, or memory without changing handler code.
    pub database: Arc<dyn MediatorStore>,
    /// Optional background task handle for WebSocket streaming.
    pub streaming_task: Option<StreamingTask>,
    /// DIDComm Discover Features protocol handler.
    #[cfg(feature = "didcomm")]
    pub discover_features: Arc<DiscoverFeatures>,
    /// Counter for active WebSocket connections (used for connection limiting).
    pub active_websocket_count: Arc<AtomicUsize>,
    /// Live WebSocket connection count per DID hash, enforcing
    /// `limits.max_websocket_connections_per_did` so a single DID can't
    /// exhaust the global connection budget. Entries are removed when a DID's
    /// count returns to zero.
    pub ws_connections_per_did: Arc<DashMap<String, u32>>,
    /// Per-DID rate limiter for authenticated endpoints.
    pub did_rate_limiter: DidRateLimiter,
    /// Cancellation token for coordinated graceful shutdown of all background tasks.
    pub shutdown_token: CancellationToken,
    /// Pre-computed `(host, port)` set used by the routing 2.0 forward
    /// handler to short-circuit when a next-hop's DIDComm service URI
    /// resolves back to this mediator. Populated from
    /// `config.listen_address` plus any operator-declared
    /// `config.local_endpoints` aliases.
    pub self_authorities: Arc<HashSet<(String, u16)>>,
    /// Live health of supervised background tasks, published by the
    /// [`TaskSupervisor`](tasks::supervisor::TaskSupervisor). The readiness
    /// handler reads this to fail `/readyz` when a load-bearing component is
    /// down and to report `degraded` for non-load-bearing ones.
    pub component_health: HealthRegistry,
    /// Source of the current time for all expiry / TTL / session-cleanup
    /// decisions on the request path. Production wires a
    /// [`SystemClock`](affinidi_messaging_mediator_common::types::clock::SystemClock);
    /// tests can inject a `TestClock` (via `TestMediatorBuilder::clock`) and
    /// advance it to exercise expiry instantly.
    pub clock: Arc<dyn affinidi_messaging_mediator_common::types::clock::Clock>,
    /// The mediator's own TSP identity (Ed25519 signing + X25519 decryption keys),
    /// derived lazily on first use from the configured DID + operating secrets.
    /// Only needed when the mediator acts as a routed TSP relay hop; Direct
    /// delivery is a blind store-and-forward and never touches it.
    #[cfg(feature = "tsp")]
    pub tsp_identity: Arc<tokio::sync::OnceCell<tsp_identity::MediatorTspIdentity>>,
}

impl SharedData {
    /// The mediator's TSP identity, derived (and cached) on first use from its
    /// configured DID document and operating secrets.
    #[cfg(feature = "tsp")]
    pub async fn tsp_identity(
        &self,
    ) -> Result<
        &tsp_identity::MediatorTspIdentity,
        affinidi_messaging_mediator_common::errors::MediatorError,
    > {
        self.tsp_identity
            .get_or_try_init(|| {
                tsp_identity::MediatorTspIdentity::derive(
                    &self.config.mediator_did,
                    &self.did_resolver,
                    &*self.config.security.mediator_secrets,
                )
            })
            .await
    }
    /// Bound for request-path storage calls made during admission/validation
    /// (see [`common::storage_timeout`]). Sourced from the existing
    /// `[database] database_timeout` (the same knob that caps Redis
    /// commands), so it is operator-configurable and backend-agnostic.
    pub fn storage_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.config.database.database_timeout as u64)
    }
}

impl Debug for SharedData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedData")
            .field("config", &self.config)
            .field("service_start_timestamp", &self.service_start_timestamp)
            .finish()
    }
}

impl<S> FromRequestParts<S> for SharedData
where
    Self: FromRef<S>,
    S: Send + Sync + Debug,
{
    type Rejection = AuthError;

    async fn from_request_parts(_parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self::from_ref(state))
    }
}
