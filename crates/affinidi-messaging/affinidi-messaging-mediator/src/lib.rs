//! Affinidi Messaging Mediator
//!
//! A DIDComm/TSP messaging mediator that routes, stores, and forwards messages
//! on behalf of connected agents. Requires at least one of the `didcomm` or `tsp`
//! features to be enabled.

#[cfg(not(any(feature = "didcomm", feature = "tsp")))]
compile_error!("At least one of the `didcomm` or `tsp` features must be enabled");

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
#[cfg(feature = "didcomm")]
use affinidi_messaging_sdk::protocols::discover_features::DiscoverFeatures;
use axum::extract::{FromRef, FromRequestParts};
use chrono::{DateTime, Utc};
use common::{config::Config, jwt_auth::AuthError};
use database::Database;
use http::request::Parts;
use std::{fmt::Debug, sync::Arc};
use tasks::websocket_streaming::StreamingTask;
use tokio_util::sync::CancellationToken;

pub mod common;
pub mod database;
#[cfg(feature = "didcomm")]
pub mod didcomm_compat;
pub mod handlers;
pub mod messages;
pub mod server;
pub mod tasks;

/// Shared application state available to all request handlers via Axum's state extraction.
#[derive(Clone)]
pub struct SharedData {
    /// Mediator configuration loaded at startup.
    pub config: Config,
    /// Timestamp when the mediator service was started.
    pub service_start_timestamp: DateTime<Utc>,
    /// Cached DID resolver for resolving DID documents.
    pub did_resolver: DIDCacheClient,
    /// Redis-backed database for sessions, messages, and accounts.
    pub database: Database,
    /// Optional background task handle for WebSocket streaming.
    pub streaming_task: Option<StreamingTask>,
    /// DIDComm Discover Features protocol handler.
    #[cfg(feature = "didcomm")]
    pub discover_features: Arc<DiscoverFeatures>,
    /// Cancellation token for coordinated graceful shutdown of all background tasks.
    pub shutdown_token: CancellationToken,
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
        Ok(Self::from_ref(state)) // <---- added this line
    }
}
