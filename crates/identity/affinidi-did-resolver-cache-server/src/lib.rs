use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use axum::{
    extract::{FromRef, FromRequestParts},
    http::request::Parts,
};
use chrono::{DateTime, Utc};
use session::SessionError;
use statistics::Statistics;
use std::{fmt::Debug, sync::Arc, time::Duration};
use tokio::sync::{Mutex, MutexGuard};

pub(crate) mod common;
pub mod config;
pub mod errors;
pub mod handlers;
pub mod server;
pub mod session;
pub mod statistics;

#[derive(Clone)]
pub struct SharedData {
    pub service_start_timestamp: DateTime<Utc>,
    pub stats: Arc<Mutex<Statistics>>,
    pub resolver: DIDCacheClient,
    /// Upper bound on a single upstream resolution before the request path
    /// returns an error rather than blocking the connection.
    pub resolve_timeout: Duration,
    /// Maximum accepted DID length in bytes; longer DIDs are rejected before
    /// resolution.
    pub max_did_size: usize,
    /// Shared HTTP client for did:webvh log fetches, built once at startup so
    /// connections are pooled instead of a fresh client per request.
    pub webvh_client: reqwest::Client,
    /// Present only when `enable_agent_names` is set. `None` means the feature
    /// is off and the route is not registered.
    pub agent_name_resolver: Option<Arc<agent_names::HttpRedirectResolver>>,
}

impl<S> FromRequestParts<S> for SharedData
where
    Self: FromRef<S>,
    S: Send + Sync + Debug,
{
    type Rejection = SessionError;

    async fn from_request_parts(_parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self::from_ref(state))
    }
}

impl SharedData {
    pub async fn stats(&'_ self) -> MutexGuard<'_, Statistics> {
        self.stats.lock().await
    }
}
