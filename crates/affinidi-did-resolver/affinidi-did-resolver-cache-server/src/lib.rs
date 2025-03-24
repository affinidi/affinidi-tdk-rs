use std::{fmt::Debug, sync::Arc};

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use axum::{
    extract::{FromRef, FromRequestParts},
    http::request::Parts,
};
use chrono::{DateTime, Utc};
use session::SessionError;
use statistics::Statistics;
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
    pub async fn stats(&self) -> MutexGuard<Statistics> {
        self.stats.lock().await
    }
}
