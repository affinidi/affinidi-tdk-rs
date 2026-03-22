use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_messaging_sdk::protocols::discover_features::DiscoverFeatures;
use axum::extract::{FromRef, FromRequestParts};
use chrono::{DateTime, Utc};
use common::{config::Config, jwt_auth::AuthError};
use database::Database;
use http::request::Parts;
use std::{fmt::Debug, sync::Arc};
use tasks::websocket_streaming::StreamingTask;

pub mod common;
pub mod database;
pub mod handlers;
pub mod messages;
pub mod server;
pub mod tasks;

#[derive(Clone)]
pub struct SharedData {
    pub config: Config,
    pub service_start_timestamp: DateTime<Utc>,
    pub did_resolver: DIDCacheClient,
    pub database: Database,
    pub streaming_task: Option<StreamingTask>,
    pub discover_features: Arc<DiscoverFeatures>,
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
