//! Statistics module for the cache server.
//! Creates a parallel task that logs cache statistics based on an interval
use crate::errors::CacheError;
use affinidi_did_resolver_cache_sdk::DIDMethod;
use ahash::AHashMap as HashMap;
use moka::future::Cache;
use ssi::dids::Document;
use std::{
    fmt::{self, Display, Formatter},
    sync::Arc,
    time::Duration,
};
use tokio::sync::Mutex;
use tracing::{Instrument, Level, debug, info, span};

/// Statistics struct for the cache server
/// Contains information about the cache, websocket connections, and resolver requests
/// ws_opened: number of opened websocket connections
/// ws_closed: number of closed websocket connections
/// cache_size: number of entries in the cache (approximate)
/// resolver_success: number of successful resolver requests
/// resolver_error: number of failed resolver requests
/// cache_hit: number of cache hits (calculate as a % against resolver_success)
/// method: number of resolver requests per DID method (success)
#[derive(Clone, Debug, Default)]
pub struct Statistics {
    ws_opened: i64,
    ws_closed: i64,
    cache_size: i64,
    resolver_success: u64,
    resolver_error: u64,
    cache_hit: u64,
    method: HashMap<DIDMethod, u64>,
}

impl Display for Statistics {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        // protects against division by zero
        debug!(
            "Calculating cache hit rate success {}",
            self.resolver_success
        );
        let cache_hit_rate = if self.resolver_success > 0 {
            (self.cache_hit as f64 / self.resolver_success as f64) * 100.0
        } else {
            0.0
        };

        write!(
            f,
            r#"
    Cache: count({}) Hits({} {:.2}%)
    Connections: ws_open({}) ws_close({}) ws_current({})
    Resolver: total({}) success({}) error({})
    Methods (METHOD: COUNT): {}
            "#,
            self.cache_size,
            self.cache_hit,
            cache_hit_rate,
            self.ws_opened,
            self.ws_closed,
            self.ws_opened - self.ws_closed,
            self.resolver_success + self.resolver_error,
            self.resolver_success,
            self.resolver_error,
            self.method
                .iter()
                .map(|(k, v)| format!("({}: {})", k, v))
                .collect::<Vec<String>>()
                .join(", ")
        )
    }
}

impl Statistics {
    pub(crate) fn delta(&self, previous: &Statistics) -> Statistics {
        Statistics {
            ws_opened: self.ws_opened - previous.ws_opened,
            ws_closed: self.ws_closed - previous.ws_closed,
            cache_size: self.cache_size - previous.cache_size,
            resolver_success: self.resolver_success - previous.resolver_success,
            resolver_error: self.resolver_error - previous.resolver_error,
            cache_hit: self.cache_hit - previous.cache_hit,
            method: self
                .method
                .iter()
                .map(|(k, v)| (k.clone(), v - previous.method.get(k).unwrap_or(&(0))))
                .collect(),
        }
    }

    /// Increments the number of opened websocket connections
    pub fn increment_ws_opened(&mut self) {
        self.ws_opened += 1;
    }

    /// Increments the number of closed websocket connections
    pub fn increment_ws_closed(&mut self) {
        self.ws_closed += 1;
    }

    /// Increments the number of successful resolver requests
    pub fn increment_resolver_success(&mut self) {
        self.resolver_success += 1;
    }

    /// Increments the number of failed resolver requests
    pub fn increment_resolver_error(&mut self) {
        self.resolver_error += 1;
    }

    /// Increments the number of cache hits
    pub fn increment_cache_hit(&mut self) {
        self.cache_hit += 1;
    }

    /// Increments the number of successful resolver requests for a specific DID method
    pub fn increment_did_method_success(&mut self, method: DIDMethod) {
        self.method
            .entry(method)
            .and_modify(|v| *v += 1)
            .or_insert(0);
    }
}

/// Periodically logs statistics about the cache.
/// Is spawned as a task from main().
pub async fn statistics(
    interval: Duration,
    stats: &Arc<Mutex<Statistics>>,
    cache: Cache<[u64; 2], Document>,
) -> Result<(), CacheError> {
    let _span = span!(Level::INFO, "statistics");

    async move {
        debug!("Starting statistics thread...");
        let mut wait = tokio::time::interval(interval);

        let mut previous_stats = Statistics::default();
        loop {
            wait.tick().await;

            let mut stats = stats.lock().await;

            cache.run_pending_tasks().await;
            stats.cache_size = cache.entry_count() as i64;

            info!("Statistics: {}", stats);
            info!("Delta: {}", stats.delta(&previous_stats));

            previous_stats = stats.clone();
        }
    }
    .instrument(_span)
    .await
}
