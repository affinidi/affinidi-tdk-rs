//! Statistics module for the cache server.
//! Creates a parallel task that logs cache statistics based on an interval
use crate::errors::CacheError;
use affinidi_did_common::Document;
use affinidi_did_resolver_cache_sdk::DIDMethod;
use ahash::AHashMap as HashMap;
use moka::future::Cache;
use std::{
    fmt::{self, Display, Formatter},
    sync::Arc,
    time::Duration,
};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
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
                .map(|(k, v)| format!("({k}: {v})"))
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
///
/// Runs until `shutdown` is cancelled, at which point it returns cleanly so the
/// supervising spawn can join it during graceful shutdown.
pub async fn statistics(
    interval: Duration,
    stats: &Arc<Mutex<Statistics>>,
    cache: Cache<[u64; 2], Document>,
    shutdown: CancellationToken,
) -> Result<(), CacheError> {
    let _span = span!(Level::INFO, "statistics");

    async move {
        debug!("Starting statistics thread...");
        let mut wait = tokio::time::interval(interval);

        let mut previous_stats = Statistics::default();
        loop {
            tokio::select! {
                _ = wait.tick() => {
                    let mut stats = stats.lock().await;

                    cache.run_pending_tasks().await;
                    stats.cache_size = cache.entry_count() as i64;

                    info!("Statistics: {}", stats);
                    info!("Delta: {}", stats.delta(&previous_stats));

                    previous_stats = stats.clone();
                }
                _ = shutdown.cancelled() => {
                    debug!("Statistics thread shutting down");
                    break;
                }
            }
        }
        Ok(())
    }
    .instrument(_span)
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn statistics_exits_promptly_on_cancel() {
        let stats = Arc::new(Mutex::new(Statistics::default()));
        let cache: Cache<[u64; 2], Document> = Cache::new(10);
        let token = CancellationToken::new();
        // Pre-cancel: with a 1h interval the loop can only leave via the
        // cancellation branch, so the call must return promptly (and Ok).
        token.cancel();

        let res = tokio::time::timeout(
            Duration::from_secs(2),
            statistics(Duration::from_secs(3600), &stats, cache, token),
        )
        .await;
        assert!(res.is_ok(), "stats task must exit promptly after cancel");
        assert!(res.unwrap().is_ok());
    }

    /// A panic in the statistics task must be caught and restarted by the
    /// supervisor (it is non-load-bearing), with the fault recorded — not
    /// silently kill cache statistics for the life of the process. This
    /// exercises the exact wiring `server.rs` uses, with an injected panic.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn supervised_statistics_restarts_after_panic() {
        use affinidi_task_utils::{ComponentState, TaskSupervisor};
        use std::sync::atomic::{AtomicU32, Ordering};

        let token = CancellationToken::new();
        let supervisor = TaskSupervisor::new(token.clone());
        let registry = supervisor.registry();
        let attempts = Arc::new(AtomicU32::new(0));

        let stats = Arc::new(Mutex::new(Statistics::default()));
        let cache: Cache<[u64; 2], Document> = Cache::new(10);
        {
            let attempts = attempts.clone();
            let stats = stats.clone();
            let cache = cache.clone();
            let token = token.clone();
            supervisor.spawn("statistics", false, move || {
                let attempts = attempts.clone();
                let stats = stats.clone();
                let cache = cache.clone();
                let token = token.clone();
                async move {
                    if attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                        panic!("injected statistics panic");
                    }
                    // Long interval so the restarted attempt stays Running
                    // until we cancel.
                    statistics(Duration::from_secs(3600), &stats, cache, token).await
                }
            });
        }

        // Poll until the supervisor has restarted the task (≥2 attempts) and
        // it is Running again, with the panic recorded as last_error.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let restarted = attempts.load(Ordering::SeqCst) >= 2;
            let running = registry
                .get("statistics")
                .map(|h| h.state == ComponentState::Running && h.restarts >= 1)
                .unwrap_or(false);
            if restarted && running {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "supervisor did not restart the statistics task after a panic"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        let health = registry.get("statistics").unwrap();
        assert!(!health.load_bearing, "stats task must be non-load-bearing");
        assert!(
            health
                .last_error
                .as_deref()
                .is_some_and(|e| e.contains("panicked")),
            "the panic must be recorded as the last error"
        );

        token.cancel();
    }
}
