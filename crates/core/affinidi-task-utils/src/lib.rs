//! Background-task supervision for long-lived `tokio` tasks.
//!
//! Every long-lived background task (a statistics poller, a network
//! reconnect loop, a queue processor, an expiry sweep) can be spawned
//! through a [`TaskSupervisor`] instead of a bare `tokio::spawn`. The
//! supervisor turns a silent task death into a *detected, recovered, and
//! observable* event:
//!
//! - **Restart on failure.** A task that returns an error or panics is
//!   restarted with capped exponential backoff (1s → 60s). The supervisor
//!   never gives up — a service with a wedged background loop keeps serving
//!   traffic while the fault is logged at ERROR with its restart history.
//!   This is the deliberate "restart-and-degrade, never fail-fast" posture:
//!   an orchestrator should not kill a process that is still answering
//!   requests just because a housekeeping loop is flapping.
//! - **Health registry.** Each task's state (`Running` / `Restarting` /
//!   `Stopped`), restart count, last error, and last-transition time are
//!   recorded in a [`HealthRegistry`] that a readiness handler can read to
//!   decide readiness (a down *load-bearing* component → fail readiness; a
//!   down non-load-bearing component → report `degraded` but stay ready).
//! - **Clean shutdown.** When the shared [`CancellationToken`] fires, the
//!   running task is aborted and marked `Stopped` with no restart.
//!
//! The supervisor owns cancellation, so supervised task bodies don't need
//! their own shutdown `select!` — they can be a plain `loop { … }` and the
//! supervisor aborts them on shutdown. Supervised loops should be
//! idempotent, so an abort mid-iteration is safe.
//!
//! # Example
//!
//! ```no_run
//! use affinidi_task_utils::{CancellationToken, TaskSupervisor};
//!
//! # async fn doc() {
//! let shutdown = CancellationToken::new();
//! let supervisor = TaskSupervisor::new(shutdown.clone());
//!
//! // `factory` is invoked once per (re)start, so build fresh state each time.
//! supervisor.spawn("heartbeat", false, || async {
//!     loop {
//!         // … do periodic work …
//!         tokio::time::sleep(std::time::Duration::from_secs(30)).await;
//!     }
//!     # #[allow(unreachable_code)]
//!     Ok::<(), std::io::Error>(())
//! });
//!
//! // A readiness handler can read component health without locking out writes:
//! let registry = supervisor.registry();
//! # let _ = registry;
//! # }
//! ```

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::Serialize;
use tracing::{error, info, warn};

pub use tokio_util::sync::CancellationToken;

/// Backoff applied after the first failure; doubles each subsequent
/// consecutive failure up to [`MAX_BACKOFF`].
const BASE_BACKOFF: Duration = Duration::from_secs(1);
/// Ceiling for the restart backoff, so a permanently-broken component
/// retries at a steady, low rate rather than hot-looping.
const MAX_BACKOFF: Duration = Duration::from_secs(60);

/// Lifecycle state of a supervised component.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ComponentState {
    /// The task future is currently executing.
    Running,
    /// The task failed and the supervisor is backing off before its next
    /// restart attempt.
    Restarting,
    /// The task was stopped by shutdown and will not restart.
    Stopped,
}

/// A point-in-time health snapshot for one supervised component.
#[derive(Clone, Debug, Serialize)]
pub struct ComponentHealth {
    /// Stable component name (e.g. `"forwarding_processor"`).
    pub name: String,
    /// Whether a non-`Running` state should fail readiness rather than
    /// merely mark the service `degraded`.
    pub load_bearing: bool,
    /// Current lifecycle state.
    pub state: ComponentState,
    /// Number of times the task has been restarted since process start.
    pub restarts: u64,
    /// Display of the most recent failure, if any.
    pub last_error: Option<String>,
    /// When the component last changed state.
    pub since: DateTime<Utc>,
}

/// Shared, concurrently-readable map of component name → health. Clone this
/// into request/shared state so a readiness handler can read it without
/// locking out the supervisor's writes.
pub type HealthRegistry = Arc<DashMap<String, ComponentHealth>>;

/// Spawns and supervises background tasks against a shared shutdown token,
/// publishing their health into a [`HealthRegistry`].
#[derive(Clone)]
pub struct TaskSupervisor {
    registry: HealthRegistry,
    shutdown: CancellationToken,
}

impl TaskSupervisor {
    /// Create a supervisor bound to `shutdown` (the same token used for
    /// graceful shutdown elsewhere in the process).
    pub fn new(shutdown: CancellationToken) -> Self {
        Self {
            registry: Arc::new(DashMap::new()),
            shutdown,
        }
    }

    /// The shared health registry. Clone this into request state so health
    /// endpoints can report component status.
    pub fn registry(&self) -> HealthRegistry {
        self.registry.clone()
    }

    /// Spawn a supervised task.
    ///
    /// `factory` is invoked once per (re)start to produce the task future;
    /// constructing fresh state each attempt keeps restarts clean. The
    /// future returns `Ok(())` on intentional completion or `Err(_)` to
    /// request a restart; a panic is caught and likewise triggers a restart.
    ///
    /// `load_bearing` controls how a readiness handler should treat a
    /// non-`Running` state — see [`ComponentHealth::load_bearing`].
    pub fn spawn<F, Fut, E>(&self, name: impl Into<String>, load_bearing: bool, factory: F)
    where
        F: Fn() -> Fut + Send + 'static,
        Fut: Future<Output = Result<(), E>> + Send + 'static,
        E: std::fmt::Display + Send + 'static,
    {
        let name = name.into();
        let registry = self.registry.clone();
        let shutdown = self.shutdown.clone();

        set_state(
            &registry,
            &name,
            load_bearing,
            ComponentState::Running,
            0,
            None,
        );

        tokio::spawn(async move {
            let mut restarts: u64 = 0;
            loop {
                // Mark Running at the top of every iteration so a task that
                // recovered after a restart is reported healthy again (the
                // prior `last_error` is preserved — `None` here leaves it
                // untouched — so operators can still see it flapped).
                set_state(
                    &registry,
                    &name,
                    load_bearing,
                    ComponentState::Running,
                    restarts,
                    None,
                );

                // Spawn the task on its own handle so a panic surfaces as a
                // `JoinError` rather than tearing down the supervisor.
                let mut handle = tokio::spawn(factory());

                let failure: String = tokio::select! {
                    joined = &mut handle => match joined {
                        Ok(Ok(())) => {
                            // Completed without error. Under shutdown that's
                            // expected; otherwise a long-lived task ending is
                            // itself a fault, so restart it.
                            if shutdown.is_cancelled() {
                                stop(&registry, &name, restarts);
                                return;
                            }
                            warn!(task = %name, "Supervised task completed unexpectedly; restarting");
                            "task returned before shutdown".to_string()
                        }
                        Ok(Err(e)) => e.to_string(),
                        Err(join_err) if join_err.is_panic() => format!("panicked: {join_err}"),
                        Err(join_err) => {
                            // Cancelled/aborted without us asking — treat as a
                            // stop rather than spin.
                            warn!(task = %name, error = %join_err, "Supervised task aborted");
                            stop(&registry, &name, restarts);
                            return;
                        }
                    },
                    _ = shutdown.cancelled() => {
                        handle.abort();
                        stop(&registry, &name, restarts);
                        info!(task = %name, "Supervised task stopped (shutdown)");
                        return;
                    }
                };

                restarts += 1;
                let backoff = backoff_for(restarts);
                error!(
                    task = %name,
                    restarts,
                    load_bearing,
                    last_error = %failure,
                    backoff_secs = backoff.as_secs(),
                    "Supervised background task failed; restarting after backoff. \
                     If this persists, inspect the backend/connectivity for this \
                     component — the process keeps serving but this function is degraded.",
                );
                set_state(
                    &registry,
                    &name,
                    load_bearing,
                    ComponentState::Restarting,
                    restarts,
                    Some(failure),
                );

                tokio::select! {
                    _ = tokio::time::sleep(backoff) => {}
                    _ = shutdown.cancelled() => {
                        stop(&registry, &name, restarts);
                        info!(task = %name, "Supervised task stopped during backoff (shutdown)");
                        return;
                    }
                }
            }
        });
    }
}

/// Exponential backoff: `BASE * 2^(restarts-1)`, capped at `MAX_BACKOFF`.
fn backoff_for(restarts: u64) -> Duration {
    // Cap the exponent so the shift can't overflow; `MAX_BACKOFF` clamps the
    // result regardless.
    let exp = restarts.saturating_sub(1).min(16) as u32;
    BASE_BACKOFF.saturating_mul(1u32 << exp).min(MAX_BACKOFF)
}

fn set_state(
    registry: &HealthRegistry,
    name: &str,
    load_bearing: bool,
    state: ComponentState,
    restarts: u64,
    last_error: Option<String>,
) {
    registry
        .entry(name.to_string())
        .and_modify(|h| {
            h.state = state;
            h.restarts = restarts;
            if last_error.is_some() {
                h.last_error = last_error.clone();
            }
            h.since = Utc::now();
        })
        .or_insert_with(|| ComponentHealth {
            name: name.to_string(),
            load_bearing,
            state,
            restarts,
            last_error,
            since: Utc::now(),
        });
}

fn stop(registry: &HealthRegistry, name: &str, restarts: u64) {
    if let Some(mut h) = registry.get_mut(name) {
        h.state = ComponentState::Stopped;
        h.restarts = restarts;
        h.since = Utc::now();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Duration;
    use tokio::time::timeout;

    fn state_of(reg: &HealthRegistry, name: &str) -> Option<ComponentState> {
        reg.get(name).map(|h| h.state)
    }

    async fn wait_for<F: Fn() -> bool>(pred: F) {
        timeout(Duration::from_secs(5), async {
            loop {
                if pred() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("condition not met within timeout");
    }

    #[tokio::test]
    async fn backoff_is_exponential_and_capped() {
        assert_eq!(backoff_for(1), Duration::from_secs(1));
        assert_eq!(backoff_for(2), Duration::from_secs(2));
        assert_eq!(backoff_for(3), Duration::from_secs(4));
        assert_eq!(backoff_for(7), Duration::from_secs(60)); // 64 → capped
        assert_eq!(backoff_for(99), Duration::from_secs(60));
    }

    #[tokio::test(start_paused = true)]
    async fn restarts_a_failing_task_with_backoff() {
        let sup = TaskSupervisor::new(CancellationToken::new());
        let reg = sup.registry();
        let attempts = Arc::new(AtomicU32::new(0));
        let a = attempts.clone();

        sup.spawn("flaky", false, move || {
            let a = a.clone();
            async move {
                a.fetch_add(1, Ordering::SeqCst);
                Err::<(), String>("boom".to_string())
            }
        });

        // First attempt runs immediately and fails; the registry should show
        // Restarting with the error recorded.
        wait_for(|| attempts.load(Ordering::SeqCst) >= 1).await;
        wait_for(|| state_of(&reg, "flaky") == Some(ComponentState::Restarting)).await;
        assert_eq!(
            reg.get("flaky").unwrap().last_error.as_deref(),
            Some("boom")
        );

        // Advancing past the 1s backoff drives the next attempt.
        tokio::time::advance(Duration::from_secs(1)).await;
        wait_for(|| attempts.load(Ordering::SeqCst) >= 2).await;
        assert!(reg.get("flaky").unwrap().restarts >= 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn restarts_after_a_panic() {
        let sup = TaskSupervisor::new(CancellationToken::new());
        let reg = sup.registry();
        let attempts = Arc::new(AtomicU32::new(0));
        let a = attempts.clone();

        sup.spawn("panicky", true, move || {
            let a = a.clone();
            async move {
                let n = a.fetch_add(1, Ordering::SeqCst);
                if n == 0 {
                    panic!("first attempt panics");
                }
                // Second attempt: run forever so it stays Running.
                std::future::pending::<()>().await;
                Ok::<(), String>(())
            }
        });

        // The panic must be caught and the task restarted into a Running
        // state — the supervisor itself must survive.
        wait_for(|| attempts.load(Ordering::SeqCst) >= 2).await;
        wait_for(|| state_of(&reg, "panicky") == Some(ComponentState::Running)).await;
        assert!(reg.get("panicky").unwrap().restarts >= 1);
        assert!(reg.get("panicky").unwrap().load_bearing);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn clean_shutdown_stops_without_restart() {
        let token = CancellationToken::new();
        let sup = TaskSupervisor::new(token.clone());
        let reg = sup.registry();
        let attempts = Arc::new(AtomicU32::new(0));
        let a = attempts.clone();

        sup.spawn("worker", true, move || {
            let a = a.clone();
            async move {
                a.fetch_add(1, Ordering::SeqCst);
                std::future::pending::<()>().await; // runs until aborted
                Ok::<(), String>(())
            }
        });

        wait_for(|| state_of(&reg, "worker") == Some(ComponentState::Running)).await;
        token.cancel();
        wait_for(|| state_of(&reg, "worker") == Some(ComponentState::Stopped)).await;

        // No restart should occur after shutdown.
        let count = attempts.load(Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            count,
            "task restarted after shutdown"
        );
    }
}
