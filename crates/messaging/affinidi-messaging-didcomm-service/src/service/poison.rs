//! Poison frames: a frame whose handler panics or hangs is not acked (ack
//! follows the handler, R1.6), so the mediator redelivers it. Without a bound
//! it would be redelivered forever, holding a handler permit each time. Each
//! handler runs under [`ListenerConfig::handler_timeout`] with its panic
//! caught, failures are counted per mediator message id, and after
//! [`ListenerConfig::max_handler_failures`] the frame is dead-lettered: acked,
//! reported on the unprocessable-message channel, and logged at error.
//!
//! [`ListenerConfig::handler_timeout`]: crate::config::ListenerConfig::handler_timeout
//! [`ListenerConfig::max_handler_failures`]: crate::config::ListenerConfig::max_handler_failures

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::sync::Mutex;
use std::time::Duration;

use affinidi_messaging_sdk::ATM;
use tokio::task::JoinHandle;
use tracing::{error, warn};

/// How many message ids the failure counts are kept for. Past it the oldest
/// is forgotten: a frame failing among that many others restarts its count,
/// which only delays its dead-lettering.
const TRACKED_FAILURES: usize = 4096;

/// What to do with a frame once its handler has run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Disposition {
    /// Handled: ack it (subject to `auto_delete`).
    Ack,
    /// Not handled, for a reason that may clear: leave it queued.
    Leave,
    /// Failed `attempts` times: ack it (always) and report it.
    DeadLetter { attempts: u32, why: &'static str },
}

/// Runs handlers under a timeout with their panics caught, and counts failures
/// per mediator message id. Shared by a listener's live stream and its offline
/// drain, so a frame's failures add up whichever path delivers it.
#[derive(Debug)]
pub(crate) struct HandlerGuard {
    timeout: Duration,
    max_failures: u32,
    failures: Mutex<Failures>,
}

#[derive(Debug, Default)]
struct Failures {
    counts: HashMap<String, u32>,
    order: VecDeque<String>,
}

/// Aborts the handler task when dropped — so aborting the task that awaits
/// it (a listener's teardown) does not leave the handler running.
struct AbortOnDrop<T>(JoinHandle<T>);

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl HandlerGuard {
    pub(crate) fn new(timeout: Duration, max_failures: u32) -> Self {
        Self {
            timeout,
            max_failures: max_failures.max(1),
            failures: Mutex::new(Failures::default()),
        }
    }

    /// Run `work` — one frame's handler, returning whether the frame may be
    /// acked — under the timeout with its panic caught, and judge the outcome
    /// for the frame `id`.
    pub(crate) async fn run<F>(&self, id: &str, work: F) -> Disposition
    where
        F: Future<Output = bool> + Send + 'static,
    {
        let mut task = AbortOnDrop(tokio::spawn(work));
        let why = match tokio::time::timeout(self.timeout, &mut task.0).await {
            Ok(Ok(true)) => {
                self.clear(id);
                return Disposition::Ack;
            }
            Ok(Ok(false)) => return Disposition::Leave,
            Ok(Err(e)) if e.is_panic() => "the handler panicked",
            Ok(Err(_)) => "the handler task was cancelled",
            Err(_) => "the handler did not finish within the handler timeout",
        };
        drop(task);
        let attempts = self.record(id);
        if attempts >= self.max_failures {
            self.clear(id);
            Disposition::DeadLetter { attempts, why }
        } else {
            warn!(
                message_id = %id,
                attempts,
                max = self.max_failures,
                reason = why,
                "handler failed; leaving the message queued for redelivery"
            );
            Disposition::Leave
        }
    }

    fn record(&self, id: &str) -> u32 {
        let mut f = self
            .failures
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !f.counts.contains_key(id) {
            if f.order.len() >= TRACKED_FAILURES
                && let Some(oldest) = f.order.pop_front()
            {
                f.counts.remove(&oldest);
            }
            f.order.push_back(id.to_string());
        }
        let n = f.counts.entry(id.to_string()).or_default();
        *n += 1;
        *n
    }

    fn clear(&self, id: &str) {
        let mut f = self
            .failures
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if f.counts.remove(id).is_some() {
            f.order.retain(|k| k != id);
        }
    }
}

/// Log a dead-lettered frame at error and report it on the unprocessable-
/// message channel. The caller acks it.
pub(crate) fn report_dead_letter(
    atm: &ATM,
    profile_alias: &str,
    id: &str,
    attempts: u32,
    why: &str,
) {
    error!(
        profile = %profile_alias,
        message_id = %id,
        attempts,
        reason = why,
        "handler failed on this message {attempts} times; dead-lettering it (acked and reported \
         on the unprocessable-message channel)"
    );
    atm.report_unprocessable(
        Some(id.to_string()),
        String::new(),
        format!("dead-lettered after {attempts} handler failures: {why}"),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_panicking_handler_is_retried_then_dead_lettered() {
        let guard = HandlerGuard::new(Duration::from_secs(5), 3);
        for _ in 0..2 {
            assert_eq!(
                guard.run("m", async { panic!("boom") }).await,
                Disposition::Leave
            );
        }
        assert_eq!(
            guard.run("m", async { panic!("boom") }).await,
            Disposition::DeadLetter {
                attempts: 3,
                why: "the handler panicked"
            }
        );
        // The count starts again for a later frame with the same id.
        assert_eq!(
            guard.run("m", async { panic!("boom") }).await,
            Disposition::Leave
        );
    }

    #[tokio::test]
    async fn a_hanging_handler_times_out() {
        let guard = HandlerGuard::new(Duration::from_millis(50), 1);
        assert_eq!(
            guard.run("m", std::future::pending::<bool>()).await,
            Disposition::DeadLetter {
                attempts: 1,
                why: "the handler did not finish within the handler timeout"
            }
        );
    }

    #[tokio::test]
    async fn success_clears_the_count_and_a_transient_leave_is_not_counted() {
        let guard = HandlerGuard::new(Duration::from_secs(5), 2);
        assert_eq!(
            guard.run("m", async { panic!("boom") }).await,
            Disposition::Leave
        );
        assert_eq!(guard.run("m", async { true }).await, Disposition::Ack);
        assert_eq!(
            guard.run("m", async { panic!("boom") }).await,
            Disposition::Leave,
            "counting started again after the success"
        );
        assert_eq!(guard.run("m", async { false }).await, Disposition::Leave);
        assert!(matches!(
            guard.run("m", async { panic!("boom") }).await,
            Disposition::DeadLetter { .. }
        ));
    }

    #[test]
    fn the_failure_counts_are_bounded() {
        let guard = HandlerGuard::new(Duration::from_secs(5), 10);
        for i in 0..TRACKED_FAILURES + 10 {
            guard.record(&format!("m{i}"));
        }
        let f = guard.failures.lock().unwrap();
        assert_eq!(f.counts.len(), TRACKED_FAILURES);
        assert_eq!(f.order.len(), TRACKED_FAILURES);
    }
}
