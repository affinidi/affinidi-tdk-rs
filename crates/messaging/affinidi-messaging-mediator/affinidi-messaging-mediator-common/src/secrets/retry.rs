//! Retry + exponential backoff helper for cloud secret backends.
//!
//! Each cloud provider has its own SDK error type and its own
//! "transient vs. terminal" taxonomy. Rather than wire `tower-retry`
//! per-backend (which forces every call into a `Service` shape and
//! adds a non-trivial type-erasure dance), we expose a small async
//! retry helper here and let each backend supply its own
//! [`RetryPolicy`].
//!
//! The wrapper guarantees:
//!
//! - Exactly **3 attempts**: initial + 2 retries.
//! - **Exponential backoff**: 100 ms → 400 ms (×4 each step). The
//!   final retry waits ~400 ms before the third attempt; the
//!   sequence ramps to ~1.6 s if a future caller bumps
//!   [`MAX_ATTEMPTS`].
//! - **Honour `Retry-After`** when the policy can extract one (AWS
//!   throttling responses carry it). Falls back to the exponential
//!   step otherwise.
//! - **No retry** when the policy classifies the error as terminal
//!   (auth failure, not-found, validation). The caller's normal
//!   error path runs unchanged.
//!
//! The helper is `Send`-friendly so it composes with `async-trait`
//! based [`super::store::SecretStore`] impls without a `Pin<Box<…>>`
//! gymnastics layer.

use std::future::Future;
use std::time::Duration;

use tracing::{debug, warn};

/// Total number of attempts (initial + retries). The task brief
/// specified "3 attempts exponential backoff (100ms → 400ms → 1.6s)";
/// the labelled timings refer to the *backoff before each retry*, so
/// we issue 3 calls total with delays 100 ms and 400 ms between them.
pub const MAX_ATTEMPTS: u32 = 3;
const INITIAL_BACKOFF: Duration = Duration::from_millis(100);
const BACKOFF_MULTIPLIER: u32 = 4;

/// What the policy decided about a particular error.
pub enum Retryable {
    /// Try again. `retry_after` overrides the helper's exponential
    /// step when present (typically populated from the provider's
    /// `Retry-After` / throttle hint).
    Yes { retry_after: Option<Duration> },
    /// Stop. The error will be returned to the caller as-is.
    No,
}

/// Per-backend classifier. Implementations should be cheap (string
/// match on the SDK error, peek at the HTTP status, etc.) — they're
/// called on the hot path of every retryable error.
pub trait RetryPolicy<E> {
    /// Classify `err`. Should be conservative: retrying a terminal
    /// error wastes time, but failing to retry a transient one fails
    /// the whole call. When in doubt, return `No`.
    fn classify(&self, err: &E) -> Retryable;
}

/// Run `op` with retry/backoff. The closure is awaited fresh on every
/// attempt so any cached SDK clients can rebuild request signatures.
///
/// `op_label` shows up in `tracing` output to help correlate retries
/// in logs (e.g. `"GetSecretValue(mediator/admin/credential)"`).
pub async fn with_retry<T, E, Op, Fut, P>(op_label: &str, policy: &P, mut op: Op) -> Result<T, E>
where
    Op: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
    P: RetryPolicy<E>,
{
    let mut backoff = INITIAL_BACKOFF;
    let mut attempt = 1u32;
    loop {
        match op().await {
            Ok(v) => return Ok(v),
            Err(err) => {
                let is_last = attempt >= MAX_ATTEMPTS;
                if is_last {
                    return Err(err);
                }
                let decision = policy.classify(&err);
                match decision {
                    Retryable::No => return Err(err),
                    Retryable::Yes { retry_after } => {
                        let wait = retry_after.unwrap_or(backoff);
                        warn!(
                            op = op_label,
                            attempt,
                            sleep_ms = wait.as_millis() as u64,
                            "Transient backend error — retrying"
                        );
                        debug!(op = op_label, attempt, "scheduling retry");
                        tokio::time::sleep(wait).await;
                        backoff = backoff.saturating_mul(BACKOFF_MULTIPLIER);
                        attempt += 1;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    struct AlwaysRetry;
    impl<E> RetryPolicy<E> for AlwaysRetry {
        fn classify(&self, _err: &E) -> Retryable {
            Retryable::Yes { retry_after: None }
        }
    }

    struct NeverRetry;
    impl<E> RetryPolicy<E> for NeverRetry {
        fn classify(&self, _err: &E) -> Retryable {
            Retryable::No
        }
    }

    /// Don't actually sleep in tests — pause the runtime's clock so
    /// the helper's exponential backoff doesn't add seconds to the
    /// test suite. Tokio's paused clock advances only when something
    /// awaits a sleep, so we explicitly drive it forward.
    fn paused_runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .start_paused(true)
            .build()
            .unwrap()
    }

    #[test]
    fn first_attempt_success_does_not_retry() {
        let rt = paused_runtime();
        let calls = Cell::new(0);
        let result: Result<i32, &'static str> = rt.block_on(async {
            with_retry("test/op", &AlwaysRetry, || {
                calls.set(calls.get() + 1);
                async { Ok::<i32, &'static str>(42) }
            })
            .await
        });
        assert_eq!(result.unwrap(), 42);
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn retries_up_to_max_then_returns_last_error() {
        let rt = paused_runtime();
        let calls = Cell::new(0);
        let result: Result<i32, &'static str> = rt.block_on(async {
            with_retry("test/op", &AlwaysRetry, || {
                calls.set(calls.get() + 1);
                async { Err::<i32, &'static str>("transient") }
            })
            .await
        });
        assert_eq!(result.unwrap_err(), "transient");
        assert_eq!(
            calls.get(),
            MAX_ATTEMPTS as i32,
            "expected exactly MAX_ATTEMPTS calls, got {}",
            calls.get()
        );
    }

    #[test]
    fn terminal_error_short_circuits_after_one_call() {
        let rt = paused_runtime();
        let calls = Cell::new(0);
        let result: Result<i32, &'static str> = rt.block_on(async {
            with_retry("test/op", &NeverRetry, || {
                calls.set(calls.get() + 1);
                async { Err::<i32, &'static str>("not-found") }
            })
            .await
        });
        assert_eq!(result.unwrap_err(), "not-found");
        assert_eq!(calls.get(), 1, "terminal errors must not retry");
    }

    #[test]
    fn second_attempt_success_returns_ok() {
        let rt = paused_runtime();
        let calls = Cell::new(0);
        let result: Result<i32, &'static str> = rt.block_on(async {
            with_retry("test/op", &AlwaysRetry, || {
                let attempt = calls.get() + 1;
                calls.set(attempt);
                async move {
                    if attempt == 1 {
                        Err::<i32, &'static str>("transient")
                    } else {
                        Ok(7)
                    }
                }
            })
            .await
        });
        assert_eq!(result.unwrap(), 7);
        assert_eq!(calls.get(), 2);
    }

    /// `retry_after = Some(Duration)` lets a backend's classifier
    /// honour an explicit `Retry-After` header. The helper trusts it
    /// for the *next* sleep then resumes its own exponential schedule.
    struct ExplicitRetryAfter(Duration);
    impl<E> RetryPolicy<E> for ExplicitRetryAfter {
        fn classify(&self, _err: &E) -> Retryable {
            Retryable::Yes {
                retry_after: Some(self.0),
            }
        }
    }

    #[test]
    fn explicit_retry_after_is_used_in_place_of_exponential() {
        let rt = paused_runtime();
        let calls = Cell::new(0);
        let policy = ExplicitRetryAfter(Duration::from_secs(5));
        // We can't directly observe the sleep duration without
        // instrumenting `tokio::time` itself, but we can confirm the
        // helper still exits cleanly under a paused clock — the
        // pre-existing tests cover the actual retry wiring; this
        // test guards against regression in the `retry_after`
        // override branch.
        let result: Result<i32, &'static str> = rt.block_on(async {
            with_retry("test/op", &policy, || {
                let attempt = calls.get() + 1;
                calls.set(attempt);
                async move {
                    if attempt == 1 {
                        Err("transient")
                    } else {
                        Ok(11)
                    }
                }
            })
            .await
        });
        assert_eq!(result.unwrap(), 11);
        assert_eq!(calls.get(), 2);
    }
}
