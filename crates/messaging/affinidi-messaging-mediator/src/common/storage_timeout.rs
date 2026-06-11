//! Bounded request-path storage calls.
//!
//! A storage call made while *admitting* or *validating* an inbound request
//! (e.g. the forward-queue-depth admission check, or the `/readyz` probe)
//! must not hang: a stalled backend would tie up the request, and client
//! retries would amplify the load.
//!
//! The production Redis backend already caps every command at
//! `[database] database_timeout` (the request path only ever uses the
//! response-timeout connection; the un-timed connection is reserved for
//! background blocking reads). This helper makes that bound **explicit,
//! configurable, and backend-agnostic** for the request-validation path —
//! it also covers in-process backends (Fjall/Memory) and any future
//! backend without its own command timeout. On expiry it returns a clean
//! `DatabaseError` (HTTP 503 / `me.res.storage.timeout`) instead of
//! hanging.

use std::future::Future;
use std::time::Duration;

use affinidi_messaging_mediator_common::errors::MediatorError;

use crate::common::error_codes;

/// Run a request-path storage future under `timeout`, returning a
/// `DatabaseError` if it does not complete in time.
///
/// `op` names the operation (for the log line); `session_id` threads the
/// caller's session through to the error so it is traceable (`"NA"` where
/// there is no session, e.g. the readiness probe).
pub async fn with_storage_timeout<T, F>(
    timeout: Duration,
    op: &str,
    session_id: &str,
    fut: F,
) -> Result<T, MediatorError>
where
    F: Future<Output = Result<T, MediatorError>>,
{
    match tokio::time::timeout(timeout, fut).await {
        Ok(result) => result,
        Err(_) => Err(MediatorError::DatabaseError(
            error_codes::DB_OPERATION_ERROR,
            session_id.to_string(),
            format!(
                "storage operation '{op}' timed out after {}s",
                timeout.as_secs()
            ),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test(start_paused = true)]
    async fn returns_value_when_inner_completes_in_time() {
        let out: Result<u8, MediatorError> =
            with_storage_timeout(Duration::from_secs(5), "noop", "NA", async { Ok(7u8) }).await;
        assert_eq!(out.unwrap(), 7);
    }

    #[tokio::test(start_paused = true)]
    async fn maps_a_hung_call_to_a_database_error() {
        // A future that never resolves stands in for a wedged backend.
        let never = std::future::pending::<Result<(), MediatorError>>();
        let fut =
            with_storage_timeout(Duration::from_secs(5), "forward_queue_len", "sess-1", never);
        tokio::pin!(fut);

        // Before the timeout elapses the call is still pending.
        assert!(
            futures_poll_pending(&mut fut).await,
            "should not resolve before the timeout"
        );

        // Advancing past the timeout yields a 503 DatabaseError, not a hang.
        tokio::time::advance(Duration::from_secs(6)).await;
        match fut.await {
            Err(MediatorError::DatabaseError(_, session, msg)) => {
                assert_eq!(session, "sess-1");
                assert!(msg.contains("forward_queue_len"), "msg was: {msg}");
                assert!(msg.contains("timed out"), "msg was: {msg}");
            }
            other => panic!("expected DatabaseError, got {other:?}"),
        }
    }

    /// Poll a pinned future once; return `true` if it is still pending.
    async fn futures_poll_pending<F: Future>(fut: &mut std::pin::Pin<&mut F>) -> bool {
        std::future::poll_fn(|cx| {
            let pending = fut.as_mut().poll(cx).is_pending();
            std::task::Poll::Ready(pending)
        })
        .await
    }
}
