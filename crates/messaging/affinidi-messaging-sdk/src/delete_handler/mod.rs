/*!
 * This module contains the implementation of the delete handler.
 *
 * A task that runs deleting messages in the background.
 * This provides a performant way to delete messages without blocking the main thread.
 *
 * Messages can still be deleted from the main thread where you may want direct control.
 *
 * A deletion message is sent to the deletionthread, containing the profile and the message ID.
 * The deletion thread then deletes the message from the profile, using whatever transport method is required.
 *
 */

use crate::{
    ATM, SharedState, errors::ATMError, messages::DeleteMessageRequest, profiles::ATMProfile,
};
use affinidi_task_utils::{CancellationToken, TaskSupervisor};
use std::sync::Arc;
use tokio::{
    select,
    sync::{
        Mutex,
        mpsc::{Receiver, Sender},
    },
    task::JoinHandle,
};
use tracing::{Instrument, Level, debug, span};

pub enum DeletionHandlerCommands {
    DeleteMessage(Arc<ATMProfile>, String),
    Exit,
}

impl ATM {
    /// Starts the Deletion Handler under the shared [`TaskSupervisor`].
    ///
    /// A panic or error in the handler is detected and the task is restarted
    /// with capped backoff (it is non-load-bearing — a wedged deletion loop
    /// must never take the SDK down), rather than silently dying and leaving
    /// background deletions unprocessed for the life of the process.
    ///
    /// The returned `JoinHandle` completes when the handler's shutdown token
    /// is cancelled (see [`abort_deletion_handler`](Self::abort_deletion_handler)).
    pub async fn start_deletion_handler(
        &self,
        from_sdk: Receiver<DeletionHandlerCommands>,
        to_sdk: Sender<DeletionHandlerCommands>,
    ) -> Result<JoinHandle<()>, ATMError> {
        let shared_state = self.inner.clone();
        let shutdown = self.inner.deletion_shutdown.clone();

        // The SDK→handler receiver isn't clonable, so share it behind a Mutex
        // and re-lock it on each (re)start.
        let from_sdk = Arc::new(Mutex::new(from_sdk));

        TaskSupervisor::new(shutdown.clone()).spawn("deletion_handler", false, move || {
            let shared_state = shared_state.clone();
            let from_sdk = from_sdk.clone();
            let to_sdk = to_sdk.clone();
            let shutdown = shutdown.clone();
            async move {
                let mut from_sdk = from_sdk.lock().await;
                ATM::deletion_handler(shared_state, &mut from_sdk, to_sdk, shutdown).await
            }
        });

        debug!("Deletion handler started (supervised)");

        // Preserve the historical `JoinHandle<()>` contract: the handle
        // completes once the handler is shut down.
        let shutdown = self.inner.deletion_shutdown.clone();
        Ok(tokio::spawn(async move {
            shutdown.cancelled().await;
        }))
    }

    /// Close the Deletion task gracefully by cancelling its shutdown token.
    /// The supervisor stops the handler (no restart) and the handler sends a
    /// final `Exit` back to the SDK.
    pub async fn abort_deletion_handler(&self) -> Result<(), ATMError> {
        self.inner.deletion_shutdown.cancel();
        Ok(())
    }

    pub(crate) async fn deletion_handler(
        shared_state: Arc<SharedState>,
        from_sdk: &mut Receiver<DeletionHandlerCommands>,
        to_sdk: Sender<DeletionHandlerCommands>,
        shutdown: CancellationToken,
    ) -> Result<(), ATMError> {
        let _span = span!(Level::INFO, "deletion_handler");
        async move {
            let atm = ATM {
                inner: shared_state,
            };
            loop {
                select! {
                    _ = shutdown.cancelled() => {
                        break;
                    }
                    value = from_sdk.recv() => {
                        match value {
                            Some(DeletionHandlerCommands::DeleteMessage(profile, message_id)) => {
                                let _ = atm.delete_messages_direct(&profile, &DeleteMessageRequest { message_ids: vec![message_id.clone()] }).await;
                            }
                            Some(DeletionHandlerCommands::Exit) | None => {
                                // Intentional stop: cancel so the supervisor
                                // records the task stopped rather than restarting it.
                                shutdown.cancel();
                                break;
                            }
                        }
                    }
                }
            }

            debug!("Deletion handler stopped");
            let _ = to_sdk.send(DeletionHandlerCommands::Exit).await;
            Ok(())
        }
        .instrument(_span)
        .await
    }
}

#[cfg(test)]
mod tests {
    use affinidi_task_utils::{CancellationToken, ComponentState, TaskSupervisor};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Duration;
    use tokio::sync::{Mutex, mpsc};

    /// A panic in the supervised deletion handler must be caught and the task
    /// restarted (it would otherwise die silently, leaving background
    /// deletions unprocessed for the life of the process), with the fault
    /// recorded. Mirrors `start_deletion_handler`'s wiring — the SDK→handler
    /// receiver shared behind a `Mutex` and re-locked per (re)start — with an
    /// injected panic, and confirms cancellation stops it without restart.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn supervised_deletion_handler_restarts_after_panic() {
        let (_tx, rx) = mpsc::channel::<u8>(4);
        let rx = Arc::new(Mutex::new(rx));
        let supervisor = TaskSupervisor::new(CancellationToken::new());
        let registry = supervisor.registry();
        let attempts = Arc::new(AtomicU32::new(0));

        {
            let rx = rx.clone();
            let attempts = attempts.clone();
            supervisor.spawn("deletion_handler", false, move || {
                let rx = rx.clone();
                let attempts = attempts.clone();
                async move {
                    // Re-lock the shared receiver across restarts.
                    let _guard = rx.lock().await;
                    if attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                        panic!("injected deletion-handler panic");
                    }
                    std::future::pending::<()>().await; // stay Running until cancel
                    Ok::<(), crate::errors::ATMError>(())
                }
            });
        }

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let restarted = attempts.load(Ordering::SeqCst) >= 2;
            let running = registry
                .get("deletion_handler")
                .map(|h| h.state == ComponentState::Running && h.restarts >= 1)
                .unwrap_or(false);
            if restarted && running {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "supervisor did not restart the deletion handler after a panic"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(
            registry
                .get("deletion_handler")
                .and_then(|h| h.last_error.clone())
                .is_some_and(|e| e.contains("panicked")),
            "the panic must be recorded as the last error"
        );
    }
}
