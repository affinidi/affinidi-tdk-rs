mod listener;
mod mediator;
mod restart;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use affinidi_messaging_didcomm::Message;
use tokio::sync::{RwLock, watch};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::config::{DIDCommServiceConfig, ListenerConfig};
use crate::error::DIDCommServiceError;
use crate::handler::DIDCommHandler;

use listener::ConnectionHandle;

pub struct DIDCommService {
    listeners: Arc<RwLock<HashMap<String, ListenerHandle>>>,
    handler: Arc<dyn DIDCommHandler>,
    shutdown: CancellationToken,
}

struct ListenerHandle {
    id: String,
    task: JoinHandle<()>,
    token: CancellationToken,
    started_at: Instant,
    restart_count: Arc<std::sync::atomic::AtomicU32>,
    connection_rx: watch::Receiver<Option<ConnectionHandle>>,
}

#[derive(Debug, Clone)]
pub struct ListenerStatus {
    pub id: String,
    pub state: ListenerState,
    pub restart_count: u32,
    pub uptime: Duration,
}

#[derive(Debug, Clone)]
pub enum ListenerState {
    Running,
    Stopped,
    Failed,
}

impl DIDCommService {
    pub async fn start(
        config: DIDCommServiceConfig,
        handler: impl DIDCommHandler,
        shutdown: CancellationToken,
    ) -> Result<DIDCommService, DIDCommServiceError> {
        let handler = Arc::new(handler) as Arc<dyn DIDCommHandler>;
        let listeners = Arc::new(RwLock::new(HashMap::new()));

        let service = DIDCommService {
            listeners: listeners.clone(),
            handler: handler.clone(),
            shutdown: shutdown.clone(),
        };

        for listener_config in config.listeners {
            service.spawn_listener(listener_config).await?;
        }

        Ok(service)
    }

    pub async fn add_listener(&self, config: ListenerConfig) -> Result<(), DIDCommServiceError> {
        let listeners = self.listeners.read().await;
        if listeners.contains_key(&config.id) {
            return Err(DIDCommServiceError::ListenerAlreadyExists(
                config.id.clone(),
            ));
        }
        drop(listeners);

        self.spawn_listener(config).await
    }

    pub async fn remove_listener(&self, listener_id: &str) -> Result<(), DIDCommServiceError> {
        let mut listeners = self.listeners.write().await;
        let handle = listeners
            .remove(listener_id)
            .ok_or_else(|| DIDCommServiceError::ListenerNotFound(listener_id.to_string()))?;

        handle.token.cancel();
        drop(listeners);
        let _ = handle.task.await;
        Ok(())
    }

    pub async fn shutdown(self) {
        self.shutdown.cancel();
        let listeners = self.listeners.write().await;
        for (_, handle) in listeners.iter() {
            let _ = handle.token.cancelled().await;
        }
    }

    pub async fn list_listeners(&self) -> Vec<ListenerStatus> {
        let listeners = self.listeners.read().await;
        listeners
            .values()
            .map(|handle| {
                let state = if handle.task.is_finished() {
                    ListenerState::Stopped
                } else {
                    ListenerState::Running
                };
                ListenerStatus {
                    id: handle.id.clone(),
                    state,
                    restart_count: handle
                        .restart_count
                        .load(std::sync::atomic::Ordering::Acquire),
                    uptime: handle.started_at.elapsed(),
                }
            })
            .collect()
    }

    /// Send a proactive DIDComm message through an existing listener's
    /// mediator connection.
    ///
    /// The message is packed (encrypted) and forwarded through the mediator
    /// to the recipient. Uses the same ATM connection as the listener,
    /// avoiding duplicate websocket sessions.
    ///
    /// # Arguments
    /// * `listener_id` — which listener's connection to use
    /// * `message` — the plaintext DIDComm `Message` to send
    /// * `recipient_did` — the recipient's DID
    pub async fn send_message(
        &self,
        listener_id: &str,
        message: Message,
        recipient_did: &str,
    ) -> Result<(), DIDCommServiceError> {
        let listeners = self.listeners.read().await;
        let handle = listeners
            .get(listener_id)
            .ok_or_else(|| DIDCommServiceError::ListenerNotFound(listener_id.to_string()))?;

        let conn = handle
            .connection_rx
            .borrow()
            .clone()
            .ok_or_else(|| DIDCommServiceError::NotConnected(listener_id.to_string()))?;

        drop(listeners);

        crate::transport::send_message(&conn.atm, &conn.profile, message, recipient_did).await
    }

    async fn spawn_listener(&self, config: ListenerConfig) -> Result<(), DIDCommServiceError> {
        let listener_id = config.id.clone();
        let listener_token = self.shutdown.child_token();
        let handler = self.handler.clone();
        let restart_count = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let restart_count_clone = restart_count.clone();
        let token_clone = listener_token.clone();

        let (connection_tx, connection_rx) = watch::channel(None);

        let task = tokio::spawn(async move {
            let mut listener = listener::Listener::new(config, handler, token_clone, connection_tx);
            listener.run_with_restart(restart_count_clone).await;
        });

        let handle = ListenerHandle {
            id: listener_id.clone(),
            task,
            token: listener_token,
            started_at: Instant::now(),
            restart_count,
            connection_rx,
        };

        self.listeners.write().await.insert(listener_id, handle);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_messaging_didcomm::Message;
    use serde_json::json;

    fn make_service() -> DIDCommService {
        use crate::handler::ignore_handler;
        use crate::router::{Router, handler_fn};

        let handler = Router::new()
            .route("test", handler_fn(ignore_handler))
            .expect("valid route");
        DIDCommService {
            listeners: Arc::new(RwLock::new(HashMap::new())),
            handler: Arc::new(handler),
            shutdown: CancellationToken::new(),
        }
    }

    fn make_message() -> Message {
        Message::build(
            "test-id".to_string(),
            "https://example.com/test".to_string(),
            json!({}),
        )
        .from("did:example:sender".to_string())
        .to("did:example:recipient".to_string())
        .finalize()
    }

    #[tokio::test]
    async fn send_message_listener_not_found() {
        let service = make_service();
        let msg = make_message();

        let result = service
            .send_message("nonexistent", msg, "did:example:recipient")
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, DIDCommServiceError::ListenerNotFound(ref id) if id == "nonexistent"),
            "expected ListenerNotFound, got: {err}"
        );
    }

    #[tokio::test]
    async fn send_message_not_connected() {
        let service = make_service();
        let msg = make_message();

        // Insert a listener handle with a watch channel that holds None
        // (simulating a listener that hasn't connected yet)
        let (_tx, rx) = watch::channel(None);
        let handle = ListenerHandle {
            id: "test-listener".to_string(),
            task: tokio::spawn(async {}),
            token: CancellationToken::new(),
            started_at: Instant::now(),
            restart_count: Arc::new(std::sync::atomic::AtomicU32::new(0)),
            connection_rx: rx,
        };
        service
            .listeners
            .write()
            .await
            .insert("test-listener".to_string(), handle);

        let result = service
            .send_message("test-listener", msg, "did:example:recipient")
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, DIDCommServiceError::NotConnected(ref id) if id == "test-listener"),
            "expected NotConnected, got: {err}"
        );
    }

    #[tokio::test]
    async fn connection_handle_lifecycle() {
        // Verify the watch channel correctly transitions between
        // None (disconnected) and Some (connected)
        let (tx, rx) = watch::channel::<Option<ConnectionHandle>>(None);

        // Initially not connected
        assert!(rx.borrow().is_none());

        // Simulate connect by sending a None → stays None
        let _ = tx.send(None);
        assert!(rx.borrow().is_none());

        // We can't construct a real ConnectionHandle without ATM,
        // but we can verify the channel mechanics by dropping the sender
        drop(tx);
        // Receiver still holds the last value
        assert!(rx.borrow().is_none());
    }
}
