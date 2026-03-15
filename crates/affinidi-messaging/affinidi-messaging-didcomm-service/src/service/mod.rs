mod listener;
mod mediator;
mod restart;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::config::{DIDCommServiceConfig, ListenerConfig};
use crate::error::DIDCommServiceError;
use crate::handler::DIDCommHandler;

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

    async fn spawn_listener(&self, config: ListenerConfig) -> Result<(), DIDCommServiceError> {
        let listener_id = config.id.clone();
        let listener_token = self.shutdown.child_token();
        let handler = self.handler.clone();
        let restart_count = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let restart_count_clone = restart_count.clone();
        let token_clone = listener_token.clone();

        let task = tokio::spawn(async move {
            let mut listener = listener::Listener::new(config, handler, token_clone);
            listener.run_with_restart(restart_count_clone).await;
        });

        let handle = ListenerHandle {
            id: listener_id.clone(),
            task,
            token: listener_token,
            started_at: Instant::now(),
            restart_count,
        };

        self.listeners.write().await.insert(listener_id, handle);
        Ok(())
    }
}
