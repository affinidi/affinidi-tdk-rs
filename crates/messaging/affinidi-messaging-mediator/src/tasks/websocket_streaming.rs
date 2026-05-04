/*!
 A task that listens for streaming notifications from the storage
 backend and sends them to clients over a websocket.

 It maintains a HashMap of channels keyed by DID hash. If a duplicate
 WebSocket is opened for the same DID the older session is forcibly
 closed so only the most recent one receives messages.

 The notification stream comes from `MediatorStore::streaming_subscribe`,
 so the task runs unchanged whether the backend is Redis pub/sub,
 Fjall's in-process broadcast, or the test MemoryStore.
*/
use affinidi_messaging_mediator_common::{
    errors::MediatorError,
    store::{MediatorStore, types::PubSubRecord},
};
use ahash::AHashMap as HashMap;
use std::{sync::Arc, time::Duration};
use tokio::{
    select,
    sync::{broadcast, mpsc},
    task::JoinHandle,
    time::sleep,
};
use tracing::{Instrument, Level, debug, error, info, span, warn};

/// Used when updating the streaming state.
/// Register: Creates the hash map entry for the DID hash and TX Channel
/// Start: Start streaming messages to clients.
/// Stop: Stop streaming messages to clients.
/// Deregister: Remove the hash map entry for the DID hash.
pub enum StreamingUpdateState {
    Register {
        channel: mpsc::Sender<WebSocketCommands>,
        session_id: String,
        did: String,
    },
    Start,
    Stop,
    Deregister,
}

/// Used to send commands from the streaming task to the websocket handler
pub enum WebSocketCommands {
    Message(String), // Send a message to the client
    Close,           // Close the websocket connection
}

/// Used to update the streaming state.
/// did_hash: The DID hash to update the state for.
/// state: The state to update to.
pub struct StreamingUpdate {
    pub did_hash: String,
    pub state: StreamingUpdateState,
}

#[derive(Clone)]
pub struct StreamingTask {
    pub uuid: String,
    pub channel: mpsc::Sender<StreamingUpdate>,
}

impl StreamingTask {
    /// Creates the streaming task handler
    pub async fn new(
        database: Arc<dyn MediatorStore>,
        mediator_uuid: &str,
    ) -> Result<(Self, JoinHandle<()>), MediatorError> {
        let _span = span!(Level::INFO, "StreamingTask::new");

        async move {
            // Create the inter-task channel - allows up to 10 queued messages
            let (tx, mut rx) = mpsc::channel(10);
            let task = StreamingTask {
                channel: tx.clone(),
                uuid: mediator_uuid.to_string(),
            };

            // Start the streaming task
            // With it's own clone of required data
            let handle = {
                let _task = task.clone();
                tokio::spawn(async move {
                    _task
                        .ws_streaming_task(database, &mut rx)
                        .await
                        .unwrap_or_else(|e| {
                            error!("websocket_streaming thread failed: {e}");
                        });
                })
            };

            Ok((task, handle))
        }
        .instrument(_span)
        .await
    }

    /// Streams messages to subscribed clients over websocket.
    /// Is spawned as a task
    async fn ws_streaming_task(
        self,
        database: Arc<dyn MediatorStore>,
        channel: &mut mpsc::Receiver<StreamingUpdate>,
    ) -> Result<(), MediatorError> {
        let _span = span!(Level::INFO, "ws_streaming_task", uuid = &self.uuid);

        async move {
            info!("WebSocket streaming task starting");

            // Clean up any existing sessions left over from previous runs
            database.streaming_clean_start(&self.uuid).await?;

            // Create a hashmap to store the clients and if they are active (true = yes)
            // Key: did_hash, Value: (channel, session_id, live_delivery_active)
            let mut clients: HashMap<String, (mpsc::Sender<WebSocketCommands>, String, bool)> =
                HashMap::new();

            // Subscribe to delivery notifications via the trait. Backends
            // are responsible for the wire-level transport (Redis pub/sub,
            // in-process broadcast, etc.) — the task just consumes
            // already-decoded `PubSubRecord`s.
            let mut rx = database.streaming_subscribe(&self.uuid).await?;

            loop {
                select! {
                    value = rx.recv() => {
                        match value {
                            Ok(payload) => {
                                self.dispatch_payload(database.as_ref(), &mut clients, payload).await;
                            }
                            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                                // Subscriber fell behind; backend's broadcast capacity
                                // was exceeded. Live messages were dropped, but the
                                // queueing path still picked them up — clients just
                                // won't get a real-time push for those entries.
                                warn!(
                                    "Streaming subscriber lagged, dropped {} live notifications",
                                    skipped
                                );
                            }
                            Err(broadcast::error::RecvError::Closed) => {
                                error!("Streaming subscription closed, attempting to resubscribe");
                                rx = loop {
                                    sleep(Duration::from_secs(1)).await;
                                    match database.streaming_subscribe(&self.uuid).await {
                                        Ok(rx) => break rx,
                                        Err(err) => {
                                            error!("Error resubscribing to streaming channel: {err}");
                                            continue;
                                        }
                                    }
                                };
                            }
                        }
                    }
                    value = channel.recv() => { // mpsc command channel
                        if let Some(value) = &value {
                            match &value.state {
                                StreamingUpdateState::Register { channel: client_tx, session_id, did } => {
                                    self._handle_registration(database.as_ref(), &mut clients, value, client_tx, session_id, did).await;
                                },
                                StreamingUpdateState::Start => {
                                    if let Some((_, _, active)) = clients.get_mut(&value.did_hash) {
                                        info!("Starting streaming for DID: ({})", value.did_hash);
                                        *active = true;
                                    };

                                    if let Err(err) = database.streaming_start_live(&value.did_hash, &self.uuid).await {
                                        error!("Error starting streaming to client ({}) streaming: {}",value.did_hash, err);
                                    }
                                },
                                StreamingUpdateState::Stop => {
                                    // Set active to false
                                    if let Some((_, _, active)) = clients.get_mut(&value.did_hash) {
                                        info!("Stopping streaming for DID: ({})", value.did_hash);
                                        *active = false;
                                    };

                                    if let Err(err) = database.streaming_stop_live(&value.did_hash, &self.uuid).await {
                                        error!("Error stopping streaming for client ({}): {}",value.did_hash, err);
                                    }
                                },
                                StreamingUpdateState::Deregister => {
                                    let count = if !clients.is_empty() {
                                        clients.len() - 1
                                    } else {
                                        warn!("Duplicate websocket channels has us off by one");
                                        0
                                    };
                                    info!("Deregistered streaming for DID: ({}) registered_clients({})", value.did_hash, count);
                                    if let Err(err) = database.streaming_deregister_client(&value.did_hash, &self.uuid).await {
                                        error!("Error stopping streaming for client ({}): {}",value.did_hash, err);
                                    }
                                    clients.remove(value.did_hash.as_str());
                                }
                            }
                        }
                    }
                }
            }
        }
        .instrument(_span)
        .await
    }

    /// Forward one streaming notification to the WebSocket sender for
    /// its target DID, dropping clients whose channels have closed.
    async fn dispatch_payload(
        &self,
        database: &dyn MediatorStore,
        clients: &mut HashMap<String, (mpsc::Sender<WebSocketCommands>, String, bool)>,
        payload: PubSubRecord,
    ) {
        match clients.get(&payload.did_hash) {
            Some((tx, _, active)) => {
                if payload.force_delivery || *active {
                    if let Err(err) = tx
                        .send(WebSocketCommands::Message(payload.message.clone()))
                        .await
                    {
                        warn!(
                            "Dead WebSocket channel for ({}), cleaning up: {}",
                            payload.did_hash, err
                        );
                        clients.remove(&payload.did_hash);
                        if let Err(e) = database
                            .streaming_deregister_client(&payload.did_hash, &self.uuid)
                            .await
                        {
                            error!(
                                "Error deregistering dead client ({}): {}",
                                payload.did_hash, e
                            );
                        }
                    } else {
                        debug!("Sent message to client ({})", payload.did_hash);
                    }
                } else {
                    debug!(
                        "pub/sub msg received for did_hash({}) but it is not active",
                        payload.did_hash
                    );
                    if let Err(err) = database
                        .streaming_stop_live(&payload.did_hash, &self.uuid)
                        .await
                    {
                        error!(
                            "Error stopping streaming for client ({}): {}",
                            payload.did_hash, err
                        );
                    }
                }
            }
            None => {
                warn!(
                    "pub/sub msg received for did_hash({}) but it doesn't exist in clients HashMap",
                    payload.did_hash
                );
            }
        }
    }

    /// Helper function to handle the registration of a new client.
    /// Handles if this is a duplicate channel for a DID
    async fn _handle_registration(
        &self,
        database: &dyn MediatorStore,
        clients: &mut HashMap<String, (mpsc::Sender<WebSocketCommands>, String, bool)>,
        value: &StreamingUpdate,
        client_tx: &mpsc::Sender<WebSocketCommands>,
        new_session_id: &str,
        did: &str,
    ) {
        // Defensive guard: an empty `did` means the upstream session
        // arrived without an authenticated DID populated. Registering
        // it would index this client under
        // `did_hash = sha256("") = e3b0c44...` and silently misroute
        // every subsequent message. Refuse and log loudly so the
        // upstream auth bug surfaces immediately.
        if did.is_empty() || value.did_hash.is_empty() {
            error!(
                session = new_session_id,
                did_hash = %value.did_hash,
                "Refusing to register streaming client with empty DID — \
                 the upstream session is missing its authenticated DID. \
                 Closing the channel."
            );
            let _ = client_tx.send(WebSocketCommands::Close).await;
            return;
        }

        if let Some((channel, old_session_id, _)) = clients.get(&value.did_hash) {
            warn!(
                did = did,
                old_session = old_session_id,
                new_session = new_session_id,
                "Duplicate WebSocket connection: closing old session in favour of new one",
            );
            // Channel already exists, close the old one
            let _ = channel.send(WebSocketCommands::Close).await;
        }

        info!(
            did = did,
            session = new_session_id,
            "Registered streaming for DID: ({}) registered_clients({})",
            value.did_hash,
            clients.len() + 1
        );
        clients.insert(
            value.did_hash.clone(),
            (client_tx.clone(), new_session_id.to_string(), false),
        );

        if let Err(err) = database
            .streaming_register_client(&value.did_hash, &self.uuid)
            .await
        {
            error!(
                "Error starting streaming to client ({}) streaming: {}",
                value.did_hash, err
            );
        }
    }
}
