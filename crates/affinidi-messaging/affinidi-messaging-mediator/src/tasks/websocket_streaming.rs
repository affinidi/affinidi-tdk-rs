/*!
 A task that listens for messages on a Redis pub/sub channel and sends them to clients over a websocket.

 It will maintain a HashSet of channels based on the DID hash. As a result, if duplicate websockets
 are created for the same DID, only the most recent one will receive messages as the older websocket
 channel will be forcibly closed.

 Any status on the existing websocket channel for a DID will need to be reset on the new channel.

*/
use crate::database::Database;
use affinidi_messaging_mediator_common::errors::MediatorError;
use ahash::AHashMap as HashMap;
use redis::aio::PubSub;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::{select, sync::mpsc, task::JoinHandle, time::sleep};
use tokio_stream::StreamExt;
use tracing::{Instrument, Level, debug, error, info, span, warn};

// Useful links on redis pub/sub in Rust:
// https://github.com/redis-rs/redis-rs/issues/509

/// Used when updating the streaming state.
/// Register: Creates the hash map entry for the DID hash and TX Channel
/// Start: Start streaming messages to clients.
/// Stop: Stop streaming messages to clients.
/// Deregister: Remove the hash map entry for the DID hash.
pub enum StreamingUpdateState {
    Register(mpsc::Sender<WebSocketCommands>),
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

/// This is the format of the JSON message that is sent to the pub/sub channel.
/// did_hash : SHA256 hash of the DID
/// message : The message to send to the client
/// force_delivery : If true, the message will be sent to the client even if they are not active.
///
/// NOTE: The force_delivery is required as when changing live_delivery status, standard says to send a status message
#[derive(Serialize, Deserialize, Debug)]
pub struct PubSubRecord {
    pub did_hash: String,
    pub message: String,
    pub force_delivery: bool,
}

impl StreamingTask {
    /// Creates the streaming task handler
    pub async fn new(
        database: Database,
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
                        .expect("Error starting websocket_streaming thread");
                })
            };

            Ok((task, handle))
        }
        .instrument(_span)
        .await
    }

    /// Starts a pubsub connection to Redis and subscribes to a channel.
    /// Useful way to restart a terminated connection from within a loop.
    async fn _start_pubsub(&self, database: Database, uuid: &str) -> Result<PubSub, MediatorError> {
        let _span = span!(Level::INFO, "_start_pubsub");

        async move {
            let mut pubsub = database.0.get_pubsub_connection().await?;

            let channel = format!("CHANNEL:{}", uuid);
            pubsub.subscribe(channel.clone()).await.map_err(|err| {
                error!("Error subscribing to channel: {}", err);
                MediatorError::DatabaseError(
                    "NA".into(),
                    format!("Error subscribing to channel: {}", err),
                )
            })?;

            info!("Subscribed to channel: {}", channel);
            Ok(pubsub)
        }
        .instrument(_span)
        .await
    }

    /// Streams messages to subscribed clients over websocket.
    /// Is spawned as a task
    async fn ws_streaming_task(
        self,
        database: Database,
        channel: &mut mpsc::Receiver<StreamingUpdate>,
    ) -> Result<(), MediatorError> {
        let _span = span!(Level::INFO, "ws_streaming_task", uuid = &self.uuid);

        async move {
            debug!("Starting...");

            // Clean up any existing sessions left over from previous runs
            database.streaming_clean_start(&self.uuid).await?;

            // Create a hashmap to store the clients and if they are active (true = yes)
            let mut clients: HashMap<String, (mpsc::Sender<WebSocketCommands>, bool)> = HashMap::new();

            // Start streaming messages to clients
            let mut pubsub = self._start_pubsub(database.clone(), &self.uuid).await?;
            loop {
                let mut stream = pubsub.on_message();

                // Listen for an update on either the redis pubsub stream, or the command channel
                // stream: redis pubsub of incoming messages destined for a client
                // channel: command channel to start/stop streaming for a client
                select! {
                    value = stream.next() => { // redis pubsub
                        if let Some(msg) = value {
                            if let Ok(payload) = msg.get_payload::<String>() {
                                let payload: PubSubRecord = serde_json::from_str(&payload).unwrap();

                                // Find the MPSC transmit channel for the associated DID hash
                                match clients.get(&payload.did_hash) { Some((tx, active)) => {
                                    if payload.force_delivery ||  *active {
                                        // Send the message to the client
                                        match tx.send(WebSocketCommands::Message(payload.message.clone())).await { Err(err) => {
                                            error!("Error sending message to client ({}): {}", payload.did_hash, err);
                                        } _ => {
                                            info!("Sent message to client ({})", payload.did_hash);
                                        }}
                                    } else {
                                        warn!("pub/sub msg received for did_hash({}) but it is not active", payload.did_hash);
                                        if let Err(err) = database.streaming_stop_live(&payload.did_hash, &self.uuid).await {
                                            error!("Error stopping streaming for client ({}): {}", payload.did_hash, err);
                                        }
                                    }
                                } _ => {
                                    warn!("pub/sub msg received for did_hash({}) but it doesn't exist in clients HashMap", payload.did_hash);
                                }}

                            } else {
                                error!("Error getting payload from message");
                                continue;
                            };
                        } else {
                            // Redis connection dropped, need to retry
                            error!("Redis connection dropped, retrying...");
                            drop(stream);

                            pubsub = loop {
                                sleep(Duration::from_secs(1)).await;
                                match self._start_pubsub(database.clone(), &self.uuid).await {
                                    Ok(pubsub) => break pubsub,
                                    Err(err) => {
                                        error!("Error starting pubsub: {}", err);
                                        continue;
                                    }
                                }
                            }
                        }
                    }
                    value = channel.recv() => { // mpsc command channel
                        if let Some(value) = &value {
                            match &value.state {
                                StreamingUpdateState::Register(client_tx) => {
                                    self._handle_registration(&database, &mut clients, value, client_tx).await;
                                },
                                StreamingUpdateState::Start => {
                                    if let Some((_, active)) = clients.get_mut(&value.did_hash) {
                                        info!("Starting streaming for DID: ({})", value.did_hash);
                                        *active = true;
                                    };

                                    if let Err(err) = database.streaming_start_live(&value.did_hash, &self.uuid).await {
                                        error!("Error starting streaming to client ({}) streaming: {}",value.did_hash, err);
                                    }
                                },
                                StreamingUpdateState::Stop => {
                                    // Set active to false
                                    if let Some((_, active)) = clients.get_mut(&value.did_hash) {
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

    /// Helper function to handle the registration of a new client.
    /// Handles if this is a duplicate channel for a DID
    async fn _handle_registration(
        &self,
        database: &Database,
        clients: &mut HashMap<String, (mpsc::Sender<WebSocketCommands>, bool)>,
        value: &StreamingUpdate,
        client_tx: &mpsc::Sender<WebSocketCommands>,
    ) {
        if let Some((channel, _)) = clients.get(&value.did_hash) {
            debug!("Duplicate WebSocket channel detected");
            // Channel already exists, close the old one
            let _ = channel.send(WebSocketCommands::Close).await;
            debug!("Sent close WebSocket command to old channel");
        }

        info!(
            "Registered streaming for DID: ({}) registered_clients({})",
            value.did_hash,
            clients.len() + 1
        );
        clients.insert(value.did_hash.clone(), (client_tx.clone(), false));

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
