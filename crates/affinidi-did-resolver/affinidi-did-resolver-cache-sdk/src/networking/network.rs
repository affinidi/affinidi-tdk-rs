//! NetworkTask handles the communication with the network.
//! This runs as a separate task in the background.
//! Allows for multiplexing of multiple requests/responses to the network.
//!
//! The SDK communicates via a MPSC channel to this task.
//! The remote server communicates via a websocket connection.
//!

use super::{WSResponseType, request_queue::RequestList};
use crate::{
    DIDCacheClient, WSRequest, config::DIDCacheConfig, errors::DIDCacheError,
    networking::utils::connect,
};
use ssi::dids::Document;
use std::{pin::Pin, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncWrite, BufReader},
    select,
    sync::{
        mpsc::{Receiver, Sender},
        oneshot,
    },
    time::{interval_at, sleep},
};
use tracing::{Instrument, Level, debug, error, info, span, warn};
#[cfg(feature = "network")]
use url::Url;
#[cfg(feature = "network")]
use web_socket::{CloseCode, DataType, Event, MessageType, WebSocket};

/// WSCommands are the commands that can be sent between the SDK and the network task
/// Connected: Signals that the websocket is connected
/// Exit: Exits the websocket handler
/// Send: Sends the response string to the websocket (Channel, ID, WSRequest)
/// ResponseReceived: Response received from the websocket
/// ErrorReceived: Error received from the remote server
/// NotFound: Response not found in the cache
/// TimeOut: SDK request timed out, contains ID and did_hash we were looking for
#[derive(Debug)]
pub(crate) enum WSCommands {
    Connected,
    Exit,
    Send(Responder, String, WSRequest),
    ResponseReceived(Box<Document>),
    ErrorReceived(String),
    TimeOut(String, [u64; 2]),
}

pub(crate) type Responder = oneshot::Sender<WSCommands>;

/// The following is to help with handling either TCP or TLS connections
pub(crate) trait ReadWrite: AsyncRead + AsyncWrite + Send {}
impl<T> ReadWrite for T where T: AsyncRead + AsyncWrite + Send {}

/// NetworkTask handles the communication with the network.
/// This runs as a separate task in the background.
///
/// sdk_tx_channel: Sender<WSCommands> - Channel to send commands to the network task from the SDK
/// sdk_rx_channel: Rc<Receiver<WSCommands>> - Channel to receive commands from the network task
/// task_rx_channel: Rc<Receiver<WSCommands>> - PRIVATE. Channel to receive commands from the SDK
/// task_tx_channel: Sender<WSCommands> - PRIVATE. Channel to send commands to the SDK
pub(crate) struct NetworkTask {
    config: DIDCacheConfig,
    service_address: String,
    cache: RequestList,
    sdk_tx: Sender<WSCommands>,
}

impl NetworkTask {
    pub async fn run(
        config: DIDCacheConfig,
        sdk_rx: &mut Receiver<WSCommands>,
        sdk_tx: &Sender<WSCommands>,
    ) -> Result<(), DIDCacheError> {
        let _span = span!(Level::INFO, "network_task");
        async move {
            debug!("Starting...");

            let service_address = if let Some(service_address) = &config.service_address {
                service_address.to_string()
            } else {
                return Err(DIDCacheError::ConfigError(
                    "Running in local mode, yet network service called!".to_string(),
                ));
            };

            let cache = RequestList::new(&config);

            let mut network_task = NetworkTask {
                config,
                service_address,
                cache,
                sdk_tx: sdk_tx.clone(),
            };

            let mut web_socket = network_task.ws_connect().await?;
            let mut watchdog = interval_at(tokio::time::Instant::now()+Duration::from_secs(20), Duration::from_secs(20));
            let mut missed_pings = 0;

            loop {
                select! {
                    _ = watchdog.tick() => {
                        let _ = web_socket.send_ping(vec![]).await;
                        if missed_pings > 2 {
                            warn!("Missed 3 pings, restarting connection");
                            let _ = web_socket.close(CloseCode::ProtocolError).await;
                            missed_pings = 0;
                            web_socket = network_task.ws_connect().await?;
                        } else {
                            missed_pings += 1;
                        }
                    }
                    value = web_socket.recv() => {
                        match value {
                            Ok(event) =>
                                match event {
                                    Event::Data { ty, data } => {
                                        let request = match ty {
                                            DataType::Complete(MessageType::Text) => String::from_utf8_lossy(&data),
                                            DataType::Complete(MessageType::Binary) => String::from_utf8_lossy(&data),
                                            DataType::Stream(_) => {
                                                warn!("Received stream - not handled");
                                                continue;
                                            }
                                        };

                                        debug!("Received DID Lookup request ({})", request);
                                        if network_task.ws_recv(request.to_string()).is_err() {
                                            // Reset the connection
                                            web_socket = network_task.ws_connect().await?;
                                        }
                                    }
                                    Event::Ping(data) => {
                                        let _ = web_socket.send_pong(data).await;
                                    }
                                    Event::Pong(..) => {
                                        missed_pings -= 1;
                                    }
                                    Event::Error(err) => {
                                        warn!("WebSocket Error: {}", err);
                                        let _ = web_socket.close(CloseCode::ProtocolError).await;
                                        web_socket = network_task.ws_connect().await?;
                                        missed_pings = 0;
                                    }
                                    Event::Close { .. } => {
                                        web_socket = network_task.ws_connect().await?;
                                        missed_pings = 0;
                                    }
                                }
                                Err(err) => {
                                    error!("Error receiving websocket message: {:?}", err);
                                    let _ = web_socket.close(CloseCode::ProtocolError).await;
                                    web_socket = network_task.ws_connect().await?;
                                    missed_pings = 0;
                                }
                            }
                    },
                    value = sdk_rx.recv(), if !network_task.cache.is_full() => {
                        if let Some(cmd) = value {
                            match cmd {
                                WSCommands::Send(channel, uid, request) => {
                                    let hash = DIDCacheClient::hash_did(&request.did);
                                    if network_task.cache.insert(hash, &uid, channel) {
                                        let _ = network_task.ws_send(&mut web_socket, &request).await;
                                    }
                                }
                                WSCommands::TimeOut(uid, did_hash) => {
                                    let _ = network_task.cache.remove(&did_hash, Some(uid));
                                }
                                WSCommands::Exit => {
                                    debug!("Exiting...");
                                    return Ok(());
                                }
                                _ => {
                                    debug!("Invalid command received: {:?}", cmd);
                                }
                            }
                        } else {
                            // MPSC Channel has closed, no real recovery can be done here
                            // exit the task
                            info!("SDK channel closed");
                            return Ok(());

                        }
                    }
                }
            }
        }
        .instrument(_span)
        .await
    }

    /// Creates the connection to the remote server via a websocket
    /// If timeouts or errors occur, it will backoff and retry
    /// NOTE: Increases in 5 second increments up to 60 seconds
    async fn ws_connect(
        &mut self,
    ) -> Result<WebSocket<BufReader<Pin<Box<dyn ReadWrite>>>>, DIDCacheError> {
        //accept_key_from(sec_ws_key);
        async fn _handle_backoff(backoff: Duration) -> Duration {
            let b = if backoff.as_secs() < 60 {
                backoff.saturating_add(Duration::from_secs(5))
            } else {
                backoff
            };

            debug!("connect backoff: {} Seconds", b.as_secs());
            sleep(b).await;
            b
        }

        let _span = span!(Level::DEBUG, "ws_connect", server = self.service_address);
        async move {
            // Connect to the DID cache server
            let mut backoff = Duration::from_secs(1);
            loop {
                debug!("Starting websocket connection");

                let timeout = tokio::time::sleep(self.config.network_timeout);
                let connection = self._create_socket();

                select! {
                    conn = connection => {
                        match conn {
                            Ok(conn) => {
                                debug!("Websocket connected");
                                self.sdk_tx.send(WSCommands::Connected).await.unwrap();
                                return Ok(conn)
                            }
                            Err(e) => {
                                error!("Error connecting to websocket: {:?}", e);
                                backoff = _handle_backoff(backoff).await;
                            }
                        }
                    }
                    _ = timeout => {
                        // Start backing off and retry
                        warn!("Connect timeout reached");
                        backoff = _handle_backoff(backoff).await;
                    }
                }
            }
        }
        .instrument(_span)
        .await
    }

    // Responsible for creating a websocket connection to the mediator
    async fn _create_socket(
        &mut self,
    ) -> Result<WebSocket<BufReader<Pin<Box<dyn ReadWrite>>>>, DIDCacheError> {
        debug!("Creating websocket connection");
        // Create a custom websocket request, turn this into a client_request
        // Allows adding custom headers later

        let url = match Url::parse(&self.service_address) {
            Ok(url) => url,
            Err(err) => {
                error!(
                    "Invalid ServiceEndpoint address {}: {}",
                    self.service_address, err
                );
                return Err(DIDCacheError::TransportError(format!(
                    "Invalid ServiceEndpoint address {}: {}",
                    self.service_address, err
                )));
            }
        };

        let web_socket = match connect(&url).await {
            Ok(web_socket) => web_socket,
            Err(err) => {
                warn!("WebSocket failed. Reason: {}", err);
                return Err(DIDCacheError::TransportError(format!(
                    "Websocket connection failed: {}",
                    err
                )));
            }
        };

        debug!("Completed websocket connection");

        Ok(web_socket)
    }

    /// Sends the request to the remote server via the websocket
    async fn ws_send(
        &self,
        websocket: &mut WebSocket<BufReader<Pin<Box<dyn ReadWrite>>>>,
        request: &WSRequest,
    ) -> Result<(), DIDCacheError> {
        match websocket
            .send(serde_json::to_string(request).unwrap().as_str())
            .await
        {
            Ok(_) => {
                debug!("Request sent: {:?}", request);
                Ok(())
            }
            Err(e) => Err(DIDCacheError::TransportError(format!(
                "Couldn't send request to network_task. Reason: {}",
                e
            ))),
        }
    }

    /// Processes inbound websocket messages from the remote server
    fn ws_recv(&mut self, message: String) -> Result<(), DIDCacheError> {
        let response: Result<WSResponseType, _> = serde_json::from_str(&message);
        match response {
            Ok(WSResponseType::Response(response)) => {
                debug!("Received response: {:?}", response.hash);
                if let Some(channels) = self.cache.remove(&response.hash, None) {
                    // Loop through and notify each registered channel
                    for channel in channels {
                        let _ = channel.send(WSCommands::ResponseReceived(Box::new(
                            response.document.clone(),
                        )));
                    }
                } else {
                    warn!("Response not found in request list: {:#?}", response.hash);
                }
            }
            Ok(WSResponseType::Error(response)) => {
                warn!(
                    "Received error: did hash({:#?}) Error: {:?}",
                    response.hash, response.error
                );
                if let Some(channels) = self.cache.remove(&response.hash, None) {
                    for channel in channels {
                        let _ = channel.send(WSCommands::ErrorReceived(response.error.clone()));
                    }
                } else {
                    warn!("Response not found in request list: {:#?}", response.hash);
                }
            }
            Err(e) => {
                warn!("Error parsing message: {:?}", e);
            }
        }

        Ok(())
    }
}
