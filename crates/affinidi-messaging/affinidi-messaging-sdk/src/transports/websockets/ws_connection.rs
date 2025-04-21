/*!
A per Profile WebSocket connection to a DIDComm Mediator.

These connections are managed by the `WsHandler` and are created and destroyed as needed.

Each WsConnection is a tokio parallel task, and responsible for unpacking incoming messages

*/
use crate::{
    ATM, SharedState, errors::ATMError, profiles::ATMProfile, protocols::Protocols,
    transports::websockets::utils::connect,
};
use affinidi_messaging_didcomm::{Message as DidcommMessage, UnpackMetadata};
use std::{pin::Pin, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncWrite, BufReader},
    select,
    sync::mpsc::{Receiver, Sender},
    task::JoinHandle,
    time::{interval_at, sleep},
};
use tracing::{Instrument, debug, error, span, warn};
use url::Url;
use web_socket::{CloseCode, DataType, Event, MessageType, WebSocket};

/// Commands between the websocket handler and the websocket connections
#[derive(Debug)]
pub(crate) enum WsConnectionCommands {
    // From Handler (or SDK)
    Send(String), // Sends the message string to the websocket
    Stop,         // Stops the connection
    /// Enables direct channel for this profile
    EnableDirectChannel(Sender<Box<(DidcommMessage, UnpackMetadata)>>),
    DisableDirectChannel,
    // To Handler
    Connected(Arc<ATMProfile>, String), // Connection is ready for profile (and status message to retrieve)
    Disconnected(Arc<ATMProfile>),      // WebSocket connection is disconnected
    MessageReceived(Box<(DidcommMessage, UnpackMetadata)>),
}

/// The following is to help with handling either TCP or TLS connections
pub(crate) trait ReadWrite: AsyncRead + AsyncWrite + Send {}
impl<T> ReadWrite for T where T: AsyncRead + AsyncWrite + Send {}

#[derive(Clone, Debug)]
enum State {
    Disconnected,
    Connecting,
    Connected,
}

pub struct WsConnection {
    profile: Arc<ATMProfile>,
    shared: Arc<SharedState>,
    state: State,
    to_handler: Sender<WsConnectionCommands>,
    from_handler: Receiver<WsConnectionCommands>,
    to_connection: Sender<WsConnectionCommands>,
}

impl WsConnection {
    pub(crate) async fn activate(
        shared_state: Arc<SharedState>,
        profile: &Arc<ATMProfile>,
        to_handler: Sender<WsConnectionCommands>,
        from_handler: Receiver<WsConnectionCommands>,
        to_connection: Sender<WsConnectionCommands>,
    ) -> Result<JoinHandle<()>, ATMError> {
        let mut connection = WsConnection {
            profile: profile.clone(),
            shared: shared_state.clone(),
            state: State::Disconnected,
            from_handler,
            to_handler,
            to_connection,
        };
        debug!(
            "Activating websocket connection for profile ({})",
            profile.inner.alias
        );

        let handle = tokio::spawn(async move {
            let _ = connection.run().await;
        });

        Ok(handle)
    }

    async fn run(&mut self) -> Result<(), ATMError> {
        //let alias = { self.profile.read().await.alias.clone() };

        let _span = span!(tracing::Level::DEBUG, "WsConnection::run", profile = %self.profile.inner.alias.clone());

        async move {
            // ATM utility for this connection
            let atm = ATM {
                inner: self.shared.clone(),
            };
            let protocols = Protocols::new();

            let mut web_socket = match self._handle_connection(&atm, &protocols, true).await {
                Ok(ws) => ws,
                Err(e) => {
                    error!("Error creating websocket connection: {:?}", e);
                    return;
                }
            };

            let mut direct_channel: Option<Sender<Box<(DidcommMessage, UnpackMetadata)>>> = None;
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
                            web_socket = match self._handle_connection(&atm, &protocols, true).await {
                                Ok(ws) => ws,
                                Err(e) => {
                                    error!("Error creating websocket connection: {:?}", e);
                                    return;
                                }
                            };
                        } else {
                            missed_pings += 1;
                        }
                    }
                    value = web_socket.recv() => {
                        match value {
                            Ok(event) =>
                                match event {
                                    Event::Data { ty, data } => {
                                        let msg = match ty {
                                            DataType::Complete(MessageType::Text) => String::from_utf8_lossy(&data),
                                            DataType::Complete(MessageType::Binary) => {
                                                warn!("Received binary message ({})", String::from_utf8_lossy(&data));
                                                continue;
                                            }
                                            DataType::Stream(_) => {
                                                warn!("Received stream - not handled");
                                                continue;
                                            }
                                        };

                                        debug!("Received text message ({})", msg);
                                        let unpack = match atm.unpack(&msg).await {
                                            Ok(unpack) => unpack,
                                            Err(e) => {
                                                error!("Error unpacking message: {:?}", e);
                                                continue;
                                            }
                                        };
                                        match &direct_channel {
                                            Some(sender) => {
                                                let _ = sender.send(Box::new(unpack)).await;
                                            } _ => {
                                                let _ = self.to_handler.send(WsConnectionCommands::MessageReceived(Box::new(unpack))).await;
                                            }
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
                                        web_socket = match self._handle_connection(&atm, &protocols, true).await {
                                            Ok(ws) => ws,
                                            Err(e) => {
                                                error!("Error creating websocket connection: {:?}", e);
                                                return;
                                            }
                                        };
                                        missed_pings = 0;
                                    }
                                    Event::Close { .. } => {
                                        web_socket = match self._handle_connection(&atm, &protocols, true).await {
                                            Ok(ws) => ws,
                                            Err(e) => {
                                                error!("Error creating websocket connection: {:?}", e);
                                                return;
                                            }
                                        };
                                        missed_pings = 0;
                                    }
                                }
                                Err(err) => {
                                    error!("Error receiving websocket message: {:?}", err);
                                    let _ = web_socket.close(CloseCode::ProtocolError).await;
                                    web_socket = match self._handle_connection(&atm, &protocols, true).await {
                                        Ok(ws) => ws,
                                        Err(e) => {
                                            error!("Error creating websocket connection: {:?}", e);
                                            return;
                                        }
                                    };
                                    missed_pings = 0;
                                }
                            }
                    }
                    value = self.from_handler.recv() => {
                        match value { Some(cmd) => {
                            match cmd {
                                WsConnectionCommands::Send(msg) => {
                                    debug!("Sending message ({}) to websocket", msg);
                                    match web_socket.send(msg.as_str()).await {
                                        Ok(_) => {
                                            debug!("Message sent");
                                        }
                                        Err(e) => {
                                            error!("Error sending message: {:?}", e);
                                        }
                                    }
                                }
                                WsConnectionCommands::Stop => {
                                    debug!("Stopping websocket connection");
                                    break;
                                }
                                WsConnectionCommands::EnableDirectChannel(sender) => {
                                    debug!("Enabling direct channel");
                                    direct_channel = Some(sender);
                                }
                                WsConnectionCommands::DisableDirectChannel => {
                                    debug!("Disabling direct channel");
                                    direct_channel = None;
                                }
                                _ => {
                                    println!("Unhandled command");
                                }
                            }
                        } _ => {
                            error!("Error getting command {:#?}", value);
                            continue;
                        }}
                    }
                }
            }
            let _ = self.to_handler.send(WsConnectionCommands::Disconnected(self.profile.clone())).await;
            let _ = web_socket.close(()).await;
            debug!("Websocket connection closed");
        }
        .instrument(_span)
        .await;

        Ok(())
    }

    // Wrapper that handles all of the logic of setting up a connection to the mediator
    async fn _handle_connection(
        &mut self,
        atm: &ATM,
        protocols: &Protocols,
        update_sdk: bool,
    ) -> Result<WebSocket<BufReader<Pin<Box<dyn ReadWrite>>>>, ATMError> {
        debug!("Starting websocket connection");

        self.state = State::Connecting;
        let mut delay: u8 = 1;
        let web_socket = loop {
            match self._create_socket().await {
                Ok(ws) => break ws,
                Err(e) => {
                    error!("Error creating websocket connection: {:?}", e);
                    sleep(Duration::from_secs(delay as u64)).await;
                    if delay < 60 {
                        delay *= 2;
                    }
                    if delay > 60 {
                        delay = 60;
                    }
                }
            }
        };

        debug!("Websocket connected");
        {
            // Update the mediator state
            if let Some(mediator) = &*self.profile.inner.mediator {
                mediator
                    .ws_connected
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                *mediator.ws_channel_tx.lock().await = Some(self.to_connection.clone());
            }
        }
        debug!("Mediator state updated to connected");
        self.state = State::Connected;

        // Enable live_streaming on this socket
        let status_id = match protocols
            .message_pickup
            .toggle_live_delivery(atm, &self.profile, true)
            .await
        {
            Ok(status_id) => {
                debug!("Live streaming enabled");
                status_id
            }
            Err(e) => {
                error!("Error enabling live streaming: {:?}", e);
                return Err(ATMError::TransportError(
                    "Error enabling live streaming".to_string(),
                ));
            }
        };

        if update_sdk {
            debug!("channel to SDK = capacity = {}", self.to_handler.capacity());
            match self.to_handler.try_send(WsConnectionCommands::Connected(
                self.profile.clone(),
                status_id,
            )) {
                Ok(_) => {}
                Err(e) => {
                    warn!("Channel to WS_handler is full: {:?}", e);
                }
            }
        }

        Ok(web_socket)
    }

    // Responsible for creating a websocket connection to the mediator
    async fn _create_socket(
        &mut self,
    ) -> Result<WebSocket<BufReader<Pin<Box<dyn ReadWrite>>>>, ATMError> {
        let (profile_did, mediator_did) = self.profile.dids()?;
        // Check if authenticated
        let tokens = self
            .shared
            .tdk_common
            .authentication
            .authenticate(profile_did.to_string(), mediator_did.to_string(), 3, None)
            .await?;

        debug!("Creating websocket connection");
        // Create a custom websocket request, turn this into a client_request
        // Allows adding custom headers later

        let Some(mediator) = &*self.profile.inner.mediator else {
            return Err(ATMError::ConfigError(format!(
                "Profile ({}) is missing a valid mediator configuration!",
                self.profile.inner.alias
            )));
        };

        let Some(address) = &mediator.websocket_endpoint else {
            return Err(ATMError::ConfigError(format!(
                "Profile ({}) is missing a valid websocket endpoint!",
                self.profile.inner.alias
            )));
        };

        let url = match Url::parse(address) {
            Ok(url) => url,
            Err(err) => {
                error!(
                    "Mediator {}: Invalid ServiceEndpoint address {}: {}",
                    mediator.did, address, err
                );
                return Err(ATMError::TransportError(format!(
                    "Mediator {}: Invalid ServiceEndpoint address {}: {}",
                    mediator.did, address, err
                )));
            }
        };

        let web_socket = match connect(&url, &tokens.access_token).await {
            Ok(web_socket) => web_socket,
            Err(err) => {
                warn!("WebSocket failed. Reason: {}", err);
                return Err(ATMError::TransportError(format!(
                    "Websocket connection failed: {}",
                    err
                )));
            }
        };

        debug!("Completed websocket connection");

        Ok(web_socket)
    }
}
