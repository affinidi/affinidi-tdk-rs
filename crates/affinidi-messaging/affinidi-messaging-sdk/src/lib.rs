use affinidi_messaging_didcomm::{Message, UnpackMetadata};
use affinidi_tdk_common::TDKSharedState;
use config::ATMConfig;
use delete_handler::DeletionHandlerCommands;
use errors::ATMError;
use profiles::Profiles;
use std::sync::Arc;
use tokio::sync::{
    Mutex, RwLock, broadcast,
    mpsc::{self, Receiver, Sender},
};

use tracing::debug;
use transports::websockets::ws_handler::{WsHandlerCommands, WsHandlerMode};

//pub mod authentication;
pub mod config;
pub mod delete_handler;
pub mod errors;
pub mod messages;
pub mod profiles;
pub mod protocols;
pub mod public;
pub mod transports;

#[derive(Clone)]
pub struct ATM {
    pub(crate) inner: Arc<SharedState>,
}

/// Private SharedState struct for the ATM to be used across tasks
pub(crate) struct SharedState {
    pub(crate) config: ATMConfig,
    pub(crate) tdk_common: TDKSharedState,
    pub(crate) ws_handler_send_stream: Sender<WsHandlerCommands>, // Sends MPSC messages to the WebSocket handler
    pub(crate) ws_handler_recv_stream: Mutex<Receiver<WsHandlerCommands>>, // Receives MPSC messages from the WebSocket handler
    pub(crate) sdk_send_stream: Sender<WsHandlerCommands>, // Sends messages to the SDK
    pub(crate) profiles: Arc<RwLock<Profiles>>,
    pub(crate) direct_stream_sender: Option<broadcast::Sender<(Message, UnpackMetadata)>>, // Used if a client outside of ATM wants to direct stream from websocket
    pub(crate) deletion_handler_send_stream: Sender<delete_handler::DeletionHandlerCommands>, // Sends MPSC messages to the Deletion Handler
    pub(crate) deletion_handler_recv_stream:
        Mutex<Receiver<delete_handler::DeletionHandlerCommands>>, // Receives MPSC messages from the Deletion Handler
}

/// Affinidi Trusted Messaging SDK
/// This is the top level struct for the SDK
///
/// Example:
/// ```ignore
/// use affinidi_messaging_sdk::ATM;
/// use affinidi_messaging_sdk::config::Config;
///
/// let config = Config::builder().build();
/// let mut atm = ATM::new(config);
///
/// // Add the DID:Peer method
/// atm.add_did_method(Box::new(DIDPeer));
///
/// let response = atm.ping("did:example:123", true);
/// ```
impl ATM {
    /// Creates a new instance of the SDK with a given configuration
    /// You need to add at least the DID Method for the SDK DID to work
    pub async fn new(config: ATMConfig, tdk_common: TDKSharedState) -> Result<ATM, ATMError> {
        // Set up the channels for the WebSocket handler
        // Create a new channel with a capacity of at most 32. This communicates from SDK to the websocket handler
        let (sdk_tx, ws_handler_rx) = mpsc::channel::<WsHandlerCommands>(32);

        // Create a new channel with a capacity of at most 32. This communicates from websocket handler to SDK
        let (ws_handler_tx, sdk_rx) = mpsc::channel::<WsHandlerCommands>(32);

        // Create a new channel with a capacity of at most 32. This communicates from SDK to the deletion handler
        let (sdk_deletion_tx, deletion_sdk_rx) = mpsc::channel::<DeletionHandlerCommands>(32);

        // Create a new channel with a capacity of at most 32. This communicates from deletion handler to the SDK
        let (deletion_sdk_tx, sdk_deletion_rx) = mpsc::channel::<DeletionHandlerCommands>(32);

        let direct_stream_sender = match config.ws_handler_mode {
            WsHandlerMode::DirectChannel => {
                let (direct_stream_sender, _) = broadcast::channel(32);
                Some(direct_stream_sender)
            }
            _ => None,
        };

        let shared_state = SharedState {
            config: config.clone(),
            tdk_common,
            ws_handler_send_stream: sdk_tx,
            ws_handler_recv_stream: Mutex::new(sdk_rx),
            sdk_send_stream: ws_handler_tx.clone(),
            profiles: Arc::new(RwLock::new(Profiles::default())),
            direct_stream_sender,
            deletion_handler_send_stream: sdk_deletion_tx,
            deletion_handler_recv_stream: Mutex::new(sdk_deletion_rx),
        };

        let atm = ATM {
            inner: Arc::new(shared_state),
        };

        // Start the websocket handler
        atm.start_websocket_handler(ws_handler_rx, ws_handler_tx)
            .await?;

        // Start the deletion handler
        atm.start_deletion_handler(deletion_sdk_rx, deletion_sdk_tx)
            .await?;

        debug!("ATM SDK initialized");

        Ok(atm)
    }

    pub async fn graceful_shutdown(&self) {
        debug!("Shutting down ATM SDK");

        // turn off incoming messages on websockets

        // Send a shutdown message to the Deletion Handler
        let _ = self.abort_deletion_handler().await;
        {
            let mut guard = self.inner.deletion_handler_recv_stream.lock().await;
            let _ = guard.recv().await;
            // Only ever send back a closing command
            // safe to exit now
            debug!("Deletion Handler stopped");
        }

        // Send a shutdown message to the WebSocket handler
        let _ = self.abort_websocket_task().await;
    }

    /// If you have set the ATM SDK to be in DirectChannel mode, you can get the inbound channel here
    /// This allows you to directly stream messages from the WebSocket Handler to your own client code
    pub fn get_inbound_channel(&self) -> Option<broadcast::Receiver<(Message, UnpackMetadata)>> {
        self.inner
            .direct_stream_sender
            .as_ref()
            .map(|sender| sender.subscribe())
    }

    /// Get the TDK Shared State
    pub fn get_tdk(&self) -> &TDKSharedState {
        &self.inner.tdk_common
    }
}
