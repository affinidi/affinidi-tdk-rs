/*!
Module for handling websocket connections to DIDComm Mediators

SDK --> WS_Handler --> WS_Connection --> Mediator

Roles:
   - SDK: The main SDK that the user interacts with
   - WS_Handler: The handler that manages and aggregates many WebSocket Connections
   - WS_Connection: A single Mediator
*/

use crate::{ATM, SharedState, errors::ATMError};
use tokio::{
    sync::mpsc::{Receiver, Sender},
    task::JoinHandle,
};
use tracing::{debug, warn};
use ws_handler::WsHandlerCommands;

pub(crate) mod handshake;
pub(crate) mod utils;
pub(crate) mod ws_cache;
pub(crate) mod ws_connection;
pub mod ws_handler;

impl ATM {
    /// Starts the WebSocket Handler - won't do anything though until Profiles requiring WebSocket connections are added
    pub async fn start_websocket_handler(
        &self,
        mut from_sdk: Receiver<WsHandlerCommands>,
        to_sdk: Sender<WsHandlerCommands>,
    ) -> Result<JoinHandle<()>, ATMError> {
        let shared_state = self.inner.clone();

        let handle = tokio::spawn(async move {
            let _ = ATM::ws_handler(shared_state, &mut from_sdk, to_sdk).await;
        });

        // Wait for Started message
        if let Some(msg) = self.inner.ws_handler_recv_stream.lock().await.recv().await {
            match msg {
                WsHandlerCommands::Started => {
                    debug!("Websocket connection started");
                }
                _ => {
                    warn!("Unknown message from ws_handler: {:?}", msg);
                }
            }
        }

        debug!("Websocket connection and handler started");

        Ok(handle)
    }

    /// Close the WebSocket task gracefully
    pub async fn abort_websocket_task(&self) -> Result<(), ATMError> {
        let _ = self
            .inner
            .ws_handler_send_stream
            .send(WsHandlerCommands::Exit)
            .await;

        Ok(())
    }
}
