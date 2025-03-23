//! Any parallel tasks that need to be run in the background.
//!
//! network task: Used to handle network requests to the DID Universal Resolver Cache.
//! network_cache: Helps with managing requests/responses that are in transit (out of order responses etc.).
//!

use network::WSCommands;
use rand::{Rng, distr::Alphanumeric};
use serde::{Deserialize, Serialize};
use ssi::dids::Document;
use tokio::{select, sync::oneshot};
use tracing::{Instrument, Level, debug, span, warn};

use crate::{DIDCacheClient, errors::DIDCacheError};
#[cfg(feature = "network")]
pub(crate) mod handshake;
pub mod network;
#[cfg(feature = "network")]
pub(crate) mod utils;

mod request_queue;
/// WSRequest is the request format to the websocket connection
/// did: DID to resolve
#[derive(Debug, Deserialize, Serialize)]
pub struct WSRequest {
    pub did: String,
}

/// WSResponse is the response format from the websocket connection
/// did: DID that was resolved
/// hash: SHA256 Hash of the DID
/// document: The resolved DID Document
#[derive(Debug, Deserialize, Serialize)]
pub struct WSResponse {
    pub did: String,
    pub hash: [u64; 2],
    pub document: Document,
}

/// WSResponseError is the response format from the websocket connection if an error occurred server side.
/// did: DID associated with the error
/// hash: SHA256 Hash of the DID
/// error: Error message
#[derive(Debug, Deserialize, Serialize)]
pub struct WSResponseError {
    pub did: String,
    pub hash: [u64; 2],
    pub error: String,
}

/// WSResponseType is the type of response received from the websocket connection
/// Response: A successful response
/// Error: An error response
#[derive(Debug, Deserialize, Serialize)]
pub enum WSResponseType {
    Response(WSResponse),
    Error(WSResponseError),
}

impl DIDCacheClient {
    /// Resolve a DID via the network
    /// Returns the resolved DID Document, or an error
    ///
    /// Send the request, and wait for the response
    pub(crate) async fn network_resolve(
        &self,
        did: &str,
        did_hash: [u64; 2],
    ) -> Result<Document, DIDCacheError> {
        let _span = span!(Level::DEBUG, "network_resolve");
        async move {
            debug!("resolving did ({}) via network hash ({:#?})", did, did_hash);

            let network_task_tx = self.network_task_tx
            .clone()
            .unwrap();

            // Set up a oneshot channel to receive the response
            let (tx, rx) = oneshot::channel::<WSCommands>();

            // create a 8-char unique-id for this request
            let unique_id: String = rand::rng()
            .sample_iter(&Alphanumeric)
            .take(8)
            .map(char::from)
            .collect();

            // 1. Send the request to the network task, which will then send via websocket to the remote server
            network_task_tx
                .send(WSCommands::Send(tx, unique_id.clone(), WSRequest { did: did.into() }))
                .await
                .map_err(|e| {
                    DIDCacheError::TransportError(format!(
                        "Couldn't send request to network_task. Reason: {}",
                        e
                    ))
                })?;

            // 2. Wait for the response from the network task

            // Setup the timer for the wait, doesn't do anything till `await` is called in the select! macro
            let sleep = tokio::time::sleep(self.config.network_timeout);
            tokio::pin!(sleep);

                select! {
                    _ = &mut sleep => {
                        warn!("Timeout reached, no message received did_hash ({:#?})", did_hash);
                        network_task_tx.send(WSCommands::TimeOut(unique_id, did_hash)).await.map_err(|err| {
                            DIDCacheError::TransportError(format!("Could not send timeout message to ws_handler: {:?}", err))
                        })?;
                         Err(DIDCacheError::NetworkTimeout)
                    }
                    value = rx => {
                        match value {
                            Ok(WSCommands::ResponseReceived(doc)) => {
                                debug!("Received response from network task ({:#?})", did_hash);
                                 Ok(*doc)
                            }
                            Ok(WSCommands::ErrorReceived(msg)) => {
                                warn!("Received error response from network task");
                                 Err(DIDCacheError::TransportError(msg))
                            }
                            Ok(_) => {
                                debug!("Received unexpected response from network task");
                                 Err(DIDCacheError::TransportError("Unexpected response from network task".into()))
                            }
                            Err(e) => {
                                debug!("Error receiving response from network task: {:?}", e);
                                 Err(DIDCacheError::TransportError(format!("Error receiving response from network task: {:?}", e)))
                            }
                        }
                    }
                }
        }
        .instrument(_span)
        .await
    }
}
