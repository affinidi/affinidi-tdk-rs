//! Any parallel tasks that need to be run in the background.
//!
//! network task: Used to handle network requests to the DID Universal Resolver Cache.
//! network_cache: Helps with managing requests/responses that are in transit (out of order responses etc.).
//!

use affinidi_did_common::Document;
use network::WSCommands;
use rand::{RngExt, distr::Alphanumeric};
use serde::{Deserialize, Serialize};
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
/// hash: HighwayHash128 of the DID
/// document: The resolved DID Document
/// did_log: Raw JSONL DID log for verifiable DID methods (e.g. did:webvh)
///          Enables client-side cryptographic verification of the document
/// did_witness_log: Raw witness proofs JSON for DID methods that use witnesses
#[derive(Debug, Deserialize, Serialize)]
pub struct WSResponse {
    pub did: String,
    pub hash: [u64; 2],
    pub document: Document,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub did_log: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub did_witness_log: Option<String>,
}

/// WSResponseError is the response format from the websocket connection if an error occurred server side.
/// did: DID associated with the error
/// hash: HighwayHash128 of the DID
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
    Response(Box<WSResponse>),
    Error(WSResponseError),
}

impl DIDCacheClient {
    /// Resolve a DID via the network
    /// Returns the resolved DID Document, or an error
    ///
    /// For did:webvh DIDs, if the server includes the raw DID log in the response,
    /// the client will independently verify the log's cryptographic chain before
    /// accepting the document. This prevents a compromised cache server from
    /// returning tampered DID documents.
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
                        "Couldn't send request to network_task. Reason: {e}",
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
                            DIDCacheError::TransportError(format!("Could not send timeout message to ws_handler: {err:?}"))
                        })?;
                         Err(DIDCacheError::NetworkTimeout)
                    }
                    value = rx => {
                        match value {
                            Ok(WSCommands::ResponseReceived(doc, did_log, did_witness_log)) => {
                                debug!("Received response from network task ({:#?})", did_hash);
                                Self::verify_network_response(did, *doc, did_log, did_witness_log).await
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
                                 Err(DIDCacheError::TransportError(format!("Error receiving response from network task: {e:?}")))
                            }
                        }
                    }
                }
        }
        .instrument(_span)
        .await
    }

    /// Verify a DID document received from the network cache server.
    ///
    /// For did:webvh DIDs with a provided raw log, this independently verifies
    /// the cryptographic chain and compares the resulting document against the
    /// one returned by the server. If they don't match, the document is rejected.
    ///
    /// For other DID methods or when no log is provided, the document is accepted as-is.
    async fn verify_network_response(
        did: &str,
        doc: Document,
        did_log: Option<String>,
        did_witness_log: Option<String>,
    ) -> Result<Document, DIDCacheError> {
        // Only verify did:webvh DIDs that include a log
        #[cfg(feature = "did-webvh")]
        if did.starts_with("did:webvh:") {
            if let Some(ref log_data) = did_log {
                use didwebvh_rs::log_entry::LogEntryMethods;

                debug!("Verifying did:webvh log for DID: {}", did);

                let mut state = didwebvh_rs::DIDWebVHState::default();
                let result = state
                    .resolve_log(
                        did,
                        log_data,
                        did_witness_log.as_deref(),
                    )
                    .await
                    .map_err(|e| {
                        DIDCacheError::DIDError(format!(
                            "WebVH log verification failed for DID {did}: {e}"
                        ))
                    })?;

                let verified_doc_value = result.0.get_did_document().map_err(|e| {
                    DIDCacheError::DIDError(format!(
                        "Failed to extract document from verified WebVH log: {e}"
                    ))
                })?;

                let verified_doc: Document =
                    serde_json::from_value(verified_doc_value).map_err(|e| {
                        DIDCacheError::DIDError(format!(
                            "Failed to deserialize verified WebVH document: {e}"
                        ))
                    })?;

                // Compare the server-provided document with the locally verified one
                if doc != verified_doc {
                    return Err(DIDCacheError::DIDError(format!(
                        "WebVH document verification failed: server document does not match \
                         locally verified document for DID {did}. \
                         The cache server may have tampered with the DID document."
                    )));
                }

                debug!("WebVH log verification passed for DID: {}", did);
                return Ok(doc);
            } else {
                warn!(
                    "No DID log provided by cache server for did:webvh DID: {}. \
                     Document accepted without cryptographic verification.",
                    did
                );
            }
        }

        Ok(doc)
    }
}
