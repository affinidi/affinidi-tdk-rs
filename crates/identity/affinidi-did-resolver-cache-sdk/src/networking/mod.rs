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
/// A resolution request sent over the WebSocket connection.
///
/// `#[non_exhaustive]`: build via [`WSRequest::new`]. Fields stay public for
/// reads.
///
/// Sealing matters here specifically because this is a **wire type**. Growing
/// the protocol means adding fields, and every added field must be
/// `#[serde(default, skip_serializing_if = ...)]` so an older peer that does not
/// know it simply ignores it — the pattern `did_log` already follows on
/// [`WSResponse`]. Sealing makes those additions non-breaking for Rust callers
/// too, rather than forcing a major release for each one.
#[derive(Debug, Deserialize, Serialize)]
#[non_exhaustive]
pub struct WSRequest {
    /// The identifier to resolve.
    ///
    /// For an agent name request this carries the **name**, not a DID. That is
    /// deliberate: `did` is the only field an older server requires, so a name
    /// request still deserializes there. It then fails to parse as a DID and
    /// comes back as a clean [`WSResponseError`] whose `hash` still matches what
    /// the client registered — an error the caller can see, rather than a frame
    /// the client cannot correlate and a wait to `network_timeout`.
    pub did: String,

    /// Set when `did` carries an agent name rather than a DID.
    ///
    /// Additive and optional, so an older server ignores it (see above) and an
    /// older client never sends it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_name: Option<String>,
}

impl WSRequest {
    /// Request resolution of `did`.
    pub fn new(did: impl Into<String>) -> Self {
        Self {
            did: did.into(),
            agent_name: None,
        }
    }

    /// Request resolution of an agent name.
    ///
    /// `name` must be the **canonical** form, since the server echoes its hash
    /// back for correlation and the client matches on the hash of what it sent.
    pub fn for_agent_name(name: impl Into<String>) -> Self {
        let name = name.into();
        Self {
            did: name.clone(),
            agent_name: Some(name),
        }
    }
}

/// WSResponse is the response format from the websocket connection
/// did: DID that was resolved
/// hash: HighwayHash128 of the DID
/// document: The resolved DID Document
/// did_log: Raw JSONL DID log for verifiable DID methods (e.g. did:webvh)
///          Enables client-side cryptographic verification of the document
/// did_witness_log: Raw witness proofs JSON for DID methods that use witnesses
/// `#[non_exhaustive]`: build via [`WSResponse::new`] and the `with_*` setters.
#[derive(Debug, Deserialize, Serialize)]
#[non_exhaustive]
pub struct WSResponse {
    pub did: String,
    pub hash: [u64; 2],
    pub document: Document,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub did_log: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub did_witness_log: Option<String>,
    /// Echoed when the request carried an agent name, so the client can confirm
    /// which name this document was resolved for before verifying `alsoKnownAs`
    /// against it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_name: Option<String>,
}

impl WSResponse {
    /// A response carrying a resolved document.
    ///
    /// `hash` must be the hash of whatever string the *client* sent, since that
    /// is what the client matches the response against. It is not necessarily
    /// `hash_did(&did)` — see `network.rs`, where inbound responses are
    /// correlated by the server-supplied `hash` rather than by re-hashing `did`.
    pub fn new(did: impl Into<String>, hash: [u64; 2], document: Document) -> Self {
        Self {
            did: did.into(),
            hash,
            document,
            did_log: None,
            did_witness_log: None,
            agent_name: None,
        }
    }

    /// Record the agent name this document was resolved for.
    pub fn with_agent_name(mut self, agent_name: Option<String>) -> Self {
        self.agent_name = agent_name;
        self
    }

    /// Attach the raw `did:webvh` logs, letting the client verify the document
    /// itself rather than trusting this server.
    pub fn with_logs(mut self, did_log: Option<String>, did_witness_log: Option<String>) -> Self {
        self.did_log = did_log;
        self.did_witness_log = did_witness_log;
        self
    }
}

/// WSResponseError is the response format from the websocket connection if an error occurred server side.
/// did: DID associated with the error
/// hash: HighwayHash128 of the DID
/// error: Error message
/// `#[non_exhaustive]`: build via [`WSResponseError::new`].
#[derive(Debug, Deserialize, Serialize)]
#[non_exhaustive]
pub struct WSResponseError {
    pub did: String,
    pub hash: [u64; 2],
    pub error: String,
}

impl WSResponseError {
    /// An error response. `hash` follows the same rule as [`WSResponse::new`]:
    /// it must match what the client sent, or the caller never sees this and
    /// waits out its timeout instead.
    pub fn new(did: impl Into<String>, hash: [u64; 2], error: impl Into<String>) -> Self {
        Self {
            did: did.into(),
            hash,
            error: error.into(),
        }
    }
}

/// What came back over the WebSocket connection.
///
/// # Do not add variants
///
/// `#[non_exhaustive]` here records a Rust-level rule, but the **wire**-level one
/// is stricter and matters more: this is an externally-tagged enum, so a new
/// variant serializes as an unrecognised key. An older client fails to
/// deserialize it, and `ws_recv` in `network.rs` logs the parse failure and
/// *drops the frame* — leaving the caller waiting out its full `network_timeout`
/// with no error to report.
///
/// A silent hang is a far worse failure than a clean error, so protocol growth
/// belongs in **additive optional fields** on [`WSResponse`] and
/// [`WSResponseError`] (as `did_log` does), never in a new variant here.
#[derive(Debug, Deserialize, Serialize)]
#[non_exhaustive]
pub enum WSResponseType {
    /// A successful resolution.
    Response(Box<WSResponse>),
    /// A failure attributable to a specific request.
    Error(WSResponseError),
}

impl DIDCacheClient {
    /// Resolve an agent name via the cache server, in **one** round trip.
    ///
    /// Returns `(resolved DID, document)`. Without this, a name lookup in
    /// network mode costs two round trips over two transports: HTTP to the
    /// server for name → DID, then WebSocket for DID → document.
    ///
    /// # Talking to an older server
    ///
    /// The name travels in `WSRequest::did` with `agent_name` alongside it. A
    /// server that predates this ignores the unknown field, tries to parse the
    /// name as a DID, fails, and answers with a `WSResponseError` carrying the
    /// hash of what we sent — which is what we registered against, so it
    /// surfaces as a clean transport error rather than a frame we cannot
    /// correlate and a wait to `network_timeout`.
    ///
    /// It is still gated behind `agent_names_over_websocket` rather than
    /// attempted optimistically, because distinguishing "old server" from "real
    /// failure" would mean matching on error strings.
    #[cfg(feature = "agent-names")]
    pub(crate) async fn network_resolve_agent_name(
        &self,
        canonical_name: &str,
    ) -> Result<(String, Document), DIDCacheError> {
        let _span = span!(Level::DEBUG, "network_resolve_agent_name");
        async move {
            let name_hash = DIDCacheClient::hash_did(canonical_name);
            debug!("resolving agent name ({canonical_name}) via network");

            let network_task_tx = self.network_task_tx.clone().unwrap();
            let (tx, rx) = oneshot::channel::<WSCommands>();
            let unique_id: String = rand::rng()
                .sample_iter(&Alphanumeric)
                .take(8)
                .map(char::from)
                .collect();

            network_task_tx
                .send(WSCommands::Send(
                    tx,
                    unique_id.clone(),
                    WSRequest::for_agent_name(canonical_name),
                ))
                .await
                .map_err(|e| {
                    DIDCacheError::TransportError(format!(
                        "Couldn't send request to network_task. Reason: {e}",
                    ))
                })?;

            let sleep = tokio::time::sleep(self.config.network_timeout);
            tokio::pin!(sleep);

            select! {
                _ = &mut sleep => {
                    warn!("Timeout resolving agent name ({canonical_name})");
                    network_task_tx
                        .send(WSCommands::TimeOut(unique_id, name_hash))
                        .await
                        .map_err(|err| {
                            DIDCacheError::TransportError(format!(
                                "Could not send timeout message to ws_handler: {err:?}"
                            ))
                        })?;
                    Err(DIDCacheError::NetworkTimeout)
                }
                value = rx => {
                    match value {
                        Ok(WSCommands::ResponseReceived(response)) => {
                            let response = *response;
                            // The server reports the DID it resolved the name to;
                            // `response.did` is that DID, not the name we sent.
                            let did = response.did.clone();
                            let document = Self::verify_network_response(
                                &did,
                                response.document,
                                response.did_log,
                                response.did_witness_log,
                            )
                            .await?;
                            Ok((did, document))
                        }
                        Ok(WSCommands::ErrorReceived(msg)) => {
                            Err(DIDCacheError::TransportError(msg))
                        }
                        Ok(_) => Err(DIDCacheError::TransportError(
                            "Unexpected response from network task".into(),
                        )),
                        Err(e) => Err(DIDCacheError::TransportError(format!(
                            "Error receiving response from network task: {e:?}"
                        ))),
                    }
                }
            }
        }
        .instrument(_span)
        .await
    }

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
                .send(WSCommands::Send(tx, unique_id.clone(), WSRequest::new(did)))
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
                            Ok(WSCommands::ResponseReceived(response)) => {
                                debug!("Received response from network task ({:#?})", did_hash);
                                let response = *response;
                                Self::verify_network_response(
                                    did,
                                    response.document,
                                    response.did_log,
                                    response.did_witness_log,
                                )
                                .await
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
                    .resolve_log(did, log_data, did_witness_log.as_deref())
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

#[cfg(test)]
mod wire_tests {
    use super::*;

    fn doc() -> Document {
        Document::new("did:example:123").unwrap()
    }

    #[test]
    fn request_serializes_to_the_documented_shape() {
        let json = serde_json::to_string(&WSRequest::new("did:example:123")).unwrap();
        assert_eq!(json, r#"{"did":"did:example:123"}"#);
    }

    /// An older peer sends only `did`. That must still deserialize, or every
    /// existing client breaks the moment this type grows a field.
    #[test]
    fn request_accepts_a_minimal_payload() {
        let req: WSRequest = serde_json::from_str(r#"{"did":"did:example:123"}"#).unwrap();
        assert_eq!(req.did, "did:example:123");
    }

    /// Unknown fields must be ignored, not rejected — this is what lets a newer
    /// client talk to an older server without a negotiation step.
    #[test]
    fn request_ignores_unknown_fields() {
        let req: WSRequest =
            serde_json::from_str(r#"{"did":"did:example:123","future_field":"x"}"#).unwrap();
        assert_eq!(req.did, "did:example:123");
    }

    #[test]
    fn response_omits_absent_logs() {
        let json =
            serde_json::to_string(&WSResponse::new("did:example:123", [1, 2], doc())).unwrap();
        assert!(!json.contains("did_log"), "got {json}");
        assert!(!json.contains("did_witness_log"), "got {json}");
    }

    #[test]
    fn response_round_trips_with_logs() {
        let original = WSResponse::new("did:example:123", [1, 2], doc())
            .with_logs(Some("log".into()), Some("witness".into()));
        let back: WSResponse =
            serde_json::from_str(&serde_json::to_string(&original).unwrap()).unwrap();
        assert_eq!(back.did, "did:example:123");
        assert_eq!(back.hash, [1, 2]);
        assert_eq!(back.did_log.as_deref(), Some("log"));
        assert_eq!(back.did_witness_log.as_deref(), Some("witness"));
    }

    /// A response from an older server carries no logs at all.
    #[test]
    fn response_accepts_a_payload_without_logs() {
        let json = r#"{"did":"did:example:123","hash":[1,2],"document":{"id":"did:example:123"}}"#;
        let response: WSResponse = serde_json::from_str(json).unwrap();
        assert!(response.did_log.is_none());
    }

    /// The enum is externally tagged. This is pinned deliberately: the tagging
    /// is what makes an added variant unparseable to older clients, which is why
    /// the type documents that variants must not be added.
    #[test]
    fn response_type_is_externally_tagged() {
        let json = serde_json::to_string(&WSResponseType::Error(WSResponseError::new(
            "d",
            [0, 0],
            "e",
        )))
        .unwrap();
        assert!(json.starts_with(r#"{"Error":"#), "got {json}");

        let json = serde_json::to_string(&WSResponseType::Response(Box::new(WSResponse::new(
            "d",
            [0, 0],
            doc(),
        ))))
        .unwrap();
        assert!(json.starts_with(r#"{"Response":"#), "got {json}");
    }

    #[test]
    fn error_round_trips() {
        let original = WSResponseError::new("did:example:123", [7, 8], "boom");
        let back: WSResponseError =
            serde_json::from_str(&serde_json::to_string(&original).unwrap()).unwrap();
        assert_eq!(back.did, "did:example:123");
        assert_eq!(back.hash, [7, 8]);
        assert_eq!(back.error, "boom");
    }
}

#[cfg(test)]
mod agent_name_wire_tests {
    use super::*;

    /// The name travels in `did` as well as `agent_name`. That is what makes an
    /// older server — which only knows `did` — answer with a correlatable error
    /// rather than leaving the caller to time out.
    #[test]
    fn agent_name_request_also_populates_did() {
        let req = WSRequest::for_agent_name("https://example.com/@alice");
        assert_eq!(req.did, "https://example.com/@alice");
        assert_eq!(
            req.agent_name.as_deref(),
            Some("https://example.com/@alice")
        );
    }

    #[test]
    fn plain_did_request_sends_no_agent_name() {
        let json = serde_json::to_string(&WSRequest::new("did:example:123")).unwrap();
        assert_eq!(json, r#"{"did":"did:example:123"}"#);
    }

    #[test]
    fn agent_name_request_serializes_both_fields() {
        let json = serde_json::to_string(&WSRequest::for_agent_name("example.com/@alice")).unwrap();
        assert!(json.contains(r#""did":"example.com/@alice""#), "got {json}");
        assert!(
            json.contains(r#""agent_name":"example.com/@alice""#),
            "got {json}"
        );
    }

    /// An older *client* sends no `agent_name`; a newer server must still parse.
    #[test]
    fn request_without_agent_name_parses() {
        let req: WSRequest = serde_json::from_str(r#"{"did":"did:example:123"}"#).unwrap();
        assert!(req.agent_name.is_none());
    }

    /// An older *server* echoes no `agent_name`; a newer client must still parse.
    #[test]
    fn response_without_agent_name_parses() {
        let json = r#"{"did":"did:example:123","hash":[1,2],"document":{"id":"did:example:123"}}"#;
        let response: WSResponse = serde_json::from_str(json).unwrap();
        assert!(response.agent_name.is_none());
    }

    #[test]
    fn response_round_trips_the_agent_name() {
        let doc = Document::new("did:example:123").unwrap();
        let original = WSResponse::new("did:example:123", [1, 2], doc)
            .with_agent_name(Some("https://example.com/@alice".into()));
        let back: WSResponse =
            serde_json::from_str(&serde_json::to_string(&original).unwrap()).unwrap();
        assert_eq!(
            back.agent_name.as_deref(),
            Some("https://example.com/@alice")
        );
        assert_eq!(back.did, "did:example:123", "did carries the RESOLVED did");
    }
}
