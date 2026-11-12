//! Any parallel tasks that need to be run in the background.
//!
//! network task: Used to handle network requests to the DID Universal Resolver Cache.
//! network_cache: Helps with managing requests/responses that are in transit (out of order responses etc.).
//!

use affinidi_did_common::{DID, Document};
use network::WSCommands;
use rand::{RngExt, distr::Alphanumeric};
use serde::{Deserialize, Serialize};
use tokio::{select, sync::oneshot};
use tracing::{Instrument, Level, debug, span, warn};

use crate::{DIDCacheClient, MethodName, errors::DIDCacheError};
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
    /// Ask the cache server for an agent name's DID and document, in one round
    /// trip.
    ///
    /// Returns the server's answer as received: `did` is the DID the server
    /// maps the name to, and nothing in it has been checked. That DID is only a
    /// hint: `resolve_agent_name` confirms the name through the registered
    /// backends, and runs [`Self::verify_network_response`] on the document
    /// only when the server's DID is the confirmed one.
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
    ) -> Result<WSResponse, DIDCacheError> {
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
                        // The server reports the DID it resolved the name to;
                        // `response.did` is that DID, not the name we sent.
                        // Unchecked: the caller verifies it only once the
                        // name's backends confirm that DID.
                        Ok(WSCommands::ResponseReceived(response)) => Ok(*response),
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

    /// Resolve a DID via the network.
    ///
    /// Returns the server's document once it has been checked as
    /// [`Self::verify_network_response`] describes, or `None` when the answer
    /// carries nothing this client can check it against and the DID must be
    /// resolved locally instead.
    pub(crate) async fn network_resolve(
        &self,
        did: &str,
        did_hash: [u64; 2],
    ) -> Result<Option<Document>, DIDCacheError> {
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
                                self.verify_network_response(
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

    /// Check a DID document received from the cache server against the DID it
    /// was resolved for, the way local resolution would check it.
    ///
    /// - A method this client resolves itself in network mode (see
    ///   [`DIDCacheClient::resolves_locally_in_network_mode`]) is never taken
    ///   from the server: `None`, resolve it locally.
    /// - did:webvh: the server's raw log is verified here (including
    ///   deactivation) and the server's document must equal the one the log
    ///   produces. An answer without the log, or a client built without the
    ///   `did-webvh` feature, gives `None`: the DID is resolved locally.
    /// - Any other method: the document's `id` must be the requested DID
    ///   (without its path, query or fragment), as did:web resolution requires.
    ///   The server's answer is otherwise taken as is: those methods carry
    ///   nothing a client could verify it against.
    pub(crate) async fn verify_network_response(
        &self,
        did: &str,
        doc: Document,
        did_log: Option<String>,
        did_witness_log: Option<String>,
    ) -> Result<Option<Document>, DIDCacheError> {
        let parsed: DID = did.parse().map_err(|e| {
            DIDCacheError::DIDError(format!(
                "The cache server answered for an invalid DID ({did}): {e}"
            ))
        })?;

        if self.resolves_locally_in_network_mode(&parsed) {
            debug!("{did} is resolved locally; the cache server's document is not used");
            return Ok(None);
        }

        if MethodName::from(&parsed.method()) == MethodName::Webvh {
            #[cfg(feature = "did-webvh")]
            if let Some(log_data) = did_log {
                return self
                    .verify_webvh_log(did, doc, &log_data, did_witness_log.as_deref())
                    .await
                    .map(Some);
            }
            #[cfg(not(feature = "did-webvh"))]
            let _ = (did_log, did_witness_log);

            warn!(
                "The cache server sent no verifiable log for {did}; resolving it locally instead"
            );
            return Ok(None);
        }

        check_document_id(&parsed, &doc)?;
        Ok(Some(doc))
    }

    /// Verify a did:webvh log and compare the server's document with the one
    /// the log produces.
    #[cfg(feature = "did-webvh")]
    async fn verify_webvh_log(
        &self,
        did: &str,
        doc: Document,
        log_data: &str,
        did_witness_log: Option<&str>,
    ) -> Result<Document, DIDCacheError> {
        use didwebvh_rs::log_entry::LogEntryMethods;

        debug!("Verifying did:webvh log for DID: {}", did);

        let mut state = didwebvh_rs::DIDWebVHState::default();
        let result = state
            .resolve_log(did, log_data, did_witness_log)
            .await
            .map_err(|e| {
                DIDCacheError::DIDError(format!("WebVH log verification failed for DID {did}: {e}"))
            })?;

        // The log verified. It must not be behind, or fork from, a version
        // already verified for this SCID: a shorter prefix of a valid log
        // verifies too, and could leave out a rotation or the deactivation.
        // Recorded before the deactivation check, so a later answer cannot
        // drop the deactivation entry.
        self.webvh_versions.accept(did, log_data)?;

        // A cache server that predates the deactivation check still
        // serves the retired document; the log it sent says otherwise.
        if result.1.deactivated {
            return Err(DIDCacheError::DIDError(
                crate::resolver::network_resolvers::webvh_deactivated(did).to_string(),
            ));
        }

        let verified_doc_value = result.0.get_did_document().map_err(|e| {
            DIDCacheError::DIDError(format!(
                "Failed to extract document from verified WebVH log: {e}"
            ))
        })?;

        let verified_doc: Document = serde_json::from_value(verified_doc_value).map_err(|e| {
            DIDCacheError::DIDError(format!(
                "Failed to deserialize verified WebVH document: {e}"
            ))
        })?;

        if doc != verified_doc {
            return Err(DIDCacheError::DIDError(format!(
                "WebVH document verification failed: the cache server's document does not \
                 match the document its log produces for DID {did}"
            )));
        }

        debug!("WebVH log verification passed for DID: {}", did);
        Ok(doc)
    }
}

/// The latest did:webvh log version this client has verified from the cache
/// server, per SCID: its number and its `versionId`.
///
/// A valid prefix of a did:webvh log verifies on its own, so a server could
/// answer with an older copy that leaves out a key rotation or the
/// deactivation. A log is accepted only if its last entry is not behind the
/// version recorded and it contains that version's entry unchanged; the
/// record then moves forward. Mirrors the did:scid source book's floor.
///
/// Only logs the cache server sends are recorded. A did:webvh resolved
/// locally (an answer without its log) is not: the resolver chain hands back
/// a document, not the log's version.
#[cfg(feature = "did-webvh")]
#[derive(Debug, Default)]
pub(crate) struct WebvhVersionFloor {
    seen: std::sync::Mutex<std::collections::HashMap<String, (u32, String)>>,
}

#[cfg(feature = "did-webvh")]
impl WebvhVersionFloor {
    /// Identities remembered; past this an arbitrary one is forgotten.
    const CAPACITY: usize = 100_000;

    fn scid(did: &str) -> Option<&str> {
        did.strip_prefix("did:webvh:")?
            .split([':', '?', '#'])
            .next()
            .filter(|scid| !scid.is_empty())
    }

    /// The `versionId` of each entry of a JSON Lines log, in order.
    fn version_ids(log: &str) -> Result<Vec<String>, DIDCacheError> {
        log.lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| {
                serde_json::from_str::<serde_json::Value>(line)
                    .ok()
                    .and_then(|entry| entry.get("versionId")?.as_str().map(str::to_string))
                    .ok_or_else(|| {
                        DIDCacheError::DIDError("a did:webvh log entry has no versionId".into())
                    })
            })
            .collect()
    }

    fn version_number(version_id: &str) -> Option<u32> {
        version_id.split_once('-')?.0.parse().ok()
    }

    #[cfg(all(test, feature = "agent-names"))]
    pub(crate) fn len(&self) -> usize {
        self.seen.lock().map(|seen| seen.len()).unwrap_or_default()
    }

    /// Check a verified log against the version recorded for its SCID, and
    /// record its last entry when it moves forward.
    pub(crate) fn accept(&self, did: &str, log: &str) -> Result<(), DIDCacheError> {
        let Some(scid) = Self::scid(did) else {
            return Ok(());
        };
        let version_ids = Self::version_ids(log)?;
        let Some(head) = version_ids.last() else {
            return Ok(());
        };
        let head_number = Self::version_number(head).ok_or_else(|| {
            DIDCacheError::DIDError(format!("invalid did:webvh versionId {head}"))
        })?;

        let Ok(mut seen) = self.seen.lock() else {
            return Err(DIDCacheError::DIDError(
                "the did:webvh version record is unavailable".into(),
            ));
        };
        if let Some((floor_number, floor_id)) = seen.get(scid) {
            if head_number < *floor_number {
                return Err(DIDCacheError::DIDError(format!(
                    "{did}: the cache server's log ends at version {head_number}, behind \
                     version {floor_number} already verified"
                )));
            }
            if !version_ids.contains(floor_id) {
                return Err(DIDCacheError::DIDError(format!(
                    "{did}: the cache server's log does not contain version {floor_id} \
                     already verified"
                )));
            }
            if head_number == *floor_number {
                return Ok(());
            }
        } else if seen.len() >= Self::CAPACITY
            && let Some(key) = seen.keys().next().cloned()
        {
            seen.remove(&key);
        }
        seen.insert(scid.to_string(), (head_number, head.clone()));
        Ok(())
    }
}

/// The document's `id` must be the DID that was resolved, without the DID
/// URL's path, query or fragment.
fn check_document_id(did: &DID, doc: &Document) -> Result<(), DIDCacheError> {
    let method = did.method();
    let expected = format!("did:{}:{}", method.name(), did.method_specific_id());
    if doc.id.as_str() == expected {
        Ok(())
    } else {
        Err(DIDCacheError::DIDError(format!(
            "The cache server's document for {expected} has id {}",
            doc.id.as_str()
        )))
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

/// Network mode checks what the cache server answers against the DID asked
/// for. Each test runs a loopback stand-in for the cache server that answers
/// with whatever the test hands it.
#[cfg(test)]
mod network_answer_tests {
    use super::*;
    use crate::{config::DIDCacheConfigBuilder, network_resolvers::HostPolicy};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tokio::{
        io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
        net::TcpListener,
        task::JoinHandle,
    };
    use web_socket::{DataType, Event, WebSocket};

    const DEADLINE: std::time::Duration = std::time::Duration::from_secs(20);
    const DID_KEY: &str = "did:key:z6MkiToqovww7vYtxm1xNM15u9JzqzUFZ1k7s7MazYJUyAxv";

    /// Called after each request with every request received so far on the
    /// connection; returns the frames to send back now.
    type Answer = Arc<dyn Fn(&[WSRequest]) -> Vec<WSResponseType> + Send + Sync>;

    /// A loopback cache server answering requests with `answer`.
    struct StandInServer {
        address: String,
        requests: Arc<AtomicUsize>,
        accept_task: JoinHandle<()>,
    }

    impl Drop for StandInServer {
        fn drop(&mut self) {
            self.accept_task.abort();
        }
    }

    impl StandInServer {
        async fn start(answer: Answer) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let requests = Arc::new(AtomicUsize::new(0));
            let counter = requests.clone();
            let accept_task = tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    tokio::spawn(Self::serve(stream, answer.clone(), counter.clone()));
                }
            });
            Self {
                address: format!("ws://127.0.0.1:{port}/did/v1/ws"),
                requests,
                accept_task,
            }
        }

        async fn serve(stream: tokio::net::TcpStream, answer: Answer, requests: Arc<AtomicUsize>) {
            let mut stream = BufReader::new(stream);
            let mut sec_key = None;
            loop {
                let mut line = String::new();
                if stream.read_line(&mut line).await.unwrap_or(0) == 0 {
                    return;
                }
                let line = line.trim_end();
                if line.is_empty() {
                    break;
                }
                if let Some((name, value)) = line.split_once(':')
                    && name.eq_ignore_ascii_case("sec-websocket-key")
                {
                    sec_key = Some(value.trim().to_string());
                }
            }
            let Some(sec_key) = sec_key else { return };
            let upgrade = format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
                 Sec-WebSocket-Accept: {}\r\n\r\n",
                handshake::accept_key_from(sec_key)
            );
            if stream.write_all(upgrade.as_bytes()).await.is_err() {
                return;
            }

            let mut socket = WebSocket::server(stream);
            let mut received = Vec::new();
            while let Ok(event) = socket.recv().await {
                match event {
                    Event::Data {
                        ty: DataType::Complete(_),
                        data,
                    } => {
                        let Ok(request) = serde_json::from_slice::<WSRequest>(&data) else {
                            continue;
                        };
                        requests.fetch_add(1, Ordering::SeqCst);
                        received.push(request);
                        for frame in answer(&received) {
                            let reply = serde_json::to_string(&frame).unwrap();
                            if socket.send(reply.as_str()).await.is_err() {
                                return;
                            }
                        }
                    }
                    Event::Ping(data) => {
                        let _ = socket.send_pong(data).await;
                    }
                    Event::Close { .. } => return,
                    _ => {}
                }
            }
        }

        fn requests(&self) -> usize {
            self.requests.load(Ordering::SeqCst)
        }
    }

    fn response(did: &str, hash_of: &str, document: Document) -> WSResponseType {
        WSResponseType::Response(Box::new(WSResponse::new(
            did,
            DIDCacheClient::hash_did(hash_of),
            document,
        )))
    }

    /// Answer each request, as it arrives, with `document` and `did_log`.
    fn answer_with(document: Document, did_log: Option<String>) -> Answer {
        Arc::new(move |received: &[WSRequest]| {
            let request = received.last().unwrap();
            vec![WSResponseType::Response(Box::new(
                WSResponse::new(
                    request.did.clone(),
                    DIDCacheClient::hash_did(&request.did),
                    document.clone(),
                )
                .with_logs(did_log.clone(), None),
            ))]
        })
    }

    async fn network_client(server: &StandInServer) -> DIDCacheClient {
        DIDCacheClient::new(
            DIDCacheConfigBuilder::default()
                .with_network_mode(&server.address)
                .with_host_policy(HostPolicy::AllowPrivate)
                .build(),
        )
        .await
        .unwrap()
    }

    async fn resolve(
        client: &DIDCacheClient,
        did: &str,
    ) -> Result<crate::ResolveResponse, DIDCacheError> {
        tokio::time::timeout(DEADLINE, client.resolve(did))
            .await
            .expect("resolution finishes within the deadline")
    }

    #[tokio::test]
    async fn a_did_web_answer_for_another_did_is_refused() {
        let did = "did:web:example.com";
        let server = StandInServer::start(answer_with(Document::new(DID_KEY).unwrap(), None)).await;
        let client = network_client(&server).await;

        let error = resolve(&client, did).await.expect_err("the id must match");
        assert!(error.to_string().contains(DID_KEY), "{error}");
        assert_eq!(server.requests(), 1);
        assert!(
            client
                .get_cache()
                .get(&DIDCacheClient::hash_did(did))
                .await
                .is_none(),
            "a refused answer is not cached"
        );
    }

    #[tokio::test]
    async fn a_did_web_answer_for_the_requested_did_is_accepted() {
        let did = "did:web:example.com";
        let server = StandInServer::start(answer_with(Document::new(did).unwrap(), None)).await;
        let client = network_client(&server).await;

        let response = resolve(&client, did).await.unwrap();
        assert_eq!(response.doc.id.as_str(), did);
        assert!(!response.cache_hit);
        assert_eq!(server.requests(), 1);
    }

    #[tokio::test]
    async fn a_did_url_is_checked_against_its_did() {
        let did = "did:web:example.com";
        let server = StandInServer::start(answer_with(Document::new(did).unwrap(), None)).await;
        let client = network_client(&server).await;

        let response = resolve(&client, &format!("{did}?service=files#key-1"))
            .await
            .unwrap();
        assert_eq!(response.doc.id.as_str(), did);
    }

    #[tokio::test]
    async fn did_key_is_derived_locally_without_asking_the_server() {
        let other = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
        let server = StandInServer::start(answer_with(Document::new(other).unwrap(), None)).await;
        let client = network_client(&server).await;

        let response = resolve(&client, DID_KEY).await.unwrap();
        assert_eq!(response.doc.id.as_str(), DID_KEY);
        assert!(!response.doc.verification_method.is_empty());
        assert_eq!(server.requests(), 0, "did:key is never asked of the server");
    }

    #[cfg(feature = "did-scid")]
    #[tokio::test]
    async fn did_scid_is_not_taken_from_the_server() {
        let did = "did:scid:vh:1:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai";
        let server = StandInServer::start(answer_with(Document::new(did).unwrap(), None)).await;
        let client = network_client(&server).await;

        // No source is known for this bare did:scid, so local resolution fails;
        // the server's unverifiable answer must not stand in for it.
        assert!(resolve(&client, did).await.is_err());
        assert_eq!(server.requests(), 0);
    }

    const WEB_A: &str = "did:web:a.example";
    const WEB_B: &str = "did:web:b.example";

    /// Once both requests are in, answer each with the other's document under
    /// its own hash.
    #[tokio::test]
    async fn answers_swapped_between_concurrent_requests_are_refused() {
        let server = StandInServer::start(Arc::new(|received: &[WSRequest]| {
            if received.len() < 2 {
                return vec![];
            }
            vec![
                response(WEB_A, WEB_A, Document::new(WEB_B).unwrap()),
                response(WEB_B, WEB_B, Document::new(WEB_A).unwrap()),
            ]
        }))
        .await;
        let client = network_client(&server).await;

        let (a, b) = tokio::join!(resolve(&client, WEB_A), resolve(&client, WEB_B));
        assert!(a.is_err(), "{a:?}");
        assert!(b.is_err(), "{b:?}");
        for did in [WEB_A, WEB_B] {
            assert!(
                client
                    .get_cache()
                    .get(&DIDCacheClient::hash_did(did))
                    .await
                    .is_none()
            );
        }
    }

    /// A's document sent under B's hash reaches B's waiter, which refuses it;
    /// A's own answer is unaffected.
    #[tokio::test]
    async fn an_answer_under_another_requests_hash_is_refused() {
        let server = StandInServer::start(Arc::new(|received: &[WSRequest]| {
            if received.len() < 2 {
                return vec![];
            }
            vec![
                response(WEB_A, WEB_B, Document::new(WEB_A).unwrap()),
                response(WEB_A, WEB_A, Document::new(WEB_A).unwrap()),
            ]
        }))
        .await;
        let client = network_client(&server).await;

        let (a, b) = tokio::join!(resolve(&client, WEB_A), resolve(&client, WEB_B));
        assert_eq!(a.unwrap().doc.id.as_str(), WEB_A);
        let error = b.expect_err("B received A's document");
        assert!(error.to_string().contains(WEB_A), "{error}");
    }

    /// A method network mode resolves locally is never asked of the server,
    /// even when this client has no resolver for it: it is unsupported, as in
    /// local mode.
    #[tokio::test]
    async fn a_local_method_without_a_resolver_is_unsupported() {
        let jwk = "did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9";
        let server = StandInServer::start(Arc::new(|received: &[WSRequest]| {
            let did = received.last().unwrap().did.clone();
            vec![response(&did, &did, Document::new(&did).unwrap())]
        }))
        .await;
        let mut client = network_client(&server).await;
        client.clear_resolvers(&MethodName::Jwk);
        client.clear_resolvers(&MethodName::Key);

        for did in [jwk, DID_KEY] {
            let error = resolve(&client, did).await.expect_err("no resolver");
            assert!(
                matches!(error, DIDCacheError::UnsupportedMethod(_)),
                "{did}: {error:?}"
            );
            assert!(
                client
                    .get_cache()
                    .get(&DIDCacheClient::hash_did(did))
                    .await
                    .is_none()
            );
        }
        assert_eq!(server.requests(), 0);
    }

    /// A document for an immutable method that came from the server is used
    /// but not kept: the cache would give it no expiry.
    #[tokio::test]
    async fn an_immutable_document_from_the_server_is_not_cached() {
        let did = "did:example:123";
        let server = StandInServer::start(answer_with(Document::new(did).unwrap(), None)).await;
        let client = network_client(&server).await;

        let response = resolve(&client, did).await.unwrap();
        assert_eq!(response.doc.id.as_str(), did);
        assert_eq!(server.requests(), 1);
        // Without the `did_example` feature this crate does not model did:example,
        // so it counts as mutable and is cached with the TTL instead.
        if !crate::is_mutable_did(did) {
            assert!(
                client
                    .get_cache()
                    .get(&DIDCacheClient::hash_did(did))
                    .await
                    .is_none()
            );
        }
    }

    #[cfg(feature = "agent-names")]
    mod agent_name {
        use super::*;
        use ::agent_names::{AgentName, AgentNameError, AgentNameResolver, NameResolution};
        use affinidi_did_common::DocumentBuilder;
        use std::{future::Future, pin::Pin};

        const NAME: &str = "https://bank.example/@bank";
        const GOOD: &str = "did:web:bank.example";
        const OTHER: &str = "did:web:elsewhere.example";

        /// The name's own backend: a fixed answer.
        struct FixedName(Option<&'static str>);

        impl AgentNameResolver for FixedName {
            fn name(&self) -> &str {
                "fixed"
            }

            fn resolve<'a>(
                &'a self,
                name: &'a AgentName,
            ) -> Pin<Box<dyn Future<Output = NameResolution> + Send + 'a>> {
                Box::pin(async move {
                    Some(
                        self.0
                            .map(str::to_string)
                            .ok_or_else(|| AgentNameError::Unresolvable(name.as_str().into())),
                    )
                })
            }
        }

        fn claiming_name(did: &str) -> Document {
            DocumentBuilder::new(did)
                .unwrap()
                .also_known_as_many([NAME])
                .build()
        }

        /// The server maps the name to OTHER, whose document claims the name;
        /// DID requests are answered with a document claiming the name.
        async fn setup(backend: Option<&'static str>) -> (StandInServer, DIDCacheClient) {
            let server = StandInServer::start(Arc::new(|received: &[WSRequest]| {
                let request = received.last().unwrap();
                if request.agent_name.is_some() {
                    vec![response(OTHER, &request.did, claiming_name(OTHER))]
                } else {
                    vec![response(
                        &request.did,
                        &request.did,
                        claiming_name(&request.did),
                    )]
                }
            }))
            .await;
            let mut client = DIDCacheClient::new(
                DIDCacheConfigBuilder::default()
                    .with_network_mode(&server.address)
                    .with_agent_names_over_websocket(true)
                    .build(),
            )
            .await
            .unwrap();
            client.set_agent_name_resolvers(vec![Box::new(FixedName(backend))]);
            (server, client)
        }

        #[tokio::test]
        async fn the_servers_mapping_is_only_a_hint() {
            let (server, client) = setup(Some(GOOD)).await;
            let name = AgentName::parse(NAME).unwrap();

            let response = tokio::time::timeout(DEADLINE, client.resolve_agent_name(&name))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(response.did, GOOD);
            assert_eq!(response.doc.id.as_str(), GOOD);
            assert!(response.shortcut.is_some());
            assert_eq!(
                client
                    .agent_name_cache
                    .get(&DIDCacheClient::hash_did(name.as_str()))
                    .await
                    .as_deref(),
                Some(GOOD)
            );
            assert!(
                client
                    .get_cache()
                    .get(&DIDCacheClient::hash_did(OTHER))
                    .await
                    .is_none(),
                "the document for the server's DID is not kept"
            );
            assert_eq!(server.requests(), 2, "the name, then the confirmed DID");
        }

        /// The server maps the name to a did:webvh with a valid log. Whether no
        /// backend confirms the name or one confirms another DID, the server's
        /// log is never verified, so no version is recorded for it.
        #[cfg(feature = "did-webvh")]
        #[tokio::test]
        async fn an_unconfirmed_hint_leaves_the_webvh_versions_unchanged() {
            let (webvh_did, log, webvh_doc) = super::webvh::signed_log(1).await;
            for backend in [None, Some(GOOD)] {
                let (hint, hint_doc, hint_log) =
                    (webvh_did.clone(), webvh_doc.clone(), log.clone());
                let server = StandInServer::start(Arc::new(move |received: &[WSRequest]| {
                    let request = received.last().unwrap();
                    if request.agent_name.is_some() {
                        vec![WSResponseType::Response(Box::new(
                            WSResponse::new(
                                hint.clone(),
                                DIDCacheClient::hash_did(&request.did),
                                hint_doc.clone(),
                            )
                            .with_logs(Some(hint_log.clone()), None),
                        ))]
                    } else {
                        vec![response(
                            &request.did,
                            &request.did,
                            claiming_name(&request.did),
                        )]
                    }
                }))
                .await;
                let mut client = DIDCacheClient::new(
                    DIDCacheConfigBuilder::default()
                        .with_network_mode(&server.address)
                        .with_agent_names_over_websocket(true)
                        .build(),
                )
                .await
                .unwrap();
                client.set_agent_name_resolvers(vec![Box::new(FixedName(backend))]);
                let name = AgentName::parse(NAME).unwrap();

                let result = tokio::time::timeout(DEADLINE, client.resolve_agent_name(&name))
                    .await
                    .unwrap();
                assert_eq!(result.is_ok(), backend.is_some(), "{backend:?}: {result:?}");
                assert_eq!(client.webvh_versions.len(), 0, "{backend:?}");
            }
        }

        #[tokio::test]
        async fn a_name_no_backend_confirms_is_refused() {
            let (_server, client) = setup(None).await;
            let name = AgentName::parse(NAME).unwrap();

            let result = tokio::time::timeout(DEADLINE, client.resolve_agent_name(&name))
                .await
                .unwrap();
            assert!(result.is_err(), "{result:?}");
            assert!(
                client
                    .agent_name_cache
                    .get(&DIDCacheClient::hash_did(name.as_str()))
                    .await
                    .is_none()
            );
            assert!(
                client
                    .get_cache()
                    .get(&DIDCacheClient::hash_did(OTHER))
                    .await
                    .is_none()
            );
        }
    }

    #[cfg(feature = "did-webvh")]
    #[test]
    fn a_webvh_log_behind_or_forking_from_the_version_verified_is_refused() {
        fn log(ids: &[&str]) -> String {
            ids.iter()
                .map(|id| format!(r#"{{"versionId":"{id}"}}"#))
                .collect::<Vec<_>>()
                .join("\n")
        }
        let did = "did:webvh:QmScid:example.com";
        let other = "did:webvh:QmOther:example.com";
        let floor = WebvhVersionFloor::default();

        floor.accept(did, &log(&["1-a", "2-b"])).unwrap();
        // Behind.
        assert!(floor.accept(did, &log(&["1-a"])).is_err());
        // Same head, or moving forward through it.
        floor.accept(did, &log(&["1-a", "2-b"])).unwrap();
        floor
            .accept(
                &format!("{did}?versionId=1-a"),
                &log(&["1-a", "2-b", "3-c"]),
            )
            .unwrap();
        // A fork that skips the verified version 3.
        assert!(
            floor
                .accept(did, &log(&["1-a", "2-b", "3-x", "4-d"]))
                .is_err()
        );
        assert!(floor.accept(did, &log(&["1-a", "2-b"])).is_err());
        // Another SCID is independent.
        floor.accept(other, &log(&["1-z"])).unwrap();
    }

    #[cfg(feature = "did-webvh")]
    mod webvh {
        use super::*;
        use affinidi_secrets_resolver::secrets::Secret;
        use didwebvh_rs::{
            DIDWebVHState, Multibase, log_entry::LogEntryMethods, parameters::Parameters,
        };
        use serde_json::json;
        use tokio::io::AsyncReadExt;

        /// A loopback HTTP listener serving `body` as `did.jsonl`.
        struct LogHost {
            accept_task: JoinHandle<()>,
        }

        impl Drop for LogHost {
            fn drop(&mut self) {
                self.accept_task.abort();
            }
        }

        fn serve_log(listener: TcpListener, body: String) -> LogHost {
            let accept_task = tokio::spawn(async move {
                while let Ok((mut stream, _)) = listener.accept().await {
                    let body = body.clone();
                    tokio::spawn(async move {
                        let mut request = [0u8; 4096];
                        let _ = stream.read(&mut request).await;
                        let response = format!(
                            "HTTP/1.1 200 OK\r\ncontent-type: text/jsonl\r\ncontent-length: {}\r\n\
                             connection: close\r\n\r\n{body}",
                            body.len()
                        );
                        let _ = stream.write_all(response.as_bytes()).await;
                    });
                }
            });
            LogHost { accept_task }
        }

        /// A signed did:webvh log hosted on loopback: (host, DID, log, document).
        async fn hosted_log() -> (LogHost, String, String, Document) {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let (did, log, document) = signed_log(port).await;
            (serve_log(listener, log.clone()), did, log, document)
        }

        /// A signed did:webvh log for `localhost:{port}`: (DID, log, document).
        pub(super) async fn signed_log(port: u16) -> (String, String, Document) {
            let mut key = Secret::generate_ed25519(None, None);
            let pk = key.get_public_keymultibase().unwrap();
            key.id = format!("did:key:{pk}#{pk}");
            let template = format!("did:webvh:{{SCID}}:localhost%3A{port}");
            let doc = json!({
                "id": template,
                "@context": ["https://www.w3.org/ns/did/v1"],
                "verificationMethod": [{
                    "id": format!("{template}#key-0"),
                    "type": "Multikey",
                    "publicKeyMultibase": pk,
                    "controller": template
                }],
                "authentication": [format!("{template}#key-0")],
            });
            let params = Parameters {
                update_keys: Some(Arc::new(vec![Multibase::new(pk)])),
                portable: Some(false),
                ..Default::default()
            };
            let mut state = DIDWebVHState::default();
            state
                .create_log_entry(None, &doc, &params, &key)
                .await
                .unwrap();
            let entry = &state.log_entries().last().unwrap().log_entry;
            let document: Document =
                serde_json::from_value(entry.get_did_document().unwrap()).unwrap();
            let log = state
                .log_entries()
                .iter()
                .map(|entry| serde_json::to_string(&entry.log_entry).unwrap())
                .collect::<Vec<_>>()
                .join("\n");
            let did = document.id.to_string();
            (did, log, document)
        }

        #[tokio::test]
        async fn an_answer_without_its_log_is_resolved_locally() {
            let (_host, did, _log, document) = hosted_log().await;
            let keyless = Document::new(&did).unwrap();
            let server = StandInServer::start(answer_with(keyless, None)).await;
            let client = network_client(&server).await;

            let response = resolve(&client, &did).await.unwrap();
            assert_eq!(server.requests(), 1);
            assert_eq!(
                response.doc, document,
                "the document comes from the log, not from the server's answer"
            );
        }

        #[tokio::test]
        async fn an_answer_whose_document_differs_from_its_log_is_refused() {
            let (_host, did, log, _document) = hosted_log().await;
            let keyless = Document::new(&did).unwrap();
            let server = StandInServer::start(answer_with(keyless, Some(log))).await;
            let client = network_client(&server).await;

            let error = resolve(&client, &did).await.expect_err("documents differ");
            assert!(error.to_string().contains("does not match"), "{error}");
        }

        /// The server first sends a log ending in a deactivation, then the same
        /// log without it. The shorter log verifies on its own; it is refused
        /// because it is behind the version already verified.
        #[tokio::test]
        async fn an_older_copy_of_a_log_cannot_drop_its_deactivation() {
            let mut key = Secret::generate_ed25519(None, None);
            let pk = key.get_public_keymultibase().unwrap();
            key.id = format!("did:key:{pk}#{pk}");
            let template = "did:webvh:{SCID}:localhost%3A1";
            let doc = json!({
                "id": template,
                "@context": ["https://www.w3.org/ns/did/v1"],
            });
            let params = Parameters {
                update_keys: Some(Arc::new(vec![Multibase::new(pk)])),
                portable: Some(false),
                ..Default::default()
            };
            let genesis_time = (chrono::Utc::now() - chrono::Duration::seconds(100)).fixed_offset();
            let mut state = DIDWebVHState::default();
            state
                .create_log_entry(Some(genesis_time), &doc, &params, &key)
                .await
                .unwrap();
            let genesis = state.log_entries()[0].log_entry.clone();
            let genesis_doc: Document =
                serde_json::from_value(genesis.get_did_document().unwrap()).unwrap();
            state.deactivate(&key).await.unwrap();
            let lines: Vec<String> = state
                .log_entries()
                .iter()
                .map(|entry| serde_json::to_string(&entry.log_entry).unwrap())
                .collect();
            let full = lines.join("\n");
            let prefix = lines[0].clone();
            let did = genesis_doc.id.to_string();

            let answers = Arc::new(AtomicUsize::new(0));
            let server = StandInServer::start(Arc::new(move |received: &[WSRequest]| {
                let request = received.last().unwrap();
                let log = if answers.fetch_add(1, Ordering::SeqCst) == 0 {
                    full.clone()
                } else {
                    prefix.clone()
                };
                vec![WSResponseType::Response(Box::new(
                    WSResponse::new(
                        request.did.clone(),
                        DIDCacheClient::hash_did(&request.did),
                        genesis_doc.clone(),
                    )
                    .with_logs(Some(log), None),
                ))]
            }))
            .await;
            let client = network_client(&server).await;

            let first = resolve(&client, &did).await.expect_err("deactivated");
            assert!(first.to_string().contains("deactivated"), "{first}");
            let second = resolve(&client, &did).await.expect_err("behind");
            assert!(second.to_string().contains("behind"), "{second}");
            assert_eq!(server.requests(), 2);
        }

        #[tokio::test]
        async fn an_answer_matching_its_log_is_accepted() {
            let (_host, did, log, document) = hosted_log().await;
            let server = StandInServer::start(answer_with(document.clone(), Some(log))).await;
            let client = network_client(&server).await;

            let response = resolve(&client, &did).await.unwrap();
            assert_eq!(response.doc, document);
            assert_eq!(server.requests(), 1);
        }
    }
}
