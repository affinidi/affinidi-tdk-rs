//! Trust Tasks framework consumer — handles inbound [Trust Task] documents
//! carried over the DIDComm binding envelope.
//!
//! A Trust Task request arrives as a DIDComm message whose `type` is the binding
//! envelope URI and whose `body` is the full `TrustTask<P>` document. This module
//! is the *single core*: it runs the framework's `consume_inbound` pipeline and
//! the per-task handlers (which delegate to the same `state.database.*` methods
//! the legacy DIDComm protocols use). The response is a `TrustTask<R>` packed back
//! through the mediator's existing outbound path — exactly like the trust-ping
//! pong — so no separate binding/agent plumbing is needed here.
//!
//! This first cut handles `messaging/ping`; account / acl / access-list follow.
//!
//! [Trust Task]: https://trusttasks.org

use affinidi_messaging_didcomm::message::Message;
use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_messaging_sdk::messages::compat::UnpackMetadata;
use affinidi_messaging_sdk::messages::problem_report::{ProblemReportScope, ProblemReportSorter};
use http::StatusCode;
use serde_json::Value;
use std::str::FromStr;
use trust_tasks_rs::specs::messaging::ping;
use trust_tasks_rs::{
    ConsumeOutcome, Payload, ProofPolicy, ProofVerifier, TransportContext, TransportHandler,
    TrustTask, TypeUri, VerificationError, consume_inbound,
};
use uuid::Uuid;

use crate::SharedData;
use crate::common::session::Session;
use crate::messages::{ProcessMessageResponse, WrapperType};

/// DIDComm `type` URI of a Trust Tasks binding envelope.
pub const ENVELOPE_TYPE: &str = "https://trusttasks.org/binding/didcomm/0.1/envelope";
/// Stable identifier for this transport binding.
const BINDING_URI: &str = "https://trusttasks.org/binding/didcomm/0.1";

/// The mediator's [`TransportHandler`] for one inbound exchange. The DIDComm
/// layer already verified the sender, so the framework's transport-authenticated
/// `issuer` is that DID and the `recipient` is the mediator.
struct MediatorTransport {
    mediator_did: String,
    sender_did: String,
}

impl TransportHandler for MediatorTransport {
    fn binding_uri(&self) -> &str {
        BINDING_URI
    }

    fn derive_parties(&self) -> TransportContext {
        TransportContext {
            issuer: Some(self.sender_did.clone()),
            recipient: Some(self.mediator_did.clone()),
        }
    }
}

/// No-op proof verifier — the management tasks are transport-authenticated, so
/// the consume pipeline runs with [`ProofPolicy::AcceptUnverified`] and this is
/// never invoked; it only satisfies the type parameter.
struct NoProof;

#[async_trait::async_trait]
impl ProofVerifier for NoProof {
    async fn verify<P>(&self, _doc: &TrustTask<P>) -> Result<(), VerificationError>
    where
        P: serde::Serialize + Send + Sync,
    {
        Ok(())
    }
}

/// Consume an inbound Trust Tasks envelope and produce the response.
pub(crate) async fn process(
    message: &Message,
    state: &SharedData,
    session: &Session,
    metadata: &UnpackMetadata,
) -> Result<ProcessMessageResponse, MediatorError> {
    let mediator_did = state.config.mediator_did.clone();

    // The DIDComm-verified sender (prefer the JWS signer, fall back to the
    // authcrypt sender), stripped of its key fragment → the framework VID.
    let sender_kid = metadata
        .sign_from
        .clone()
        .or_else(|| metadata.encrypted_from_kid.clone())
        .ok_or_else(|| {
            tt_problem(
                session,
                "message.trust_task.unauthenticated",
                "Trust Task envelopes require an authenticated sender".into(),
                StatusCode::BAD_REQUEST,
            )
        })?;
    let sender_did = sender_kid
        .split('#')
        .next()
        .unwrap_or(&sender_kid)
        .to_string();

    // The body is the full TrustTask document.
    let doc: TrustTask<Value> = serde_json::from_value(message.body.clone()).map_err(|e| {
        tt_problem(
            session,
            "message.trust_task.malformed",
            format!("body is not a Trust Task document: {e}"),
            StatusCode::BAD_REQUEST,
        )
    })?;

    let now_secs = state.clock.unix_secs();
    let now = chrono::DateTime::from_timestamp(now_secs as i64, 0).unwrap_or_else(chrono::Utc::now);

    // Route by task type. (PR-T1: ping only; the account/acl/access-list families
    // extend this match.)
    let ping_type =
        TypeUri::from_str(<ping::v0_1::Payload as Payload>::TYPE_URI).expect("valid const type URI");

    let response_value: Value = if doc.type_uri == ping_type {
        let typed: TrustTask<ping::v0_1::Payload> =
            serde_json::from_value(serde_json::to_value(&doc).map_err(serialize_err)?)
                .map_err(|e| {
                    tt_problem(
                        session,
                        "message.trust_task.malformed",
                        format!("not a valid ping payload: {e}"),
                        StatusCode::BAD_REQUEST,
                    )
                })?;

        match consume_ping(typed, &mediator_did, &sender_did, now).await? {
            Some(value) => value,
            // identity_mismatch with no transport sender → emit nothing.
            None => return Ok(ProcessMessageResponse::default()),
        }
    } else {
        return Err(tt_problem(
            session,
            "protocol.trust_task.unsupported",
            format!("unsupported Trust Task type: {}", doc.type_uri),
            StatusCode::NOT_IMPLEMENTED,
        ));
    };

    // Pack the response back through the mediator's existing outbound path.
    let response_msg = Message::build(Uuid::new_v4().to_string(), ENVELOPE_TYPE.to_string(), response_value)
        .to(sender_did)
        .from(mediator_did)
        .created_time(now_secs)
        .expires_time(now_secs + 300)
        .finalize();

    Ok(ProcessMessageResponse {
        store_message: true,
        force_live_delivery: false,
        data: WrapperType::Message(Box::new(response_msg)),
        forward_message: false,
    })
}

fn tt_problem(
    session: &Session,
    code: &str,
    message: String,
    status: StatusCode,
) -> MediatorError {
    MediatorError::problem(
        37,
        &session.session_id,
        None,
        ProblemReportSorter::Error,
        ProblemReportScope::Protocol,
        code,
        &message,
        vec![],
        status,
    )
}

fn serialize_err(e: serde_json::Error) -> MediatorError {
    MediatorError::InternalError(
        14,
        "NA".to_string(),
        format!("couldn't serialise Trust Task response: {e}"),
    )
}

/// Run the `ping` task through the framework's consume pipeline, returning the
/// response document as JSON (`None` when the framework suppresses the response).
async fn consume_ping(
    doc: TrustTask<ping::v0_1::Payload>,
    mediator_did: &str,
    sender_did: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Option<Value>, MediatorError> {
    let transport = MediatorTransport {
        mediator_did: mediator_did.to_string(),
        sender_did: sender_did.to_string(),
    };
    let outcome = consume_inbound(
        &transport,
        ProofPolicy::<NoProof>::AcceptUnverified,
        doc,
        mediator_did,
        now,
        || Uuid::new_v4().to_string(),
        |req, _parties| async move {
            let response = ping::v0_1::Response {
                ext: None,
                nonce: req.payload.nonce.clone(),
                protocols: vec!["didcomm".to_string(), "tsp".to_string()],
                server_time: now,
                status: ping::v0_1::ResponseStatus::Ok,
            };
            Ok(req.respond_with(Uuid::new_v4().to_string(), response))
        },
    )
    .await;

    Ok(match outcome {
        ConsumeOutcome::Handled(resp) => Some(serde_json::to_value(&resp).map_err(serialize_err)?),
        ConsumeOutcome::Rejected(err) => Some(serde_json::to_value(&err).map_err(serialize_err)?),
        ConsumeOutcome::Suppressed => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use trust_tasks_rs::TrustTask;

    #[tokio::test]
    async fn ping_consume_returns_ok_and_echoes_nonce() {
        let mut doc = TrustTask::for_payload(
            "urn:uuid:ping-1",
            ping::v0_1::Payload {
                nonce: Some("nonce-xyz".to_string()),
                ext: None,
            },
        );
        doc.issuer = Some("did:example:alice".to_string());
        doc.recipient = Some("did:example:mediator".to_string());

        let value =
            consume_ping(doc, "did:example:mediator", "did:example:alice", chrono::Utc::now())
                .await
                .expect("consume ok")
                .expect("a response, not suppressed");

        let resp: TrustTask<ping::v0_1::Response> =
            serde_json::from_value(value).expect("ping response document");
        assert!(matches!(resp.payload.status, ping::v0_1::ResponseStatus::Ok));
        assert_eq!(resp.payload.nonce.as_deref(), Some("nonce-xyz"));
        assert!(resp.payload.protocols.iter().any(|p| p == "tsp"));
        // respond_with swaps the parties: the mediator answers alice.
        assert_eq!(resp.issuer.as_deref(), Some("did:example:mediator"));
        assert_eq!(resp.recipient.as_deref(), Some("did:example:alice"));
    }
}
