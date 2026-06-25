#[cfg(feature = "tsp")]
use crate::messages::inbound::handle_inbound_tsp;
use crate::{
    SharedData,
    common::authz::{self, Capability},
    common::jwt_auth::MaybeSession,
    messages::inbound::handle_inbound,
};
use affinidi_messaging_mediator_common::errors::{AppError, MediatorError, SuccessResponse};
use affinidi_messaging_sdk::messages::{
    problem_report::{ProblemReportScope, ProblemReportSorter},
    sending::InboundMessageResponse,
};
use axum::{Json, body::Bytes, extract::State};
use http::StatusCode;
use serde::{Deserialize, Serialize};
use tracing::{Instrument, Level, span};

use crate::common::metrics::names;

#[derive(Serialize, Deserialize, Debug)]
pub struct RecipientHeader {
    pub kid: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Recipient {
    pub header: RecipientHeader,
    pub encrypted_key: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct InboundMessage {
    pub protected: String,
    pub recipients: Vec<Recipient>,
    pub iv: String,
    pub ciphertext: String,
    pub tag: String,
}

/// Handles inbound messages to the mediator.
///
/// Authenticated (JWT Bearer) requests are always accepted. Anonymous requests
/// — used by remote mediator ForwardingProcessors for inter-mediator relay —
/// are accepted only when the mediator is configured as a relay (global default
/// ACL grants `SEND_FORWARDED`); otherwise they are rejected like any other
/// unauthenticated request. Such anonymous sessions carry only a minimal
/// relay-scoped ACL (`SEND_MESSAGES` + `SEND_FORWARDED`), not the full global
/// default. See `MaybeSession`.
///
/// ACL_MODE: Requires SEND_MESSAGES in the session ACL (checked below).
/// Forwarded relay and direct delivery additionally enforce per-sender /
/// per-recipient ACLs downstream in `routing.rs` and `inbound.rs`.
pub async fn message_inbound_handler(
    MaybeSession(session): MaybeSession,
    State(state): State<SharedData>,
    body: Bytes,
) -> Result<(StatusCode, Json<SuccessResponse<InboundMessageResponse>>), AppError> {
    let _span = span!(
        Level::DEBUG,
        "message_inbound_handler",
        session = session.session_id
    );
    async move {
        // ACL Check — applies to both protocols.
        if authz::require_capability(&session.acls, Capability::SendMessages).is_err() {
            metrics::counter!(names::ACL_DENIALS_TOTAL, "action" => "send").increment(1);
            return Err(MediatorError::problem(
                44,
                session.session_id,
                None,
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "authorization.send",
                "DID isn't allowed to send messages through this mediator",
                vec![],
                StatusCode::FORBIDDEN,
            )
            .into());
        }

        // Protocol sniff: a TSP message leads with the CESR `1AAF` magic byte
        // (0xD4); a DIDComm JWE/JWS is JSON (`{` / `ey…`). Only compiled into a
        // dual didcomm+tsp build. DIDComm bytes fall through to the unchanged path.
        #[cfg(feature = "tsp")]
        if affinidi_tsp::is_tsp(&body) {
            let response = handle_inbound_tsp(&state, &session, &body).await?;
            return Ok((
                StatusCode::OK,
                Json(SuccessResponse {
                    session_id: session.session_id,
                    http_code: StatusCode::OK.as_u16(),
                    error_code: 0,
                    error_code_str: "NA".to_string(),
                    message: "Success".to_string(),
                    data: Some(response),
                }),
            ));
        }

        // DIDComm: parse the JWE envelope, then re-serialise it to the exact
        // canonical string used historically (the `Json<InboundMessage>`
        // extractor parsed then the handler `to_string`'d it). Re-creating that
        // canonical form here keeps the stored blob and its sha256 message-id
        // byte-identical for existing DIDComm clients.
        let body: InboundMessage = serde_json::from_slice(&body).map_err(|e| {
            MediatorError::problem_with_log(
                19,
                session.session_id.clone(),
                None,
                ProblemReportSorter::Warning,
                ProblemReportScope::Message,
                "message.deserialize",
                "Couldn't parse DIDComm message envelope. Reason: {1}",
                vec![e.to_string()],
                StatusCode::BAD_REQUEST,
                "Couldn't parse DIDComm message envelope",
            )
        })?;

        let s = match serde_json::to_string(&body) {
            Ok(s) => s,
            Err(e) => {
                return Err(MediatorError::problem_with_log(
                    19,
                    session.session_id,
                    None,
                    ProblemReportSorter::Warning,
                    ProblemReportScope::Message,
                    "message.serialize",
                    "Couldn't serialize DIDComm message envelope. Reason: {1}",
                    vec![e.to_string()],
                    StatusCode::BAD_REQUEST,
                    "Couldn't serialize DIDComm message envelope",
                )
                .into());
            }
        };

        metrics::counter!(names::MESSAGES_INBOUND_TOTAL).increment(1);
        metrics::counter!(names::MESSAGE_BYTES_INBOUND_TOTAL).increment(s.len() as u64);

        let response = handle_inbound(&state, &session, &s).await?;

        Ok((
            StatusCode::OK,
            Json(SuccessResponse {
                session_id: session.session_id,
                http_code: StatusCode::OK.as_u16(),
                error_code: 0,
                error_code_str: "NA".to_string(),
                message: "Success".to_string(),
                data: Some(response),
            }),
        ))
    }
    .instrument(_span)
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha256::digest;

    fn sample() -> InboundMessage {
        InboundMessage {
            protected: "eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLWVuY3J5cHRlZCtqc29uIn0".to_string(),
            recipients: vec![Recipient {
                header: RecipientHeader {
                    kid: "did:example:bob#key-1".to_string(),
                },
                encrypted_key: "encrypted-key-value".to_string(),
            }],
            iv: "iv-value".to_string(),
            ciphertext: "ciphertext-value".to_string(),
            tag: "tag-value".to_string(),
        }
    }

    /// Regression guard for the `/inbound` switch from `Json<InboundMessage>` to
    /// raw `Bytes`. The DIDComm branch now does `from_slice` + `to_string`; this
    /// MUST yield the exact canonical string the old extractor + `to_string`
    /// produced, so the stored blob and its sha256 message-id are byte-identical
    /// for existing DIDComm clients — independent of how the client formatted the
    /// JSON on the wire (compact, pretty, or with surrounding whitespace).
    #[test]
    fn didcomm_canonicalization_is_stable_and_format_independent() {
        let msg = sample();
        // The canonical stored form: `to_string` of the parsed envelope, exactly
        // as the historical handler produced from the `Json`-extracted body.
        let canonical = serde_json::to_string(&msg).unwrap();
        let canonical_id = digest(canonical.as_bytes());

        for wire in [
            serde_json::to_string(&msg).unwrap(),        // compact
            serde_json::to_string_pretty(&msg).unwrap(), // pretty-printed
            format!("  {}\n", serde_json::to_string(&msg).unwrap()), // surrounding whitespace
        ] {
            // Exactly what the handler now does for the DIDComm branch.
            let parsed: InboundMessage = serde_json::from_slice(wire.as_bytes()).unwrap();
            let stored = serde_json::to_string(&parsed).unwrap();

            assert_eq!(
                stored, canonical,
                "stored blob must be the canonical form regardless of wire formatting"
            );
            // The store keys the message by sha256(stored_bytes); it must not move.
            assert_eq!(digest(stored.as_bytes()), canonical_id);
        }
    }

    /// `InboundMessage` round-trips through serde without altering field order,
    /// so re-serialisation is idempotent (a second store of the same message is
    /// deduplicated by id).
    #[test]
    fn inbound_message_serialisation_is_idempotent() {
        let s = serde_json::to_string(&sample()).unwrap();
        let back: InboundMessage = serde_json::from_str(&s).unwrap();
        assert_eq!(serde_json::to_string(&back).unwrap(), s);
    }
}
