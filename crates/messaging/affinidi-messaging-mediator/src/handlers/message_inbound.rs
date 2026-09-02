#[cfg(feature = "tsp")]
use crate::messages::inbound::handle_inbound_tsp;
use crate::{
    SharedData,
    common::authz::{self, Capability},
    common::jwt_auth::MaybeSession,
    messages::inbound::handle_inbound,
};
use affinidi_messaging_mediator_common::errors::{AppError, MediatorError, SuccessResponse};
use affinidi_messaging_sdk::messages::problem_report::{ProblemReportScope, ProblemReportSorter};
use axum::{
    Json,
    body::Bytes,
    extract::State,
    response::{IntoResponse, Response},
};
use http::StatusCode;
use serde::{Deserialize, Serialize};
use tracing::{Instrument, Level, span};

use crate::common::metrics::names;

/// Content type for a raw DIDComm v1 envelope returned via Aries return-route.
///
/// Credo sniffs the body structure rather than trusting this header, but a
/// truthful content type keeps proxies and logs from treating the reply as
/// generic JSON.
#[cfg(feature = "didcomm-v1")]
const DIDCOMM_V1_CONTENT_TYPE: &str = "application/ssi-agent-wire";

/// Does `bytes` lead with the TSP magic byte?
///
/// Compiled only into a build *without* the `tsp` feature, where
/// `affinidi_tsp::is_tsp` is unavailable — which is precisely the build that
/// needs to recognise a frame it cannot process. Recognising takes one byte;
/// only processing needs the stack. Same split, and same reasoning, as
/// `affinidi_messaging_sdk::tsp_wire` applies on the client side.
///
/// The byte comes from `affinidi_messaging_sdk::TSP_MAGIC_BYTE` rather than a
/// local copy, so this adds no third definition to drift: the SDK already pins
/// its copy against `affinidi_tsp` with a test. Reusing the published constant
/// is also what keeps this change to one crate — a new SDK helper could not be
/// depended on until it was released, which `cargo publish --dry-run` catches
/// as an unsatisfiable requirement.
#[cfg(not(feature = "tsp"))]
pub(crate) fn looks_like_tsp_bytes(bytes: &[u8]) -> bool {
    // Both framings: Rev 3 widened the `-E` count to cover the ciphertext, so a
    // message over roughly 12 KB is framed `--E#####` and leads with the long
    // byte instead. Recognising only the short one drops exactly the large
    // messages.
    matches!(
        bytes.first(),
        Some(&affinidi_messaging_sdk::TSP_MAGIC_BYTE)
            | Some(&affinidi_messaging_sdk::TSP_MAGIC_BYTE_LONG)
    )
}

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
) -> Result<Response, AppError> {
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

        // Recognising a TSP frame and processing one are different jobs (see
        // `affinidi_messaging_sdk::tsp_wire`): processing needs the whole TSP
        // stack, recognising needs one byte. So the *classification* below is
        // unconditional and only the handling is gated — a build without the
        // feature can still say what it received.
        //
        // Without this arm, a CESR frame fell through to the DIDComm JSON parse
        // and came back as `w.m.message.deserialize` / "expected value at line 1
        // column 1". That answer names DIDComm, never TSP, and never the missing
        // feature; it reads as a malformed message from a broken client. It cost
        // a downstream deployment an hour, chasing a *different* mediator —
        // because a TSP send posts to the sender's own mediator while the error
        // the client surfaces names the recipient's advertised one.
        #[cfg(not(feature = "tsp"))]
        if looks_like_tsp_bytes(&body) {
            return Err(MediatorError::problem(
                37,
                session.session_id,
                None,
                ProblemReportSorter::Error,
                ProblemReportScope::Message,
                "message.tsp.unsupported",
                "This is a well-formed TSP message, but this mediator was built \
                 without TSP support (cargo feature `tsp`). Rebuild it with \
                 `--features didcomm,tsp` to accept TSP traffic.",
                vec![],
                StatusCode::BAD_REQUEST,
            )
            .into());
        }

        // Protocol sniff: a TSP message leads with the CESR `-E` magic byte
        // (0xF8); a DIDComm JWE/JWS is JSON (`{` / `ey…`). Only compiled into a
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
            )
                .into_response());
        }

        // DIDComm v1 (Aries RFC 0019). Sniffed before the v2 parse because a v1
        // envelope has no top-level `recipients` and would otherwise fail the v2
        // deserialise with a misleading error. See `is_didcomm_v1`.
        #[cfg(feature = "didcomm-v1")]
        {
            let is_v1 = crate::messages::inbound_v1::is_didcomm_v1(&body);

            // A session admitted *only* by `allow_unauthenticated_forwards` is
            // scoped to v1: anything else on it is refused here, so opening the
            // door for Aries wallets does not also open anonymous v2 inbound.
            if session.session_id == crate::common::jwt_auth::ANON_V1_SESSION_ID && !is_v1 {
                return Err(MediatorError::problem(
                    44,
                    session.session_id,
                    None,
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "authorization.authentication_required",
                    "Anonymous inbound is accepted only for DIDComm v1 forwards on this mediator",
                    vec![],
                    StatusCode::UNAUTHORIZED,
                )
                .into());
            }

            if is_v1 {
                let raw = std::str::from_utf8(&body).map_err(|e| {
                    MediatorError::problem(
                        19,
                        session.session_id.clone(),
                        None,
                        ProblemReportSorter::Warning,
                        ProblemReportScope::Message,
                        "message.deserialize",
                        "DIDComm v1 envelope is not valid UTF-8. Reason: {1}",
                        vec![e.to_string()],
                        StatusCode::BAD_REQUEST,
                    )
                })?;

                metrics::counter!(names::MESSAGES_INBOUND_TOTAL).increment(1);
                metrics::counter!(names::MESSAGE_BYTES_INBOUND_TOTAL).increment(raw.len() as u64);

                let outcome =
                    crate::messages::inbound_v1::handle_inbound_didcomm_v1(&state, &session, raw)
                        .await?;

                return Ok(match outcome {
                    // A routed forward answers like any other stored message.
                    crate::messages::inbound_v1::V1Outcome::Stored(response) => (
                        StatusCode::OK,
                        Json(SuccessResponse {
                            session_id: session.session_id,
                            http_code: StatusCode::OK.as_u16(),
                            error_code: 0,
                            error_code_str: "NA".to_string(),
                            message: "Success".to_string(),
                            data: Some(response),
                        }),
                    )
                        .into_response(),

                    // A protocol reply goes back as the raw packed envelope —
                    // Aries' return-route, which the client parses as an
                    // inbound message. See `V1Outcome::Reply`.
                    crate::messages::inbound_v1::V1Outcome::Reply(packed) => (
                        StatusCode::OK,
                        [(http::header::CONTENT_TYPE, DIDCOMM_V1_CONTENT_TYPE)],
                        packed,
                    )
                        .into_response(),
                });
            }
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
        )
            .into_response())
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
