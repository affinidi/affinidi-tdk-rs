#[cfg(feature = "didcomm")]
use crate::common::time::unix_timestamp_secs;
#[cfg(feature = "didcomm")]
use crate::didcomm_compat::{self, MetaEnvelope};
#[cfg(feature = "didcomm")]
use crate::messages::MessageHandler;
use crate::{SharedData, database::session::Session, messages::store::store_message};
use affinidi_messaging_mediator_common::errors::MediatorError;
#[cfg(feature = "didcomm")]
use affinidi_messaging_sdk::messages::compat::UnpackMetadata;
use affinidi_messaging_sdk::messages::{
    problem_report::{ProblemReportScope, ProblemReportSorter},
    sending::InboundMessageResponse,
};
use http::StatusCode;
#[cfg(feature = "didcomm")]
use sha256::digest;
use tracing::{Instrument, debug, span};

use super::{ProcessMessageResponse, WrapperType};

pub(crate) async fn handle_inbound(
    state: &SharedData,
    session: &Session,
    message: &str,
) -> Result<InboundMessageResponse, MediatorError> {
    // Try DIDComm first if enabled
    #[cfg(feature = "didcomm")]
    {
        return handle_inbound_didcomm(state, session, message).await;
    }

    // If only TSP is enabled, we don't support text-based inbound yet
    #[cfg(not(feature = "didcomm"))]
    {
        Err(MediatorError::problem(
            37,
            &session.session_id,
            None,
            ProblemReportSorter::Error,
            ProblemReportScope::Protocol,
            "protocol.unsupported",
            "No protocol handler available for this message format",
            vec![],
            StatusCode::BAD_REQUEST,
        ))
    }
}

#[cfg(feature = "didcomm")]
async fn handle_inbound_didcomm(
    state: &SharedData,
    session: &Session,
    message: &str,
) -> Result<InboundMessageResponse, MediatorError> {
    let _span = span!(
        tracing::Level::DEBUG,
        "handle_inbound",
        session = &session.session_id
    );

    async move {
        let envelope = match MetaEnvelope::new(message, &state.did_resolver).await {
            Ok(envelope) => envelope,
            Err(e) => {
                return Err(MediatorError::problem_with_log(
                    37,
                    &session.session_id,
                    None,
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "message.envelope.read",
                    "Couldn't read DIDComm envelope: {1}",
                    vec![e.to_string()],
                    StatusCode::BAD_REQUEST,
                    format!("Couldn't read DIDComm envelope: {e}"),
                ));
            }
        };

        match &envelope.to_did {
            Some(to_did) => {
                if to_did == &state.config.mediator_did {
                    // Message is to the mediator
                    let (msg, metadata) = match didcomm_compat::unpack(
                        message,
                        &state.did_resolver,
                        &*state.config.security.mediator_secrets,
                    )
                    .await
                    {
                        Ok(ok) => ok,
                        Err(e) => {
                            return Err(MediatorError::problem_with_log(
                                32,
                                &session.session_id,
                                None,
                                ProblemReportSorter::Error,
                                ProblemReportScope::Protocol,
                                "message.unpack",
                                "Message unpack failed: envelope {1} Reason: {2}",
                                vec![message.to_string(), e.to_string()],
                                StatusCode::FORBIDDEN,
                                format!("Message unpack failed. Reason: {e}"),
                            ));
                        }
                    };

                    debug!(
                        id = msg.id,
                        typ = msg.typ,
                        from = msg.from.as_deref().unwrap_or("anon"),
                        "Message unpacked"
                    );

                    // Block truly anonymous messages (no sender authentication).
                    // A message is considered authenticated if EITHER:
                    // - authcrypt (ECDH-1PU) was used (metadata.authenticated == true), OR
                    // - a JWS signature is present (metadata.sign_from.is_some())
                    if !metadata.authenticated
                        && metadata.sign_from.is_none()
                        && state.config.security.block_anonymous_outer_envelope
                    {
                        return Err(MediatorError::problem(
                            50,
                            &session.session_id,
                            Some(msg.id.clone()),
                            ProblemReportSorter::Warning,
                            ProblemReportScope::Message,
                            "message.anonymous",
                            "Mediator is not allowing anonymous messages (no authcrypt or JWS signature)",
                            vec![],
                            StatusCode::BAD_REQUEST,
                        ));
                    }

                    // Does the sender identity match the session DID?
                    // The sender can be identified by JWS signing (sign_from) or
                    // authcrypt encryption (encrypted_from_kid).
                    if state.config.security.force_session_did_match {
                        let sender_kid =
                            metadata.sign_from.as_ref().or(metadata.encrypted_from_kid.as_ref());
                        check_session_sender_match(session, &msg.id, &sender_kid)?;
                    }

                    // Process the message
                    let response = msg.process(state, session, &metadata).await?;
                    debug!("Message processed successfully");
                    store_message(state, session, &response, &metadata).await
                } else {
                    // this is a direct delivery method
                    if !state.config.security.local_direct_delivery_allowed {
                        return Err(MediatorError::problem(
                            71,
                            &session.session_id,
                            None,
                            ProblemReportSorter::Warning,
                            ProblemReportScope::Message,
                            "direct_delivery.denied",
                            "Mediator is not accepting direct delivery of DIDComm messages. They must be wrapped in a forwarding envelope",
                            vec![],
                            StatusCode::FORBIDDEN,
                        ));
                    }

                    // Check that the recipient account is local to the mediator
                    if !state.database.account_exists(&digest(to_did)).await? {
                        return Err(MediatorError::problem(
                            72,
                            &session.session_id,
                            None,
                            ProblemReportSorter::Warning,
                            ProblemReportScope::Message,
                            "direct_delivery.recipient.unknown",
                            "Direct Delivery Recipient is not known on this Mediator",
                            vec![],
                            StatusCode::FORBIDDEN,
                        ));
                    }

                    let from_hash = envelope.from_did.as_ref().map(digest);
                    // Check if the message will pass ACL Checks
                    if let Some(from) = &envelope.from_did {
                        let from_acls = if let Some(acl) = state
                            .database
                            .get_did_acl(&digest(from))
                            .await? {
                                acl
                        } else {
                            state.config.security.global_acl_default.clone()
                        };

                        if !from_acls.get_send_messages().0 {
                            return Err(MediatorError::problem(
                                44,
                                &session.session_id,
                                None,
                                ProblemReportSorter::Error,
                                ProblemReportScope::Protocol,
                                "authorization.send",
                                "Sender DID is not authorized to send messages through this mediator",
                                vec![],
                                StatusCode::FORBIDDEN,
                            ));
                        }
                    } else if !state.config.security.local_direct_delivery_allow_anon {
                        return Err(MediatorError::problem(
                            50,
                            &session.session_id,
                            None,
                            ProblemReportSorter::Warning,
                            ProblemReportScope::Message,
                            "message.anonymous",
                            "Anonymous direct delivery is not allowed by this mediator",
                            vec![],
                            StatusCode::FORBIDDEN,
                        ));
                    }
                    if !state
                        .database
                        .access_list_allowed(&digest(to_did), from_hash.as_deref())
                        .await
                    {
                        return Err(MediatorError::problem(
                            73,
                            &session.session_id,
                            None,
                            ProblemReportSorter::Error,
                            ProblemReportScope::Protocol,
                            "authorization.access_list.denied",
                            "Delivery blocked due to ACLs (access_list denied)",
                            vec![],
                            StatusCode::FORBIDDEN,
                        ));
                    }

                    let data = ProcessMessageResponse {
                        store_message: true,
                        force_live_delivery: false,
                        forward_message: false,
                        data: WrapperType::Envelope(
                            to_did.into(),
                            message.into(),
                            unix_timestamp_secs()
                                + state.config.limits.message_expiry_seconds,
                        ),
                    };

                    debug!("Direct delivery message from({:?}) to({}) msg_hash({})", envelope.from_did, to_did, envelope.sha256_hash);

                    store_message(state, session, &data, &UnpackMetadata::default()).await
                }
            }
            _ =>   Err(MediatorError::problem_with_log(
                51,
                &session.session_id,
                None,
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "message.to",
                "There is no to_did on the envelope! Can't deliver an unknown message. Message: {1}",
                vec![message.to_string()],
                StatusCode::UNPROCESSABLE_ENTITY,
                "There is no to_did on the envelope! Can't deliver an unknown message.",
            ))
        }
    }
    .instrument(_span)
    .await
}

/// Ensure the Session DID and the message sender DID match.
/// The sender can be identified by either a JWS signature (`sign_from`)
/// or authcrypt encryption (`encrypted_from_kid`). Both are key IDs
/// in the form `did:...#key-N` — the DID is extracted from the fragment.
#[cfg(feature = "didcomm")]
fn check_session_sender_match(
    session: &Session,
    msg_id: &str,
    sender_kid: &Option<&String>,
) -> Result<(), MediatorError> {
    if let Some(kid) = sender_kid
        && let Some((did, _fragment)) = kid.split_once('#')
        && did == session.did
    {
        return Ok(());
    }

    let sender_display = sender_kid.map(|s| s.as_str()).unwrap_or("anonymous");

    Err(MediatorError::problem_with_log(
        52,
        &session.session_id,
        Some(msg_id.to_string()),
        ProblemReportSorter::Error,
        ProblemReportScope::Protocol,
        "authorization.did.session_mismatch",
        "Sender DID ({1}) doesn't match session DID",
        vec![sender_display.to_string()],
        StatusCode::BAD_REQUEST,
        format!("Sender DID ({sender_display}) doesn't match session DID"),
    ))
}
