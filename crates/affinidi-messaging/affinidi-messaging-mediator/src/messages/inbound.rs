use std::time::SystemTime;

use crate::{
    SharedData,
    database::session::Session,
    messages::{MessageHandler, error_response::generate_error_response, store::store_message},
};
use affinidi_messaging_didcomm::{Message, UnpackMetadata, UnpackOptions, envelope::MetaEnvelope};
use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_messaging_sdk::messages::{
    problem_report::{ProblemReport, ProblemReportScope, ProblemReportSorter},
    sending::InboundMessageResponse,
};
use sha256::digest;
use tracing::{Instrument, debug, info, span};

use super::{ProcessMessageResponse, WrapperType};

pub(crate) async fn handle_inbound(
    state: &SharedData,
    session: &Session,
    message: &str,
) -> Result<InboundMessageResponse, MediatorError> {
    let _span = span!(tracing::Level::DEBUG, "handle_inbound",);

    async move {
        let mut envelope = match MetaEnvelope::new(message, &state.did_resolver).await {
            Ok(envelope) => envelope,
            Err(e) => {
                return Err(MediatorError::ParseError(
                    session.session_id.clone(),
                    "Raw inbound DIDComm message".into(),
                    e.to_string(),
                ));
            }
        };

        match &envelope.to_did {
            Some(to_did) => {
                if to_did == &state.config.mediator_did {
                    // Message is to the mediator
                    let (msg, metadata) = match Message::unpack(
                        &mut envelope,
                        &state.did_resolver,
                        &*state.config.security.mediator_secrets,
                        &UnpackOptions {
                            crypto_operations_limit_per_message: state
                                .config
                                .limits
                                .crypto_operations_per_message,
                            ..UnpackOptions::default()
                        },
                    )
                    .await
                    {
                        Ok(ok) => ok,
                        Err(e) => {
                            return Err(MediatorError::MessageUnpackError(
                                session.session_id.clone(),
                                format!("Couldn't unpack incoming message. Reason: {}", e),
                            ));
                        }
                    };

                    debug!("message unpacked:\n{:#?}", msg);

                    // Allow anonymous (unsigned) messages?
                    if metadata.sign_from.is_none()
                        && state.config.security.block_anonymous_outer_envelope
                    {
                        let error = generate_error_response(state, session, &msg.id, ProblemReport::new(
                            ProblemReportSorter::Error,
                            ProblemReportScope::Protocol,
                            "unauthorized".into(),
                            "Anonymous messages sent to the mediator are NOT allowed".into(),
                            vec![], None
                        ), false)?;
                        return store_message(state, session, &error, &metadata).await;
                    }

                    // Does the signing key match the session DID?
                    if state.config.security.force_session_did_match {
                        match check_session_signing_match(session, &metadata.sign_from) {
                            Ok(_) => {}
                            Err(e) => {
                                let error = generate_error_response(state, session, &msg.id, ProblemReport::new(
                                    ProblemReportSorter::Error,
                                    ProblemReportScope::Protocol,
                                    "unauthorized".into(),
                                    "unauthorized to access Mediator Administration protocol. Session mismatch to admin DID!".into(),
                                    vec![e.to_string()], None
                                ), false)?;
                                return store_message(state, session, &error, &metadata).await;
                            },
                        }
                    }

                    // Process the message
                    let response = match msg.process(state, session, &metadata).await {
                        Ok(response) => response,
                        Err(e) => {
                            generate_error_response(state, session, &msg.id, ProblemReport::new(
                                ProblemReportSorter::Error,
                                ProblemReportScope::Protocol,
                                "inbound_processing_error".into(),
                                "An error occurred while handling inbound message: {1}".into(),
                                vec![e.to_string()], None
                            ), false)?
                        }
                    };
                    debug!("message processed:\n{:#?}", response);
                    store_message(state, session, &response, &metadata).await
                } else {
                    // this is a direct delivery method
                    if !state.config.security.local_direct_delivery_allowed {
                        return Err(MediatorError::PermissionError(
                            session.session_id.clone(),
                            "Direct delivery is not allowed".into(),
                        ));
                    }

                    // Check that the recipient account is local to the mediator
                    if !state.database.account_exists(&digest(to_did)).await? {
                        return Err(MediatorError::PermissionError(
                            session.session_id.clone(),
                            "Recipient is not local to the mediator".into(),
                        ));
                    }

                    // Check if the message will pass ACL Checks
                    let from_hash = envelope.from_did.as_ref().map(digest);
                    if !state
                        .database
                        .access_list_allowed(&digest(to_did), from_hash)
                        .await?
                    {
                        // Message is not allowed
                        info!(
                            "Message from {} to {} is not allowed",
                            envelope.from_did.clone().as_deref().unwrap_or("Unknown"),
                            to_did
                        );
                        return Err(MediatorError::ACLDenied(
                            "Message blocked due to ACL".into(),
                        ));
                    }

                    let data = ProcessMessageResponse {
                        store_message: true,
                        force_live_delivery: false,
                        forward_message: false,
                        data: WrapperType::Envelope(
                            to_did.into(),
                            message.into(),
                            SystemTime::now()
                                .duration_since(SystemTime::UNIX_EPOCH)
                                .unwrap()
                                .as_secs()
                                + state.config.limits.message_expiry_seconds,
                        ),
                    };

                    store_message(state, session, &data, &UnpackMetadata::default()).await
                }
            }
            _ => Err(MediatorError::ParseError(
                session.session_id.clone(),
                "to_did".into(),
                "Missing to_did in the envelope".into(),
            )),
        }
    }
    .instrument(_span)
    .await
}

/// Ensure the Session DID and the message signing DID match
fn check_session_signing_match(
    session: &Session,
    sign_from: &Option<String>,
) -> Result<(), MediatorError> {
    if let Some(sign_from) = sign_from {
        if let Some(sign_did) = sign_from.split_once('#') {
            if sign_did.0 == session.did {
                return Ok(());
            }
        }
    }
    Err(MediatorError::PermissionError(
        session.session_id.clone(),
        "Message signature does not match session DID".into(),
    ))
}
