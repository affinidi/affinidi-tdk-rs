use std::time::SystemTime;

use crate::{
    SharedData,
    database::session::Session,
    messages::{MessageHandler, store::store_message},
};
use affinidi_messaging_didcomm::{Message, UnpackMetadata, UnpackOptions, envelope::MetaEnvelope};
use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_messaging_sdk::messages::{
    problem_report::{ProblemReport, ProblemReportScope, ProblemReportSorter},
    sending::InboundMessageResponse,
};
use http::StatusCode;
use sha256::digest;
use tracing::{Instrument, debug, span};

use super::{ProcessMessageResponse, WrapperType};

pub(crate) async fn handle_inbound(
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
        let mut envelope = match MetaEnvelope::new(message, &state.did_resolver).await {
            Ok(envelope) => envelope,
            Err(e) => {
                return Err(MediatorError::MediatorError(
                    37,
                    session.session_id.to_string(),
                                        None,
                    Box::new(ProblemReport::new(
                        ProblemReportSorter::Error,
                        ProblemReportScope::Protocol,
                        "message.envelope.read".into(),
                        "Couldn't read DIDComm envelope: {1}".into(),
                        vec![e.to_string()],
                        None,
                    )),
                    StatusCode::BAD_REQUEST.as_u16(),
                    format!("Couldn't read DIDComm envelope: {}", e),
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
                            return Err(MediatorError::MediatorError(
                                32,
                                session.session_id.to_string(),
                                None,
                                Box::new(ProblemReport::new(
                                    ProblemReportSorter::Error,
                                    ProblemReportScope::Protocol,
                                    "message.unpack".into(),
                                    "Message unpack failed: envelope {1} Reason: {2}".into(),
                                    vec![message.to_string(), e.to_string()],
                                    None,
                                )),
                                StatusCode::FORBIDDEN.as_u16(),
                                format!("Message unpack failed. Reason: {}", e),
                            ));
                        }
                    };

                    debug!("message unpacked:\n{:#?}", msg);

                    // Allow anonymous (unsigned) messages?
                    if metadata.sign_from.is_none()
                        && state.config.security.block_anonymous_outer_envelope
                    {
                        return Err(MediatorError::MediatorError(
                            50,
                            session.session_id.to_string(),
                            Some(msg.id.clone()),
                            Box::new(ProblemReport::new(
                                ProblemReportSorter::Warning,
                                ProblemReportScope::Message,
                                "message.anonymous".into(),
                                "Mediator is not allowing anonymous messages".into(),
                                vec![],
                                None,
                            )),
                            StatusCode::BAD_REQUEST.as_u16(),
                            "Mediator is not allowing anonymous messages".to_string(),
                        ));
                    }

                    // Does the signing key match the session DID?
                    if state.config.security.force_session_did_match {
                        check_session_signing_match(session, &msg.id, &metadata.sign_from)?;
                    }

                    // Process the message
                    let response = msg.process(state, session, &metadata).await?;
                    debug!("message processed:\n{:#?}", response);
                    store_message(state, session, &response, &metadata).await
                } else {
                    // this is a direct delivery method
                    if !state.config.security.local_direct_delivery_allowed {
                        return Err(MediatorError::MediatorError(
                            71,
                            session.session_id.to_string(),
                            None,
                            Box::new(ProblemReport::new(
                                ProblemReportSorter::Warning,
                                ProblemReportScope::Message,
                                "direct_delivery.denied".into(),
                                "Mediator is not accepting direct delivery of DIDComm messages. They must be wrapped in a forwarding envelope".into(),
                                vec![],
                                None,
                            )),
                            StatusCode::FORBIDDEN.as_u16(),
                            "Mediator is not accepting direct delivery of DIDComm messages. They must be wrapped in a forwarding envelope".to_string(),
                        ));
                    }

                    // Check that the recipient account is local to the mediator
                    if !state.database.account_exists(&digest(to_did)).await? {
                        return Err(MediatorError::MediatorError(
                            72,
                            session.session_id.to_string(),
                            None,
                            Box::new(ProblemReport::new(
                                ProblemReportSorter::Warning,
                                ProblemReportScope::Message,
                                "direct_delivery.recipient.unknown".into(),
                                "Direct Delivery Recipient is not known on this Mediator".into(),
                                vec![],
                                None,
                            )),
                            StatusCode::FORBIDDEN.as_u16(),
                            "Direct Delivery Recipient is not known on this Mediator".to_string(),
                        ));
                    }

                    // Check if the message will pass ACL Checks
                    let from_hash = envelope.from_did.as_ref().map(digest);
                    if !state
                        .database
                        .access_list_allowed(&digest(to_did), from_hash)
                        .await?
                    {
                        return Err(MediatorError::MediatorError(
                            73,
                            session.session_id.to_string(),
                            None,
                            Box::new(ProblemReport::new(
                                ProblemReportSorter::Error,
                                ProblemReportScope::Protocol,
                                "authorization.access_list.denied".into(),
                                "Delivery blocked due to ACLs (access_list denied)".into(),
                                vec![],
                                None,
                            )),
                            StatusCode::FORBIDDEN.as_u16(),
                            "Delivery blocked due to ACLs (access_list denied)".to_string(),
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
            _ =>   Err(MediatorError::MediatorError(
                51,
                session.session_id.to_string(),
                None,
                Box::new(ProblemReport::new(
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "message.to".into(),
                    "There is no to_did on the envelope! Can't deliver an unknown message. Message: {1}".into(),
                    vec![message.to_string()],
                    None,
                )),
                StatusCode::UNPROCESSABLE_ENTITY.as_u16(),
                "There is no to_did on the envelope! Can't deliver an unknown message.".to_string(),
            ))
        }
    }
    .instrument(_span)
    .await
}

/// Ensure the Session DID and the message signing DID match
fn check_session_signing_match(
    session: &Session,
    msg_id: &str,
    sign_from: &Option<String>,
) -> Result<(), MediatorError> {
    if let Some(sign_from) = sign_from {
        if let Some(sign_did) = sign_from.split_once('#') {
            if sign_did.0 == session.did {
                return Ok(());
            }
        }
    }

    Err(MediatorError::MediatorError(
        52,
        session.session_id.to_string(),
        Some(msg_id.to_string()),
        Box::new(ProblemReport::new(
            ProblemReportSorter::Error,
            ProblemReportScope::Protocol,
            "authorization.did.session_mismatch".into(),
            "signing DID ({1}) doesn't match this sessions DID".into(),
            vec![
                sign_from
                    .clone()
                    .unwrap_or("Anonymous".to_string())
                    .to_string(),
            ],
            None,
        )),
        StatusCode::BAD_REQUEST.as_u16(),
        format!(
            "signing DID ({}) doesn't match this sessions DID",
            sign_from.clone().unwrap_or("Anonymous".to_string())
        ),
    ))
}
