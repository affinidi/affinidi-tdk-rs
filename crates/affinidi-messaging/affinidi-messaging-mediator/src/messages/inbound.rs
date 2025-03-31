use std::time::SystemTime;

use crate::{
    SharedData,
    database::session::Session,
    messages::{MessageHandler,  store::store_message},
};
use affinidi_messaging_didcomm::{Message, UnpackMetadata, UnpackOptions, envelope::MetaEnvelope};
use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_messaging_sdk::messages::{
    problem_report::{ProblemReport, ProblemReportScope, ProblemReportSorter},
    sending::InboundMessageResponse,
};
use http::StatusCode;
use sha256::digest;
use tracing::{Instrument, debug,  span};

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
                    session.session_id.to_string(),
                    None,
                    Box::new(ProblemReport::new(
                        ProblemReportSorter::Error,
                        ProblemReportScope::Protocol,
                        "unprocessable_content".into(),
                        "Outer DIDComm envelope could not be processed: Error({1}) : message: {2}"
                            .into(),
                        vec![e.to_string(), message.to_string()],
                        None,
                    )),
                    StatusCode::UNPROCESSABLE_ENTITY.as_u16(),
                    format!("Outer DIDComm envelope could not be processed: {e}"),
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
                                session.session_id.to_string(),
                                None,
                                Box::new(ProblemReport::new(
                                    ProblemReportSorter::Error,
                                    ProblemReportScope::Protocol,
                                    "unprocessable_content".into(),
                                    "Message could not be unpacked: Error({1}) : message: {2}"
                                        .into(),
                                    vec![e.to_string(), message.to_string()],
                                    None,
                                )),
                                StatusCode::UNPROCESSABLE_ENTITY.as_u16(),
                                format!("Message could not be unpacked: {e}"),
                            ));
                        }
                    };

                    debug!("message unpacked:\n{:#?}", msg);

                    // Allow anonymous (unsigned) messages?
                    if metadata.sign_from.is_none()
                        && state.config.security.block_anonymous_outer_envelope
                    {
                        return Err(MediatorError::MediatorError(
                            session.session_id.to_string(),
                            Some(msg.id),
                            Box::new(ProblemReport::new(
                                ProblemReportSorter::Error,
                                ProblemReportScope::Protocol,
                                "forbidden".into(),
                                "Anonymous messages sent to the mediator are NOT allowed: Message: {1}".into(),
                                vec![ message.to_string()],
                                None,
                            )),
                            StatusCode::FORBIDDEN.as_u16(),
                            "Anonymous messages sent to the mediator are NOT allowed".to_string(),
                        ));
                    }

                    // Does the signing key match the session DID?
                    if state.config.security.force_session_did_match {
                        match check_session_signing_match(session, &metadata.sign_from) {
                            Ok(_) => {}
                            Err(_) => {
                                return Err(MediatorError::MediatorError(
                                    session.session_id.to_string(),
                                    Some(msg.id),
                                    Box::new(ProblemReport::new(
                                        ProblemReportSorter::Error,
                                        ProblemReportScope::Protocol,
                                        "forbidden".into(),
                                        "Authenticated session and signing DID must match: session_did({1}) message.sign_from({2})".into(),
                                        vec![ session.did.to_string(), metadata.sign_from.unwrap_or("Anonymous".to_string())],
                                        None,
                                    )),
                                    StatusCode::FORBIDDEN.as_u16(),
                                    "Authenticated session and signing DID must match".to_string(),
                                ));
                            }
                        }
                    }

                    // Process the message
                    let response = match msg.process(state, session, &metadata).await {
                        Ok(response) => response,
                        Err(e) => return Err(MediatorError::MediatorError(
                            session.session_id.to_string(),
                            Some(msg.id),
                            Box::new(ProblemReport::new(
                                ProblemReportSorter::Error,
                                ProblemReportScope::Protocol,
                                "unprocessable_content".into(),
                                "Couldn't process plaintext message contents: error: ({1})".into(),
                                vec![ session.did.to_string(), metadata.sign_from.unwrap_or("Anonymous".to_string())],
                                None,
                            )),
                            StatusCode::UNPROCESSABLE_ENTITY.as_u16(),
                            format!("Couldn't process plaintext message contents: error: {e}"),
                        ))
                    };
                    debug!("message processed:\n{:#?}", response);
                    store_message(state, session, &response, &metadata).await
                } else {
                    // this is a direct delivery method
                    if !state.config.security.local_direct_delivery_allowed {
                        return Err(MediatorError::MediatorError(
                            session.session_id.to_string(),
                            None,
                            Box::new(ProblemReport::new(
                                ProblemReportSorter::Error,
                                ProblemReportScope::Protocol,
                                "forbidden".into(),
                                "Direct Delivery to a DID is forbidden. Must be wrapped in a forward envelope".into(),
                                vec![],
                                None,
                            )),
                            StatusCode::FORBIDDEN.as_u16(),
                            "Direct Delivery to a DID is forbidden. Must be wrapped in a forward envelope".to_string(),
                        ));
                    }

                    // Check that the recipient account is local to the mediator
                    if !state.database.account_exists(&digest(to_did)).await? {
                        return Err(MediatorError::MediatorError(
                            session.session_id.to_string(),
                            None,
                            Box::new(ProblemReport::new(
                                ProblemReportSorter::Error,
                                ProblemReportScope::Protocol,
                                "forbidden".into(),
                                "Direct Delivery Recipient does not exist on this Mediator".into(),
                                vec![],
                                None,
                            )),
                            StatusCode::FORBIDDEN.as_u16(),
                            "Direct Delivery Recipient does not exist on this Mediator".to_string(),
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
                            session.session_id.to_string(),
                            None,
                            Box::new(ProblemReport::new(
                                ProblemReportSorter::Error,
                                ProblemReportScope::Protocol,
                                "forbidden".into(),
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
                session.session_id.to_string(),
                None,
                Box::new(ProblemReport::new(
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "unprocessable_content".into(),
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
