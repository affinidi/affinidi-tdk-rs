use std::time::SystemTime;

use crate::database::Database;
use crate::database::session::Session;
use crate::messages::MessageHandler;
use crate::{SharedData, messages::PackOptions};
use affinidi_messaging_didcomm::{PackEncryptedMetadata, UnpackMetadata};
use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_messaging_sdk::messages::problem_report::{
    ProblemReport, ProblemReportScope, ProblemReportSorter,
};
use affinidi_messaging_sdk::messages::sending::{InboundMessageList, InboundMessageResponse};
use http::StatusCode;
use sha256::digest;
use tracing::{Instrument, debug, error, span, trace, warn};

use super::{ProcessMessageResponse, WrapperType};

async fn _store_message(
    state: &SharedData,
    session: &Session,
    response: &ProcessMessageResponse,
    data: &str,
    to_did_hash: &str,
    from_did_hash: Option<&str>,
    expiry: u64,
) -> Result<String, MediatorError> {
    // Live stream the message?
    if let Some(stream_uuid) = state
        .database
        .streaming_is_client_live(to_did_hash, response.force_live_delivery)
        .await
    {
        _live_stream(
            &state.database,
            to_did_hash,
            &stream_uuid,
            data,
            response.force_live_delivery,
        )
        .await;
    }

    state
        .database
        .store_message(
            &session.session_id,
            data,
            to_did_hash,
            from_did_hash,
            expiry,
        )
        .await
}

/// Stores a message in the mediator's database
/// handles a lot of higher order logic for storing messages
/// - state: SharedData
/// - session: Session
/// - response: ProcessMessageResponse
/// - metadata: UnpackMetadata
pub(crate) async fn store_message(
    state: &SharedData,
    session: &Session,
    response: &ProcessMessageResponse,
    metadata: &UnpackMetadata,
) -> Result<InboundMessageResponse, MediatorError> {
    let _span = span!(tracing::Level::DEBUG, "store_message",);

    async move {
        if response.forward_message {
            Ok(InboundMessageResponse::Forwarded)
        } else if response.store_message {
            let mut stored_messages = InboundMessageList::default();
            match &response.data {
                WrapperType::None => {}
                WrapperType::Message(message) => {
                    // Pack the message for the next recipient(s)
                    let Some(to_dids) = &message.to else {
                        return Err(MediatorError::MediatorError(
                            75,
                            session.session_id.clone(),
                            Some(message.id.to_string()),
                            Box::new(ProblemReport::new(
                                ProblemReportSorter::Error,
                                ProblemReportScope::Protocol,
                                "message.recipients.missing".into(),
                                "Message has no recipients"
                                    .into(),
                                vec![],
                                None,
                            )),
                            StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                            "message has no recipients"
                                .to_string(),
                        ));
                    };
                    debug!(
                        "response to_dids: count({}) vec({:?})",
                        to_dids.len(),
                        to_dids
                    );

                    if to_dids.len() > state.config.limits.to_recipients {
                        return Err(MediatorError::MediatorError(
                            76,
                            session.session_id.clone(),
                            Some(message.id.to_string()),
                            Box::new(ProblemReport::new(
                                ProblemReportSorter::Error,
                                ProblemReportScope::Protocol,
                                "message.recipients.too_many".into(),
                                "Message has too many recipients ({1}). Max: {2}"
                                    .into(),
                                vec![to_dids.len().to_string(), state.config.limits.to_recipients.to_string()],
                                None,
                            )),
                            StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                            format!("Message has too many recipients ({}). Max: {}", to_dids.len(), state.config.limits.to_recipients),
                        ));
                    }

                    let expires_at = if let Some(expires_at) = message.expires_time {
                        let now = SystemTime::now()
                            .duration_since(SystemTime::UNIX_EPOCH)
                            .unwrap()
                            .as_secs();

                        if expires_at > now + state.config.limits.message_expiry_seconds {
                            now + state.config.limits.message_expiry_seconds
                        } else {
                            expires_at
                        }
                    } else {
                        SystemTime::now()
                            .duration_since(SystemTime::UNIX_EPOCH)
                            .unwrap()
                            .as_secs()
                            + state.config.limits.message_expiry_seconds
                    };

                    for recipient in to_dids {
                        let (packed, _): (String, PackEncryptedMetadata) = message
                            .pack(
                                &session.session_id,
                                recipient,
                                &state.config.mediator_did,
                                metadata,
                                &*state.config.security.mediator_secrets,
                                &state.did_resolver,
                                &PackOptions {
                                    to_keys_per_recipient_limit: state
                                        .config
                                        .limits
                                        .to_keys_per_recipient,
                                    forward: true,
                                },
                                &state.config.processors.forwarding.blocked_forwarding,
                            )
                            .await?;

                        match _store_message(
                            state, session, response, &packed,  &digest(recipient), Some(&state.config.mediator_did_hash), expires_at,
                        )
                        .await
                        {
                            Ok(msg_id) => {
                                debug!(
                                    "message id({}) stored successfully recipient({})",
                                    msg_id, recipient
                                );
                                stored_messages
                                    .messages
                                    .push((recipient.to_string(), msg_id));
                            }
                            Err(e) => {
                                warn!("error storing message recipient({}): {:?}", recipient, e);
                                stored_messages
                                    .errors
                                    .push((recipient.to_string(), e.to_string()));
                            }
                        }
                    }
                }
                WrapperType::Envelope(to_did, message, expiry) => {
                    // Message is already packed, likely a direct delivery from a client
                    match _store_message(state, session, response, message,  &digest(to_did), Some(&session.did_hash), *expiry).await {
                        Ok(msg_id) => {
                            debug!(
                                "message id({}) stored successfully recipient({})",
                                msg_id, to_did
                            );
                            stored_messages.messages.push((to_did.to_string(), msg_id));
                        }
                        Err(e) => {
                            warn!("error storing message recipient({}): {:?}", to_did, e);
                            stored_messages
                                .errors
                                .push((to_did.to_string(), e.to_string()));
                        }
                    }
                }
            }

            Ok(InboundMessageResponse::Stored(stored_messages))
        } else if let WrapperType::Message(message) = &response.data {
            let (packed, meta) = message
                .pack(
                    &session.session_id,
                    &session.did,
                    &state.config.mediator_did,
                    metadata,
                    &*state.config.security.mediator_secrets,
                    &state.did_resolver,
                    &PackOptions {
                        to_keys_per_recipient_limit: state.config.limits.to_keys_per_recipient,
                        forward: true,
                    },
                    &state.config.processors.forwarding.blocked_forwarding,
                )
                .await?;
            if meta.messaging_service.is_some() {
                error!("TODO: Forwarded message - but will be sent to the wrong address!!!");
                return Err(MediatorError::MediatorError(
                        66,
                        session.session_id.clone(),
                        Some(message.id.to_string()),
                        Box::new(ProblemReport::new(
                            ProblemReportSorter::Error,
                            ProblemReportScope::Protocol,
                            "me.not_implemented".into(),
                            "Feature is not implemented by the mediator: Forwarding not implemented when mediator creating a packed message"
                                .into(),
                            vec![],
                            None,
                        )),
                        StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                        "Feature is not implemented by the mediator: Forwarding not implemented when mediator creating a packed message"
                            .to_string(),
                    ));
            }
            trace!("Ephemeral message packed (meta):\n{:#?}", meta);
            trace!("Ephemeral message (msg):\n{:#?}", packed);
            // Live stream the message?
            if let Some(stream_uuid) = state
                .database
                .streaming_is_client_live(&session.did_hash, response.force_live_delivery)
                .await
            {
                _live_stream(
                    &state.database,
                    &session.did_hash,
                    &stream_uuid,
                    &packed,
                    response.force_live_delivery,
                )
                .await;
            }
            Ok(InboundMessageResponse::Ephemeral(packed))
        } else {
            error!("No message to return");
            Err(MediatorError::MediatorError(
                77,
                session.session_id.clone(),
                None,
                Box::new(ProblemReport::new(
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "me.storage.message.error".into(),
                    "Expected a message to store, instead got None"
                        .into(),
                    vec![],
                    None,
                )),
                StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                "Expected a message to store, instead got None"
                    .to_string(),
            ))
        }
    }
    .instrument(_span)
    .await
}

/// If live streaming is enabled, this function will send the message to the live stream
/// Ok to ignore errors here
async fn _live_stream(
    database: &Database,
    did_hash: &str,
    stream_uuid: &str,
    message: &str,
    force_live_delivery: bool,
) {
    if database
        .streaming_publish_message(did_hash, stream_uuid, message, force_live_delivery)
        .await
        .is_ok()
    {
        debug!("Live streaming message to UUID: {}", stream_uuid);
    }
}

/// Stores a message in the mediator's database that has been forwarded
/// handles a lot of higher order logic for storing messages
/// - state: SharedData
/// - session: Session
/// - response: ProcessMessageResponse
/// - metadata: UnpackMetadata
/// - expires_at: Option<u64>
///   - None: use default expiry
///   - Some: use the provided expiry time in seconds
pub(crate) async fn store_forwarded_message(
    state: &SharedData,
    session: &Session,
    message: &str,
    sender_hash: Option<&str>,
    recipient: &str,
    expires_at: Option<u64>,
) -> Result<(), MediatorError> {
    let _span = span!(
        tracing::Level::DEBUG,
        "store_forwarded_message",
        session = session.session_id
    );

    async move {
        let recipient_did_hash = digest(recipient);
        // Live stream the message?
        if let Some(stream_uuid) = state
            .database
            .streaming_is_client_live(&recipient_did_hash, false)
            .await
        {
            _live_stream(
                &state.database,
                &recipient_did_hash,
                &stream_uuid,
                message,
                false,
            )
            .await;
            debug!("Live streaming message to did_hash: {}", recipient_did_hash);
        }

        let expires_at = if let Some(expires_at) = expires_at {
            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            if expires_at > now + state.config.limits.message_expiry_seconds {
                now + state.config.limits.message_expiry_seconds
            } else {
                expires_at
            }
        } else {
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + state.config.limits.message_expiry_seconds
        };

        match state
            .database
            .store_message(
                &session.session_id,
                message,
                &recipient_did_hash,
                sender_hash,
                expires_at,
            )
            .await
        {
            Ok(msg_id) => {
                debug!(
                    "message id({}) stored successfully recipient({})",
                    msg_id, recipient
                );
            }
            Err(e) => {
                warn!("error storing message recipient({}): {:?}", recipient, e);
            }
        }

        Ok(())
    }
    .instrument(_span)
    .await
}
