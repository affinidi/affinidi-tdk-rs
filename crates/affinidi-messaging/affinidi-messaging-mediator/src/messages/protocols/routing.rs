use std::time::SystemTime;

use crate::{
    SharedData,
    database::session::Session,
    messages::{
        ProcessMessageResponse, WrapperType,
        error_response::generate_error_response,
        store::{store_forwarded_message, store_message},
    },
};
use affinidi_messaging_didcomm::{AttachmentData, Message, UnpackMetadata, envelope::MetaEnvelope};
use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_messaging_sdk::{
    messages::problem_report::{ProblemReport, ProblemReportScope, ProblemReportSorter},
    protocols::mediator::{accounts::Account, acls::MediatorACLSet},
};
use base64::prelude::*;
use http::StatusCode;
use serde::Deserialize;
use sha256::digest;
use ssi::dids::{Document, document::service::Endpoint};
use tracing::{Instrument, debug, span, warn};

// Reads the body of an incoming forward message
#[derive(Default, Deserialize)]
struct ForwardRequest {
    next: Option<String>, // Defaults to true
}

/// Process a forward message, run checks and then if accepted place into FORWARD_TASKS stream
pub(crate) async fn process(
    msg: &Message,
    metadata: &UnpackMetadata,
    state: &SharedData,
    session: &Session,
) -> Result<ProcessMessageResponse, MediatorError> {
    let _span = span!(
        tracing::Level::DEBUG,
        "routing",
        session_id = session.session_id.as_str()
    );
    async move {
        let ephemeral = if let Some(ephemeral) = msg.extra_headers.get("ephemeral") {
            match ephemeral.as_bool() {
                Some(true) => true,
                Some(false) => false,
                None => {
                    // Handle this slightly differently so that the sender gets a notification regardless that they have an incorrect header set
                    let error = generate_error_response(state, session, &msg.id, ProblemReport::new(
                        ProblemReportSorter::Warning,
                        ProblemReportScope::Message,
                        "message.header.ephemera.invalid".into(),
                        "Ephemeral header isn't a JSON bool value. Defaults to false and still sends message".into(),
                        vec![],
                        None,
                    ), true)?;

                    store_message(state, session, &error, metadata).await?;
                    false
                }
            }
        } else {
            false
        };

        let next: String = match serde_json::from_value::<ForwardRequest>(msg.body.to_owned()) {
            Ok(body) => match body.next {
                Some(next_str) => next_str,
                None => {
                    return Err(MediatorError::MediatorError(
                        56,
                        session.session_id.to_string(),
                        Some(msg.id.to_string()),
                        Box::new(ProblemReport::new(
                            ProblemReportSorter::Warning,
                            ProblemReportScope::Message,
                            "protocol.forwarding.next.missing".into(),
                            "Forwarding message is missing next field".into(),
                            vec![],
                            None,
                        )),
                        StatusCode::BAD_REQUEST.as_u16(),
                        "Forwarding message is missing next field".to_string(),
                    ));
                }
            },
            Err(e) => {
                return Err(MediatorError::MediatorError(
                    57,
                    session.session_id.to_string(),
                    Some(msg.id.to_string()),
                    Box::new(ProblemReport::new(
                        ProblemReportSorter::Warning,
                        ProblemReportScope::Message,
                        "protocol.forwarding.parse".into(),
                        "Couldn't parse forwarding message body. Reason: {1}".into(),
                        vec![e.to_string()],
                        None,
                    )),
                    StatusCode::BAD_REQUEST.as_u16(),
                    format!("Couldn't parse forwarding message body. Reason: {}", e),
                ));
            }
        };
        let next_did_hash = sha256::digest(next.as_bytes());

        // ****************************************************
        // Get the next account if it exists
        let next_account = match state.database.account_get(&next_did_hash).await {
            Ok(Some(next_account)) => next_account,
            Ok(None) => {
                debug!("Next account not found, creating a new one");
                state
                    .database
                    .account_add(
                        &next_did_hash,
                        &state.config.security.global_acl_default,
                        None,
                    )
                    .await
                    .map_err(|e| {
                        MediatorError::MediatorError(
                            14,
                            session.session_id.to_string(),
                            Some(msg.id.to_string()),
                            Box::new(ProblemReport::new(
                                ProblemReportSorter::Error,
                                ProblemReportScope::Protocol,
                                "me.res.storage.error".into(),
                                "Database transaction error: {1}".into(),
                                vec![e.to_string()],
                                None,
                            )),
                            StatusCode::SERVICE_UNAVAILABLE.as_u16(),
                            format!("Database transaction error: {}", e),
                        )
                    })?
            }
            Err(e) => {
                return Err(MediatorError::MediatorError(
                    14,
                    session.session_id.to_string(),
                    Some(msg.id.to_string()),
                    Box::new(ProblemReport::new(
                        ProblemReportSorter::Error,
                        ProblemReportScope::Protocol,
                        "me.res.storage.error".into(),
                        "Database transaction error: {1}".into(),
                        vec![e.to_string()],
                        None,
                    )),
                    StatusCode::SERVICE_UNAVAILABLE.as_u16(),
                    format!("Database transaction error: {}", e),
                ));
            }
        };

        // ****************************************************
        // Check if the next hop is allowed to receive forwarded messages
        let next_acls = MediatorACLSet::from_u64(next_account.acls);
        if !next_acls.get_receive_forwarded().0 {
            return Err(MediatorError::MediatorError(
                58,
                session.session_id.clone(),
                Some(msg.id.to_string()),
                Box::new(ProblemReport::new(
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "authorization.receive_forwarded".into(),
                    "Recipient isn't accepting forwarded messages".into(),
                    vec![],
                    None,
                )),
                StatusCode::FORBIDDEN.as_u16(),
                "Recipient isn't accepting forwarded messages".to_string(),
            ));
        }

        let attachments = if let Some(attachments) = &msg.attachments {
            attachments.to_owned()
        } else {
            return Err(MediatorError::MediatorError(
                59,
                session.session_id.to_string(),
                Some(msg.id.to_string()),
                Box::new(ProblemReport::new(
                    ProblemReportSorter::Warning,
                    ProblemReportScope::Message,
                    "protocol.forwarding.attachments.missing".into(),
                    "There were no attachments for this forward message".into(),
                    vec![],
                    None,
                )),
                StatusCode::BAD_REQUEST.as_u16(),
                "There were no attachments for this forward message".to_string(),
            ));
        };
        let attachments_bytes = attachments
            .iter()
            .map(|a| a.byte_count.unwrap_or(0))
            .sum::<u64>();
        debug!(
            "Attachments: count({}) bytes({})",
            attachments.len(),
            attachments_bytes
        );

        // ****************************************************
        // Determine who the from did is
        // If message is anonymous, then use the session DID

        let from_account = if let Some(from) = &msg.from {
            let from_account = match state.database.account_get(&digest(from.as_str())).await {
                Ok(Some(from_account)) => from_account,
                Ok(None) => Account {
                    did_hash: digest(from.as_str()),
                    acls: state.config.security.global_acl_default.to_u64(),
                    ..Default::default()
                },
                Err(e) => {
                    return Err(MediatorError::MediatorError(
                        14,
                        session.session_id.to_string(),
                        Some(msg.id.to_string()),
                        Box::new(ProblemReport::new(
                            ProblemReportSorter::Error,
                            ProblemReportScope::Protocol,
                            "me.res.storage.error".into(),
                            "Database transaction error: {1}".into(),
                            vec![e.to_string()],
                            None,
                        )),
                        StatusCode::SERVICE_UNAVAILABLE.as_u16(),
                        format!("Database transaction error: {}", e),
                    ));
                }
            };
            let from_acls = MediatorACLSet::from_u64(from_account.acls);

            if !from_acls.get_send_forwarded().0 {
                return Err(MediatorError::MediatorError(
                    60,
                    session.session_id.clone(),
                    Some(msg.id.to_string()),
                    Box::new(ProblemReport::new(
                        ProblemReportSorter::Error,
                        ProblemReportScope::Protocol,
                        "authorization.send_forwarded".into(),
                        "Sender isn't allowed to send forwarded messages".into(),
                        vec![],
                        None,
                    )),
                    StatusCode::FORBIDDEN.as_u16(),
                    "Sender isn't allowed to send forwarded messages".to_string(),
                ));
            }

            from_account
        } else if !session.acls.get_send_forwarded().0 {
            return Err(MediatorError::MediatorError(
                60,
                session.session_id.clone(),
                Some(msg.id.to_string()),
                Box::new(ProblemReport::new(
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "authorization.send_forwarded".into(),
                    "Sender isn't allowed to send forwarded messages".into(),
                    vec![],
                    None,
                )),
                StatusCode::FORBIDDEN.as_u16(),
                "Sender isn't allowed to send forwarded messages".to_string(),
            ));
        } else {
            Account {
                acls: state.config.security.global_acl_default.to_u64(),
                ..Default::default()
            }
        };

        // ****************************************************

        // ****************************************************
        // Is the sending DID allowed by the next DID access_list and ACL?
        if state
            .database
            .access_list_allowed(&next_did_hash, Some(&from_account.did_hash))
            .await
        {
            debug!(
                "Sender DID ({}) is allowed to send to next DID ({})",
                from_account.did_hash, next_did_hash
            );
        } else {
            return Err(MediatorError::MediatorError(
                73,
                session.session_id.to_string(),
                Some(msg.id.to_string()),
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

        // Check against the limits
        let send_limit = from_account
            .queue_send_limit
            .unwrap_or(state.config.limits.queued_send_messages_soft);
        if send_limit != -1
            && !ephemeral
            && from_account.send_queue_count + attachments.len() as u32 >= send_limit as u32
        {
            warn!(
                "Sender DID ({}) has too many messages waiting to be delivered",
                session.did_hash
            );
            return Err(MediatorError::MediatorError(
                61,
                session.session_id.clone(),
                Some(msg.id.to_string()),
                Box::new(ProblemReport::new(
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "limits.queue.sender".into(),
                    "Sender has too many messages waiting to be delivered".into(),
                    vec![],
                    None,
                )),
                StatusCode::SERVICE_UNAVAILABLE.as_u16(),
                "Sender has too many messages waiting to be delivered".to_string(),
            ));
        }

        // Check limits and if this forward is accepted?
        // Does next (receiver) have too many messages in queue?
        // Does the sender have too many messages in queue?
        // Too many attachments?
        // Forwarding task queue is full?
        let recv_limit = next_account
            .queue_receive_limit
            .unwrap_or(state.config.limits.queued_receive_messages_soft);
        if recv_limit != -1
            && !ephemeral
            && next_account.receive_queue_count + attachments.len() as u32 >= recv_limit as u32
        {
            warn!(
                "Next DID ({}) has too many messages waiting to be delivered",
                next_did_hash
            );
            return Err(MediatorError::MediatorError(
                62,
                session.session_id.clone(),
                Some(msg.id.to_string()),
                Box::new(ProblemReport::new(
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "limits.queue.recipient".into(),
                    "Recipient (next) has too many messages waiting to be delivered".into(),
                    vec![],
                    None,
                )),
                StatusCode::SERVICE_UNAVAILABLE.as_u16(),
                "Recipient (next) has too many messages waiting to be delivered".to_string(),
            ));
        }

        if attachments.len() > state.config.limits.attachments_max_count {
            warn!(
                "Too many attachments in message, limit is {}",
                state.config.limits.attachments_max_count
            );
            return Err(MediatorError::MediatorError(
                63,
                session.session_id.clone(),
                Some(msg.id.to_string()),
                Box::new(ProblemReport::new(
                    ProblemReportSorter::Warning,
                    ProblemReportScope::Message,
                    "protocol.forwarding.attachments.too_many".into(),
                    "Forwarded message has too many attachments ({1}). Limit is ({2})".into(),
                    vec![
                        attachments.len().to_string(),
                        state.config.limits.attachments_max_count.to_string(),
                    ],
                    None,
                )),
                StatusCode::BAD_REQUEST.as_u16(),
                format!(
                    "Forwarded message has too many attachments ({}). Limit is ({})",
                    attachments.len(),
                    state.config.limits.attachments_max_count
                ),
            ));
        }

        if !ephemeral
            && state.database.get_forward_tasks_len().await?
                >= state.config.limits.forward_task_queue
        {
            warn!(
                "Forward task queue is full, limit is {}",
                state.config.limits.forward_task_queue
            );
            return Err(MediatorError::MediatorError(
                64,
                session.session_id.clone(),
                Some(msg.id.to_string()),
                Box::new(ProblemReport::new(
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "me.res.forwarding.queue.limit".into(),
                    "Mediator forwarding queue is at max limit, try again later".into(),
                    vec![
                        attachments.len().to_string(),
                        state.config.limits.attachments_max_count.to_string(),
                    ],
                    None,
                )),
                StatusCode::SERVICE_UNAVAILABLE.as_u16(),
                "Mediator forwarding queue is at max limit, try again later".to_string(),
            ));
        }

        // Check if a delay has been specified and if so, is it longer than we allow?
        let delay_milli = if let Some(delay_milli) = msg.extra_headers.get("delay_milli") {
            debug!("forward delay requested: ({:?})", delay_milli);
            delay_milli.as_i64().unwrap_or(0)
        } else {
            0
        };

        if delay_milli.abs() > (state.config.processors.forwarding.future_time_limit as i64 * 1000)
        {
            warn!(
                "Forwarding delay is too long, limit is {}",
                state.config.processors.forwarding.future_time_limit
            );
            return Err(MediatorError::MediatorError(
                65,
                session.session_id.clone(),
                Some(msg.id.to_string()),
                Box::new(ProblemReport::new(
                    ProblemReportSorter::Warning,
                    ProblemReportScope::Message,
                    "protocol.forwarding.delay_milli".into(),
                    "Forward delay_milli field isn't valid. Max field value: {1}".into(),
                    vec![(state.config.processors.forwarding.future_time_limit * 1000).to_string()],
                    None,
                )),
                StatusCode::BAD_REQUEST.as_u16(),
                format!(
                    "Forward delay_milli field isn't valid. Max field value: {}",
                    state.config.processors.forwarding.future_time_limit * 1000
                ),
            ));
        }

        // Forward is good, lets process the attachments and add to the queues
        // First step is to determine if the next hop is local to the mediator or remote?
        //if next_did_doc.service

        let attachment = attachments.first().unwrap();
        let data = match attachment.data {
            AttachmentData::Base64 { ref value } => {
                match BASE64_URL_SAFE_NO_PAD.decode(&value.base64) {
                    Ok(data) => match String::from_utf8(data) {
                        Ok(data) => data,
                        Err(e) => {
                            return Err(MediatorError::MediatorError(
                                68,
                                session.session_id.clone(),
                                Some(msg.id.to_string()),
                                Box::new(ProblemReport::new(
                                    ProblemReportSorter::Warning,
                                    ProblemReportScope::Message,
                                    "protocol.forwarding.attachments.base64".into(),
                                    "Couldn't parse base64 attachment. Error: {1}".into(),
                                    vec![e.to_string()],
                                    None,
                                )),
                                StatusCode::BAD_REQUEST.as_u16(),
                                format!("Couldn't parse base64 attachment. Error: {}", e),
                            ));
                        }
                    },
                    Err(e) => {
                        return Err(MediatorError::MediatorError(
                            68,
                            session.session_id.clone(),
                            Some(msg.id.to_string()),
                            Box::new(ProblemReport::new(
                                ProblemReportSorter::Warning,
                                ProblemReportScope::Message,
                                "protocol.forwarding.attachments.base64".into(),
                                "Couldn't decode base64 attachment. Error: {1}".into(),
                                vec![e.to_string()],
                                None,
                            )),
                            StatusCode::BAD_REQUEST.as_u16(),
                            format!("Couldn't decode base64 attachment. Error: {}", e),
                        ));
                    }
                }
            }
            AttachmentData::Json { ref value } => {
                if value.jws.is_some() {
                    // TODO: Implement JWS verification
                    return Err(MediatorError::MediatorError(
                        66,
                        session.session_id.clone(),
                        Some(msg.id.to_string()),
                        Box::new(ProblemReport::new(
                            ProblemReportSorter::Error,
                            ProblemReportScope::Protocol,
                            "me.not_implemented".into(),
                            "Feature is not implemented by the mediator: JWS Verified Attachment"
                                .into(),
                            vec![],
                            None,
                        )),
                        StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                        "Feature is not implemented by the mediator: JWS Verified Attachment"
                            .to_string(),
                    ));
                } else {
                    match serde_json::to_string(&value.json) {
                        Ok(data) => data,
                        Err(e) => {
                            return Err(MediatorError::MediatorError(
                                67,
                                session.session_id.clone(),
                                Some(msg.id.to_string()),
                                Box::new(ProblemReport::new(
                                    ProblemReportSorter::Warning,
                                    ProblemReportScope::Message,
                                    "protocol.forwarding.attachments.json.invalid".into(),
                                    "JSON schema for attachment is incorrect: JSON({1}) Error: {2}"
                                        .into(),
                                    vec![value.json.to_string(), e.to_string()],
                                    None,
                                )),
                                StatusCode::BAD_REQUEST.as_u16(),
                                format!(
                                    "JSON schema for attachment is incorrect: JSON({}) Error: {}",
                                    value.json, e
                                ),
                            ));
                        }
                    }
                }
            }
            AttachmentData::Links { .. } => {
                return Err(MediatorError::MediatorError(
                    66,
                    session.session_id.clone(),
                    Some(msg.id.to_string()),
                    Box::new(ProblemReport::new(
                        ProblemReportSorter::Error,
                        ProblemReportScope::Protocol,
                        "me.not_implemented".into(),
                        "Feature is not implemented by the mediator: Attachment Links".into(),
                        vec![],
                        None,
                    )),
                    StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                    "Feature is not implemented by the mediator: Attachment Links".to_string(),
                ));
            }
        };

        let expires_at = if let Some(expires_at) = msg.expires_time {
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

        // Check attached message for routing information
        let next_envelope = match MetaEnvelope::new(&data, &state.did_resolver).await {
            Ok(envelope) => envelope,
            Err(e) => {
                return Err(MediatorError::MediatorError(
                    37,
                    session.session_id.clone(),
                    Some(msg.id.to_string()),
                    Box::new(ProblemReport::new(
                        ProblemReportSorter::Error,
                        ProblemReportScope::Protocol,
                        "message.envelope.read".into(),
                        "Couldn't read forward attached DIDComm envelope: {1}".into(),
                        vec![e.to_string()],
                        None,
                    )),
                    StatusCode::BAD_REQUEST.as_u16(),
                    format!("Couldn't read DIDComm envelope: {}", e),
                ));
            }
        };

        if next_envelope.from_did.is_none() && !next_acls.get_anon_receive().0 {
            return Err(MediatorError::MediatorError(
                69,
                session.session_id.clone(),
                Some(msg.id.to_string()),
                Box::new(ProblemReport::new(
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "authorization.receive_anon".into(),
                    "Recipient isn't accepting anonymous messages".into(),
                    vec![],
                    None,
                )),
                StatusCode::FORBIDDEN.as_u16(),
                "Recipient isn't accepting anonymous messages".to_string(),
            ));
        }

        debug!(" *************************************** ");
        debug!(" TO: {}", next);
        debug!(" FROM: {:?}", msg.from);
        debug!(" Forwarded message:\n{}", data);
        debug!(" Ephemeral: {}", ephemeral);
        debug!(" *************************************** ");

        if ephemeral {
            // Live stream the message?
            if let Some(stream_uuid) = state
                .database
                .streaming_is_client_live(&next_did_hash, false)
                .await && state
                    .database
                    .streaming_publish_message(&next_did_hash, &stream_uuid, &data, false)
                    .await
                    .is_ok()
                {
                    debug!("Live streaming message to UUID: {}", stream_uuid);
                }
        } else {
            store_forwarded_message(
                state,
                session,
                &data,
                Some(&from_account.did_hash),
                &next,
                Some(expires_at),
            )
            .await?;
        }

        Ok(ProcessMessageResponse {
            store_message: false,
            force_live_delivery: false,
            forward_message: true,
            data: WrapperType::None,
        })
    }
    .instrument(_span)
    .await
}

/// Determines if the next hop is local to the mediator or remote
/// The next field of a routing message is a DID
/// https://identity.foundation/didcomm-messaging/spec/#routing-protocol-20
/// - next: DID (may include key ID) of the next hop
/// - next_doc: Resolved DID Document of the next hop
///
/*
{
    "id": "did:example:123456789abcdefghi#didcomm-1",
    "type": "DIDCommMessaging",
    "serviceEndpoint": [{
        "uri": "https://example.com/path",
        "accept": [
            "didcomm/v2",
            "didcomm/aip2;env=rfc587"
        ],
        "routingKeys": ["did:example:somemediator#somekey"]
    }]
}
*/
fn _service_local(
    session: &Session,
    state: &SharedData,
    next: &str,
    next_doc: &Document,
    msg_id: &str,
) -> Result<bool, MediatorError> {
    let mut _error = None;

    // If the next hop is the mediator itself, then this is a recursive forward
    if next == state.config.mediator_did {
        warn!(
            "next hop is the mediator itself, but this should have been unpacked. not accepting this message"
        );
        return Err(MediatorError::MediatorError(
            70,
            session.session_id.clone(),
            Some(msg_id.to_string()),
            Box::new(ProblemReport::new(
                ProblemReportSorter::Warning,
                ProblemReportScope::Message,
                "protocol.forwarding.next.mediator.self".into(),
                "Forwarded next hop is the same mediator. Not allowed due to creating loops".into(),
                vec![],
                None,
            )),
            StatusCode::FORBIDDEN.as_u16(),
            "Forwarded next hop is the same mediator. Not allowed due to creating loops"
                .to_string(),
        ));
    }

    let local = next_doc
        .service
        .iter()
        .filter(|s| s.type_.contains(&"DIDCommMessaging".to_string()))
        .any(|s| {
            // Service Type is DIDCommMessaging
            if let Some(service_endpoint) = &s.service_endpoint {
                service_endpoint.into_iter().any(|endpoint| {
                    match endpoint {
                        Endpoint::Uri(uri) => {
                            if uri.as_str().eq(&state.config.mediator_did) {
                                warn!("next hop is the mediator itself, but this should have been unpacked. not accepting this message");
                                _error = Some(MediatorError::MediatorError(
                                    70,
                                    session.session_id.clone(),
                                    Some(msg_id.to_string()),
                                    Box::new(ProblemReport::new(
                                        ProblemReportSorter::Warning,
                                        ProblemReportScope::Message,
                                        "protocol.forwarding.next.mediator.self".into(),
                                        "Forwarded next hop is the same mediator. Not allowed due to creating loops".into(),
                                        vec![],
                                        None,
                                    )),
                                    StatusCode::FORBIDDEN.as_u16(),
                                    "Forwarded next hop is the same mediator. Not allowed due to creating loops"
                                        .to_string(),
                                ));
                                false
                            } else {
                                // Next hop is remote to the mediator
                                false
                            }
                        }
                        Endpoint::Map(_) => {true}
                    }
                })
            } else {
                false
            }
        });

    if let Some(e) = _error {
        Err(e)
    } else {
        Ok(local)
    }
}
