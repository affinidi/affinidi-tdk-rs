use std::time::{SystemTime, UNIX_EPOCH};

use crate::{
    SharedData,
    database::{forwarding::ForwardQueueEntry, session::Session},
    messages::{
        ProcessMessageResponse, WrapperType,
        error_response::generate_error_response,
        store::{store_forwarded_message, store_message},
    },
};
use affinidi_did_common::Document;
use affinidi_messaging_didcomm::message::Message;
use affinidi_messaging_sdk::messages::compat::UnpackMetadata;
use crate::didcomm_compat::MetaEnvelope;
use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_messaging_sdk::{
    messages::problem_report::{ProblemReport, ProblemReportScope, ProblemReportSorter},
    protocols::mediator::{accounts::Account, acls::MediatorACLSet},
};
use base64::prelude::*;
use http::StatusCode;
use serde::Deserialize;
use sha256::digest;
use tracing::{Instrument, debug, info, span, warn};

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
        let ephemeral = if let Some(ephemeral) = msg.extra.get("ephemeral") {
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
                    format!("Couldn't parse forwarding message body. Reason: {e}"),
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
                            format!("Database transaction error: {e}"),
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
                    format!("Database transaction error: {e}"),
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
                        format!("Database transaction error: {e}"),
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
        let delay_milli = if let Some(delay_milli) = msg.extra.get("delay_milli") {
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
        let data = if let Some(ref b64) = attachment.data.base64 {
                match BASE64_URL_SAFE_NO_PAD.decode(b64) {
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
                                format!("Couldn't parse base64 attachment. Error: {e}"),
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
                            format!("Couldn't decode base64 attachment. Error: {e}"),
                        ));
                    }
                }
        } else if let Some(ref json_val) = attachment.data.json {
                if attachment.data.jws.is_some() {
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
                    match serde_json::to_string(json_val) {
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
                                    vec![json_val.to_string(), e.to_string()],
                                    None,
                                )),
                                StatusCode::BAD_REQUEST.as_u16(),
                                format!(
                                    "JSON schema for attachment is incorrect: JSON({}) Error: {}",
                                    json_val, e
                                ),
                            ));
                        }
                    }
                }
        } else if attachment.data.links.is_some() {
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
        } else {
                return Err(MediatorError::MediatorError(
                    67,
                    session.session_id.clone(),
                    Some(msg.id.to_string()),
                    Box::new(ProblemReport::new(
                        ProblemReportSorter::Warning,
                        ProblemReportScope::Message,
                        "protocol.forwarding.attachments.unknown".into(),
                        "Attachment data format is not supported".into(),
                        vec![],
                        None,
                    )),
                    StatusCode::BAD_REQUEST.as_u16(),
                    "Attachment data format is not supported".to_string(),
                ));
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
                    format!("Couldn't read DIDComm envelope: {e}"),
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
            // Determine if the next hop is local or remote by resolving the DID Document
            let remote_endpoint = if state.config.processors.forwarding.external_forwarding {
                match state.did_resolver.resolve(&next).await {
                    Ok(resolve_response) => {
                        match service_endpoint_for_remote(state, &resolve_response.doc) {
                            Some(endpoint_url) => {
                                debug!(
                                    "Next hop ({}) is remote, endpoint: {}",
                                    next, endpoint_url
                                );
                                Some(endpoint_url)
                            }
                            None => {
                                debug!("Next hop ({}) is local to this mediator", next);
                                None
                            }
                        }
                    }
                    Err(e) => {
                        // Can't resolve the DID — treat as local (store normally)
                        warn!(
                            "Couldn't resolve DID document for {}: {}. Treating as local.",
                            next, e
                        );
                        None
                    }
                }
            } else {
                None
            };

            if let Some(endpoint_url) = remote_endpoint {
                // Remote destination — enqueue to FORWARD_Q for the forwarding processor
                let now_ms = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis();

                // Get the sender's full DID for problem reports
                let from_did = msg.from.clone().unwrap_or_default();

                let entry = ForwardQueueEntry {
                    stream_id: String::new(), // Set by Redis on XADD
                    message: data.clone(),
                    to_did_hash: next_did_hash.clone(),
                    from_did_hash: from_account.did_hash.clone(),
                    from_did,
                    to_did: next.clone(),
                    endpoint_url: endpoint_url.clone(),
                    received_at_ms: now_ms,
                    delay_milli,
                    expires_at,
                    retry_count: 0,
                };

                state.database.forward_queue_enqueue(&entry).await.map_err(|e| {
                    MediatorError::MediatorError(
                        90,
                        session.session_id.clone(),
                        Some(msg.id.to_string()),
                        Box::new(ProblemReport::new(
                            ProblemReportSorter::Error,
                            ProblemReportScope::Protocol,
                            "me.res.forwarding.enqueue".into(),
                            "Failed to enqueue message for remote forwarding: {1}".into(),
                            vec![e.to_string()],
                            None,
                        )),
                        StatusCode::SERVICE_UNAVAILABLE.as_u16(),
                        format!("Failed to enqueue message for remote forwarding: {e}"),
                    )
                })?;

                info!(
                    "FORWARD_ENQUEUED: to_did_hash={} from_did_hash={} endpoint={}",
                    next_did_hash, from_account.did_hash, endpoint_url
                );
            } else {
                // Local destination — store as before
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

/// Checks if the next hop's DID Document contains a DIDCommMessaging service
/// that points to a different mediator (remote endpoint).
///
/// Returns `Some(endpoint_url)` if the next hop should be forwarded to a remote mediator,
/// or `None` if the next hop is local to this mediator.
///
/// A DIDCommMessaging service with a `uri` field pointing to this mediator's DID
/// means the recipient uses this mediator — so it's local.
/// A `uri` pointing elsewhere (an HTTP/HTTPS URL) means the message should be
/// forwarded to that remote mediator endpoint.
fn service_endpoint_for_remote(state: &SharedData, next_doc: &Document) -> Option<String> {
    for service in &next_doc.service {
        if !service.type_.contains(&"DIDCommMessaging".to_string()) {
            continue;
        }

        let uris = service.service_endpoint.get_uris();
        for uri in &uris {
            // Strip surrounding quotes if present (from JSON serialization)
            let uri_clean = uri.trim_matches('"');

            // If the service endpoint points to this mediator's DID, it's local
            if uri_clean == state.config.mediator_did {
                return None;
            }

            // If the service endpoint is an HTTP(S) URL, it's a remote mediator
            if uri_clean.starts_with("http://") || uri_clean.starts_with("https://") {
                return Some(uri_clean.to_string());
            }
        }
    }

    // No DIDCommMessaging service found with a remote endpoint — treat as local
    None
}
