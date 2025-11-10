/*!
 * Message Pickup Protocol 3.0 implementation
 *
 * NOTE: All messages generated from this protocol are ephemeral and are not stored in the database
 * They are fire and forget messages
 */
use affinidi_messaging_didcomm::{Attachment, Message};
use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_messaging_sdk::{
    messages::{
        fetch::FetchOptions,
        problem_report::{ProblemReport, ProblemReportScope, ProblemReportSorter},
    },
    protocols::message_pickup::{
        MessagePickupDeliveryRequest, MessagePickupLiveDelivery, MessagePickupMessagesReceived,
        MessagePickupStatusReply, MessagePickupStatusRequest,
    },
};
use base64::prelude::*;
use http::StatusCode;
use itertools::Itertools;
use redis::{Value, from_redis_value};
use serde_json::json;
use sha256::digest;
use std::time::SystemTime;
use tracing::{Instrument, debug, info, span, warn};
use uuid::Uuid;

use crate::{
    SharedData,
    database::session::Session,
    messages::ProcessMessageResponse,
    tasks::websocket_streaming::{StreamingUpdate, StreamingUpdateState},
};

const MAX_RETRIEVED_MSGS: usize = 100;
const MIN_RETRIEVED_MSGS: usize = 1;

/// Process a Status Request message and generates a response
pub(crate) async fn status_request(
    msg: &Message,
    state: &SharedData,
    session: &Session,
) -> Result<ProcessMessageResponse, MediatorError> {
    let _span = span!(tracing::Level::DEBUG, "status_request",);
    async move {
        _validate_msg(msg, state, session)?;
        // Get or create the thread id for the response
        let thid = if let Some(thid) = &msg.thid {
            thid.to_owned()
        } else {
            msg.id.clone()
        };
        debug!("thid = ({})", thid);

        // Pull recipient_did from message body
        let recipient_did: String = if let Ok(body) =
            serde_json::from_value::<MessagePickupStatusRequest>(msg.body.to_owned())
        {
            if let Some(recipient_did) = body.recipient_did {
                if recipient_did != session.did {
                    debug!(
                        "recipient_did: ({}) doesn't match session.did!",
                        recipient_did
                    );
                    return Err(MediatorError::MediatorError(
                        52,
                        session.session_id.to_string(),
                        Some(msg.id.clone()),
                        Box::new(ProblemReport::new(
                            ProblemReportSorter::Error,
                            ProblemReportScope::Protocol,
                            "authorization.did.session_mismatch".into(),
                            "recipient_did ({1}) doesn't match this sessions DID".into(),
                            vec![recipient_did.to_string()],
                            None,
                        )),
                        StatusCode::BAD_REQUEST.as_u16(),
                        "recipient_did doesn't match session.did".to_string(),
                    ));
                } else {
                    digest(recipient_did)
                }
            } else {
                session.did_hash.clone()
            }
        } else {
            session.did_hash.clone()
        };
        debug!("Body: recipient_did: {}", recipient_did);

        info!(
            "MessagePickup Status-Request received from: ({}) recipient_did_hash({:?})",
            msg.from.clone().unwrap_or_else(|| "ANONYMOUS".to_string()),
            recipient_did
        );

        generate_status_reply(state, session, &recipient_did, &thid, false, None).await
    }
    .instrument(_span)
    .await
}

/// Creates the reply to a valid StatusRequest message
/// force_live_delivery: If true, will force the message to be live streamed even if live streaming is disabled.
///           Required due to the protocol specification to send a status update on live_streaming changes
/// override_live_delivery: If Some(bool), will override the live delivery status of the recipient
///           Because we are async handling streaming updates, we send the response before the streaming task has updated the status
async fn generate_status_reply(
    state: &SharedData,
    session: &Session,
    did_hash: &str,
    thid: &str,
    force_live_delivery: bool,
    override_live_delivery: Option<bool>,
) -> Result<ProcessMessageResponse, MediatorError> {
    let _span = span!(tracing::Level::DEBUG, "generate_status_reply",);

    async move {
        let mut conn = state.database.0.get_async_connection().await?;

        let response: Vec<Value> = deadpool_redis::redis::cmd("FCALL")
            .arg("get_status_reply")
            .arg(1)
            .arg(did_hash)
            .query_async(&mut conn)
            .await
            .map_err(|e| {
                MediatorError::MediatorError(
                    14,
                    session.session_id.clone(),
                    Some(thid.to_string()),
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
            })?;

        let mut status = MessagePickupStatusReply {
            recipient_did: session.did.clone(),
            ..Default::default()
        };

        for (k, v) in response.into_iter().tuples() {
            match from_redis_value::<String>(&k).unwrap_or("".into()).as_str() {
                "newest_received" => {
                    if let Ok(v) = from_redis_value::<String>(&v) {
                        let a: Vec<&str> = v.split('-').collect();
                        if a.len() != 2 {
                            continue;
                        }
                        status.newest_received_time = if let Ok(t) = a[0].parse::<u64>() {
                            Some(t / 1000)
                        } else {
                            None
                        };
                    }
                }
                "oldest_received" => {
                    if let Ok(v) = from_redis_value::<String>(&v) {
                        let a: Vec<&str> = v.split('-').collect();
                        if a.len() != 2 {
                            continue;
                        }
                        status.oldest_received_time = if let Ok(t) = a[0].parse::<u64>() {
                            Some(t / 1000)
                        } else {
                            None
                        };
                    }
                }
                "message_count" => {
                    if let Ok(v) = from_redis_value::<u32>(&v) {
                        status.message_count = v;
                    }
                }
                "queue_count" => continue,
                "live_delivery" => {
                    if let Ok(v) = from_redis_value::<bool>(&v) {
                        status.live_delivery = v;
                    }
                }
                "total_bytes" => {
                    if let Ok(v) = from_redis_value::<u64>(&v) {
                        status.total_bytes = v;
                    }
                }
                "recipient_did" => continue,
                _ => {
                    warn!("Unknown key: ({:?}) with value: ({:?})", k, v);
                }
            }
        }

        if let Some(live_delivery) = override_live_delivery {
            status.live_delivery = live_delivery;
        }

        let now = _get_time_now();

        if let Some(t) = status.oldest_received_time {
            // Using wrapping sub because result could overflow u64
            status.longest_waited_seconds = Some(now.wrapping_sub(t));
        }

        // Build the message
        let status_msg = Message::build(
            Uuid::new_v4().into(),
            "https://didcomm.org/messagepickup/3.0/status".to_owned(),
            json!(status),
        )
        .thid(thid.to_owned())
        .to(session.did.clone())
        .from(state.config.mediator_did.clone())
        .created_time(now)
        .expires_time(now + 300)
        .finalize();

        debug!("status message =\n{:?}", status_msg);

        Ok(ProcessMessageResponse {
            store_message: false,
            force_live_delivery,
            data: crate::messages::WrapperType::Message(Box::new(status_msg)),
            forward_message: false,
        })
    }
    .instrument(_span)
    .await
}

/// Allows for turning on and off live delivery within ATM for a client
pub(crate) async fn toggle_live_delivery(
    msg: &Message,
    state: &SharedData,
    session: &Session,
) -> Result<ProcessMessageResponse, MediatorError> {
    let _span = span!(tracing::Level::DEBUG, "toggle_live_delivery",);
    async move {
        _validate_msg(msg, state, session).unwrap();

        // Get or create the thread id for the response
        let thid = if let Some(thid) = &msg.thid {
            thid.to_owned()
        } else {
            msg.id.clone()
        };
        debug!("thid = ({})", thid);

        // Pull live_delivery from message body
        let live_delivery: bool =
            match serde_json::from_value::<MessagePickupLiveDelivery>(msg.body.to_owned()) {
                Ok(body) => body.live_delivery,
                Err(e) => {
                    return Err(MediatorError::MediatorError(
                        54,
                        session.session_id.to_string(),
                        Some(msg.id.clone()),
                        Box::new(ProblemReport::new(
                            ProblemReportSorter::Warning,
                            ProblemReportScope::Message,
                            "protocol.pickup.parse".into(),
                            "Couldn't parse live_delivery body. Reason: {1}".into(),
                            vec![e.to_string()],
                            None,
                        )),
                        StatusCode::BAD_REQUEST.as_u16(),
                        format!("Couldn't parse live_delivery body. Reason: {e}"),
                    ));
                }
            };
        debug!("Body: live_delivery: {}", live_delivery);

        info!(
            "MessagePickup live_delivery received from: ({}) live_delivery?({})",
            msg.from.clone().unwrap_or_else(|| "ANONYMOUS".to_string()),
            live_delivery
        );

        // Take action to change live delivery status
        if live_delivery {
            // Enable Live delivery
            if let Some(stream_task) = &state.streaming_task {
                stream_task
                    .channel
                    .send(StreamingUpdate {
                        did_hash: session.did_hash.clone(),
                        state: StreamingUpdateState::Start,
                    })
                    .await
                    .map_err(|e| {
                        MediatorError::MediatorError(
                            55,
                            session.session_id.to_string(),
                            Some(msg.id.clone()),
                            Box::new(ProblemReport::new(
                                ProblemReportSorter::Error,
                                ProblemReportScope::Protocol,
                                "protocol.pickup.live_streaming".into(),
                                "Couldn't send START signal to streaming task. Reason: {1}".into(),
                                vec![e.to_string()],
                                None,
                            )),
                            StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                            format!("Couldn't send START signal to streaming task. Reason: {e}"),
                        )
                    })?;
            }
        } else {
            // Disable live delivery
            if let Some(stream_task) = &state.streaming_task {
                stream_task
                    .channel
                    .send(StreamingUpdate {
                        did_hash: session.did_hash.clone(),
                        state: StreamingUpdateState::Stop,
                    })
                    .await
                    .map_err(|e| {
                        MediatorError::MediatorError(
                            55,
                            session.session_id.to_string(),
                            Some(msg.id.clone()),
                            Box::new(ProblemReport::new(
                                ProblemReportSorter::Error,
                                ProblemReportScope::Protocol,
                                "protocol.pickup.live_streaming".into(),
                                "Couldn't send STOP signal to streaming task. Reason: {1}".into(),
                                vec![e.to_string()],
                                None,
                            )),
                            StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                            format!("Couldn't send STOP signal to streaming task. Reason: {e}"),
                        )
                    })?;
            }
        }

        generate_status_reply(
            state,
            session,
            &session.did_hash,
            &thid,
            true,
            Some(live_delivery),
        )
        .await
    }
    .instrument(_span)
    .await
}

/// Process a Delivery Request message and generates a response
pub(crate) async fn delivery_request(
    msg: &Message,
    state: &SharedData,
    session: &Session,
) -> Result<ProcessMessageResponse, MediatorError> {
    let _span = span!(tracing::Level::DEBUG, "delivery_request",);
    async move {
        _validate_msg(msg, state, session).unwrap();
        // Get or create the thread id for the response
        let thid = if let Some(thid) = &msg.thid {
            thid.to_owned()
        } else {
            msg.id.clone()
        };
        debug!("thid = ({})", thid);

        // Pull recipient_did and limit from message body
        let (recipient_did, limit): (String, usize) =
            _parse_and_validate_delivery_request_body(session, msg)?;

        let recipient_did_hash = digest(recipient_did.clone());

        debug!(
            "Body: recipient_did: {}, limit: {}",
            recipient_did_hash, limit
        );

        info!(
            "MessagePickup Delivery-Request received from: ({}) recipient_did({}) limit({})",
            msg.from.clone().unwrap_or_else(|| "ANONYMOUS".to_string()),
            recipient_did_hash,
            limit
        );

        // All the parsing is done, lets attempt to retrieve messages
        let messages = state
            .database
            .fetch_messages(
                &session.session_id,
                &recipient_did_hash,
                &FetchOptions {
                    limit,
                    ..Default::default()
                },
            )
            .await?;
        debug!("msgs fetched: {}", messages.success.len());

        if !messages.success.is_empty() {
            let response_msg = Message::build(
                Uuid::new_v4().into(),
                "https://didcomm.org/messagepickup/3.0/delivery".to_string(),
                json!({"recipient_did": recipient_did}),
            )
            .thid(thid.clone());

            let mut attachments: Vec<Attachment> = Vec::new();

            for element in messages.success {
                if let Some(msg) = element.msg {
                    let attachment =
                        Attachment::base64(BASE64_URL_SAFE_NO_PAD.encode(msg)).id(element.msg_id);

                    attachments.push(attachment.finalize())
                }
            }
            let now = _get_time_now();

            let response_msg = response_msg
                .attachments(attachments)
                .to(session.did.clone())
                .from(state.config.mediator_did.clone())
                .created_time(now)
                .expires_time(now + 300)
                .finalize();

            debug!("delivery message =\n{:?}", response_msg);

            Ok(ProcessMessageResponse {
                store_message: false,
                force_live_delivery: false,
                data: crate::messages::WrapperType::Message(Box::new(response_msg)),
                forward_message: false,
            })
        } else {
            generate_status_reply(state, session, &recipient_did_hash, &thid, false, None).await
        }
    }
    .instrument(_span)
    .await
}

// Process a Messages Received message and generates a response
pub(crate) async fn messages_received(
    msg: &Message,
    state: &SharedData,
    session: &Session,
) -> Result<ProcessMessageResponse, MediatorError> {
    let _span = span!(tracing::Level::DEBUG, "messages_received",);
    async move {
        _validate_msg(msg, state, session).unwrap();
        // Get or create the thread id for the response
        let thid = if let Some(thid) = &msg.thid {
            thid.to_owned()
        } else {
            msg.id.clone()
        };
        debug!("thid = ({})", thid);

        // Pull messages ids list from message body
        let message_id_list: Vec<String> = _parse_message_received_body(session, msg)?;

        debug!("Messages Id list: {:?}", message_id_list);

        for msg_id in &message_id_list {
            debug!("getting message with id: {}", msg_id);
            match state.database.get_message(&session.did_hash, msg_id).await {
                Ok(msg) => {
                    debug!("Got message: {:?}", msg);
                    debug!("Deleting message: {}", msg_id);
                    match state
                        .database
                        .0
                        .delete_message(
                            Some(&session.session_id),
                            &session.did_hash,
                            msg_id,
                            Some(&thid),
                        )
                        .await
                    {
                        Ok(_) => {
                            info!("Deleted message: {}", msg_id);
                        }
                        Err(err) => {
                            info!("Error deleting message: {:?}", err);
                        }
                    }
                }
                Err(err) => {
                    warn!("Error getting message: {:?}", err);
                }
            }
        }

        Ok(
            generate_status_reply(state, session, &session.did_hash, &thid, false, None)
                .await
                .unwrap(),
        )
    }
    .instrument(_span)
    .await
}

fn _parse_message_received_body(
    session: &Session,
    msg: &Message,
) -> Result<Vec<String>, MediatorError> {
    let message_id_list: Vec<String> =
        match serde_json::from_value::<MessagePickupMessagesReceived>(msg.body.to_owned()) {
            Ok(body) => body.message_id_list,
            Err(e) => {
                return Err(MediatorError::MediatorError(
                    54,
                    session.session_id.to_string(),
                    Some(msg.id.clone()),
                    Box::new(ProblemReport::new(
                        ProblemReportSorter::Warning,
                        ProblemReportScope::Message,
                        "protocol.pickup.parse".into(),
                        "Couldn't parse messages-received body. Reason: {1}".into(),
                        vec![e.to_string()],
                        None,
                    )),
                    StatusCode::BAD_REQUEST.as_u16(),
                    format!("Couldn't parse messages-received body. Reason: {e}"),
                ));
            }
        };

    Ok(message_id_list)
}

fn _parse_and_validate_delivery_request_body(
    session: &Session,
    msg: &Message,
) -> Result<(String, usize), MediatorError> {
    let (recipient_did, limit): (String, usize) =
        match serde_json::from_value::<MessagePickupDeliveryRequest>(msg.body.to_owned()) {
            Ok(body) => (body.recipient_did, body.limit),
            Err(e) => {
                return Err(MediatorError::MediatorError(
                    54,
                    session.session_id.to_string(),
                    Some(msg.id.clone()),
                    Box::new(ProblemReport::new(
                        ProblemReportSorter::Warning,
                        ProblemReportScope::Message,
                        "protocol.pickup.parse".into(),
                        "Couldn't parse delivery-request body. Reason: {1}".into(),
                        vec![e.to_string()],
                        None,
                    )),
                    StatusCode::BAD_REQUEST.as_u16(),
                    format!("Couldn't parse delivery-request body. Reason: {e}"),
                ));
            }
        };

    if session.did != recipient_did {
        return Err(MediatorError::MediatorError(
            52,
            session.session_id.to_string(),
            Some(msg.id.clone()),
            Box::new(ProblemReport::new(
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "authorization.did.session_mismatch".into(),
                "recipient_did ({1}) doesn't match this sessions DID".into(),
                vec![recipient_did.to_string()],
                None,
            )),
            StatusCode::BAD_REQUEST.as_u16(),
            "recipient_did doesn't match session.did".to_string(),
        ));
    }

    if !(MIN_RETRIEVED_MSGS..=MAX_RETRIEVED_MSGS).contains(&limit) {
        return Err(MediatorError::MediatorError(
            53,
            session.session_id.to_string(),
            Some(msg.id.clone()),
            Box::new(ProblemReport::new(
                ProblemReportSorter::Warning,
                ProblemReportScope::Message,
                "protocol.pickup.delivery_request.limit".into(),
                "limit must be between 1 and 100 inclusive. Received limit({1})".into(),
                vec![limit.to_string()],
                None,
            )),
            StatusCode::BAD_REQUEST.as_u16(),
            format!("limit must be between 1 and 100 inclusive. Received limit({limit})"),
        ));
    }

    Ok((recipient_did, limit))
}

fn _get_time_now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn _validate_msg(
    msg: &Message,
    state: &SharedData,
    session: &Session,
) -> Result<(), MediatorError> {
    let now = _get_time_now();

    if let Some(expires) = msg.expires_time
        && expires <= now
    {
        debug!(
            "Message expired at ({}) now({}) seconds_ago({})",
            expires,
            now,
            now - expires
        );
        return Err(MediatorError::MediatorError(
            31,
            "".to_string(),
            None,
            Box::new(ProblemReport::new(
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "message.expired".into(),
                "Message has expired: {1}".into(),
                vec![expires.to_string()],
                None,
            )),
            StatusCode::BAD_REQUEST.as_u16(),
            "Message has expired".to_string(),
        ));
    }

    // Ensure to: exists and is valid
    let to: String = if let Some(to) = &msg.to {
        if let Some(first) = to.first() {
            first.to_owned()
        } else {
            return Err(MediatorError::MediatorError(
                51,
                session.session_id.to_string(),
                Some(msg.id.clone()),
                Box::new(ProblemReport::new(
                    ProblemReportSorter::Warning,
                    ProblemReportScope::Message,
                    "message.to".into(),
                    "Invalid to: header, couldn't get first DID from the field.".into(),
                    vec![],
                    None,
                )),
                StatusCode::BAD_REQUEST.as_u16(),
                "Invalid to: header, couldn't get first DID from the field.".to_string(),
            ));
        }
    } else {
        return Err(MediatorError::MediatorError(
            51,
            session.session_id.to_string(),
            Some(msg.id.clone()),
            Box::new(ProblemReport::new(
                ProblemReportSorter::Warning,
                ProblemReportScope::Message,
                "message.to".into(),
                "Missing to: header in message".into(),
                vec![],
                None,
            )),
            StatusCode::BAD_REQUEST.as_u16(),
            "Missing to: header in message".to_string(),
        ));
    };

    // Must be addressed to Mediator
    if to != state.config.mediator_did {
        debug!(
            "to: ({}) doesn't match Mediator DID ({})",
            to, state.config.mediator_did
        );
        return Err(MediatorError::MediatorError(
            51,
            session.session_id.to_string(),
            Some(msg.id.clone()),
            Box::new(ProblemReport::new(
                ProblemReportSorter::Warning,
                ProblemReportScope::Message,
                "message.to".into(),
                "Message Pickup messages must be addressed to the Mediator DID. Received to: {1}"
                    .into(),
                vec![to.to_string()],
                None,
            )),
            StatusCode::BAD_REQUEST.as_u16(),
            "Message Pickup messages must be addressed to the Mediator DID".to_string(),
        ));
    }

    // Message can not be anonymous
    if msg.from.is_none() {
        return Err(MediatorError::MediatorError(
                50,
            session.session_id.to_string(),
            Some(msg.id.clone()),
                Box::new(ProblemReport::new(
                    ProblemReportSorter::Warning,
                    ProblemReportScope::Message,
                    "message.anonymous".into(),
                    "Message Pickup 3.0 messages-received can not be anonymous as it is needed from to validate permissions".into(),
                    vec![],
                    None,
                )),
                StatusCode::BAD_REQUEST.as_u16(),
                "Message Pickup 3.0 messages-received can not be anonymous as it is needed from to validate permissions".to_string(),
            ));
    };

    // Check for extra-header `return_route`
    if let Some(header) = msg.extra_headers.get("return_route") {
        if header.as_str() != Some("all") {
            debug!(
                "return_route: extra-header exists. Expected (all) but received ({})",
                header
            );
            return Err(MediatorError::MediatorError(
                49,
                session.session_id.to_string(),
                Some(msg.id.clone()),
                Box::new(ProblemReport::new(
                    ProblemReportSorter::Warning,
                    ProblemReportScope::Message,
                    "protocol.pickup.return_route".into(),
                    "return_route header is incorrect. Expected (all) but it contains ({1})".into(),
                    vec![header.to_string()],
                    None,
                )),
                StatusCode::BAD_REQUEST.as_u16(),
                format!("return_route header is incorrect. Expected (all) but received ({header})"),
            ));
        }
    } else {
        debug!("return_route: extra-header does not exist!");
        return Err(MediatorError::MediatorError(
            49,
            session.session_id.to_string(),
            Some(msg.id.clone()),
            Box::new(ProblemReport::new(
                ProblemReportSorter::Warning,
                ProblemReportScope::Message,
                "protocol.pickup.return_route".into(),
                "return_route header is missing".into(),
                vec![],
                None,
            )),
            StatusCode::BAD_REQUEST.as_u16(),
            "return_route header is missing".to_string(),
        ));
    }

    Ok(())
}
