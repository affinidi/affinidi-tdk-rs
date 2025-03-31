use std::time::SystemTime;

use crate::{
    SharedData,
    database::session::Session,
    messages::{ProcessMessageResponse, WrapperType, store::store_forwarded_message},
};
use affinidi_messaging_didcomm::{AttachmentData, Message, envelope::MetaEnvelope};
use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_messaging_sdk::protocols::mediator::{accounts::Account, acls::MediatorACLSet};
use base64::prelude::*;
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
    state: &SharedData,
    session: &Session,
) -> Result<ProcessMessageResponse, MediatorError> {
    let _span = span!(
        tracing::Level::DEBUG,
        "routing",
        session_id = session.session_id.as_str()
    );
    async move {
        let next: String =
            if let Ok(body) = serde_json::from_value::<ForwardRequest>(msg.body.to_owned()) {
                match body.next {
                    Some(next_str) => next_str,
                    None => {
                        return Err(MediatorError::RequestDataError(
                            session.session_id.clone(),
                            "Message missing valid 'next' field".into(),
                        ));
                    }
                }
            } else {
                return Err(MediatorError::RequestDataError(
                    session.session_id.clone(),
                    "Message is not a valid ForwardRequest, next is required in body".into(),
                ));
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
                    .await?
            }
            Err(e) => {
                return Err(MediatorError::DatabaseError(
                    session.session_id.clone(),
                    format!("Error getting next account: {}", e),
                ));
            }
        };

        // ****************************************************
        // Check if the next hop is allowed to receive forwarded messages
        let next_acls = MediatorACLSet::from_u64(next_account.acls);
        if !next_acls.get_receive_forwarded().0 {
            return Err(MediatorError::ACLDenied(format!(
                "Next DID({}) is blocked from receiving forwarded messages",
                &next
            )));
        }

        // End of ACL Check for forward_to
        // ****************************************************

        let attachments = if let Some(attachments) = &msg.attachments {
            attachments.to_owned()
        } else {
            return Err(MediatorError::RequestDataError(
                session.session_id.clone(),
                "Nothing to forward, attachments are not defined!".into(),
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
                    return Err(MediatorError::DatabaseError(
                        session.session_id.clone(),
                        format!("Error getting from account: {}", e),
                    ));
                }
            };
            let from_acls = MediatorACLSet::from_u64(from_account.acls);

            if !from_acls.get_send_forwarded().0 {
                return Err(MediatorError::ACLDenied(
                    "DID is blocked from sending forwarded messages".into(),
                ));
            }

            from_account
        } else if !session.acls.get_send_forwarded().0 {
            return Err(MediatorError::ACLDenied(
                "DID is blocked from sending forwarding messages".into(),
            ));
        } else {
            Account {
                acls: state.config.security.global_acl_default.to_u64(),
                ..Default::default()
            }
        };

        // ****************************************************

        // Check against the limits
        let send_limit = from_account
            .queue_send_limit
            .unwrap_or(state.config.limits.queued_send_messages_soft);
        if send_limit != -1
            && from_account.send_queue_count + attachments.len() as u32 >= send_limit as u32
        {
            warn!(
                "Sender DID ({}) has too many messages waiting to be delivered",
                session.did_hash
            );
            return Err(MediatorError::ServiceLimitError(
                session.session_id.clone(),
                "Sender DID has too many messages waiting to be delivered. Try again later".into(),
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
            && next_account.receive_queue_count + attachments.len() as u32 >= recv_limit as u32
        {
            warn!(
                "Next DID ({}) has too many messages waiting to be delivered",
                next_did_hash
            );
            return Err(MediatorError::ServiceLimitError(
                session.session_id.clone(),
                "Next DID has too many messages waiting to be delivered. Try again later".into(),
            ));
        }

        if attachments.len() > state.config.limits.attachments_max_count {
            warn!(
                "Too many attachments in message, limit is {}",
                state.config.limits.attachments_max_count
            );
            return Err(MediatorError::ServiceLimitError(
                session.session_id.clone(),
                format!(
                    "Too many attachments in message. Max ({})",
                    state.config.limits.attachments_max_count
                ),
            ));
        }

        if state.database.get_forward_tasks_len().await? >= state.config.limits.forward_task_queue {
            warn!(
                "Forward task queue is full, limit is {}",
                state.config.limits.forward_task_queue
            );
            return Err(MediatorError::ServiceLimitError(
                session.session_id.clone(),
                format!(
                    "Forward task queue is full. Max ({})",
                    state.config.limits.forward_task_queue
                ),
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
            return Err(MediatorError::ServiceLimitError(
                session.session_id.clone(),
                format!(
                    "Forwarding delay is too long. Max ({})",
                    state.config.processors.forwarding.future_time_limit
                ),
            ));
        }

        // Forward is good, lets process the attachments and add to the queues
        // First step is to determine if the next hop is local to the mediator or remote?
        //if next_did_doc.service

        let attachment = attachments.first().unwrap();
        let data = match attachment.data {
            AttachmentData::Base64 { ref value } => {
                String::from_utf8(BASE64_URL_SAFE_NO_PAD.decode(&value.base64).unwrap()).unwrap()
            }
            AttachmentData::Json { ref value } => {
                if value.jws.is_some() {
                    // TODO: Implement JWS verification
                    return Err(MediatorError::NotImplemented(
                        session.session_id.clone(),
                        "Attachment contains a JWS encrypted JSON payload.".into(),
                    ));
                } else {
                    match serde_json::to_string(&value.json) {
                        Ok(data) => data,
                        Err(e) => {
                            return Err(MediatorError::RequestDataError(
                                session.session_id.clone(),
                                format!("Attachment is not valid JSON: {}", e),
                            ));
                        }
                    }
                }
            }
            _ => {
                return Err(MediatorError::RequestDataError(
                    session.session_id.clone(),
                    "Attachment is wrong format".into(),
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

        // Check inner message for routing
        let next_envelope = match MetaEnvelope::new(&data, &state.did_resolver).await {
            Ok(envelope) => envelope,
            Err(e) => {
                return Err(MediatorError::ParseError(
                    session.session_id.clone(),
                    "Inner envelope inside forwarded envelope DIDComm message".into(),
                    e.to_string(),
                ));
            }
        };
        if next_envelope.from_did.is_none() && !next_acls.get_anon_receive().0 {
            return Err(MediatorError::ACLDenied(
                "Inner message is anonymous and receiver isn't accepting anonymous messages".into(),
            ));
        }

        debug!(" *************************************** ");
        debug!(" TO: {}", next);
        debug!(" FROM: {:?}", msg.from);
        debug!(" Forwarded message:\n{}", data);
        debug!(" Ephemeral: {:?}", msg.extra_headers.get("ephemeral"));
        debug!(" *************************************** ");

        let ephemeral = if let Some(ephemeral) = msg.extra_headers.get("ephemeral") {
            ephemeral.as_bool().unwrap_or(false)
        } else {
            false
        };

        if ephemeral {
            // Live stream the message?
            if let Some(stream_uuid) = state
                .database
                .streaming_is_client_live(&next_did_hash, false)
                .await
            {
                if state
                    .database
                    .streaming_publish_message(&next_did_hash, &stream_uuid, &data, false)
                    .await
                    .is_ok()
                {
                    debug!("Live streaming message to UUID: {}", stream_uuid);
                }
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
) -> Result<bool, MediatorError> {
    let mut _error = None;

    // If the next hop is the mediator itself, then this is a recursive forward
    if next == state.config.mediator_did {
        warn!(
            "next hop is the mediator itself, but this should have been unpacked. not accepting this message"
        );
        return Err(MediatorError::ForwardMessageError(
            session.session_id.clone(),
            "next hop is the mediator, recursive forward found".into(),
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
                                _error = Some(MediatorError::ForwardMessageError(session.session_id.clone(), "next hop is the mediator, recursive forward found".into()));
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
