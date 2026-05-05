use crate::common::time::{unix_timestamp_millis, unix_timestamp_secs};

use crate::didcomm_compat::MetaEnvelope;
use crate::{
    SharedData,
    common::session::Session,
    messages::{
        ProcessMessageResponse, WrapperType,
        error_response::generate_error_response,
        store::{store_forwarded_message, store_message},
    },
};
use affinidi_did_common::Document;
use affinidi_messaging_didcomm::message::Message;
use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_messaging_mediator_common::store::types::ForwardQueueEntry;
use affinidi_messaging_sdk::messages::compat::UnpackMetadata;
use affinidi_messaging_sdk::{
    messages::problem_report::{ProblemReport, ProblemReportScope, ProblemReportSorter},
    protocols::mediator::{accounts::Account, acls::MediatorACLSet},
};
use base64::prelude::*;
use http::StatusCode;
use serde::Deserialize;
use sha256::digest;
use tracing::{Instrument, debug, info, span, warn};
use url::Url;

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
                    return Err(MediatorError::problem(
                        56,
                        &session.session_id,
                        Some(msg.id.to_string()),
                        ProblemReportSorter::Warning,
                        ProblemReportScope::Message,
                        "protocol.forwarding.next.missing",
                        "Forwarding message is missing next field",
                        vec![],
                        StatusCode::BAD_REQUEST,
                    ));
                }
            },
            Err(e) => {
                return Err(MediatorError::problem_with_log(
                    57,
                    &session.session_id,
                    Some(msg.id.to_string()),
                    ProblemReportSorter::Warning,
                    ProblemReportScope::Message,
                    "protocol.forwarding.parse",
                    "Failed to parse forwarding message body. Reason: {1}",
                    vec![e.to_string()],
                    StatusCode::BAD_REQUEST,
                    format!("Failed to parse forwarding message body. Reason: {e}"),
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
                        MediatorError::problem_with_log(
                            14,
                            &session.session_id,
                            Some(msg.id.to_string()),
                            ProblemReportSorter::Error,
                            ProblemReportScope::Protocol,
                            "me.res.storage.error",
                            "Database transaction error: {1}",
                            vec![e.to_string()],
                            StatusCode::SERVICE_UNAVAILABLE,
                            format!("Database transaction error: {e}"),
                        )
                    })?
            }
            Err(e) => {
                return Err(MediatorError::problem_with_log(
                    14,
                    &session.session_id,
                    Some(msg.id.to_string()),
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "me.res.storage.error",
                    "Database transaction error: {1}",
                    vec![e.to_string()],
                    StatusCode::SERVICE_UNAVAILABLE,
                    format!("Database transaction error: {e}"),
                ));
            }
        };

        // ****************************************************
        // Check if the next hop is allowed to receive forwarded messages
        let next_acls = MediatorACLSet::from_u64(next_account.acls);
        if !next_acls.get_receive_forwarded().0 {
            return Err(MediatorError::problem(
                58,
                &session.session_id,
                Some(msg.id.to_string()),
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "authorization.receive_forwarded",
                "Recipient isn't accepting forwarded messages",
                vec![],
                StatusCode::FORBIDDEN,
            ));
        }

        let attachments = if let Some(attachments) = &msg.attachments {
            attachments.to_owned()
        } else {
            return Err(MediatorError::problem(
                59,
                &session.session_id,
                Some(msg.id.to_string()),
                ProblemReportSorter::Warning,
                ProblemReportScope::Message,
                "protocol.forwarding.attachments.missing",
                "There were no attachments for this forward message",
                vec![],
                StatusCode::BAD_REQUEST,
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
                    return Err(MediatorError::problem_with_log(
                        14,
                        &session.session_id,
                        Some(msg.id.to_string()),
                        ProblemReportSorter::Error,
                        ProblemReportScope::Protocol,
                        "me.res.storage.error",
                        "Database transaction error: {1}",
                        vec![e.to_string()],
                        StatusCode::SERVICE_UNAVAILABLE,
                        format!("Database transaction error: {e}"),
                    ));
                }
            };
            let from_acls = MediatorACLSet::from_u64(from_account.acls);

            if !from_acls.get_send_forwarded().0 {
                return Err(MediatorError::problem(
                    60,
                    &session.session_id,
                    Some(msg.id.to_string()),
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "authorization.send_forwarded",
                    "Sender isn't allowed to send forwarded messages",
                    vec![],
                    StatusCode::FORBIDDEN,
                ));
            }

            from_account
        } else if !session.acls.get_send_forwarded().0 {
            return Err(MediatorError::problem(
                60,
                &session.session_id,
                Some(msg.id.to_string()),
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "authorization.send_forwarded",
                "Sender isn't allowed to send forwarded messages",
                vec![],
                StatusCode::FORBIDDEN,
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
            return Err(MediatorError::problem(
                73,
                &session.session_id,
                Some(msg.id.to_string()),
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "authorization.access_list.denied",
                "Delivery blocked due to ACLs (access_list denied)",
                vec![],
                StatusCode::FORBIDDEN,
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
            return Err(MediatorError::problem(
                61,
                &session.session_id,
                Some(msg.id.to_string()),
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "limits.queue.sender",
                "Sender has too many messages waiting to be delivered",
                vec![],
                StatusCode::SERVICE_UNAVAILABLE,
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
            return Err(MediatorError::problem(
                62,
                &session.session_id,
                Some(msg.id.to_string()),
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "limits.queue.recipient",
                "Recipient (next) has too many messages waiting to be delivered",
                vec![],
                StatusCode::SERVICE_UNAVAILABLE,
            ));
        }

        if attachments.len() > state.config.limits.attachments_max_count {
            warn!(
                "Too many attachments in message, limit is {}",
                state.config.limits.attachments_max_count
            );
            return Err(MediatorError::problem_with_log(
                63,
                &session.session_id,
                Some(msg.id.to_string()),
                ProblemReportSorter::Warning,
                ProblemReportScope::Message,
                "protocol.forwarding.attachments.too_many",
                "Forwarded message has too many attachments ({1}). Limit is ({2})",
                vec![
                    attachments.len().to_string(),
                    state.config.limits.attachments_max_count.to_string(),
                ],
                StatusCode::BAD_REQUEST,
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
            return Err(MediatorError::problem(
                64,
                &session.session_id,
                Some(msg.id.to_string()),
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "me.res.forwarding.queue.limit",
                "Mediator forwarding queue is at max limit, try again later",
                vec![
                    attachments.len().to_string(),
                    state.config.limits.attachments_max_count.to_string(),
                ],
                StatusCode::SERVICE_UNAVAILABLE,
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
            return Err(MediatorError::problem_with_log(
                65,
                &session.session_id,
                Some(msg.id.to_string()),
                ProblemReportSorter::Warning,
                ProblemReportScope::Message,
                "protocol.forwarding.delay_milli",
                "Forward delay_milli field isn't valid. Max field value: {1}",
                vec![(state.config.processors.forwarding.future_time_limit * 1000).to_string()],
                StatusCode::BAD_REQUEST,
                format!(
                    "Forward delay_milli field isn't valid. Max field value: {}",
                    state.config.processors.forwarding.future_time_limit * 1000
                ),
            ));
        }

        // Forward is good, lets process the attachments and add to the queues
        // First step is to determine if the next hop is local to the mediator or remote?
        //if next_did_doc.service

        let attachment = match attachments.first() {
            Some(a) => a,
            None => {
                return Err(MediatorError::problem(
                    59,
                    &session.session_id,
                    Some(msg.id.to_string()),
                    ProblemReportSorter::Warning,
                    ProblemReportScope::Message,
                    "protocol.forwarding.attachments.missing",
                    "Forward message has empty attachments list",
                    vec![],
                    StatusCode::BAD_REQUEST,
                ));
            }
        };
        let data = if let Some(ref b64) = attachment.data.base64 {
                match BASE64_URL_SAFE_NO_PAD.decode(b64) {
                    Ok(data) => match String::from_utf8(data) {
                        Ok(data) => data,
                        Err(e) => {
                            return Err(MediatorError::problem_with_log(
                                68,
                                &session.session_id,
                                Some(msg.id.to_string()),
                                ProblemReportSorter::Warning,
                                ProblemReportScope::Message,
                                "protocol.forwarding.attachments.base64",
                                "Failed to decode base64 attachment. Reason: {1}",
                                vec![e.to_string()],
                                StatusCode::BAD_REQUEST,
                                format!("Failed to decode base64 attachment. Reason: {e}"),
                            ));
                        }
                    },
                    Err(e) => {
                        return Err(MediatorError::problem_with_log(
                            68,
                            &session.session_id,
                            Some(msg.id.to_string()),
                            ProblemReportSorter::Warning,
                            ProblemReportScope::Message,
                            "protocol.forwarding.attachments.base64",
                            "Failed to decode base64 attachment. Reason: {1}",
                            vec![e.to_string()],
                            StatusCode::BAD_REQUEST,
                            format!("Failed to decode base64 attachment. Reason: {e}"),
                        ));
                    }
                }
        } else if let Some(ref json_val) = attachment.data.json {
                if attachment.data.jws.is_some() {
                    // JSON-with-JWS attachments would need a full
                    // verification path: parse the protected header,
                    // resolve the kid via the DID resolver, extract
                    // the Ed25519 verification key, then verify before
                    // forwarding. Until that lands, we reject rather
                    // than forward untrusted signed payloads. Most
                    // DIDComm clients use base64-encoded encrypted
                    // attachments instead, which don't require this
                    // path. Tracked as future work in PR #286's
                    // follow-up section.
                    return Err(MediatorError::problem(
                        66,
                        &session.session_id,
                        Some(msg.id.to_string()),
                        ProblemReportSorter::Error,
                        ProblemReportScope::Protocol,
                        "me.not_implemented",
                        "JWS verified attachments are not yet supported by this mediator",
                        vec![],
                        StatusCode::NOT_IMPLEMENTED,
                    ));
                } else {
                    match serde_json::to_string(json_val) {
                        Ok(data) => data,
                        Err(e) => {
                            return Err(MediatorError::problem_with_log(
                                67,
                                &session.session_id,
                                Some(msg.id.to_string()),
                                ProblemReportSorter::Warning,
                                ProblemReportScope::Message,
                                "protocol.forwarding.attachments.json.invalid",
                                "Invalid attachment JSON schema. Reason: {1}",
                                vec![e.to_string()],
                                StatusCode::BAD_REQUEST,
                                format!(
                                    "Invalid attachment JSON schema. Reason: {e}"
                                ),
                            ));
                        }
                    }
                }
        } else if attachment.data.links.is_some() {
                return Err(MediatorError::problem(
                    66,
                    &session.session_id,
                    Some(msg.id.to_string()),
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "me.not_implemented",
                    "Linked attachments are not yet supported by this mediator",
                    vec![],
                    StatusCode::NOT_IMPLEMENTED,
                ));
        } else {
                return Err(MediatorError::problem(
                    67,
                    &session.session_id,
                    Some(msg.id.to_string()),
                    ProblemReportSorter::Warning,
                    ProblemReportScope::Message,
                    "protocol.forwarding.attachments.unknown",
                    "Attachment data format is not supported",
                    vec![],
                    StatusCode::BAD_REQUEST,
                ));
        };

        let expires_at = if let Some(expires_at) = msg.expires_time {
            let now = unix_timestamp_secs();

            if expires_at > now + state.config.limits.message_expiry_seconds {
                now + state.config.limits.message_expiry_seconds
            } else {
                expires_at
            }
        } else {
            unix_timestamp_secs()
                + state.config.limits.message_expiry_seconds
        };

        // Check attached message for routing information
        let next_envelope = match MetaEnvelope::new(&data, &state.did_resolver).await {
            Ok(envelope) => envelope,
            Err(e) => {
                return Err(MediatorError::problem_with_log(
                    37,
                    &session.session_id,
                    Some(msg.id.to_string()),
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "message.envelope.read",
                    "Couldn't read forward attached DIDComm envelope: {1}",
                    vec![e.to_string()],
                    StatusCode::BAD_REQUEST,
                    format!("Couldn't read DIDComm envelope: {e}"),
                ));
            }
        };

        if next_envelope.from_did.is_none() && !next_acls.get_anon_receive().0 {
            return Err(MediatorError::problem(
                69,
                &session.session_id,
                Some(msg.id.to_string()),
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "authorization.receive_anon",
                "Recipient isn't accepting anonymous messages",
                vec![],
                StatusCode::FORBIDDEN,
            ));
        }

        debug!("Forwarded message: to_did_hash={}, ephemeral={}", next_did_hash, ephemeral);

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

                // Check hop count for loop detection
                let hop_count = msg
                    .extra
                    .get("hop_count")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as u32;

                if hop_count >= state.config.processors.forwarding.max_hops {
                    metrics::counter!(crate::common::metrics::names::FORWARD_LOOP_DETECTED_TOTAL).increment(1);
                    return Err(MediatorError::problem_with_log(
                        94,
                        &session.session_id,
                        Some(msg.id.to_string()),
                        ProblemReportSorter::Error,
                        ProblemReportScope::Protocol,
                        "protocol.forwarding.loop_detected",
                        "Message exceeded maximum hop count ({1}), possible forwarding loop",
                        vec![state.config.processors.forwarding.max_hops.to_string()],
                        StatusCode::LOOP_DETECTED,
                        format!(
                            "Message exceeded maximum hop count ({}), possible forwarding loop",
                            state.config.processors.forwarding.max_hops
                        ),
                    ));
                }

                let now_ms = unix_timestamp_millis();

                // Get the sender's full DID for problem reports
                let from_did = msg.from.as_deref().unwrap_or("").to_string();

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
                    hop_count: hop_count + 1,
                };

                state.database.forward_queue_enqueue_with_limit(
                    &entry,
                    state.config.limits.forward_task_queue,
                ).await.map_err(|e| {
                    MediatorError::problem_with_log(
                        90,
                        &session.session_id,
                        Some(msg.id.to_string()),
                        ProblemReportSorter::Error,
                        ProblemReportScope::Protocol,
                        "me.res.forwarding.enqueue",
                        "Failed to enqueue message for remote forwarding: {1}",
                        vec![e.to_string()],
                        StatusCode::SERVICE_UNAVAILABLE,
                        format!("Failed to enqueue message for remote forwarding: {e}"),
                    )
                })?;

                metrics::counter!(crate::common::metrics::names::MESSAGES_FORWARDED_TOTAL).increment(1);
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
/// A DIDCommMessaging service is treated as local when:
/// - the `uri` is this mediator's DID, OR
/// - the `uri` is an HTTP/HTTPS/WS/WSS URL whose `(host, port)` matches
///   one of the authorities recorded in `state.self_authorities`
///   (the bind address plus any operator-declared `local_endpoints`).
///
/// Anything else with an HTTP-shaped URI is treated as a remote mediator
/// and forwarded; non-HTTP URIs that don't match a known authority are
/// treated as local (preserving the original conservative default).
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

            // If the service endpoint is an HTTP(S)/WS(S) URL, decide
            // local-vs-remote by comparing its authority against the
            // mediator's known self-authorities. URLs that point back
            // at this instance (different hostname, same address; or a
            // public alias declared via `local_endpoints`) are
            // collapsed to local delivery instead of being relayed
            // through FORWARD_Q to themselves.
            if uri_clean.starts_with("http://")
                || uri_clean.starts_with("https://")
                || uri_clean.starts_with("ws://")
                || uri_clean.starts_with("wss://")
            {
                if uri_points_at_self(uri_clean, &state.self_authorities) {
                    debug!(
                        "Service endpoint {} resolves to a self-authority — treating as local",
                        uri_clean
                    );
                    return None;
                }
                return Some(uri_clean.to_string());
            }
        }
    }

    // No DIDCommMessaging service found with a remote endpoint — treat as local
    None
}

/// Parse `uri` and return `true` when its `(host, port)` matches any
/// entry in `self_authorities`. Hostnames are normalized via
/// [`crate::server::normalize_host`] (strips outer `[ ]` from IPv6
/// literals, lowercases) so the lookup matches the form inserted by
/// [`crate::server::compute_self_authorities`]. Port falls back to the
/// scheme default via [`crate::server::default_port_for`].
/// Returns `false` for unparseable URLs or schemes without a default port.
fn uri_points_at_self(
    uri: &str,
    self_authorities: &std::collections::HashSet<(String, u16)>,
) -> bool {
    let Ok(url) = Url::parse(uri) else {
        return false;
    };
    let Some(host) = url.host_str() else {
        return false;
    };
    let Some(port) = crate::server::default_port_for(&url) else {
        return false;
    };
    self_authorities.contains(&(crate::server::normalize_host(host), port))
}

#[cfg(test)]
mod tests {
    use super::uri_points_at_self;
    use crate::server::{compute_self_authorities_from, normalize_host};
    use std::collections::HashSet;

    /// Build an authorities set the same way `compute_self_authorities`
    /// does — normalizing each host — so tests stay consistent with the
    /// production insertion path. Tests that want to assert the
    /// normalization itself should use `compute_self_authorities_from`.
    fn authorities(entries: &[(&str, u16)]) -> HashSet<(String, u16)> {
        entries
            .iter()
            .map(|(host, port)| (normalize_host(host), *port))
            .collect()
    }

    #[test]
    fn http_url_matches_listen_address_authority() {
        let auth = authorities(&[("127.0.0.1", 7037)]);
        assert!(uri_points_at_self(
            "http://127.0.0.1:7037/mediator/v1/",
            &auth
        ));
    }

    #[test]
    fn https_url_with_default_port_matches() {
        let auth = authorities(&[("mediator.example.com", 443)]);
        assert!(uri_points_at_self(
            "https://mediator.example.com/mediator/v1/",
            &auth
        ));
    }

    #[test]
    fn ws_url_with_default_port_matches() {
        let auth = authorities(&[("mediator.example.com", 80)]);
        assert!(uri_points_at_self("ws://mediator.example.com/ws", &auth));
    }

    #[test]
    fn wss_url_with_default_port_matches() {
        let auth = authorities(&[("mediator.example.com", 443)]);
        assert!(uri_points_at_self("wss://mediator.example.com/ws", &auth));
    }

    #[test]
    fn host_comparison_is_case_insensitive() {
        let auth = authorities(&[("mediator.example.com", 443)]);
        assert!(uri_points_at_self("https://Mediator.Example.COM/", &auth));
    }

    #[test]
    fn different_host_does_not_match() {
        let auth = authorities(&[("127.0.0.1", 7037)]);
        assert!(!uri_points_at_self(
            "http://other.mediator.example.com:7037/",
            &auth
        ));
    }

    #[test]
    fn different_port_does_not_match() {
        let auth = authorities(&[("127.0.0.1", 7037)]);
        assert!(!uri_points_at_self(
            "http://127.0.0.1:8080/mediator/v1/",
            &auth
        ));
    }

    #[test]
    fn unparseable_uri_does_not_match() {
        let auth = authorities(&[("127.0.0.1", 7037)]);
        assert!(!uri_points_at_self("not a url", &auth));
    }

    #[test]
    fn empty_authority_set_never_matches() {
        let auth = authorities(&[]);
        assert!(!uri_points_at_self("http://127.0.0.1:7037/", &auth));
    }

    // ── IPv6 ─────────────────────────────────────────────────────────────

    /// `Url::host_str()` returns IPv6 literals wrapped in brackets
    /// (`"[::1]"`), but `SocketAddr::ip().to_string()` returns them bare
    /// (`"::1"`). Both forms must funnel through `normalize_host` so a
    /// bracketed URL host matches a bare authority key.
    #[test]
    fn ipv6_bracketed_url_matches_bare_authority() {
        let auth = authorities(&[("::1", 7037)]);
        assert!(uri_points_at_self("http://[::1]:7037/mediator/v1/", &auth));
    }

    /// And the reverse — a bracketed authority entry (e.g. one already
    /// pre-normalized by the operator) must also match a bracketed URL.
    #[test]
    fn ipv6_bracketed_authority_matches_bracketed_url() {
        let auth = authorities(&[("[::1]", 7037)]);
        assert!(uri_points_at_self("http://[::1]:7037/mediator/v1/", &auth));
    }

    /// Full IPv6 address with default https port (no explicit port in URL).
    #[test]
    fn ipv6_full_address_with_default_port_matches() {
        let auth = authorities(&[("2001:db8::1", 443)]);
        assert!(uri_points_at_self(
            "https://[2001:db8::1]/mediator/v1/",
            &auth
        ));
    }

    /// Different IPv6 address must not match.
    #[test]
    fn ipv6_different_address_does_not_match() {
        let auth = authorities(&[("::1", 7037)]);
        assert!(!uri_points_at_self(
            "http://[2001:db8::1]:7037/mediator/v1/",
            &auth
        ));
    }

    // ── URI shape variants — query, path, fragment ──────────────────────

    /// Path components are irrelevant to authority matching.
    #[test]
    fn path_does_not_affect_match() {
        let auth = authorities(&[("mediator.example.com", 443)]);
        assert!(uri_points_at_self(
            "https://mediator.example.com/very/deep/path/",
            &auth
        ));
    }

    /// Query strings are irrelevant.
    #[test]
    fn query_does_not_affect_match() {
        let auth = authorities(&[("mediator.example.com", 443)]);
        assert!(uri_points_at_self(
            "https://mediator.example.com/mediator/v1/?foo=bar&baz=1",
            &auth
        ));
    }

    /// Fragments are irrelevant.
    #[test]
    fn fragment_does_not_affect_match() {
        let auth = authorities(&[("mediator.example.com", 443)]);
        assert!(uri_points_at_self(
            "https://mediator.example.com/mediator/v1/#section",
            &auth
        ));
    }

    /// Scheme without a known default port (and no explicit port) is rejected.
    #[test]
    fn unknown_scheme_without_explicit_port_does_not_match() {
        let auth = authorities(&[("mediator.example.com", 443)]);
        assert!(!uri_points_at_self(
            "ftp://mediator.example.com/mediator/v1/",
            &auth
        ));
    }

    // ── compute_self_authorities_from integration ──────────────────────

    /// `listen_address` and `local_endpoints` together populate the
    /// authority set with normalized keys.
    #[test]
    fn compute_self_authorities_combines_bind_and_endpoints() {
        let auth = compute_self_authorities_from(
            "127.0.0.1:7037",
            &["https://mediator.example.com".to_string()],
        );
        assert!(auth.contains(&("127.0.0.1".to_string(), 7037)));
        assert!(auth.contains(&("mediator.example.com".to_string(), 443)));
        assert_eq!(auth.len(), 2);
    }

    /// IPv6 listen_address round-trips: a `[::1]`-shaped DID-Doc URI
    /// finds the `"::1"` authority cached from the bind address. This
    /// is the regression test for the IPv6 host-normalization bug.
    #[test]
    fn ipv6_listen_address_round_trips_through_authorities() {
        let auth = compute_self_authorities_from("[::1]:7037", &[]);
        assert!(uri_points_at_self("http://[::1]:7037/mediator/v1/", &auth));
    }

    /// Full IPv6 listen_address with operator-declared bracketed alias —
    /// both should normalize to the same key set.
    #[test]
    fn compute_self_authorities_normalizes_ipv6_endpoints() {
        let auth = compute_self_authorities_from(
            "[2001:db8::1]:7037",
            &["http://[2001:db8::1]:7037".to_string()],
        );
        // Single entry — the bracketed endpoint normalizes to match the bind.
        assert_eq!(auth.len(), 1);
        assert!(auth.contains(&("2001:db8::1".to_string(), 7037)));
    }

    /// Malformed `local_endpoints` entries are skipped, not fatal.
    #[test]
    fn compute_self_authorities_skips_malformed_endpoints() {
        let auth = compute_self_authorities_from(
            "127.0.0.1:7037",
            &[
                "not-a-url".to_string(),
                "ftp://no-default-port-known/".to_string(),
                "https://valid.example.com".to_string(),
            ],
        );
        // Only the bind address + the one valid HTTPS endpoint survive.
        assert!(auth.contains(&("127.0.0.1".to_string(), 7037)));
        assert!(auth.contains(&("valid.example.com".to_string(), 443)));
        assert_eq!(auth.len(), 2);
    }

    /// An empty bind + empty endpoints yields an empty authority set,
    /// which by construction never matches anything.
    #[test]
    fn compute_self_authorities_with_empty_inputs_is_empty() {
        let auth = compute_self_authorities_from("", &[]);
        assert!(auth.is_empty());
    }
}
