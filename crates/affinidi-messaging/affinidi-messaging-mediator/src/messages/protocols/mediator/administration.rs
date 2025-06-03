//! Adds and removed administration accounts from the mediator
//! Must be a administrator to use this protocol
use std::time::SystemTime;

use affinidi_messaging_didcomm::{Message, UnpackMetadata};
use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_messaging_sdk::{
    messages::problem_report::{ProblemReport, ProblemReportScope, ProblemReportSorter},
    protocols::mediator::administration::MediatorAdminRequest,
};
use http::StatusCode;
use serde_json::{Value, json};
use sha256::digest;
use subtle::ConstantTimeEq;
use tracing::{Instrument, span, warn};
use uuid::Uuid;

use crate::{SharedData, database::session::Session, messages::ProcessMessageResponse};

use super::acls::check_admin_signature;

/// Responsible for processing a Mediator Administration message
pub(crate) async fn process(
    msg: &Message,
    state: &SharedData,
    session: &Session,
    metadata: &UnpackMetadata,
) -> Result<ProcessMessageResponse, MediatorError> {
    let _span = span!(tracing::Level::DEBUG, "mediator_administration");

    async move {
        // Check if message is valid from an expiry perspective
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if let Some(created_time) = msg.created_time {
            if (created_time + state.config.security.admin_messages_expiry) <= now
                || created_time > now
            {
                warn!("ADMIN related message has an invalid created_time header.");
                return Err(MediatorError::MediatorError(
                    31,
                    session.session_id.to_string(),
                    Some(msg.id.to_string()),
                    Box::new(ProblemReport::new(
                        ProblemReportSorter::Error,
                        ProblemReportScope::Protocol,
                        "message.expired".into(),
                        "Message was created too long ago for admin requests: {1}".into(),
                        vec![created_time.to_string()],
                        None,
                    )),
                    StatusCode::BAD_REQUEST.as_u16(),
                    "Message was created too long ago for admin requests".to_string(),
                ));
            }
        } else {
            warn!("ADMIN related message has no created_time header. Required.");
            return Err(MediatorError::MediatorError(
                31,
                session.session_id.to_string(),
                Some(msg.id.to_string()),
                Box::new(ProblemReport::new(
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "message.expired".into(),
                    "Message missing created_time header".into(),
                    vec![],
                    None,
                )),
                StatusCode::BAD_REQUEST.as_u16(),
                "Message missing created_time header".to_string(),
            ));
        }

        // Check to ensure this account is an admin account
        if !state
            .database
            .check_admin_account(&session.did_hash)
            .await?
            || (state.config.security.block_remote_admin_msgs
                && !check_admin_signature(session, &metadata.sign_from))
        {
            warn!("DID ({}) is not an admin account", session.did_hash);
            return Err(MediatorError::MediatorError(
                45,
                session.session_id.to_string(),
                Some(msg.id.to_string()),
                Box::new(ProblemReport::new(
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "authorization.permission".into(),
                    "DID does not have permission to access the requested resource".into(),
                    vec![],
                    None,
                )),
                StatusCode::FORBIDDEN.as_u16(),
                "DID does not have permission to access the requested resource".to_string(),
            ));
        }

        // Parse the message body
        let request: MediatorAdminRequest = match serde_json::from_value(msg.body.clone()) {
            Ok(request) => request,
            Err(err) => {
                warn!(
                    "Error parsing Mediator Administration request. Reason: {}",
                    err
                );
                return Err(MediatorError::MediatorError(
                    83,
                    session.session_id.to_string(),
                    Some(msg.id.to_string()),
                    Box::new(ProblemReport::new(
                        ProblemReportSorter::Warning,
                        ProblemReportScope::Message,
                        "protocol.mediator.administration.parse".into(),
                        "Message body couldn't be parsed correctly".into(),
                        vec![],
                        None,
                    )),
                    StatusCode::BAD_REQUEST.as_u16(),
                    "Message body couldn't be parsed correctly".to_string(),
                ));
            }
        };

        // Process the request
        match request {
            MediatorAdminRequest::AdminList { cursor, limit } => {
                match state.database.list_admin_accounts(cursor, limit).await {
                    Ok(response) => _generate_response_message(
                        &msg.id,
                        &session.did,
                        &state.config.mediator_did,
                        &json!(response),
                    ),
                    Err(e) => {
                        warn!("Error listing admin accounts. Reason: {}", e);
                        Err(MediatorError::MediatorError(
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
                        ))
                    }
                }
            }
            MediatorAdminRequest::AdminAdd(attr) => {
                match state
                    .database
                    .add_admin_accounts(attr, &state.config.security.global_acl_default)
                    .await
                {
                    Ok(response) => _generate_response_message(
                        &msg.id,
                        &session.did,
                        &state.config.mediator_did,
                        &json!(response),
                    ),
                    Err(e) => {
                        warn!("Error adding admin accounts. Reason: {}", e);
                        Err(MediatorError::MediatorError(
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
                        ))
                    }
                }
            }
            MediatorAdminRequest::AdminStrip(attr) => {
                // Remove root admin DID and Mediator DID in case it is in the list
                // Protects accidentally deleting the only admin account or the mediator itself
                let root_admin = digest(&state.config.admin_did);
                let attr: Vec<String> = attr
                    .iter()
                    .filter_map(|a| {
                        if a.as_bytes().ct_eq(root_admin.as_bytes()).unwrap_u8() == 1
                            || a.as_bytes()
                                .ct_eq(state.config.mediator_did_hash.as_bytes())
                                .unwrap_u8()
                                == 1
                        {
                            None
                        } else {
                            Some(a.to_owned())
                        }
                    })
                    .collect();
                if attr.is_empty() {
                    return Err(MediatorError::MediatorError(
                        84,
                        session.session_id.to_string(),
                        Some(msg.id.to_string()),
                        Box::new(ProblemReport::new(
                            ProblemReportSorter::Warning,
                            ProblemReportScope::Message,
                            "protocol.mediator.administration.strip.missing".into(),
                            "Missing admin DID to strip admin type from".into(),
                            vec![],
                            None,
                        )),
                        StatusCode::BAD_REQUEST.as_u16(),
                        "Missing admin DID to strip admin type from".to_string(),
                    ));
                }
                match state.database.strip_admin_accounts(attr).await {
                    Ok(response) => _generate_response_message(
                        &msg.id,
                        &session.did,
                        &state.config.mediator_did,
                        &json!(response),
                    ),
                    Err(e) => {
                        warn!("Error removing admin accounts. Reason: {}", e);
                        Err(MediatorError::MediatorError(
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
                        ))
                    }
                }
            }
            MediatorAdminRequest::Configuration(_) => {
                // Return the current configuration
                let config = json!({"version": env!("CARGO_PKG_VERSION"), "config": state.config});
                _generate_response_message(
                    &msg.id,
                    &session.did,
                    &state.config.mediator_did,
                    &config,
                )
            }
        }
    }
    .instrument(_span)
    .await
}

/// Helper method that generates a response message
/// - `thid` - The thread ID of the message
/// - `to` - The recipient of the message
/// - `from` - The sender of the message
/// - `value` - The value to send in the message
fn _generate_response_message(
    thid: &str,
    to: &str,
    from: &str,
    value: &Value,
) -> Result<ProcessMessageResponse, MediatorError> {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Build the message
    let response = Message::build(
        Uuid::new_v4().into(),
        "https://didcomm.org/mediator/1.0/admin-management".to_owned(),
        value.to_owned(),
    )
    .thid(thid.to_owned())
    .to(to.to_owned())
    .from(from.to_owned())
    .created_time(now)
    .expires_time(now + 300)
    .finalize();

    Ok(ProcessMessageResponse {
        store_message: true,
        force_live_delivery: false,
        data: crate::messages::WrapperType::Message(Box::new(response)),
        forward_message: false,
    })
}
