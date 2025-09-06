use std::{slice, time::SystemTime};

use super::acls::check_permissions;
use crate::{SharedData, database::session::Session, messages::ProcessMessageResponse};
use affinidi_messaging_didcomm::{Message, UnpackMetadata};
use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_messaging_sdk::{
    messages::problem_report::{ProblemReport, ProblemReportScope, ProblemReportSorter},
    protocols::mediator::{
        accounts::{AccountChangeQueueLimitsResponse, AccountType, MediatorAccountRequest},
        acls::{AccessListModeType, MediatorACLSet},
    },
};
use http::StatusCode;
use serde_json::{Value, json};
use sha256::digest;
use subtle::ConstantTimeEq;
use tracing::{Instrument, debug, info, span, warn};
use uuid::Uuid;

pub(crate) async fn process(
    msg: &Message,
    state: &SharedData,
    session: &Session,
    metadata: &UnpackMetadata,
) -> Result<ProcessMessageResponse, MediatorError> {
    let _span = span!(tracing::Level::DEBUG, "mediator_accounts");

    async move {
        // Check if message is valid from an expiry perspective (for any admin accounts)
        if session.account_type == AccountType::Admin
        || session.account_type == AccountType::RootAdmin
        {
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
        }

        // Parse the message body
        let request: MediatorAccountRequest = match serde_json::from_value(msg.body.clone()) {
            Ok(request) => request,
            Err(err) => {
                warn!(
                    "Error parsing Mediator Account request. Reason: {}",
                    err
                );
                return Err(MediatorError::MediatorError(
                    81,
                    session.session_id.to_string(),
                    Some(msg.id.to_string()),
                    Box::new(ProblemReport::new(
                        ProblemReportSorter::Warning,
                        ProblemReportScope::Message,
                        "protocol.mediator.accounts.parse".into(),
                        "Message body couldn't be parsed correctly".into(),
                        vec![],
                        None,
                    )),
                    StatusCode::BAD_REQUEST.as_u16(),
                    "Message body couldn't be parsed correctly".to_string(),
                ));
            }
        };
        debug!("Received Mediator Account request: {:?}", request);

        // Process the request
        match request {
            MediatorAccountRequest::AccountGet(did_hash) => {
                // Check permissions and ACLs
                if !check_permissions(session, slice::from_ref(&did_hash), state.config.security.block_remote_admin_msgs, &metadata.sign_from) {
                    warn!("ACL Request from DID ({}) failed. ", session.did_hash);
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

                match state.database.account_get(&did_hash).await {
                    Ok(response) => _generate_response_message(
                        &msg.id,
                        &session.did,
                        &state.config.mediator_did,
                        &json!(response),
                    ),
                    Err(e) => {
                        warn!("database error account_get(). Reason: {}", e);
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
            MediatorAccountRequest::AccountList { cursor, limit } => {
                if !(session.account_type == AccountType::Admin || session.account_type == AccountType::RootAdmin) {
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

                match state.database.account_list(cursor, limit).await {
                    Ok(response) => _generate_response_message(
                        &msg.id,
                        &session.did,
                        &state.config.mediator_did,
                        &json!(response),
                    ),
                    Err(e) => {
                        warn!("Error listing accounts. Reason: {}", e);
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
            MediatorAccountRequest::AccountAdd {did_hash, acls } => {
                // Check permissions and ACLs
                // 1. Is mediator in explicit_allow mode and is the requestor an ADMIN?
                if state.config.security.mediator_acl_mode == AccessListModeType::ExplicitAllow && !(session.account_type == AccountType::Admin || session.account_type == AccountType::RootAdmin) {
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

                // 2. Setup the ACLs correctly if not an admin account
                let acls = if session.account_type == AccountType::Admin || session.account_type == AccountType::RootAdmin {
                    if let Some(acls) = acls {
                        MediatorACLSet::from_u64(acls)
                    } else {
                        state.config.security.global_acl_default.clone()
                    }
                } else {
                    state.config.security.global_acl_default.clone()
                };

                match state
                    .database
                    .account_add(&did_hash, &acls, None)
                    .await
                {
                    Ok(response) => _generate_response_message(
                        &msg.id,
                        &session.did,
                        &state.config.mediator_did,
                        &json!(response),
                    ),
                    Err(e) => {
                        warn!("Error adding account. Reason: {}", e);
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
            MediatorAccountRequest::AccountRemove(did_hash) => {
                // Check permissions and ACLs
                if !check_permissions(session, slice::from_ref(&did_hash), state.config.security.block_remote_admin_msgs, &metadata.sign_from) {
                    warn!("ACL Request from DID ({}) failed. ", session.did_hash);
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

                // Check if the mediator DID is being removed
                // Protects accidentally deleting the mediator itself
                if state.config.mediator_did_hash.as_bytes().ct_eq(did_hash.as_bytes()).unwrap_u8() == 1 {
                    return Err(MediatorError::MediatorError(
                        18,
                        session.session_id.to_string(),
                        Some(msg.id.to_string()),
                        Box::new(ProblemReport::new(
                            ProblemReportSorter::Warning,
                            ProblemReportScope::Message,
                            "database.account.remove.protected".into(),
                            "Tried to remove a protected account (Mediator, Root-Admin)".into(),
                            vec![],
                            None,
                        )),
                        StatusCode::FORBIDDEN.as_u16(),
                        "Tried to remove a protected account (Mediator, Root-Admin)".to_string(),
                    ));
                }

                // Check if the root admin DID is being removed
                // Protects accidentally deleting the only admin account
                let root_admin = digest(&state.config.admin_did);
                if root_admin.as_bytes().ct_eq(did_hash.as_bytes()).unwrap_u8() == 1 {
                    return Err(MediatorError::MediatorError(
                        18,
                        session.session_id.to_string(),
                        Some(msg.id.to_string()),
                        Box::new(ProblemReport::new(
                            ProblemReportSorter::Warning,
                            ProblemReportScope::Message,
                            "database.account.remove.protected".into(),
                            "Tried to remove a protected account (Mediator, Root-Admin)".into(),
                            vec![],
                            None,
                        )),
                        StatusCode::FORBIDDEN.as_u16(),
                        "Tried to remove a protected account (Mediator, Root-Admin)".to_string(),
                    ));
                }
                match state.database.account_remove(session,&did_hash, false, false).await {
                    Ok(response) => _generate_response_message(
                        &msg.id,
                        &session.did,
                        &state.config.mediator_did,
                        &json!(response),
                    ),
                    Err(e) => {
                        warn!("Error removing account. Reason: {}", e);
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
            MediatorAccountRequest::AccountChangeType {did_hash, _type } => {
                // Must be an admin level account to change this
                if !state.database.check_admin_account(&session.did_hash).await? {
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

                // Only RootAdmin account can change account type to RootAdmin
                if _type == AccountType::RootAdmin && session.account_type != AccountType::RootAdmin {
                    warn!("DID ({}) is not a RootAdmin account", session.did_hash);
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

                // Get current account type and handle any shift to/from admin
                let current = state.database.account_get(&did_hash).await?;
                if let Some(current) = &current {
                    if current._type == AccountType::RootAdmin && session.account_type != AccountType::RootAdmin {
                        warn!("DID ({}) is not a RootAdmin account", session.did_hash);
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
                    } else if current._type == _type {
                        // Types are the same, no need to change.
                        return _generate_response_message(
                            &msg.id,
                            &session.did,
                            &state.config.mediator_did,
                            &json!(true),
                        );
                    } else if current._type.is_admin() && _type.is_admin() {
                        // Changing between different admin types is ok
                        debug!("Switching admin type for DID: {} from ({}) to ({})", did_hash, current._type, _type);
                    } else if current._type.is_admin() && !_type.is_admin() {
                        // Need to strip admin rights first
                        state.database.strip_admin_accounts(vec![did_hash.clone()]).await?;
                    } else if !current._type.is_admin() && _type.is_admin() {
                        // Need to add admin rights
                        state.database.setup_admin_account(&did_hash, _type, &MediatorACLSet::from_u64(current.acls)).await?;
                        info!("Added admin ({}) rights to DID: {}", _type, did_hash);
                        return _generate_response_message(
                            &msg.id,
                            &session.did,
                            &state.config.mediator_did,
                            &json!(true),
                        );
                    }
                }

                // If here, then it is a simple type change at this point

                match state.database.account_change_type(&did_hash, &_type).await {
                    Ok(_) => {
                        let current_type = if let Some(current) = &current {
                            current._type.to_string()
                        } else {
                            "Unknown".to_string()
                        };
                        info!("Changed account type for DID: ({}) from ({}) to ({})", did_hash, current_type, _type);
                        _generate_response_message(
                        &msg.id,
                        &session.did,
                        &state.config.mediator_did,
                        &json!(true),
                    )}
                    Err(e) => {
                        warn!("Error Changing account type. Reason: {}", e);
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
            MediatorAccountRequest::AccountChangeQueueLimits {did_hash, send_queue_limit, receive_queue_limit } => {
                 // Check permissions and ACLs
                 if !check_permissions(session, slice::from_ref(&did_hash), state.config.security.block_remote_admin_msgs, &metadata.sign_from) {
                    warn!("ACL Request from DID ({}) failed. ", session.did_hash);
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

                // Check ACL's
                let (send_queue_limit, receive_queue_limit) = if session.account_type == AccountType::Standard {
                    // Check send queue limit ACL and limits
                    let send_queue_limit = if session.acls.get_self_manage_send_queue_limit() {
                        if let Some(limit) = send_queue_limit {
                            if limit == -1 || limit == -2 {
                                send_queue_limit
                            } else if limit > state.config.limits.queued_send_messages_hard {
                                Some(state.config.limits.queued_send_messages_hard)
                            } else {
                                send_queue_limit
                            }
                        } else {
                            None
                        }
                    } else {
                        None
                    };

                    let receive_queue_limit = if session.acls.get_self_manage_receive_queue_limit() {
                        if let Some(limit) = receive_queue_limit {
                            if limit == -1 || limit == -2 {
                                receive_queue_limit
                            } else if limit > state.config.limits.queued_receive_messages_hard {
                                Some(state.config.limits.queued_receive_messages_hard)
                            } else {
                                receive_queue_limit
                            }
                        } else {
                            None
                        }
                    } else {
                        None
                    };

                    (send_queue_limit, receive_queue_limit)
                } else {
                    // Admin account
                    (send_queue_limit, receive_queue_limit)
                };

                match state.database.account_change_queue_limits(&did_hash, send_queue_limit, receive_queue_limit).await {
                    Ok(_) => {
                        info!("Changed account queue_limits for DID: ({}) to send({:?}) receive({:?})", did_hash, send_queue_limit, receive_queue_limit);
                        _generate_response_message(
                        &msg.id,
                        &session.did,
                        &state.config.mediator_did,
                        &json!(AccountChangeQueueLimitsResponse { send_queue_limit, receive_queue_limit}),
                    )}
                    Err(e) => {
                        warn!("Error Changing account type. Reason: {}", e);
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
        "https://didcomm.org/mediator/1.0/account-management".to_owned(),
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
