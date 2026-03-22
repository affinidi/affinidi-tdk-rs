use std::{slice, time::SystemTime};

use crate::{SharedData, database::session::Session, messages::ProcessMessageResponse};
use affinidi_messaging_didcomm::{Message, UnpackMetadata};
use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_messaging_sdk::{
    messages::problem_report::{ProblemReport, ProblemReportScope, ProblemReportSorter},
    protocols::mediator::{
        accounts::AccountType, acls::MediatorACLSet, acls_handler::MediatorACLRequest,
    },
};
use http::StatusCode;
use serde_json::{Value, json};
use subtle::ConstantTimeEq;
use tracing::{Instrument, span, warn};
use uuid::Uuid;

pub(crate) async fn process(
    msg: &Message,
    state: &SharedData,
    session: &Session,
    metadata: &UnpackMetadata,
) -> Result<ProcessMessageResponse, MediatorError> {
    let _span = span!(tracing::Level::DEBUG, "mediator_acls");

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
        let request: MediatorACLRequest = match serde_json::from_value(msg.body.clone()) {
            Ok(request) => request,
            Err(err) => {
                warn!("Error parsing Mediator ACL request. Reason: {}", err);
                return Err(MediatorError::MediatorError(
                    82,
                    session.session_id.to_string(),
                    Some(msg.id.to_string()),
                    Box::new(ProblemReport::new(
                        ProblemReportSorter::Warning,
                        ProblemReportScope::Message,
                        "protocol.mediator.acls.parse".into(),
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
            MediatorACLRequest::GetACL(dids) => {
                // Check permissions and ACLs
                if !check_permissions(
                    session,
                    &dids,
                    state.config.security.block_remote_admin_msgs,
                    &metadata.sign_from,
                ) {
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

                match state
                    .database
                    .get_did_acls(&dids, state.config.security.mediator_acl_mode.clone())
                    .await
                {
                    Ok(response) => _generate_response_message(
                        &msg.id,
                        &session.did,
                        &state.config.mediator_did,
                        &json!(response),
                    ),
                    Err(e) => {
                        warn!("Error getting ACLs. Reason: {}", e);
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
                            format!("Database transaction error: {e}"),
                        ))
                    }
                }
            }
            MediatorACLRequest::SetACL { did_hash, acls } => {
                // Check permissions and ACLs
                if !check_permissions(
                    session,
                    slice::from_ref(&did_hash),
                    state.config.security.block_remote_admin_msgs,
                    &metadata.sign_from,
                ) {
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

                // Additional checks for ACL changes for non-admin accounts
                if session.account_type != AccountType::RootAdmin
                    && session.account_type != AccountType::Admin
                {
                    let current_acls = match state.database.get_did_acl(&did_hash).await {
                        Ok(Some(response)) => response,
                        Ok(None) => state.config.security.global_acl_default.clone(),
                        Err(e) => {
                            warn!("Error getting ACLs. Reason: {}", e);
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

                    if let Some(errors) = acl_change_ok(&current_acls, &MediatorACLSet::from_u64(acls)) {
                        warn!("Can't change ACLs. Reason: self_change not allowed");

                        // Creates a string placement for each error. E.g. {1}, {2}, {3}
                        let mut s = String::new();
                        let mut i = 1;
                        for _ in &errors {
                            s.push_str(&format!(" ({{{i}}})"));
                            i += 1;
                        }

                        return Err(MediatorError::MediatorError(
                            80,
                            session.session_id.to_string(),
                            Some(msg.id.to_string()),
                            Box::new(ProblemReport::new(
                                ProblemReportSorter::Warning,
                                ProblemReportScope::Message,
                                "protocol.acls.change.denied".into(),
                                format!("A non-admin account tried to change ACL Flags but self-change is not allowed:{s}"),
                                errors,
                                None,
                            )),
                            StatusCode::FORBIDDEN.as_u16(),
                            "A non-admin account tried to change ACL Flags but self-change is not allowed".to_string(),
                        ));
                    }
                }

                match state
                    .database
                    .set_did_acl(&did_hash, &MediatorACLSet::from_u64(acls))
                    .await
                {
                    Ok(response) => _generate_response_message(
                        &msg.id,
                        &session.did,
                        &state.config.mediator_did,
                        &json!({"acls": response}),
                    ),
                    Err(e) => {
                        warn!("Error setting ACLs. Reason: {}", e);
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
                            format!("Database transaction error: {e}"),
                        ))
                    }
                }
            }
            MediatorACLRequest::AccessListList { did_hash, cursor } => {
                // Check permissions and ACLs
                if !check_permissions(
                    session,
                    slice::from_ref(&did_hash),
                    state.config.security.block_remote_admin_msgs,
                    &metadata.sign_from,
                ) {
                    warn!("List Access List from DID ({}) failed. ", session.did_hash);
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

                match state
                    .database
                    .access_list_list(&did_hash, cursor.unwrap_or_default())
                    .await
                {
                    Ok(response) => _generate_response_message(
                        &msg.id,
                        &session.did,
                        &state.config.mediator_did,
                        &json!(response),
                    ),
                    Err(e) => {
                        warn!("Error Listing Access List. Reason: {}", e);
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
                            format!("Database transaction error: {e}"),
                        ))
                    }
                }
            }
            MediatorACLRequest::AccessListAdd { did_hash, hashes } => {
                // Check permissions and ACLs
                if !check_permissions(
                    session,
                    slice::from_ref(&did_hash),
                    state.config.security.block_remote_admin_msgs,
                    &metadata.sign_from,
                ) {
                    warn!("Add Access List from DID ({}) failed. ", session.did_hash);
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

                // Check if self_change is allowed
                if !session.acls.get_self_manage_list() && session.account_type == AccountType::Standard {
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

                if hashes.is_empty() || hashes.len() > 100 {
                    return Err(MediatorError::MediatorError(
                        82,
                        session.session_id.to_string(),
                        Some(msg.id.to_string()),
                        Box::new(ProblemReport::new(
                            ProblemReportSorter::Error,
                            ProblemReportScope::Protocol,
                            "protocol.mediator.access_list.limit".into(),
                            "Error Adding to Access List: limits exceeded (must be 0 < count <= 100)".into(),
                            vec![],
                            None,
                        )),
                        StatusCode::BAD_REQUEST.as_u16(),
                        "Error Adding to Access List: limits exceeded (must be 0 < count <= 100)".to_string(),
                    ));
                }

                match state
                    .database
                    .access_list_add(state.config.limits.access_list_limit, &did_hash, &hashes)
                    .await
                {
                    Ok(response) => _generate_response_message(
                        &msg.id,
                        &session.did,
                        &state.config.mediator_did,
                        &json!(response),
                    ),
                    Err(e) => {
                        warn!("Error Add to Access List. Reason: {}", e);
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
                            format!("Database transaction error: {e}"),
                        ))
                    }
                }
            }
            MediatorACLRequest::AccessListRemove { did_hash, hashes } => {
                // Check permissions and ACLs
                if !check_permissions(
                    session,
                    slice::from_ref(&did_hash),
                    state.config.security.block_remote_admin_msgs,
                    &metadata.sign_from,
                ) {
                    warn!(
                        "Remove Access List from DID ({}) failed. ",
                        session.did_hash
                    );
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

                // Check if self_change is allowed
                if !session.acls.get_self_manage_list() && session.account_type == AccountType::Standard {
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

                if hashes.is_empty() || hashes.len() > 100 {
                    return Err(MediatorError::MediatorError(
                        82,
                        session.session_id.to_string(),
                        Some(msg.id.to_string()),
                        Box::new(ProblemReport::new(
                            ProblemReportSorter::Error,
                            ProblemReportScope::Protocol,
                            "protocol.mediator.access_list.limit".into(),
                            "Error Removing from Access List: limits exceeded (must be 0 < count <= 100)".into(),
                            vec![],
                            None,
                        )),
                        StatusCode::BAD_REQUEST.as_u16(),
                        "Error Removing from Access List: limits exceeded (must be 0 < count <= 100)".to_string(),
                    ));
                }

                match state.database.access_list_remove(&did_hash, &hashes).await {
                    Ok(response) => _generate_response_message(
                        &msg.id,
                        &session.did,
                        &state.config.mediator_did,
                        &json!(response),
                    ),
                    Err(e) => {
                        warn!("Error Remove from Access List. Reason: {}", e);
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
                            format!("Database transaction error: {e}"),
                        ))
                    }
                }
            }
            MediatorACLRequest::AccessListClear { did_hash } => {
                // Check permissions and ACLs
                if !check_permissions(
                    session,
                    slice::from_ref(&did_hash),
                    state.config.security.block_remote_admin_msgs,
                    &metadata.sign_from,
                ) {
                    warn!("Clear Access List for DID ({}) failed. ", session.did_hash);
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

                // Check if self_change is allowed
                if !session.acls.get_self_manage_list() && session.account_type == AccountType::Standard {
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

                match state.database.access_list_clear(&did_hash).await {
                    Ok(response) => _generate_response_message(
                        &msg.id,
                        &session.did,
                        &state.config.mediator_did,
                        &json!(response),
                    ),
                    Err(e) => {
                        warn!("Error Clearing Access List. Reason: {}", e);
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
                            format!("Database transaction error: {e}"),
                        ))
                    }
                }
            }
            MediatorACLRequest::AccessListGet { did_hash, hashes } => {
                // Check permissions and ACLs
                if !check_permissions(
                    session,
                    slice::from_ref(&did_hash),
                    state.config.security.block_remote_admin_msgs,
                    &metadata.sign_from,
                ) {
                    warn!(
                        "Get from Access List for DID ({}) failed. ",
                        session.did_hash
                    );
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

                match state.database.access_list_get(&did_hash, &hashes).await {
                    Ok(response) => _generate_response_message(
                        &msg.id,
                        &session.did,
                        &state.config.mediator_did,
                        &json!(response),
                    ),
                    Err(e) => {
                        warn!("Error Getting from Access List. Reason: {}", e);
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
                            format!("Database transaction error: {e}"),
                        ))
                    }
                }
            }
        }
    }
    .instrument(_span)
    .await
}

/// Helper function to ensure the signing DID matches the session DID
/// returns true if all ok, false otherwise
pub(crate) fn check_admin_signature(session: &Session, sign_by: &Option<String>) -> bool {
    if let Some(sign_by) = sign_by {
        if let Some(sign_did) = sign_by.split_once('#') {
            if sign_did.0 != session.did {
                return false;
            }
        } else {
            return false;
        }
    } else {
        return false;
    }

    true
}

/// Helper method that determines if an ACL Request can be processed
/// Checks if the account is an admin account (blanket allow/approval)
/// If not admin, then ensures we are only operating on the account's own DID
/// Returns true if the request can be processed, false otherwise
pub(crate) fn check_permissions(
    session: &Session,
    dids: &[String],
    check_admin_signing: bool,
    sign_by: &Option<String>,
) -> bool {
    // If we need to check message signature for an admin request
    if check_admin_signing
        && (session.account_type == AccountType::Admin
            || session.account_type == AccountType::RootAdmin)
        && !check_admin_signature(session, sign_by)
    {
        return false;
    }

    session.account_type == AccountType::RootAdmin
        || session.account_type == AccountType::Admin
        || dids.len() == 1
            && dids[0]
                .as_bytes()
                .ct_eq(session.did_hash.as_bytes())
                .unwrap_u8()
                == 1
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
        "https://affinidi.com/messaging/global-acl-management".to_owned(),
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

/// Helper method that checks if the ACL change is valid for non-admin accounts
/// checks if self_change would block any modification of the ACLs
/// returns None if ok
/// returns Some(vec) with errors if not ok
fn acl_change_ok(current_acls: &MediatorACLSet, new_acls: &MediatorACLSet) -> Option<Vec<String>> {
    let mut errors = Vec::new();

    if (current_acls.get_access_list_mode().0 != new_acls.get_access_list_mode().0)
        && !current_acls.get_access_list_mode().1
    {
        errors.push("access_list_mode not allowed to change".to_string());
    }

    if current_acls.get_access_list_mode().1 != new_acls.get_access_list_mode().1 {
        errors.push("access_list_mode:self_change can't modify!".to_string());
    }

    if (current_acls.get_send_messages().0 != new_acls.get_send_messages().0)
        && !current_acls.get_send_messages().1
    {
        errors.push("send_messages not allowed to change".to_string());
    }

    if current_acls.get_send_messages().1 != new_acls.get_send_messages().1 {
        errors.push("send_messages:self_change can't modify!".to_string());
    }

    if (current_acls.get_receive_messages().0 != new_acls.get_receive_messages().0)
        && !current_acls.get_receive_messages().1
    {
        errors.push("receive_messages not allowed to change".to_string());
    }

    if current_acls.get_receive_messages().1 != new_acls.get_receive_messages().1 {
        errors.push("receive_messages:self_change can't modify!".to_string());
    }

    if (current_acls.get_send_forwarded().0 != new_acls.get_send_forwarded().0)
        && !current_acls.get_send_forwarded().1
    {
        errors.push("send_forwarded not allowed to change".to_string());
    }

    if current_acls.get_send_forwarded().1 != new_acls.get_send_forwarded().1 {
        errors.push("send_forwarded:self_change can't modify!".to_string());
    }

    if (current_acls.get_receive_forwarded().0 != new_acls.get_receive_forwarded().0)
        && !current_acls.get_receive_forwarded().1
    {
        errors.push("get_receive_forwarded not allowed to change".to_string());
    }

    if current_acls.get_receive_forwarded().1 != new_acls.get_receive_forwarded().1 {
        errors.push("get_receive_forwarded:self_change can't modify!".to_string());
    }

    if (current_acls.get_create_invites().0 != new_acls.get_create_invites().0)
        && !current_acls.get_create_invites().1
    {
        errors.push("create_invites not allowed to change".to_string());
    }

    if current_acls.get_create_invites().1 != new_acls.get_create_invites().1 {
        errors.push("create_invites:self_change can't modify!".to_string());
    }

    if (current_acls.get_anon_receive().0 != new_acls.get_anon_receive().0)
        && !current_acls.get_anon_receive().1
    {
        errors.push("anon_receive not allowed to change".to_string());
    }

    if current_acls.get_anon_receive().1 != new_acls.get_anon_receive().1 {
        errors.push("anon_receive:self_change can't modify!".to_string());
    }

    if errors.is_empty() {
        None
    } else {
        Some(errors)
    }
}

#[cfg(test)]
mod tests {
    use sha256::digest;

    use super::*;

    #[test]
    fn test_check_permissions_admin_success() {
        let session = Session {
            did: "did:example:123".to_string(),
            account_type: AccountType::Admin,
            ..Default::default()
        };
        let dids = vec![digest("did:example:123")];
        assert!(check_permissions(&session, &dids, false, &None));
    }

    #[test]
    fn test_check_permissions_root_admin_success() {
        let session = Session {
            did: "did:example:123".to_string(),
            did_hash: digest("did:example:123"),
            account_type: AccountType::RootAdmin,
            ..Default::default()
        };
        let dids = vec![digest("did:example:1234")];
        assert!(check_permissions(&session, &dids, false, &None));
    }

    #[test]
    fn test_check_permissions_standard_success() {
        let session = Session {
            did: "did:example:123".to_string(),
            did_hash: digest("did:example:123"),
            account_type: AccountType::Standard,
            ..Default::default()
        };
        let dids = vec![digest("did:example:123")];
        assert!(check_permissions(&session, &dids, false, &None));
    }

    #[test]
    fn test_check_permissions_standard_multiple_dids_failure() {
        let session = Session {
            did: "did:example:123".to_string(),
            did_hash: digest("did:example:123"),
            account_type: AccountType::Standard,
            ..Default::default()
        };
        let dids = vec![digest("did:example:123"), digest("did:example:hacker")];
        assert!(!check_permissions(&session, &dids, false, &None));
    }

    #[test]
    fn test_check_permissions_standard_wrong_did_failure() {
        let session = Session {
            did: "did:example:123".to_string(),
            account_type: AccountType::Standard,
            ..Default::default()
        };
        let dids = vec![digest("did:example:1234")];
        assert!(!check_permissions(&session, &dids, false, &None));
    }

    #[test]
    fn test_check_permissions_correct_admin_session_match() {
        let session = Session {
            did: "did:example:123".to_string(),
            did_hash: digest("did:example:123"),
            account_type: AccountType::Admin,
            ..Default::default()
        };
        let dids = vec![digest("did:example:123")];
        assert!(check_permissions(
            &session,
            &dids,
            true,
            &Some("did:example:123#key1".to_string())
        ));
    }

    #[test]
    fn test_check_permissions_incorrect_admin_session_match() {
        let session = Session {
            did: "did:example:123".to_string(),
            did_hash: digest("did:example:123"),
            account_type: AccountType::Admin,
            ..Default::default()
        };
        let dids = vec![digest("did:example:123")];
        assert!(!check_permissions(
            &session,
            &dids,
            true,
            &Some("did:example:mallory#key1".to_string())
        ));
    }
}
