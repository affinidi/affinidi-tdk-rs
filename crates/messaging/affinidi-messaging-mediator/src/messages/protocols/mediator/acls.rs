use std::slice;

use crate::common::time::unix_timestamp_secs;

use crate::{SharedData, common::session::Session, messages::ProcessMessageResponse};
use affinidi_messaging_didcomm::message::Message;
use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_messaging_sdk::messages::compat::UnpackMetadata;
use affinidi_messaging_sdk::{
    messages::problem_report::{ProblemReportScope, ProblemReportSorter},
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
            let now = unix_timestamp_secs();
            if let Some(created_time) = msg.created_time {
                if (created_time + state.config.security.admin_messages_expiry) <= now
                    || created_time > now
                {
                    warn!("ADMIN related message has an invalid created_time header.");
                    return Err(MediatorError::problem_with_log(
                        31,
                        &session.session_id,
                        Some(msg.id.to_string()),
                        ProblemReportSorter::Error,
                        ProblemReportScope::Protocol,
                        "message.expired",
                        "Message was created too long ago for admin requests: {1}",
                        vec![created_time.to_string()],
                        StatusCode::BAD_REQUEST,
                        "Message was created too long ago for admin requests",
                    ));
                }
            } else {
                warn!("ADMIN related message has no created_time header. Required.");
                return Err(MediatorError::problem(
                    91,
                    &session.session_id,
                    Some(msg.id.to_string()),
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "message.created_time.missing",
                    "Admin messages must include a created_time header",
                    vec![],
                    StatusCode::BAD_REQUEST,
                ));
            }
        }

        // Parse the message body
        let request: MediatorACLRequest = match serde_json::from_value(msg.body.clone()) {
            Ok(request) => request,
            Err(err) => {
                warn!("Error parsing Mediator ACL request. Reason: {}", err);
                return Err(MediatorError::problem(
                    82,
                    &session.session_id,
                    Some(msg.id.to_string()),
                    ProblemReportSorter::Warning,
                    ProblemReportScope::Message,
                    "protocol.mediator.acls.parse",
                    "Message body couldn't be parsed correctly",
                    vec![],
                    StatusCode::BAD_REQUEST,
                ));
            }
        };

        // Sender identity: prefer JWS signature, fall back to authcrypt sender
        let sender_kid = metadata
            .sign_from
            .clone()
            .or(metadata.encrypted_from_kid.clone());

        // Process the request
        match request {
            MediatorACLRequest::GetACL(dids) => {
                // Check permissions and ACLs
                if !check_permissions(
                    session,
                    &dids,
                    state.config.security.block_remote_admin_msgs,
                    &sender_kid,
                ) {
                    warn!("ACL Request from DID ({}) failed. ", session.did_hash);
                    return Err(MediatorError::problem(
                        45,
                        &session.session_id,
                        Some(msg.id.to_string()),
                        ProblemReportSorter::Error,
                        ProblemReportScope::Protocol,
                        "authorization.permission",
                        "Not authorized to view ACLs for this DID",
                        vec![],
                        StatusCode::FORBIDDEN,
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
                        Err(MediatorError::problem_with_log(
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
                    &sender_kid,
                ) {
                    warn!("ACL Request from DID ({}) failed. ", session.did_hash);
                    return Err(MediatorError::problem(
                        45,
                        &session.session_id,
                        Some(msg.id.to_string()),
                        ProblemReportSorter::Error,
                        ProblemReportScope::Protocol,
                        "authorization.permission",
                        "Not authorized to modify ACLs for this DID",
                        vec![],
                        StatusCode::FORBIDDEN,
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

                    if let Some(errors) = acl_change_ok(&current_acls, &MediatorACLSet::from_u64(acls)) {
                        warn!("Can't change ACLs. Reason: self_change not allowed");

                        // Creates a string placement for each error. E.g. {1}, {2}, {3}
                        let mut s = String::new();
                        let mut i = 1;
                        for _ in &errors {
                            s.push_str(&format!(" ({{{i}}})"));
                            i += 1;
                        }

                        return Err(MediatorError::problem_with_log(
                            80,
                            &session.session_id,
                            Some(msg.id.to_string()),
                            ProblemReportSorter::Warning,
                            ProblemReportScope::Message,
                            "protocol.acls.change.denied",
                            &format!("A non-admin account tried to change ACL Flags but self-change is not allowed:{s}"),
                            errors,
                            StatusCode::FORBIDDEN,
                            "A non-admin account tried to change ACL Flags but self-change is not allowed",
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
                        Err(MediatorError::problem_with_log(
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
                    &sender_kid,
                ) {
                    warn!("List Access List from DID ({}) failed. ", session.did_hash);
                    return Err(MediatorError::problem(
                        45,
                        &session.session_id,
                        Some(msg.id.to_string()),
                        ProblemReportSorter::Error,
                        ProblemReportScope::Protocol,
                        "authorization.permission",
                        "Not authorized to view access list for this DID",
                        vec![],
                        StatusCode::FORBIDDEN,
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
                        Err(MediatorError::problem_with_log(
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
                    &sender_kid,
                ) {
                    warn!("Add Access List from DID ({}) failed. ", session.did_hash);
                    return Err(MediatorError::problem(
                        45,
                        &session.session_id,
                        Some(msg.id.to_string()),
                        ProblemReportSorter::Error,
                        ProblemReportScope::Protocol,
                        "authorization.permission",
                        "Not authorized to modify access list for this DID",
                        vec![],
                        StatusCode::FORBIDDEN,
                    ));
                }

                // Check if self_change is allowed
                if !session.acls.get_self_manage_list() && session.account_type == AccountType::Standard {
                    return Err(MediatorError::problem(
                        45,
                        &session.session_id,
                        Some(msg.id.to_string()),
                        ProblemReportSorter::Error,
                        ProblemReportScope::Protocol,
                        "authorization.permission",
                        "Self-manage access list is not enabled for this account",
                        vec![],
                        StatusCode::FORBIDDEN,
                    ));
                }

                if hashes.is_empty() || hashes.len() > 100 {
                    return Err(MediatorError::problem(
                        93,
                        &session.session_id,
                        Some(msg.id.to_string()),
                        ProblemReportSorter::Error,
                        ProblemReportScope::Protocol,
                        "protocol.mediator.access_list.limit",
                        "Access list batch must contain 1-100 entries",
                        vec![],
                        StatusCode::BAD_REQUEST,
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
                        Err(MediatorError::problem_with_log(
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
                    &sender_kid,
                ) {
                    warn!(
                        "Remove Access List from DID ({}) failed. ",
                        session.did_hash
                    );
                    return Err(MediatorError::problem(
                        45,
                        &session.session_id,
                        Some(msg.id.to_string()),
                        ProblemReportSorter::Error,
                        ProblemReportScope::Protocol,
                        "authorization.permission",
                        "Not authorized to modify access list for this DID",
                        vec![],
                        StatusCode::FORBIDDEN,
                    ));
                }

                // Check if self_change is allowed
                if !session.acls.get_self_manage_list() && session.account_type == AccountType::Standard {
                    return Err(MediatorError::problem(
                        45,
                        &session.session_id,
                        Some(msg.id.to_string()),
                        ProblemReportSorter::Error,
                        ProblemReportScope::Protocol,
                        "authorization.permission",
                        "Self-manage access list is not enabled for this account",
                        vec![],
                        StatusCode::FORBIDDEN,
                    ));
                }

                if hashes.is_empty() || hashes.len() > 100 {
                    return Err(MediatorError::problem(
                        93,
                        &session.session_id,
                        Some(msg.id.to_string()),
                        ProblemReportSorter::Error,
                        ProblemReportScope::Protocol,
                        "protocol.mediator.access_list.limit",
                        "Access list batch must contain 1-100 entries",
                        vec![],
                        StatusCode::BAD_REQUEST,
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
                        Err(MediatorError::problem_with_log(
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
                    &sender_kid,
                ) {
                    warn!("Clear Access List for DID ({}) failed. ", session.did_hash);
                    return Err(MediatorError::problem(
                        45,
                        &session.session_id,
                        Some(msg.id.to_string()),
                        ProblemReportSorter::Error,
                        ProblemReportScope::Protocol,
                        "authorization.permission",
                        "Not authorized to clear access list for this DID",
                        vec![],
                        StatusCode::FORBIDDEN,
                    ));
                }

                // Check if self_change is allowed
                if !session.acls.get_self_manage_list() && session.account_type == AccountType::Standard {
                    return Err(MediatorError::problem(
                        45,
                        &session.session_id,
                        Some(msg.id.to_string()),
                        ProblemReportSorter::Error,
                        ProblemReportScope::Protocol,
                        "authorization.permission",
                        "Self-manage access list is not enabled for this account",
                        vec![],
                        StatusCode::FORBIDDEN,
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
                        Err(MediatorError::problem_with_log(
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
                    &sender_kid,
                ) {
                    warn!(
                        "Get from Access List for DID ({}) failed. ",
                        session.did_hash
                    );
                    return Err(MediatorError::problem(
                        45,
                        &session.session_id,
                        Some(msg.id.to_string()),
                        ProblemReportSorter::Error,
                        ProblemReportScope::Protocol,
                        "authorization.permission",
                        "Not authorized to view access list for this DID",
                        vec![],
                        StatusCode::FORBIDDEN,
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
                        Err(MediatorError::problem_with_log(
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
/// Check that the sender (identified by JWS signature or authcrypt key ID)
/// matches the session DID. The `sender_kid` is a key ID like `did:...#key-N`.
pub(crate) fn check_admin_signature(session: &Session, sender_kid: &Option<String>) -> bool {
    match sender_kid {
        Some(kid) => kid
            .split_once('#')
            .is_some_and(|(did, _)| did == session.did),
        None => false,
    }
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
    let now = unix_timestamp_secs();

    // Build the message
    let response = Message::build(
        Uuid::new_v4().to_string(),
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

    // --- check_admin_signature tests ---

    #[test]
    fn admin_sig_jws_matching_did() {
        let session = Session {
            did: "did:example:alice".to_string(),
            ..Default::default()
        };
        assert!(check_admin_signature(
            &session,
            &Some("did:example:alice#key-0".to_string())
        ));
    }

    #[test]
    fn admin_sig_authcrypt_kid_matching_did() {
        // Authcrypt sender identified by encrypted_from_kid (same format as JWS)
        let session = Session {
            did: "did:webvh:Qmc572jbs:webvh.example.com:vta".to_string(),
            ..Default::default()
        };
        assert!(check_admin_signature(
            &session,
            &Some("did:webvh:Qmc572jbs:webvh.example.com:vta#key-1".to_string())
        ));
    }

    #[test]
    fn admin_sig_mismatched_did() {
        let session = Session {
            did: "did:example:alice".to_string(),
            ..Default::default()
        };
        assert!(!check_admin_signature(
            &session,
            &Some("did:example:mallory#key-0".to_string())
        ));
    }

    #[test]
    fn admin_sig_none_is_anonymous() {
        let session = Session {
            did: "did:example:alice".to_string(),
            ..Default::default()
        };
        assert!(!check_admin_signature(&session, &None));
    }

    #[test]
    fn admin_sig_kid_without_fragment_rejected() {
        let session = Session {
            did: "did:example:alice".to_string(),
            ..Default::default()
        };
        // A key ID without a # fragment is malformed and should be rejected
        assert!(!check_admin_signature(
            &session,
            &Some("did:example:alice".to_string())
        ));
    }

    // --- check_permissions tests ---

    #[test]
    fn perms_admin_any_dids_no_signing_check() {
        let session = Session {
            did: "did:example:admin".to_string(),
            account_type: AccountType::Admin,
            ..Default::default()
        };
        let dids = vec![digest("did:example:someone_else")];
        assert!(check_permissions(&session, &dids, false, &None));
    }

    #[test]
    fn perms_root_admin_any_dids() {
        let session = Session {
            did: "did:example:root".to_string(),
            did_hash: digest("did:example:root"),
            account_type: AccountType::RootAdmin,
            ..Default::default()
        };
        let dids = vec![digest("did:example:other")];
        assert!(check_permissions(&session, &dids, false, &None));
    }

    #[test]
    fn perms_standard_own_did() {
        let session = Session {
            did: "did:example:alice".to_string(),
            did_hash: digest("did:example:alice"),
            account_type: AccountType::Standard,
            ..Default::default()
        };
        let dids = vec![digest("did:example:alice")];
        assert!(check_permissions(&session, &dids, false, &None));
    }

    #[test]
    fn perms_standard_wrong_did_rejected() {
        let session = Session {
            did: "did:example:alice".to_string(),
            did_hash: digest("did:example:alice"),
            account_type: AccountType::Standard,
            ..Default::default()
        };
        let dids = vec![digest("did:example:bob")];
        assert!(!check_permissions(&session, &dids, false, &None));
    }

    #[test]
    fn perms_standard_multiple_dids_rejected() {
        let session = Session {
            did: "did:example:alice".to_string(),
            did_hash: digest("did:example:alice"),
            account_type: AccountType::Standard,
            ..Default::default()
        };
        let dids = vec![digest("did:example:alice"), digest("did:example:bob")];
        assert!(!check_permissions(&session, &dids, false, &None));
    }

    #[test]
    fn perms_admin_with_jws_signing_check_matching() {
        let session = Session {
            did: "did:example:admin".to_string(),
            did_hash: digest("did:example:admin"),
            account_type: AccountType::Admin,
            ..Default::default()
        };
        let dids = vec![digest("did:example:admin")];
        assert!(check_permissions(
            &session,
            &dids,
            true,
            &Some("did:example:admin#key-0".to_string())
        ));
    }

    #[test]
    fn perms_admin_with_authcrypt_kid_signing_check() {
        // When check_admin_signing is true and sender is identified by authcrypt kid
        let session = Session {
            did: "did:example:admin".to_string(),
            did_hash: digest("did:example:admin"),
            account_type: AccountType::Admin,
            ..Default::default()
        };
        let dids = vec![digest("did:example:admin")];
        // This simulates passing encrypted_from_kid as the sender identity
        assert!(check_permissions(
            &session,
            &dids,
            true,
            &Some("did:example:admin#key-1".to_string())
        ));
    }

    #[test]
    fn perms_admin_signing_check_wrong_did_rejected() {
        let session = Session {
            did: "did:example:admin".to_string(),
            did_hash: digest("did:example:admin"),
            account_type: AccountType::Admin,
            ..Default::default()
        };
        let dids = vec![digest("did:example:admin")];
        assert!(!check_permissions(
            &session,
            &dids,
            true,
            &Some("did:example:mallory#key-0".to_string())
        ));
    }

    #[test]
    fn perms_admin_signing_check_none_rejected() {
        // Anonymous message to admin endpoint should fail when signing check enabled
        let session = Session {
            did: "did:example:admin".to_string(),
            did_hash: digest("did:example:admin"),
            account_type: AccountType::Admin,
            ..Default::default()
        };
        let dids = vec![digest("did:example:admin")];
        assert!(!check_permissions(&session, &dids, true, &None));
    }

    #[test]
    fn perms_standard_no_signing_check_ignores_sender() {
        // Standard account with check_admin_signing=false: sender_kid is irrelevant
        let session = Session {
            did: "did:example:alice".to_string(),
            did_hash: digest("did:example:alice"),
            account_type: AccountType::Standard,
            ..Default::default()
        };
        let dids = vec![digest("did:example:alice")];
        assert!(check_permissions(&session, &dids, false, &None));
        assert!(check_permissions(
            &session,
            &dids,
            false,
            &Some("did:example:mallory#key-0".to_string())
        ));
    }
}
