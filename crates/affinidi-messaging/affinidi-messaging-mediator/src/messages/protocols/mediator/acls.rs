use std::time::SystemTime;

use crate::{
    SharedData,
    database::session::Session,
    messages::{ProcessMessageResponse, error_response::generate_error_response},
};
use affinidi_messaging_didcomm::{Message, UnpackMetadata};
use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_messaging_sdk::{
    messages::problem_report::{ProblemReport, ProblemReportScope, ProblemReportSorter},
    protocols::mediator::{
        accounts::AccountType, acls::MediatorACLSet, acls_handler::MediatorACLRequest,
    },
};
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
                    return generate_error_response(
                        state,
                        session,
                        &msg.id,
                        ProblemReport::new(
                            ProblemReportSorter::Error,
                            ProblemReportScope::Protocol,
                            "expired".into(),
                            "admin related message does not meet mediator created_time constraints"
                                .into(),
                            vec![],
                            None,
                        ),
                        false,
                    );
                }
            } else {
                warn!("ADMIN related message has no created_time header. Required.");
                return generate_error_response(
                    state,
                    session,
                    &msg.id,
                    ProblemReport::new(
                        ProblemReportSorter::Error,
                        ProblemReportScope::Protocol,
                        "missing_expiry".into(),
                        "missing created_time header on an admin related message".into(),
                        vec![],
                        None,
                    ),
                    false,
                );
            }
        }

        // Parse the message body
        let request: MediatorACLRequest = match serde_json::from_value(msg.body.clone()) {
            Ok(request) => request,
            Err(err) => {
                warn!("Error parsing Mediator ACL request. Reason: {}", err);
                return generate_error_response(
                    state,
                    session,
                    &msg.id,
                    ProblemReport::new(
                        ProblemReportSorter::Error,
                        ProblemReportScope::Protocol,
                        "invalid_request".into(),
                        "Error parsing Mediator ACL request. Reason: {1}".into(),
                        vec![err.to_string()],
                        None,
                    ),
                    false,
                );
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
                    return generate_error_response(
                        state,
                        session,
                        &msg.id,
                        ProblemReport::new(
                            ProblemReportSorter::Error,
                            ProblemReportScope::Protocol,
                            "permission_error".into(),
                            "Error getting ACLs {1}".into(),
                            vec!["Permission denied".to_string()],
                            None,
                        ),
                        false,
                    );
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
                    Err(err) => {
                        warn!("Error getting ACLs. Reason: {}", err);
                        generate_error_response(
                            state,
                            session,
                            &msg.id,
                            ProblemReport::new(
                                ProblemReportSorter::Error,
                                ProblemReportScope::Protocol,
                                "database_error".into(),
                                "Error getting ACLs {1}".into(),
                                vec![err.to_string()],
                                None,
                            ),
                            false,
                        )
                    }
                }
            }
            MediatorACLRequest::SetACL { did_hash, acls } => {
                // Check permissions and ACLs
                if !check_permissions(
                    session,
                    &[did_hash.clone()],
                    state.config.security.block_remote_admin_msgs,
                    &metadata.sign_from,
                ) {
                    warn!("ACL Request from DID ({}) failed. ", session.did_hash);
                    return generate_error_response(
                        state,
                        session,
                        &msg.id,
                        ProblemReport::new(
                            ProblemReportSorter::Error,
                            ProblemReportScope::Protocol,
                            "permission_error".into(),
                            "Error setting ACLs {1}".into(),
                            vec!["Permission denied".to_string()],
                            None,
                        ),
                        false,
                    );
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
                    Err(err) => {
                        warn!("Error setting ACLs. Reason: {}", err);
                        generate_error_response(
                            state,
                            session,
                            &msg.id,
                            ProblemReport::new(
                                ProblemReportSorter::Error,
                                ProblemReportScope::Protocol,
                                "database_error".into(),
                                "Error setting ACLs {1}".into(),
                                vec![err.to_string()],
                                None,
                            ),
                            false,
                        )
                    }
                }
            }
            MediatorACLRequest::AccessListList { did_hash, cursor } => {
                // Check permissions and ACLs
                if !check_permissions(
                    session,
                    &[did_hash.clone()],
                    state.config.security.block_remote_admin_msgs,
                    &metadata.sign_from,
                ) {
                    warn!("List Access List from DID ({}) failed. ", session.did_hash);
                    return generate_error_response(
                        state,
                        session,
                        &msg.id,
                        ProblemReport::new(
                            ProblemReportSorter::Error,
                            ProblemReportScope::Protocol,
                            "permission_error".into(),
                            "Error Listing Access List {1}".into(),
                            vec!["Permission denied".to_string()],
                            None,
                        ),
                        false,
                    );
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
                    Err(err) => {
                        warn!("Error Listing Access List. Reason: {}", err);
                        generate_error_response(
                            state,
                            session,
                            &msg.id,
                            ProblemReport::new(
                                ProblemReportSorter::Error,
                                ProblemReportScope::Protocol,
                                "database_error".into(),
                                "Error listing Access List {1}".into(),
                                vec![err.to_string()],
                                None,
                            ),
                            false,
                        )
                    }
                }
            }
            MediatorACLRequest::AccessListAdd { did_hash, hashes } => {
                // Check permissions and ACLs
                if !check_permissions(
                    session,
                    &[did_hash.clone()],
                    state.config.security.block_remote_admin_msgs,
                    &metadata.sign_from,
                ) {
                    warn!("Add Access List from DID ({}) failed. ", session.did_hash);
                    return generate_error_response(
                        state,
                        session,
                        &msg.id,
                        ProblemReport::new(
                            ProblemReportSorter::Error,
                            ProblemReportScope::Protocol,
                            "permission_error".into(),
                            "Error Adding to Access List {1}".into(),
                            vec!["Permission denied".to_string()],
                            None,
                        ),
                        false,
                    );
                }

                if hashes.is_empty() || hashes.len() > 100 {
                    return generate_error_response(
                        state,
                        session,
                        &msg.id,
                        ProblemReport::new(
                            ProblemReportSorter::Error,
                            ProblemReportScope::Other("limits exceeded".into()),
                            "limits_exceeded".into(),
                            "Error Adding to Access List {1}".into(),
                            vec!["limits exceeded (must be 0 < count <= 100)".to_string()],
                            None,
                        ),
                        false,
                    );
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
                    Err(err) => {
                        warn!("Error Add to Access List. Reason: {}", err);
                        generate_error_response(
                            state,
                            session,
                            &msg.id,
                            ProblemReport::new(
                                ProblemReportSorter::Error,
                                ProblemReportScope::Protocol,
                                "database_error".into(),
                                "Error Add to Access List {1}".into(),
                                vec![err.to_string()],
                                None,
                            ),
                            false,
                        )
                    }
                }
            }
            MediatorACLRequest::AccessListRemove { did_hash, hashes } => {
                // Check permissions and ACLs
                if !check_permissions(
                    session,
                    &[did_hash.clone()],
                    state.config.security.block_remote_admin_msgs,
                    &metadata.sign_from,
                ) {
                    warn!(
                        "Remove Access List from DID ({}) failed. ",
                        session.did_hash
                    );
                    return generate_error_response(
                        state,
                        session,
                        &msg.id,
                        ProblemReport::new(
                            ProblemReportSorter::Error,
                            ProblemReportScope::Protocol,
                            "permission_error".into(),
                            "Error Remove from Access List {1}".into(),
                            vec!["Permission denied".to_string()],
                            None,
                        ),
                        false,
                    );
                }

                if hashes.is_empty() || hashes.len() > 100 {
                    return generate_error_response(
                        state,
                        session,
                        &msg.id,
                        ProblemReport::new(
                            ProblemReportSorter::Error,
                            ProblemReportScope::Other("limits exceeded".into()),
                            "limits_exceeded".into(),
                            "Error Removing from Access List {1}".into(),
                            vec!["limits exceeded (must be 0 < count <= 100)".to_string()],
                            None,
                        ),
                        false,
                    );
                }

                match state.database.access_list_remove(&did_hash, &hashes).await {
                    Ok(response) => _generate_response_message(
                        &msg.id,
                        &session.did,
                        &state.config.mediator_did,
                        &json!(response),
                    ),
                    Err(err) => {
                        warn!("Error Remove from Access List. Reason: {}", err);
                        generate_error_response(
                            state,
                            session,
                            &msg.id,
                            ProblemReport::new(
                                ProblemReportSorter::Error,
                                ProblemReportScope::Protocol,
                                "database_error".into(),
                                "Error Remove from Access List {1}".into(),
                                vec![err.to_string()],
                                None,
                            ),
                            false,
                        )
                    }
                }
            }
            MediatorACLRequest::AccessListClear { did_hash } => {
                // Check permissions and ACLs
                if !check_permissions(
                    session,
                    &[did_hash.clone()],
                    state.config.security.block_remote_admin_msgs,
                    &metadata.sign_from,
                ) {
                    warn!("Clear Access List for DID ({}) failed. ", session.did_hash);
                    return generate_error_response(
                        state,
                        session,
                        &msg.id,
                        ProblemReport::new(
                            ProblemReportSorter::Error,
                            ProblemReportScope::Protocol,
                            "permission_error".into(),
                            "Error Clearing Access List {1}".into(),
                            vec!["Permission denied".to_string()],
                            None,
                        ),
                        false,
                    );
                }

                match state.database.access_list_clear(&did_hash).await {
                    Ok(response) => _generate_response_message(
                        &msg.id,
                        &session.did,
                        &state.config.mediator_did,
                        &json!(response),
                    ),
                    Err(err) => {
                        warn!("Error Clearing Access List. Reason: {}", err);
                        generate_error_response(
                            state,
                            session,
                            &msg.id,
                            ProblemReport::new(
                                ProblemReportSorter::Error,
                                ProblemReportScope::Protocol,
                                "database_error".into(),
                                "Error Clearing Access List {1}".into(),
                                vec![err.to_string()],
                                None,
                            ),
                            false,
                        )
                    }
                }
            }
            MediatorACLRequest::AccessListGet { did_hash, hashes } => {
                // Check permissions and ACLs
                if !check_permissions(
                    session,
                    &[did_hash.clone()],
                    state.config.security.block_remote_admin_msgs,
                    &metadata.sign_from,
                ) {
                    warn!(
                        "Get from Access List for DID ({}) failed. ",
                        session.did_hash
                    );
                    return generate_error_response(
                        state,
                        session,
                        &msg.id,
                        ProblemReport::new(
                            ProblemReportSorter::Error,
                            ProblemReportScope::Protocol,
                            "permission_error".into(),
                            "Error Getting from Access List {1}".into(),
                            vec!["Permission denied".to_string()],
                            None,
                        ),
                        false,
                    );
                }

                match state.database.access_list_get(&did_hash, &hashes).await {
                    Ok(response) => _generate_response_message(
                        &msg.id,
                        &session.did,
                        &state.config.mediator_did,
                        &json!(response),
                    ),
                    Err(err) => {
                        warn!("Error Getting from Access List. Reason: {}", err);
                        generate_error_response(
                            state,
                            session,
                            &msg.id,
                            ProblemReport::new(
                                ProblemReportSorter::Error,
                                ProblemReportScope::Protocol,
                                "database_error".into(),
                                "Error Getting from Access List {1}".into(),
                                vec![err.to_string()],
                                None,
                            ),
                            false,
                        )
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
        data: crate::messages::WrapperType::Message(response),
        forward_message: false,
    })
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
