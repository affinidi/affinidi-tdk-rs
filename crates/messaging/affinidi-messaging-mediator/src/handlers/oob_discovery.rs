/*!
 Handles HTTP(s) routes dealing with Out Of Band (OOB) Discovery.

 This is used when you want to create a communication channel and need a way
 to discover each others DID with privacy.

 [DIDComm V2 OOB Discover](https://identity.foundation/didcomm-messaging/spec/#out-of-band-messages)

 Alice wants to connect with Bob, she first of all issues an invite [oob_invite_handler] to Bob
 Alice turns the returned shortened URL into a QR code (or similar) and shares with Bob
 Bob scans the QR Code, which causes him to load [oobid_handler] with the ID from the URL

 Alice and Bob then swap messages and create a confidential communication channel between themselves.
*/

use crate::{SharedData, database::session::Session};
use affinidi_messaging_didcomm::message::Message;
use affinidi_messaging_mediator_common::errors::{AppError, MediatorError, SuccessResponse};
use affinidi_messaging_sdk::{
    messages::problem_report::{ProblemReportScope, ProblemReportSorter},
    protocols::{mediator::accounts::AccountType, oob_discovery::OOBInviteResponse},
};
use axum::{
    Json,
    extract::{Query, State},
};
use http::StatusCode;
use serde::Deserialize;
use subtle::ConstantTimeEq;

#[derive(Deserialize)]
pub struct Parameters {
    _oobid: String,
}

/// Takes a plaintext DIDComm message and creates a shortened URL for OOB Discovery
/// Takes the plaintext DIDComm message, coverts to a JSON string with spaces removed
/// Base64 encode the JSON String, create a SHA256 hash of this
/// Store the base64 encoded string in a redis hashmap with the SHA256 hash as key
/// Returns a fully formed URL as the body of the Post Response
pub async fn oob_invite_handler(
    session: Session,
    State(state): State<SharedData>,
    Json(body): Json<Message>,
) -> Result<(StatusCode, Json<SuccessResponse<OOBInviteResponse>>), AppError> {
    // ACL Check
    if !session.acls.get_create_invites().0 {
        return Err(MediatorError::problem(
            45,
            session.session_id,
            None,
            ProblemReportSorter::Error,
            ProblemReportScope::Protocol,
            "authorization.permission",
            "Not authorized to create OOB invitations",
            vec![],
            StatusCode::FORBIDDEN,
        )
        .into());
    }

    // The trait takes the already-encoded invitation + an absolute
    // expiry timestamp. Compute both up-front so backends don't have
    // to know about DIDComm `Message` shape.
    let invite_b64 = match crate::store::encode_oob_invite(&body) {
        Ok(b) => b,
        Err(e) => return Err(e.into()),
    };
    let expires_at = crate::store::oob_expires_at(&body, state.config.limits.oob_invite_ttl as u64);

    let oob_id = match state
        .database
        .oob_discovery_store(&session.did_hash, &invite_b64, expires_at)
        .await
    {
        Ok(oob_id) => oob_id,
        Err(MediatorError::InternalError(code, _, text)) => {
            return Err(MediatorError::problem_with_log(
                code,
                session.session_id,
                None,
                ProblemReportSorter::Warning,
                ProblemReportScope::Message,
                "message.serialize",
                "Couldn't serialize DIDComm message envelope. Reason: {1}",
                vec![text],
                StatusCode::BAD_REQUEST,
                "Couldn't serialize DIDComm message envelope",
            )
            .into());
        }
        Err(MediatorError::DatabaseError(code, _, text)) => {
            return Err(MediatorError::problem_with_log(
                code,
                session.session_id,
                None,
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "me.res.storage.error",
                "Database transaction error: {1}",
                vec![text.to_string()],
                StatusCode::SERVICE_UNAVAILABLE,
                format!("Database transaction error: {text}"),
            )
            .into());
        }
        Err(e) => {
            return Err(MediatorError::problem_with_log(
                46,
                session.session_id,
                None,
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "oob.store",
                "Couldn't store OOB invite. Reason: {1}",
                vec![e.to_string()],
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Couldn't store OOB invite. Reason: {e}"),
            )
            .into());
        }
    };

    Ok((
        StatusCode::OK,
        Json(SuccessResponse {
            session_id: session.session_id,
            http_code: StatusCode::OK.as_u16(),
            error_code: 0,
            error_code_str: "NA".to_string(),
            message: "Success".to_string(),
            data: Some(OOBInviteResponse { _oobid: oob_id }),
        }),
    ))
}

/// Unauthenticated route that if you know a unique invite ID you can retrieve the invitation
pub async fn oobid_handler(
    State(state): State<SharedData>,
    oobid: Query<Parameters>,
) -> Result<(StatusCode, Json<SuccessResponse<String>>), AppError> {
    match state.database.oob_discovery_get(&oobid._oobid).await {
        Ok(Some((invite, _))) => Ok((
            StatusCode::OK,
            Json(SuccessResponse {
                session_id: "NA".into(),
                http_code: StatusCode::OK.as_u16(),
                error_code: 0,
                error_code_str: "NA".to_string(),
                message: "Success".to_string(),
                data: Some(invite),
            }),
        )),
        Ok(None) => Ok((
            StatusCode::OK,
            Json(SuccessResponse {
                session_id: "NA".into(),
                http_code: StatusCode::NOT_FOUND.as_u16(),
                error_code: 0,
                error_code_str: "NA".to_string(),
                message: "NO CONTENT".to_string(),
                data: None,
            }),
        )),
        Err(MediatorError::DatabaseError(code, _, text)) => Err(MediatorError::problem_with_log(
            code,
            "NA",
            None,
            ProblemReportSorter::Error,
            ProblemReportScope::Protocol,
            "me.res.storage.error",
            "Database transaction error: {1}",
            vec![text.to_string()],
            StatusCode::SERVICE_UNAVAILABLE,
            format!("Database transaction error: {text}"),
        )
        .into()),
        Err(e) => Err(MediatorError::problem_with_log(
            87,
            "NA",
            None,
            ProblemReportSorter::Error,
            ProblemReportScope::Protocol,
            "oob.retrieve",
            "Couldn't retrieve OOB invite. Reason: {1}",
            vec![e.to_string()],
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Couldn't retrieve OOB invite. Reason: {e}"),
        )
        .into()),
    }
}

/// Removes a OOB Invitation if it exists
/// These will also naturally expire after a certain amount of time has passed
pub async fn delete_oobid_handler(
    session: Session,
    State(state): State<SharedData>,
    oobid: Query<Parameters>,
) -> Result<(StatusCode, Json<SuccessResponse<String>>), AppError> {
    // Check if non ADMIN level account, do they own this OOB invite?
    if session.account_type != AccountType::Admin && session.account_type != AccountType::RootAdmin
    {
        let oob_did_owner = match state
            .database
            .oob_discovery_get(&oobid._oobid)
            .await
            .map_err(|e| {
                MediatorError::problem_with_log(
                    14,
                    session.session_id.clone(),
                    None,
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "me.res.storage.error",
                    "Database transaction error: {1}",
                    vec![e.to_string()],
                    StatusCode::SERVICE_UNAVAILABLE,
                    format!("Database transaction error: {e}"),
                )
            })? {
            Some((_, oob_owner)) => oob_owner,
            _ => {
                return Ok((
                    StatusCode::OK,
                    Json(SuccessResponse {
                        session_id: "NA".into(),
                        http_code: StatusCode::NO_CONTENT.as_u16(),
                        error_code: 0,
                        error_code_str: "NA".to_string(),
                        message: "NO CONTENT".to_string(),
                        data: None,
                    }),
                ));
            }
        };

        if oob_did_owner
            .as_bytes()
            .ct_eq(session.did_hash.as_bytes())
            .unwrap_u8()
            == 0
        {
            return Err(MediatorError::problem(
                45,
                session.session_id.clone(),
                None,
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "authorization.permission",
                "Not authorized to delete this OOB invitation",
                vec![],
                StatusCode::FORBIDDEN,
            )
            .into());
        }
    }

    let response = state.database.oob_discovery_delete(&oobid._oobid).await?;

    Ok((
        StatusCode::OK,
        Json(SuccessResponse {
            session_id: session.session_id,
            http_code: StatusCode::OK.as_u16(),
            error_code: 0,
            error_code_str: "NA".to_string(),
            message: "Success".to_string(),
            data: Some(response.to_string()),
        }),
    ))
}
