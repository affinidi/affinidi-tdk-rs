use serde::{Deserialize, Serialize};

pub mod compat;
pub mod delete;
pub mod fetch;
pub mod get;
pub mod known;
pub mod list;
pub mod pack;
pub mod problem_report;
pub mod sending;
pub mod unpack;

// ── Re-exports of the storage-trait–facing message vocabulary ──────────
//
// The data types below live in `affinidi-messaging-mediator-common`'s
// `types::messages` module so the mediator's storage trait can describe
// its API without depending on the client SDK. They're re-exported here
// so existing call sites keep their `affinidi_messaging_sdk::messages::*`
// paths working unchanged.
pub use affinidi_messaging_mediator_common::types::messages::{
    FetchDeletePolicy, Folder, GenericDataStruct, GetMessagesResponse, MessageList,
    MessageListElement,
};

pub trait MessageDelete<T> {
    fn delete_message(response: &T) -> Result<&T, String>;
}
/// Generic response structure for all responses from the ATM API
#[derive(Serialize, Deserialize, Debug)]
#[allow(non_snake_case)]
pub struct SuccessResponse<T: GenericDataStruct> {
    pub sessionId: String,
    pub httpCode: u16,
    pub errorCode: i32,
    pub errorCodeStr: String,
    pub message: String,
    #[serde(bound(deserialize = ""))]
    pub data: Option<T>,
}

/// Specific response structure for the authentication challenge response
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct AuthenticationChallenge {
    pub challenge: String,
    pub session_id: String,
}
impl GenericDataStruct for AuthenticationChallenge {}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct AuthorizationResponse {
    pub access_token: String,
    pub access_expires_at: u64,
    pub refresh_token: String,
    pub refresh_expires_at: u64,
}
impl GenericDataStruct for AuthorizationResponse {}

/// Response from message_delete
/// - successful: Contains list of message_id's that were deleted successfully
/// - errors: Contains a list of message_id's and error messages for failed deletions
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct DeleteMessageResponse {
    pub success: Vec<String>,
    pub errors: Vec<(String, String)>,
}
impl GenericDataStruct for DeleteMessageResponse {}
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct DeleteMessageRequest {
    pub message_ids: Vec<String>,
}
impl GenericDataStruct for DeleteMessageRequest {}

/// Get messages Request struct
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct GetMessagesRequest {
    pub message_ids: Vec<String>,
    pub delete: bool,
}
impl GenericDataStruct for GetMessagesRequest {}

#[derive(Serialize, Deserialize)]
pub struct EmptyResponse;
impl GenericDataStruct for EmptyResponse {}
