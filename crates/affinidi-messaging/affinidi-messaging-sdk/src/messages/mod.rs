use std::fmt::Display;

use serde::{Deserialize, Serialize, de::DeserializeOwned};

pub mod delete;
pub mod fetch;
pub mod get;
pub mod known;
pub mod list;
pub mod pack;
pub mod problem_report;
pub mod sending;
pub mod unpack;

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

/// A list of messages that are stored in the ATM for a given DID
/// - msg_id        : The unique identifier of the message
/// - send_id       : The unique identifier of the element in the senders stream
/// - receive_id    : The unique identifier of the element in the senders stream
/// - size          : The size of the message in bytes
/// - timestamp     : The date the message was stored in the ATM (milliseconds since epoch)
/// - to_address    : Address the message was sent to
/// - from_address  : Address the message was sent from (if applicable)
/// - msg           : The message itself
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct MessageListElement {
    pub msg_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub send_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receive_id: Option<String>,
    pub size: u64,
    pub timestamp: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub msg: Option<String>,
}
impl GenericDataStruct for MessageListElement {}

pub type MessageList = Vec<MessageListElement>;
impl GenericDataStruct for MessageList {}

/// enum of ATM folder types
/// inbox = messages inbound to the caller
/// outbox = messages outbound from the caller
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Folder {
    Inbox,
    Outbox,
}

impl Display for Folder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Folder::Inbox => write!(f, "inbox"),
            Folder::Outbox => write!(f, "outbox"),
        }
    }
}

/// Get messages Request struct
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct GetMessagesRequest {
    pub message_ids: Vec<String>,
    pub delete: bool,
}
impl GenericDataStruct for GetMessagesRequest {}

/// Get messages Response struct
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct GetMessagesResponse {
    pub success: MessageList,
    pub get_errors: Vec<(String, String)>,
    pub delete_errors: Vec<(String, String)>,
}
impl GenericDataStruct for GetMessagesResponse {}

/// Enum for the delete policy when retrieving messages
#[derive(Default, Serialize, Deserialize, Debug)]
pub enum FetchDeletePolicy {
    /// Optimistic  - Deletes messages as they are fetched, occurs automatically within ATM
    Optimistic,
    /// OnReceive   - Will delete messages after they are received by the SDK
    OnReceive,
    /// DoNotDelete - Messages are not deleted (Default behavior)
    ///               It is up to the caller as to when and how they want to delete messages
    #[default]
    DoNotDelete,
}

impl Display for FetchDeletePolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FetchDeletePolicy::Optimistic => write!(f, "optimistic"),
            FetchDeletePolicy::OnReceive => write!(f, "on_receive"),
            FetchDeletePolicy::DoNotDelete => write!(f, "do_not_delete"),
        }
    }
}

/// Helps with deserializing the generic data field in the SuccessResponse struct
pub trait GenericDataStruct: DeserializeOwned + Serialize {}

#[derive(Serialize, Deserialize)]
pub struct EmptyResponse;
impl GenericDataStruct for EmptyResponse {}
