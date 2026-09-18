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
pub mod wrapping;

// ── Re-exports of the storage-trait–facing message vocabulary ──────────
//
// The data types below live in `affinidi-messaging-mediator-common`'s
// `types::messages` module so the mediator's storage trait can describe
// its API without depending on the client SDK. They're re-exported here
// so existing call sites keep their `affinidi_messaging_sdk::messages::*`
// paths working unchanged.
pub use affinidi_messaging_mediator_common::types::messages::{
    FetchDeletePolicy, Folder, GenericDataStruct, GetMessagesResponse, MessageList,
    MessageListElement, MessageProtocol,
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

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct AuthorizationResponse {
    pub access_token: String,
    pub access_expires_at: u64,
    pub refresh_token: String,
    pub refresh_expires_at: u64,
}
impl GenericDataStruct for AuthorizationResponse {}

impl std::fmt::Debug for AuthorizationResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthorizationResponse")
            .field("access_token", &"[REDACTED]")
            .field("access_expires_at", &self.access_expires_at)
            .field("refresh_token", &"[REDACTED]")
            .field("refresh_expires_at", &self.refresh_expires_at)
            .finish()
    }
}

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

/// Response from purging a queue.
/// - count: how many messages were removed
/// - bytes: how much they occupied
///
/// Both are reported because a purge is destructive and unrecoverable — the
/// messages are gone, not returned to their senders — so the caller should be
/// able to record what it destroyed.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct PurgeQueueResponse {
    pub count: usize,
    pub bytes: usize,
}
impl GenericDataStruct for PurgeQueueResponse {}

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

#[cfg(test)]
mod purge_response_tests {
    use super::*;

    /// The route is `/purge/{folder}` and `Folder` is `rename_all =
    /// "lowercase"`, so the path segment the SDK builds from `Display` and the
    /// one axum deserialises must be the same string. They are produced by two
    /// different impls, so nothing but a test ties them together — and a
    /// mismatch would be a 404 on the one call a wedged node makes to recover.
    #[test]
    fn a_folders_path_segment_round_trips() {
        for folder in [Folder::Inbox, Folder::Outbox] {
            let segment = folder.to_string();
            let parsed: Folder =
                serde_json::from_value(serde_json::Value::String(segment.clone())).unwrap();
            assert_eq!(parsed, folder, "`{segment}` did not parse back");
        }
        assert_eq!(Folder::Inbox.to_string(), "inbox");
        assert_eq!(Folder::Outbox.to_string(), "outbox");
    }

    /// A purge reports what it destroyed; the fields are the record that those
    /// messages existed.
    #[test]
    fn a_purge_response_carries_the_count_and_bytes() {
        let decoded: PurgeQueueResponse =
            serde_json::from_str(r#"{"count":1000,"bytes":4096}"#).unwrap();
        assert_eq!(decoded.count, 1000);
        assert_eq!(decoded.bytes, 4096);
    }
}
