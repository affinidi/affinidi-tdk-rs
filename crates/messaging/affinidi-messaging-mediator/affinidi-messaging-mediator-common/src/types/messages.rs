//! Mediator message-pickup types — the storage-trait–facing subset of
//! the SDK's `messages` module. Lives here so the
//! [`crate::store::MediatorStore`] trait can describe its API without
//! depending on the SDK.
//!
//! The SDK re-exports each type from
//! `affinidi_messaging_sdk::messages::*` for backwards compatibility.

use std::fmt::Display;

use serde::{Deserialize, Serialize, de::DeserializeOwned};

/// A list of messages stored for a given DID.
///
/// - `msg_id`        : The unique identifier of the message
/// - `send_id`       : The unique identifier of the element in the senders stream
/// - `receive_id`    : The unique identifier of the element in the senders stream
/// - `size`          : The size of the message in bytes
/// - `timestamp`     : The date the message was stored (milliseconds since epoch)
/// - `to_address`    : Address the message was sent to
/// - `from_address`  : Address the message was sent from (if applicable)
/// - `msg`           : The message itself
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

/// Mediator folder enum.
/// - `Inbox` — messages inbound to the caller.
/// - `Outbox` — messages outbound from the caller.
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

/// Get-messages response struct.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct GetMessagesResponse {
    pub success: MessageList,
    pub get_errors: Vec<(String, String)>,
    pub delete_errors: Vec<(String, String)>,
}
impl GenericDataStruct for GetMessagesResponse {}

/// Delete policy when retrieving messages.
#[derive(Default, Serialize, Deserialize, Debug)]
pub enum FetchDeletePolicy {
    /// Optimistic — deletes messages as they are fetched, automatically.
    Optimistic,
    /// OnReceive — deletes messages after they are received by the SDK.
    OnReceive,
    /// DoNotDelete — messages are not deleted (default).
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

/// Helper marker trait used to deserialize the generic `data` field
/// in the SDK's `SuccessResponse` envelope.
pub trait GenericDataStruct: DeserializeOwned + Serialize {}

// Blanket impl for `String` — used by the SDK's protocol responses
// where the body is just an opaque string. Lives here (alongside the
// trait) to satisfy the orphan rule from the SDK side.
impl GenericDataStruct for String {}

/// `fetch_messages()` options.
#[derive(Serialize, Deserialize, Debug)]
pub struct FetchOptions {
    /// The maximum number of messages to fetch. Default: 10.
    pub limit: usize,
    /// The receive_id to start fetching from. Default: None.
    pub start_id: Option<String>,
    /// Delete policy for messages after fetching. Default: DoNotDelete.
    pub delete_policy: FetchDeletePolicy,
}

impl Default for FetchOptions {
    fn default() -> Self {
        FetchOptions {
            limit: 10,
            start_id: None,
            delete_policy: FetchDeletePolicy::DoNotDelete,
        }
    }
}
