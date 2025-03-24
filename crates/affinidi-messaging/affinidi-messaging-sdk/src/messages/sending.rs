use serde::{Deserialize, Serialize};

use super::GenericDataStruct;

/// Response from the ATM API when sending messages (inbound messages)
/// Stored messages will have a list of messages that were stored
/// Ephemeral messages contain the actual message response (it is not stored anywhere)
/// Empty is used when there is no expected response
#[derive(Serialize, Deserialize, Debug)]
pub enum InboundMessageResponse {
    Stored(InboundMessageList),
    Ephemeral(String),
    Forwarded,
    Empty,
}
impl GenericDataStruct for InboundMessageResponse {}

/// Response from the ATM API when sending a message that is stored
/// Contains a list of messages that were stored
/// - messages : List of successful stored messages (recipient, message_ids)
/// - errors   : List of errors that occurred while storing messages (recipient, error)
///
/// NOTE: Sending a single message can result in multiple forward messages being stored!
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct InboundMessageList {
    pub messages: Vec<(String, String)>,
    pub errors: Vec<(String, String)>,
}
impl GenericDataStruct for InboundMessageList {}
