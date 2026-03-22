/*!
Module for handling websocket connections to DIDComm Mediators

SDK --> Profile --> WebSocket --> Mediator

Roles:
   - SDK: The main SDK that the client interacts with
   - Profile: A DID profile that requires it's own connection to a mediator
   - WebSocket: WebSocket management + Profile Message Cache
   - Mediator: The DIDComm Mediator that the websocket connects to
*/

use affinidi_messaging_didcomm::{Message as DidcommMessage, UnpackMetadata};

pub(crate) mod websocket;
pub(crate) mod ws_cache;

/// Responses to WebSocketCommands
#[derive(Clone)]
pub enum WebSocketResponses {
    /// MessageReceived - sent to SDK when a message is received
    MessageReceived(Box<DidcommMessage>, Box<UnpackMetadata>),

    /// PackedMessageReceived - sent to SDK when a message is received (still packed as string)
    PackedMessageReceived(Box<String>),
}
