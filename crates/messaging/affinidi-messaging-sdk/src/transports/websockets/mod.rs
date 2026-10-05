/*!
Module for handling websocket connections to DIDComm Mediators

SDK --> Profile --> WebSocket --> Mediator

Roles:
   - SDK: The main SDK that the client interacts with
   - Profile: A DID profile that requires it's own connection to a mediator
   - WebSocket: WebSocket management + Profile Message Cache
   - Mediator: The DIDComm Mediator that the websocket connects to
*/

use affinidi_messaging_didcomm::message::Message as DidcommMessage;

use crate::messages::compat::UnpackMetadata;

pub(crate) mod proxy;
pub(crate) mod receive_leg;
pub(crate) mod websocket;
pub(crate) mod ws_cache;

/// The health of a websocket transport's **receive** side.
///
/// [`ConnState`](affinidi_messaging_core::ConnState) says whether the socket
/// is up, which is what a sender needs. It cannot say whether anything is
/// arriving: a socket can answer every ping while the mediator has stopped
/// delivering to it, or while the application has stopped taking what it
/// delivers. Either way the inbox fills, and every peer writing to this DID is
/// refused `limits.queue.peer` once its own per-recipient quota is used up —
/// the failure is felt by the senders, not here.
///
/// Published by the transport over a `watch` channel on every change; read it
/// with [`ATMProfile::receive_health`](crate::profiles::ATMProfile::receive_health).
/// Times are Unix seconds from the configured clock.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ReceiveHealth {
    /// When the last data (Text/Binary) frame arrived — not a ping or pong,
    /// which prove the socket and nothing about delivery. `None` until the
    /// first one.
    pub last_data_frame_at: Option<u64>,
    /// Frames held in the transport's caches waiting for the application.
    pub held_frames: u32,
    /// Set while frames have been held and not taken for longer than the stall
    /// threshold: the application is not collecting, so nothing is deleted at
    /// the mediator. Cleared when it drains.
    pub consumer_stalled_since: Option<u64>,
    /// Set while a receive-leg probe (a live-delivery request written after
    /// inbound has been silent) is waiting to be answered by any frame.
    pub probe_outstanding_since: Option<u64>,
    /// How many times an unanswered probe forced a reconnect.
    pub probe_reconnects: u64,
    /// Inbound frames that could not be unpacked and were deleted from the
    /// mediator so they stop counting against their sender's queue.
    pub unprocessable_deleted: u64,
    /// Frames that failed to unpack transiently and are being left for
    /// redelivery (bounded per frame).
    pub unprocessable_retained: u32,
}

impl ReceiveHealth {
    /// Whether the application has stopped taking frames.
    pub fn consumer_stalled(&self) -> bool {
        self.consumer_stalled_since.is_some()
    }
}

/// Responses to WebSocketCommands
#[derive(Clone)]
pub enum WebSocketResponses {
    /// MessageReceived - sent to SDK when a message is received
    MessageReceived(Box<DidcommMessage>, Box<UnpackMetadata>),

    /// PackedMessageReceived - sent to SDK when a message is received (still packed as string)
    PackedMessageReceived(Box<String>),

    /// Disconnected - sent to any in-flight request waiter when the underlying
    /// websocket connection is lost, so the caller fails fast instead of
    /// blocking until its own timeout elapses. The request is gone; it will not
    /// be answered on the (re)connected socket.
    Disconnected,
}
