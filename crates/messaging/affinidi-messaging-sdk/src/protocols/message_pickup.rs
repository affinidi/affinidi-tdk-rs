/*!
 * Message Pickup Protocol 3.0
 *
 * NOTE: All Message ID's are SHA256 hashes of the message
 *
 * Do not pass message ID's to the mediator, it cannot see inside messages that it is handling.
 *
 */
use crate::messages::compat::UnpackMetadata;
use affinidi_messaging_didcomm::message::Message;
use base64::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio::select;
use tracing::{Instrument, Level, debug, span, warn};
use uuid::Uuid;

use crate::{
    ATM,
    errors::ATMError,
    messages::GenericDataStruct,
    profiles::ATMProfile,
    transports::{
        SendMessageResponse,
        websockets::{WebSocketResponses, websocket::WebSocketCommands},
    },
};

#[derive(Default)]
pub struct MessagePickup {}

/// A pickup attachment the drain could not deliver and is about to purge.
/// Broadcast on the optional poison channel (enable it with
/// [`crate::config::ATMConfigBuilder::with_poison_message_channel`], subscribe
/// with [`crate::ATM::get_poison_channel`]) *before* the purge, so a consumer
/// can retain or quarantine it instead of losing it to the best-effort delete.
#[derive(Clone, Debug)]
pub struct PoisonMessage {
    /// The delivery attachment id (== the mediator message id), if present.
    pub attachment_id: Option<String>,
    /// The raw attachment payload as received. Empty when the attachment had no
    /// base64 body.
    pub raw: String,
    /// Human-readable reason the message was rejected.
    pub reason: String,
}

/// Broadcast a [`PoisonMessage`] on the configured poison channel, if any.
/// A full or closed channel must never block or fail the caller.
pub(crate) fn emit_poison(atm: &ATM, attachment_id: Option<String>, raw: String, reason: String) {
    if let Some(ch) = &atm.inner.config.poison_message_channel {
        let _ = ch.send(PoisonMessage {
            attachment_id,
            raw,
            reason,
        });
    }
}

/// A single inbound frame off the live-delivery stream, tagged by transport.
///
/// `live_stream_next` yields only DIDComm and errors on a TSP frame;
/// `live_stream_next_packed` yields only TSP and errors on a DIDComm frame. A
/// node that speaks **both** protocols over one websocket can't know which will
/// arrive next, so neither single-protocol method fits. `live_stream_next_frame`
/// returns whichever arrives, tagged here, so a multiplexing consumer (e.g.
/// `AffinidiMessageService`) can route by transport off a single stream.
#[derive(Debug)]
#[non_exhaustive]
pub enum InboundFrame {
    /// An unpacked DIDComm message and its unpack metadata.
    DidComm(Box<Message>, Box<UnpackMetadata>),
    /// A still-packed TSP frame (CESR/qb64), to be handed to
    /// `atm.tsp().unpack_bytes`. Carried opaquely — the SDK does not unpack it.
    Tsp(Box<String>),
}

// Reads the body of an incoming Message Pickup 3.0 Status Request Message
#[derive(Default, Deserialize)]
pub struct MessagePickupStatusRequest {
    pub recipient_did: Option<String>,
}

// Reads the body of an incoming Message Pickup 3.0 Live Delivery Message
#[derive(Default, Deserialize)]
pub struct MessagePickupLiveDelivery {
    pub live_delivery: bool,
}

// Body of a StatusRequest reply
#[derive(Default, Debug, Serialize, Deserialize)]
pub struct MessagePickupStatusReply {
    pub recipient_did: String,
    pub message_count: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub longest_waited_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub newest_received_time: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oldest_received_time: Option<u64>,
    pub total_bytes: u64,
    pub live_delivery: bool,
}
impl GenericDataStruct for MessagePickupStatusReply {}

// Reads the body of an incoming Message Pickup 3.0 Delivery Request Message
#[derive(Default, Deserialize, Serialize)]
pub struct MessagePickupDeliveryRequest {
    pub recipient_did: String,
    pub limit: usize,
}

// Reads the body of an incoming Message Pickup 3.0 Messages Received Message
#[derive(Default, Deserialize, Serialize)]
pub struct MessagePickupMessagesReceived {
    pub message_id_list: Vec<String>,
}

impl MessagePickup {
    /// Sends a Message Pickup 3.0 `Status Request` message
    /// recipient_did : Optional, allows you to ask for status for a specific DID. If none, will ask for default DID in ATM
    /// mediator_did  : Optional, allows you to ask a specific mediator. If none, will ask for default mediator in ATM
    /// wait_for_response : If true, will wait for a response from the server. If false, will return immediately
    /// wait          : Time Duration to wait for a response from websocket. Default (10 Seconds)
    ///
    /// Returns a StatusReply if successful
    pub async fn send_status_request(
        &self,
        atm: &ATM,
        profile: &Arc<ATMProfile>,
        wait_for_response: bool,
        wait: Option<Duration>,
    ) -> Result<Option<MessagePickupStatusReply>, ATMError> {
        let _span = span!(Level::DEBUG, "send_status_request",);

        async move {
            debug!(
                "Profile ({}): Status Request wait: {:?}",
                profile.inner.alias, wait
            );

            let (profile_did, mediator_did) = profile.dids()?;

            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let mut msg = Message::build(
                Uuid::new_v4().to_string(),
                "https://didcomm.org/messagepickup/3.0/status-request".to_owned(),
                json!({"recipient_did": profile_did}),
            )
            .to(mediator_did.to_string())
            .from(profile_did.to_string())
            .created_time(now)
            .expires_time(now + 300)
            .finalize();
            msg.extra
                .insert("return_route".to_string(), Value::String("all".into()));

            let msg_id = msg.id.clone();

            debug!("Status-Request message: {:?}", msg);

            // Pack the message
            let (msg, _) = atm
                .inner
                .pack_encrypted(&msg, mediator_did, Some(profile_did))
                .await
                .map_err(|e| ATMError::MsgSendError(format!("Error packing message: {e}")))?;

            match atm
                .send_message(profile, &msg, &msg_id, wait_for_response, false)
                .await?
            {
                SendMessageResponse::Message(message) => {
                    if wait_for_response {
                        self._parse_status_response(&message).await
                    } else {
                        Ok(None)
                    }
                }
                _ => Err(ATMError::MsgReceiveError(
                    "Invalid response from API".into(),
                )),
            }
        }
        .instrument(_span)
        .await
    }

    pub(crate) async fn _parse_status_response(
        &self,
        message: &Message,
    ) -> Result<Option<MessagePickupStatusReply>, ATMError> {
        let status: MessagePickupStatusReply = serde_json::from_value(message.body.clone())
            .map_err(|err| {
                ATMError::MsgReceiveError(format!("Error reading status response: {err}"))
            })?;
        Ok(Some(status))
    }

    /// Sends a Message Pickup 3.0 `Live Delivery` message
    /// Returns the msg_id of the message sent, helpful to get the status response
    pub async fn toggle_live_delivery(
        &self,
        atm: &ATM,
        profile: &Arc<ATMProfile>,
        live_delivery: bool,
    ) -> Result<String, ATMError> {
        let _span = span!(Level::DEBUG, "toggle_live_delivery",);
        async move {
            debug!("Setting live_delivery to ({})", live_delivery);
            let (packed, msg_id) =
                Self::packed_live_delivery_change(atm, profile, live_delivery).await?;

            atm.send_message(profile, &packed, &msg_id, false, false)
                .await?;
            Ok(msg_id)
        }
        .instrument(_span)
        .await
    }

    /// Build and pack a Message Pickup 3.0 `live-delivery-change` message
    /// without sending it. Returns `(packed_message, msg_id)`.
    ///
    /// Exists so the websocket transport's connection setup can write the
    /// frame **directly** to the socket it is holding: that code runs *on*
    /// the transport task, and routing it through [`ATM::send_message`] would
    /// enqueue a `SendMessage` command into the transport's own channel and
    /// then await a reply that only the (currently busy) transport task could
    /// produce — a deadlock that made every connect attempt time out (#611).
    /// All other callers should use
    /// [`toggle_live_delivery`](Self::toggle_live_delivery), which sends
    /// through the normal transport path.
    pub(crate) async fn packed_live_delivery_change(
        atm: &ATM,
        profile: &Arc<ATMProfile>,
        live_delivery: bool,
    ) -> Result<(String, String), ATMError> {
        let (profile_did, mediator_did) = profile.dids()?;

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut msg = Message::build(
            Uuid::new_v4().to_string(),
            "https://didcomm.org/messagepickup/3.0/live-delivery-change".to_owned(),
            json!({"live_delivery": live_delivery}),
        )
        .created_time(now)
        .expires_time(now + 300)
        .from(profile_did.into())
        .to(mediator_did.into())
        .finalize();
        msg.extra
            .insert("return_route".to_string(), Value::String("all".into()));
        let msg_id = msg.id.clone();

        let (packed, _) = atm
            .inner
            .pack_encrypted(&msg, mediator_did, Some(profile_did))
            .await
            .map_err(|e| ATMError::MsgSendError(format!("Error packing message: {e}")))?;

        Ok((packed, msg_id))
    }

    /// Waits for the next message to be received via websocket live delivery
    /// atm         : The ATM SDK to use
    /// profile     : The profile to use
    /// wait        : How long to wait (in milliseconds) for a message before returning None
    ///                 If None, will block forever until a message is received
    /// auto_delete : If true, will delete the message after receiving it
    /// Returns a tuple of the message and metadata, or None if no message was received
    pub async fn live_stream_next(
        &self,
        atm: &ATM,
        profile: &Arc<ATMProfile>,
        wait: Option<Duration>,
        auto_delete: bool,
    ) -> Result<Option<(Message, Box<UnpackMetadata>)>, ATMError> {
        let _span = span!(Level::DEBUG, "live_stream_next");

        async move {
            let Some(mediator) = &*profile.inner.mediator else {
                warn!("Mediator not set for profile {}", profile.inner.alias);
                return Err(ATMError::ProfileError("No Mediator set for profile".into()));
            };

            let (tx, rx) = tokio::sync::oneshot::channel();
            // Send the next request to the profile websocket
            let Some(ws_channel) = &*mediator.ws_channel_tx.read().await else {
                warn!(
                    "WebSocket channel not set for profile {}",
                    profile.inner.alias
                );
                return Err(ATMError::ProfileError(
                    "No WebSocket channel set for profile".into(),
                ));
            };

            let tx_uuid = mediator.get_tx_uuid();
            ws_channel
                .send(WebSocketCommands::Next(tx_uuid, tx))
                .await
                .map_err(|err| {
                    ATMError::TransportError(format!(
                        "Could not send Next command to websocket: {err:?}"
                    ))
                })?;
            debug!("sent next request to websocket");

            // Setup the timer for the wait, doesn't do anything till `await` is called in the select! macro
            let sleep: tokio::time::Sleep = tokio::time::sleep(wait.unwrap_or(Duration::MAX));

            select! {
                _ = sleep, if wait.is_some() => {
                    debug!("Timeout reached, no message received");
                    ws_channel.send(WebSocketCommands::CancelNext(tx_uuid)).await.map_err(|err| {
                        ATMError::TransportError(format!(
                            "Could not send CancelNext command to websocket: {err:?}"
                        ))
                    })?;
                    Ok(None)
                }
                value = rx => {
                    match value {
                        Ok(WebSocketResponses::MessageReceived(msg, meta)) => {
                             // If auto_delete is true, delete the message
                             if auto_delete {
                                atm.delete_message_background(profile, &meta.sha256_hash).await?;
                            }
                            Ok(Some((*msg, meta)))
                        }
                        Ok(WebSocketResponses::Disconnected) => {
                            // Connection dropped while waiting. Treat as "no
                            // message right now" so streaming callers quietly
                            // retry on the reconnected socket instead of logging
                            // a spurious receive error.
                            debug!("WebSocket disconnected while awaiting next message");
                            Ok(None)
                        }
                        Ok(WebSocketResponses::PackedMessageReceived(packed_msg)) => {
                            // A DIDComm-only stream can't handle a packed (e.g.
                            // TSP/CESR) frame. Erroring here without removing it
                            // left the message in the mediator queue, so the
                            // pickup redelivered it every cycle — a poison loop.
                            // Delete it (when auto_delete) and skip; a consumer
                            // that wants packed frames uses `live_stream_next_frame`
                            // / `live_stream_next_packed`.
                            warn!(
                                "Dropping unexpected packed message on a DIDComm-only stream \
                                 (use live_stream_next_frame for multiplexed TSP + DIDComm)"
                            );
                            if auto_delete {
                                let sha256_hash = sha256::digest(packed_msg.as_str());
                                atm.delete_message_background(profile, &sha256_hash).await?;
                            }
                            Ok(None)
                        }
                        Err(e) => {
                            warn!("Error receiving message: {:?}", e);
                            Err(ATMError::MsgReceiveError(format!(
                                "Error receiving message: {e:?}"
                            )))
                        }
                    }
                }
            }
        }
        .instrument(_span)
        .await
    }

    /// Waits for the next inbound frame — **DIDComm or TSP** — via websocket
    /// live delivery, returning it tagged as an [`InboundFrame`].
    ///
    /// Unlike [`live_stream_next`](Self::live_stream_next) (DIDComm-only, errors
    /// on a TSP frame) and [`live_stream_next_packed`](Self::live_stream_next_packed)
    /// (TSP-only, errors on a DIDComm frame), this accepts **both** off the one
    /// stream so a multiplexing consumer can route by transport. `auto_delete`
    /// deletes the received message in the background (by unpack `sha256_hash`
    /// for DIDComm, by hash of the packed frame for TSP), matching the two
    /// single-protocol methods.
    pub async fn live_stream_next_frame(
        &self,
        atm: &ATM,
        profile: &Arc<ATMProfile>,
        wait: Option<Duration>,
        auto_delete: bool,
    ) -> Result<Option<InboundFrame>, ATMError> {
        let _span = span!(Level::DEBUG, "live_stream_next_frame");

        async move {
            let Some(mediator) = &*profile.inner.mediator else {
                warn!("Mediator not set for profile {}", profile.inner.alias);
                return Err(ATMError::ProfileError("No Mediator set for profile".into()));
            };

            let (tx, rx) = tokio::sync::oneshot::channel();
            let Some(ws_channel) = &*mediator.ws_channel_tx.read().await else {
                warn!(
                    "WebSocket channel not set for profile {}",
                    profile.inner.alias
                );
                return Err(ATMError::ProfileError(
                    "No WebSocket channel set for profile".into(),
                ));
            };

            let tx_uuid = mediator.get_tx_uuid();
            ws_channel
                .send(WebSocketCommands::Next(tx_uuid, tx))
                .await
                .map_err(|err| {
                    ATMError::TransportError(format!(
                        "Could not send Next command to websocket: {err:?}"
                    ))
                })?;
            debug!("sent next request to websocket for inbound frame");

            let sleep: tokio::time::Sleep = tokio::time::sleep(wait.unwrap_or(Duration::MAX));

            select! {
                _ = sleep, if wait.is_some() => {
                    debug!("Timeout reached, no message received");
                    ws_channel.send(WebSocketCommands::CancelNext(tx_uuid)).await.map_err(|err| {
                        ATMError::TransportError(format!(
                            "Could not send CancelNext command to websocket: {err:?}"
                        ))
                    })?;
                    Ok(None)
                }
                value = rx => {
                    match value {
                        Ok(WebSocketResponses::MessageReceived(msg, meta)) => {
                            if auto_delete {
                                atm.delete_message_background(profile, &meta.sha256_hash).await?;
                            }
                            Ok(Some(InboundFrame::DidComm(msg, meta)))
                        }
                        Ok(WebSocketResponses::PackedMessageReceived(packed_msg)) => {
                            if auto_delete {
                                let sha256_hash = sha256::digest(packed_msg.as_str());
                                atm.delete_message_background(profile, &sha256_hash).await?;
                            }
                            Ok(Some(InboundFrame::Tsp(packed_msg)))
                        }
                        Ok(WebSocketResponses::Disconnected) => {
                            // Connection dropped while waiting — treat as "no
                            // message right now" so the consumer's loop quietly
                            // retries on the reconnected socket.
                            debug!("WebSocket disconnected while awaiting next frame");
                            Ok(None)
                        }
                        Err(e) => {
                            warn!("Error receiving frame: {:?}", e);
                            Err(ATMError::MsgReceiveError(format!(
                                "Error receiving frame: {e:?}"
                            )))
                        }
                    }
                }
            }
        }
        .instrument(_span)
        .await
    }

    /// Attempts to retrieve a specific message from the server via websocket live delivery
    /// atm                 : The ATM SDK to use
    /// profile             : The profile to use
    /// msg_id              : The ID of the message to retrieve (matches on either `id` or `pthid`)
    /// wait                : How long to wait (in milliseconds) for a message before returning None
    ///                       If 0, will not block
    /// auto_delete         : If true, will delete the message after receiving it
    /// Returns a tuple of the message and metadata, or None if no message was received
    pub async fn live_stream_get(
        &self,
        atm: &ATM,
        profile: &Arc<ATMProfile>,
        msg_id: &str,
        wait: Duration,
        auto_delete: bool,
    ) -> Result<Option<(Message, Box<UnpackMetadata>)>, ATMError> {
        let _span = span!(Level::DEBUG, "live_stream_get");

        async move {
            let Some(mediator) = &*profile.inner.mediator else {
                warn!("Mediator not set for profile {}", profile.inner.alias);
                return Err(ATMError::ProfileError("No Mediator set for profile".into()));
            };

            let (tx, rx) = tokio::sync::oneshot::channel();
            // Send the next request to the profile websocket
            let Some(ws_channel) = &*mediator.ws_channel_tx.read().await else {
                warn!(
                    "WebSocket channel not set for profile {}",
                    profile.inner.alias
                );
                return Err(ATMError::ProfileError(
                    "No WebSocket channel set for profile".into(),
                ));
            };

            // Send the get request to the ws_handler
            ws_channel.send(WebSocketCommands::GetMessage(msg_id.to_string(), tx)).await.map_err(|err| {
                ATMError::TransportError(format!(
                    "Could not send GetMessage({msg_id}) Command to websocket: {err:?}"
                ))
            })?;
            debug!("sent get request to ws_handler");

            // Setup the timer for the wait, doesn't do anything till `await` is called in the select! macro
            let sleep = tokio::time::sleep(wait);
            tokio::pin!(sleep);

            select! {
                _ = &mut sleep, if wait.as_millis() > 0 => {
                    debug!("Timeout reached, no message received");
                    ws_channel.send(WebSocketCommands::CancelGetMessage(msg_id.to_string())).await.map_err(|err| {
                        ATMError::TransportError(format!(
                            "Could not send CancelGetMessage command to websocket: {err:?}"
                        ))
                    })?;
                    Ok(None)
                }
                value = rx => {
                    match value {
                        Ok(WebSocketResponses::MessageReceived(msg, meta)) => {
                            // If auto_delete is true, delete the message
                            if auto_delete {
                                atm.delete_message_background(profile, &meta.sha256_hash).await?;
                            }
                            Ok(Some((*msg, meta)))
                        }
                        Ok(WebSocketResponses::Disconnected) => {
                            // Connection dropped while waiting for this specific
                            // response. The request was lost with the socket, so
                            // fail fast with a typed error — this lets callers
                            // tell a reconnect race apart from a genuine
                            // no-response and avoid a misleading send-failure log.
                            debug!("WebSocket disconnected while awaiting message {msg_id}");
                            Err(ATMError::Disconnected(format!(
                                "Connection reset while awaiting response for {msg_id}"
                            )))
                        }
                        Ok(WebSocketResponses::PackedMessageReceived(packed_msg)) => {
                            // A DIDComm-only stream can't handle a packed (e.g.
                            // TSP/CESR) frame. Erroring here without removing it
                            // left the message in the mediator queue, so the
                            // pickup redelivered it every cycle — a poison loop.
                            // Delete it (when auto_delete) and skip; a consumer
                            // that wants packed frames uses `live_stream_next_frame`
                            // / `live_stream_next_packed`.
                            warn!(
                                "Dropping unexpected packed message on a DIDComm-only stream \
                                 (use live_stream_next_frame for multiplexed TSP + DIDComm)"
                            );
                            if auto_delete {
                                let sha256_hash = sha256::digest(packed_msg.as_str());
                                atm.delete_message_background(profile, &sha256_hash).await?;
                            }
                            Ok(None)
                        }
                        Err(e) => {
                            warn!("Error receiving message: {:?}", e);
                            Err(ATMError::MsgReceiveError(format!(
                                "Error receiving message: {e:?}"
                            )))
                        }
                    }
                }
            }
    }
        .instrument(_span)
        .await
    }

    /// Sends a Message Pickup 3.0 `Delivery Request` message
    /// atm           : The ATM SDK to use
    /// limit         : # of messages to retrieve, defaults to 10 if None
    pub async fn send_delivery_request(
        &self,
        atm: &ATM,
        profile: &Arc<ATMProfile>,
        limit: Option<usize>,
        wait_for_response: bool,
    ) -> Result<Vec<(Message, UnpackMetadata)>, ATMError> {
        let message = self
            ._request_delivery(atm, profile, limit, wait_for_response)
            .await?;
        self._handle_delivery(atm, profile, &message).await
    }

    /// TSP-aware sibling of [`send_delivery_request`]: returns each queued
    /// message as an [`InboundFrame`] (DIDComm or TSP) paired with the
    /// attachment id needed to acknowledge/delete it — so an offline-sync
    /// consumer can route TSP frames to a TSP handler instead of DIDComm-
    /// unpacking (and poison-looping on) them. Undeliverable attachments yield
    /// `(None, id)` so the caller still acks them. Requires the `tsp` feature.
    #[cfg(feature = "tsp")]
    pub async fn send_delivery_request_frames(
        &self,
        atm: &ATM,
        profile: &Arc<ATMProfile>,
        limit: Option<usize>,
        wait_for_response: bool,
    ) -> Result<Vec<(Option<InboundFrame>, String)>, ATMError> {
        let message = self
            ._request_delivery(atm, profile, limit, wait_for_response)
            .await?;
        self._handle_delivery_frames(atm, &message).await
    }

    /// Send a Message-Pickup 3.0 delivery-request and return the mediator's
    /// `delivery` message (whose attachments are the queued messages). Shared by
    /// [`send_delivery_request`] and [`send_delivery_request_frames`].
    async fn _request_delivery(
        &self,
        atm: &ATM,
        profile: &Arc<ATMProfile>,
        limit: Option<usize>,
        wait_for_response: bool,
    ) -> Result<Message, ATMError> {
        let _span = span!(Level::DEBUG, "send_delivery_request",);

        async move {
            debug!(
                "Profile ({}): Delivery Request limit: {:?}",
                profile.inner.alias, limit
            );
            let (profile_did, mediator_did) = profile.dids()?;

            let body = MessagePickupDeliveryRequest {
                recipient_did: profile_did.into(),
                limit: limit.unwrap_or(10),
            };

            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let mut msg = Message::build(
                Uuid::new_v4().to_string(),
                "https://didcomm.org/messagepickup/3.0/delivery-request".to_owned(),
                serde_json::to_value(body).unwrap(),
            )
            .to(mediator_did.into())
            .from(profile_did.into())
            .created_time(now)
            .expires_time(now + 300)
            .finalize();
            msg.extra
                .insert("return_route".to_string(), Value::String("all".into()));

            let msg_id = msg.id.clone();

            debug!("Delivery-Request message: {:?}", msg);

            // Pack the message
            let msg = {
                let (msg, _) = atm
                    .inner
                    .pack_encrypted(&msg, mediator_did, Some(profile_did))
                    .await
                    .map_err(|e| ATMError::MsgSendError(format!("Error packing message: {e}")))?;

                msg
            };

            match atm
                .send_message(profile, &msg, &msg_id, wait_for_response, false)
                .await?
            {
                SendMessageResponse::Message(message) => Ok(*message),
                _ => Err(ATMError::MsgReceiveError("No Messages from API".into())),
            }
        }
        .instrument(_span)
        .await
    }

    /// TSP-aware sibling of [`_handle_delivery`]: classify each delivered
    /// attachment (DIDComm vs TSP) and return it as an [`InboundFrame`] paired
    /// with the attachment id needed to ack/delete it. Undeliverable
    /// attachments — bad base64/utf8, or a non-TSP frame that fails DIDComm
    /// unpack — yield `(None, id)` so the caller still acks them and the
    /// mediator stops redelivering (no poison loop). Unlike [`_handle_delivery`],
    /// a TSP frame is surfaced (`InboundFrame::Tsp`) rather than DIDComm-unpacked
    /// and dropped.
    #[cfg(feature = "tsp")]
    pub(crate) async fn _handle_delivery_frames(
        &self,
        atm: &ATM,
        message: &Message,
    ) -> Result<Vec<(Option<InboundFrame>, String)>, ATMError> {
        let mut out: Vec<(Option<InboundFrame>, String)> = Vec::new();

        let Some(attachments) = &message.attachments else {
            return Ok(out);
        };

        for attachment in attachments {
            // No id => we can't ack/delete it individually; skip (leaving it
            // queued is preferable to acking the wrong message).
            let Some(id) = attachment.id.clone() else {
                warn!("Delivery attachment has no id; cannot ack — skipping");
                continue;
            };
            let Some(b64) = &attachment.data.base64 else {
                warn!("Attachment type not supported: {:?}", attachment.data);
                emit_poison(
                    atm,
                    Some(id.clone()),
                    String::new(),
                    format!("unsupported attachment type: {:?}", attachment.data),
                );
                out.push((None, id));
                continue;
            };
            let decoded = match BASE64_URL_SAFE_NO_PAD.decode(b64.clone()) {
                Ok(bytes) => match String::from_utf8(bytes) {
                    Ok(s) => s,
                    Err(e) => {
                        warn!("Error decoding attachment to utf8: ({e:?}). id({id})");
                        emit_poison(
                            atm,
                            Some(id.clone()),
                            b64.clone(),
                            format!("attachment payload is not valid UTF-8: {e}"),
                        );
                        out.push((None, id));
                        continue;
                    }
                },
                Err(e) => {
                    warn!("Error decoding base64: ({e:?}). id({id})");
                    emit_poison(
                        atm,
                        Some(id.clone()),
                        b64.clone(),
                        format!("attachment is not valid base64: {e}"),
                    );
                    out.push((None, id));
                    continue;
                }
            };

            if atm.tsp().is_tsp(&decoded) {
                out.push((Some(InboundFrame::Tsp(Box::new(decoded))), id));
            } else {
                // DIDComm frames pulled via pickup are unpacked under the same
                // configured secure `unpack_policy` as a direct `atm.unpack`, so
                // an envelope the policy rejects (e.g. an unauthenticated
                // wrapping, or a forged `from`) is dropped rather than surfaced.
                match atm
                    .inner
                    .unpack_with(&decoded, atm.inner.config.unpack_policy())
                    .await
                {
                    Ok((mut m, u)) => {
                        m.id = id.clone();
                        out.push((Some(InboundFrame::DidComm(Box::new(m), Box::new(u))), id));
                    }
                    Err(e) => {
                        warn!("Error unpacking message: ({e:?}); dropping. id({id})");
                        emit_poison(atm, Some(id.clone()), decoded.clone(), e.to_string());
                        out.push((None, id));
                    }
                }
            }
        }

        Ok(out)
    }

    /// Iterates through each attachment and unpacks each message into an array to return.
    ///
    /// Each attachment is unpacked under the **configured
    /// [`UnpackPolicy`](crate::config::UnpackPolicy)** — the same secure
    /// authcrypt-only default that [`crate::ATM::unpack`] applies — so messages
    /// pulled via pickup get the same guarantees as a direct unpack.
    ///
    /// An attachment that can never be processed — malformed base64/utf8, an
    /// unsupported attachment type, or a message the policy *deterministically*
    /// rejects (a disallowed wrapping, too many signatures, an addressing
    /// mismatch, a non-conformant envelope) — is **purged from the mediator**
    /// (best-effort, by its message id) so it can't be redelivered forever.
    /// Without this a "poison" message would be handed back every pickup,
    /// stalling the queue and, under backpressure, the mediator connection.
    /// Failures that might be *transient* (e.g. a temporarily unresolvable
    /// signer DID) are left queued for retry.
    pub(crate) async fn _handle_delivery(
        &self,
        atm: &ATM,
        profile: &Arc<ATMProfile>,
        message: &Message,
    ) -> Result<Vec<(Message, UnpackMetadata)>, ATMError> {
        let mut response: Vec<(Message, UnpackMetadata)> = Vec::new();

        // Best-effort: report the poison message on the optional channel (so a
        // consumer can retain/quarantine it) then remove it from the mediator by
        // its id (== the delivery attachment id) so it cannot poison-loop.
        async fn report_and_purge(
            atm: &ATM,
            profile: &Arc<ATMProfile>,
            id: &Option<String>,
            raw: String,
            reason: String,
        ) {
            // Report first (so a consumer can retain/quarantine it), then purge.
            emit_poison(atm, id.clone(), raw, reason);
            if let Some(id) = id
                && let Err(e) = atm.delete_message_background(profile, id).await
            {
                warn!("Couldn't purge undeliverable message id({id}): {e:?}");
            }
        }

        if let Some(attachments) = &message.attachments {
            for attachment in attachments {
                if let Some(b64) = &attachment.data.base64 {
                    let decoded = match BASE64_URL_SAFE_NO_PAD.decode(b64.clone()) {
                        Ok(decoded) => match String::from_utf8(decoded) {
                            Ok(decoded) => decoded,
                            Err(e) => {
                                warn!(
                                    "Undeliverable attachment (not utf8: {e:?}); purging. id({:?})",
                                    attachment.id
                                );
                                report_and_purge(
                                    atm,
                                    profile,
                                    &attachment.id,
                                    b64.clone(),
                                    format!("attachment payload is not valid UTF-8: {e}"),
                                )
                                .await;
                                continue;
                            }
                        },
                        Err(e) => {
                            warn!(
                                "Undeliverable attachment (bad base64: {e:?}); purging. id({:?})",
                                attachment.id
                            );
                            report_and_purge(
                                atm,
                                profile,
                                &attachment.id,
                                b64.clone(),
                                format!("attachment is not valid base64: {e}"),
                            )
                            .await;
                            continue;
                        }
                    };

                    match atm
                        .inner
                        .unpack_with(&decoded, atm.inner.config.unpack_policy())
                        .await
                    {
                        Ok((mut m, u)) => {
                            if let Some(attachment_id) = &attachment.id {
                                m.id = attachment_id.to_string();
                            }
                            response.push((m, u))
                        }
                        // A deterministic policy/addressing/format rejection will
                        // fail identically on every redelivery — a poison
                        // message. Purge it. Anything else may be transient, so
                        // leave it queued for retry.
                        Err(
                            e @ (ATMError::UnexpectedEnvelope(_) | ATMError::AddressingMismatch(_)),
                        ) => {
                            warn!(
                                "Purging poison message (deterministic reject: {e:?}). id({:?})",
                                attachment.id
                            );
                            report_and_purge(
                                atm,
                                profile,
                                &attachment.id,
                                decoded.clone(),
                                e.to_string(),
                            )
                            .await;
                            continue;
                        }
                        Err(e) => {
                            warn!(
                                "Error unpacking message ({e:?}); left queued for retry. id({:?})",
                                attachment.id
                            );
                            continue;
                        }
                    };
                } else {
                    warn!(
                        "Undeliverable attachment (unsupported type: {:?}); purging. id({:?})",
                        attachment.data, attachment.id
                    );
                    report_and_purge(
                        atm,
                        profile,
                        &attachment.id,
                        String::new(),
                        format!("unsupported attachment type: {:?}", attachment.data),
                    )
                    .await;
                    continue;
                }
            }
        }

        Ok(response)
    }

    /// Sends a Message Pickup 3.0 `Messages Received` message
    /// This effectively deletes the messages from the server
    /// atm           : The ATM SDK to use
    /// list          : List of messages to delete (SHA256 message Hashes)
    ///
    /// A status reply will be returned if successful
    pub async fn send_messages_received(
        &self,
        atm: &ATM,
        profile: &Arc<ATMProfile>,
        list: &Vec<String>,
        wait_for_response: bool,
    ) -> Result<Option<MessagePickupStatusReply>, ATMError> {
        let _span = span!(Level::DEBUG, "send_messages_received",);

        async move {
            debug!(
                "Profile ({}): Messages Received, # msgs to delete: {}",
                profile.inner.alias,
                list.len()
            );

            let (profile_did, mediator_did) = profile.dids()?;

            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let mut msg = Message::build(
                Uuid::new_v4().to_string(),
                "https://didcomm.org/messagepickup/3.0/messages-received".to_owned(),
                json!({"message_id_list": list}),
            )
            .to(mediator_did.into())
            .from(profile_did.into())
            .created_time(now)
            .expires_time(now + 300)
            .finalize();
            msg.extra
                .insert("return_route".to_string(), Value::String("all".into()));

            let msg_id = msg.id.clone();

            debug!("messages-received message: {:?}", msg);

            // Pack the message
            let (msg, _) = atm
                .inner
                .pack_encrypted(&msg, mediator_did, Some(profile_did))
                .await
                .map_err(|e| ATMError::MsgSendError(format!("Error packing message: {e}")))?;

            match atm
                .send_message(profile, &msg, &msg_id, wait_for_response, false)
                .await
            {
                Ok(SendMessageResponse::Message(message)) => {
                    if wait_for_response {
                        self._parse_status_response(&message).await
                    } else {
                        Ok(None)
                    }
                }
                Ok(SendMessageResponse::EmptyResponse) => Ok(None),
                Err(err) => Err(ATMError::MsgReceiveError(format!(
                    "Invalid response from API: {err}"
                ))),
                _ => Err(ATMError::MsgReceiveError(
                    "Wrong type received from API".into(),
                )),
            }

            /*if let SendMessageResponse::Message(message) = atm
                .send_message(profile, &msg, &msg_id, wait_for_response)
                .await?
            {
                if wait_for_response {
                    self._parse_status_response(&message).await
                } else {
                    Ok(None)
                }
            } else {
                Err(ATMError::MsgReceiveError(
                    "Invalid response from API".into(),
                ))
            }*/
        }
        .instrument(_span)
        .await
    }

    /// Waits for the next message to be received via websocket live delivery
    /// Returns the message as a packed string without unpacking
    /// atm         : The ATM SDK to use
    /// profile     : The profile to use
    /// wait        : How long to wait (in milliseconds) for a message before returning None
    ///                 If None, will block forever until a message is received
    /// auto_delete : If true, will delete the message after receiving it
    /// Returns the packed message string, or None if no message was received
    pub async fn live_stream_next_packed(
        &self,
        atm: &ATM,
        profile: &Arc<ATMProfile>,
        wait: Option<Duration>,
        auto_delete: bool,
    ) -> Result<Option<String>, ATMError> {
        let _span = span!(Level::DEBUG, "live_stream_next_packed");

        async move {
            let Some(mediator) = &*profile.inner.mediator else {
                warn!("Mediator not set for profile {}", profile.inner.alias);
                return Err(ATMError::ProfileError("No Mediator set for profile".into()));
            };

            let (tx, rx) = tokio::sync::oneshot::channel();
            // Send the next request to the profile websocket
            let Some(ws_channel) = &*mediator.ws_channel_tx.read().await else {
                warn!(
                    "WebSocket channel not set for profile {}",
                    profile.inner.alias
                );
                return Err(ATMError::ProfileError(
                    "No WebSocket channel set for profile".into(),
                ));
            };

            let tx_uuid = mediator.get_tx_uuid();
            ws_channel
                .send(WebSocketCommands::Next(tx_uuid, tx))
                .await
                .map_err(|err| {
                    ATMError::TransportError(format!(
                        "Could not send Next command to websocket: {err:?}"
                    ))
                })?;
            debug!("sent next request to websocket for packed message");

            // Setup the timer for the wait, doesn't do anything till `await` is called in the select! macro
            let sleep: tokio::time::Sleep = tokio::time::sleep(wait.unwrap_or(Duration::MAX));

            select! {
                _ = sleep, if wait.is_some() => {
                    debug!("Timeout reached, no message received");
                    ws_channel.send(WebSocketCommands::CancelNext(tx_uuid)).await.map_err(|err| {
                        ATMError::TransportError(format!(
                            "Could not send CancelNext command to websocket: {err:?}"
                        ))
                    })?;
                    Ok(None)
                }
                value = rx => {
                    match value {
                        Ok(WebSocketResponses::PackedMessageReceived(packed_msg)) => {
                            // If auto_delete is true, delete the message
                            if auto_delete {
                                let sha256_hash = sha256::digest(packed_msg.as_str());
                                debug!("Trying to delete message in background with hash: {}", sha256_hash);
                                atm.delete_message_background(profile, &sha256_hash).await?;
                                debug!("Deleted message in background with hash: {}", sha256_hash);
                            }
                            Ok(Some(*packed_msg))
                        }
                        Ok(WebSocketResponses::Disconnected) => {
                            // Connection dropped while waiting. Treat as "no
                            // message right now" so streaming callers quietly
                            // retry on the reconnected socket.
                            debug!("WebSocket disconnected while awaiting next packed message");
                            Ok(None)
                        }
                        Ok(WebSocketResponses::MessageReceived(_, _)) => {
                            Err(ATMError::MsgReceiveError(
                                "Received unpacked message when expecting packed message. Make sure WebSocket is configured with skip_unpack_messages=true".into()
                            ))
                        }
                        Err(e) => {
                            warn!("Error receiving message: {:?}", e);
                            Err(ATMError::MsgReceiveError(format!(
                                "Error receiving message: {e:?}"
                            )))
                        }
                    }
                }
            }
        }
        .instrument(_span)
        .await
    }

    /// Attempts to retrieve a specific message from the server via websocket live delivery (packed version)
    /// Note: This method is not yet implemented as it requires changes to the message cache to support packed messages
    #[allow(dead_code)]
    async fn live_stream_get_packed(
        &self,
        _profile: &Arc<ATMProfile>,
        _msg_id: &str,
        _wait: Duration,
    ) -> Result<Option<String>, ATMError> {
        Err(ATMError::MsgReceiveError(
            "live_stream_get_packed is not yet implemented. The message cache currently only supports unpacked messages. Use live_stream_next_packed() instead.".into()
        ))
    }
}

/// Wrapper struct that holds a reference to ATM, enabling the `atm.message_pickup().method()` pattern
pub struct MessagePickupOps<'a> {
    pub(crate) atm: &'a ATM,
}

impl<'a> MessagePickupOps<'a> {
    /// Sends a Message Pickup 3.0 `Status Request` message
    /// See [`MessagePickup::send_status_request`] for full documentation
    pub async fn send_status_request(
        &self,
        profile: &Arc<ATMProfile>,
        wait_for_response: bool,
        wait: Option<Duration>,
    ) -> Result<Option<MessagePickupStatusReply>, ATMError> {
        MessagePickup::default()
            .send_status_request(self.atm, profile, wait_for_response, wait)
            .await
    }

    /// Sends a Message Pickup 3.0 `Live Delivery` message
    /// See [`MessagePickup::toggle_live_delivery`] for full documentation
    pub async fn toggle_live_delivery(
        &self,
        profile: &Arc<ATMProfile>,
        live_delivery: bool,
    ) -> Result<String, ATMError> {
        MessagePickup::default()
            .toggle_live_delivery(self.atm, profile, live_delivery)
            .await
    }

    /// Waits for the next message to be received via websocket live delivery
    /// See [`MessagePickup::live_stream_next`] for full documentation
    pub async fn live_stream_next(
        &self,
        profile: &Arc<ATMProfile>,
        wait: Option<Duration>,
        auto_delete: bool,
    ) -> Result<Option<(Message, Box<UnpackMetadata>)>, ATMError> {
        MessagePickup::default()
            .live_stream_next(self.atm, profile, wait, auto_delete)
            .await
    }

    /// Attempts to retrieve a specific message from the server via websocket live delivery
    /// See [`MessagePickup::live_stream_get`] for full documentation
    pub async fn live_stream_get(
        &self,
        profile: &Arc<ATMProfile>,
        msg_id: &str,
        wait: Duration,
        auto_delete: bool,
    ) -> Result<Option<(Message, Box<UnpackMetadata>)>, ATMError> {
        MessagePickup::default()
            .live_stream_get(self.atm, profile, msg_id, wait, auto_delete)
            .await
    }

    /// Sends a Message Pickup 3.0 `Delivery Request` message
    /// See [`MessagePickup::send_delivery_request`] for full documentation
    pub async fn send_delivery_request(
        &self,
        profile: &Arc<ATMProfile>,
        limit: Option<usize>,
        wait_for_response: bool,
    ) -> Result<Vec<(Message, UnpackMetadata)>, ATMError> {
        MessagePickup::default()
            .send_delivery_request(self.atm, profile, limit, wait_for_response)
            .await
    }

    /// Sends a Message Pickup 3.0 `Messages Received` message
    /// See [`MessagePickup::send_messages_received`] for full documentation
    pub async fn send_messages_received(
        &self,
        profile: &Arc<ATMProfile>,
        list: &Vec<String>,
        wait_for_response: bool,
    ) -> Result<Option<MessagePickupStatusReply>, ATMError> {
        MessagePickup::default()
            .send_messages_received(self.atm, profile, list, wait_for_response)
            .await
    }

    /// Waits for the next message to be received via websocket live delivery (packed)
    /// See [`MessagePickup::live_stream_next_packed`] for full documentation
    pub async fn live_stream_next_packed(
        &self,
        profile: &Arc<ATMProfile>,
        wait: Option<Duration>,
        auto_delete: bool,
    ) -> Result<Option<String>, ATMError> {
        MessagePickup::default()
            .live_stream_next_packed(self.atm, profile, wait, auto_delete)
            .await
    }

    /// Waits for the next inbound frame (DIDComm or TSP) via websocket live delivery
    /// See [`MessagePickup::live_stream_next_frame`] for full documentation
    pub async fn live_stream_next_frame(
        &self,
        profile: &Arc<ATMProfile>,
        wait: Option<Duration>,
        auto_delete: bool,
    ) -> Result<Option<InboundFrame>, ATMError> {
        MessagePickup::default()
            .live_stream_next_frame(self.atm, profile, wait, auto_delete)
            .await
    }

    /// Sends a Message Pickup 3.0 `Delivery Request` and returns each queued
    /// message as an [`InboundFrame`] (DIDComm or TSP) paired with its ack id —
    /// the offline/backlog counterpart of [`live_stream_next_frame`].
    /// See [`MessagePickup::send_delivery_request_frames`] for full documentation.
    #[cfg(feature = "tsp")]
    pub async fn send_delivery_request_frames(
        &self,
        profile: &Arc<ATMProfile>,
        limit: Option<usize>,
        wait_for_response: bool,
    ) -> Result<Vec<(Option<InboundFrame>, String)>, ATMError> {
        MessagePickup::default()
            .send_delivery_request_frames(self.atm, profile, limit, wait_for_response)
            .await
    }
}

#[cfg(test)]
mod tests {
    //! Poison-message resistance of the delivery drain ([`MessagePickup::_handle_delivery`]).
    //!
    //! A pickup delivery batch is attacker-influenced: anyone can forward an
    //! arbitrary (malformed, or policy-rejected) envelope into a recipient's
    //! mediator queue. These tests confirm such a message cannot take the drain
    //! (and therefore the pickup loop / mediator connection) down: every poison
    //! attachment is skipped (purged best-effort) while the valid messages
    //! around it are still surfaced, and the call never panics, errors, or
    //! hangs.
    use super::*;
    use crate::config::ATMConfig;
    use crate::profiles::{ATMProfile, ATMProfileInner};
    use affinidi_crypto::jose::key_agreement::{Curve, PrivateKeyAgreement, PublicKeyAgreement};
    use affinidi_did_common::{DID, PeerCreateKey, PeerKeyPurpose, PeerKeyType};
    use affinidi_messaging_didcomm::jwe::encrypt::authcrypt;
    use affinidi_messaging_didcomm::message::{Attachment, Message as DcMessage};
    use affinidi_secrets_resolver::SecretsResolver;
    use affinidi_secrets_resolver::secrets::Secret;
    use affinidi_tdk_common::TDKSharedState;
    use affinidi_tdk_common::config::TDKConfig;
    use serde_json::json;

    /// A did:peer:2 with Ed25519 (V, #key-1) + X25519 (E, #key-2); returns the
    /// DID and the X25519 secret keyed at `#key-2`.
    fn peer_with_x25519() -> (String, Secret) {
        let x = Secret::generate_x25519(Some("t"), None).unwrap();
        let x_mb = x.get_public_keymultibase().unwrap();
        let keys = vec![
            PeerCreateKey::new(PeerKeyPurpose::Verification, PeerKeyType::Ed25519),
            PeerCreateKey::from_multibase(PeerKeyPurpose::Encryption, x_mb),
        ];
        let (did, _) = DID::generate_peer(&keys, None).unwrap();
        let did = did.to_string();
        let mut s = x;
        s.id = format!("{did}#key-2");
        (did, s)
    }

    /// An ATM with the **secure default** policy and one recipient secret loaded.
    async fn atm_with_secret(secret: Secret) -> ATM {
        let config = ATMConfig::builder().build().unwrap();
        let tdk = Arc::new(
            TDKSharedState::new(TDKConfig::headless().unwrap())
                .await
                .unwrap(),
        );
        tdk.secrets_resolver().insert(secret).await;
        ATM::new(config, tdk).await.unwrap()
    }

    /// A profile with no mediator — the drain only uses the profile for the
    /// (channel-based, fire-and-forget) purge, which needs no live mediator.
    fn fake_profile() -> Arc<ATMProfile> {
        Arc::new(ATMProfile {
            inner: Arc::new(ATMProfileInner {
                did: "did:peer:fake".to_string(),
                alias: "test".to_string(),
                mediator: Arc::new(None),
            }),
        })
    }

    /// `authcrypt(plaintext)` from sender → recipient, base64url-no-pad encoded
    /// as it would appear inside a pickup delivery attachment.
    fn authcrypt_b64(
        sender_did: &str,
        sender_x: &Secret,
        recipient_did: &str,
        recipient_x: &Secret,
        id: &str,
    ) -> String {
        let msg = DcMessage::build(
            id.to_string(),
            "example/v1".to_string(),
            json!({"hello": "world"}),
        )
        .from(sender_did.to_string())
        .to(recipient_did.to_string())
        .finalize();
        let plaintext = serde_json::to_string(&msg).unwrap();
        let sender_priv =
            PrivateKeyAgreement::from_raw_bytes(Curve::X25519, sender_x.get_private_bytes())
                .unwrap();
        let recipient_pub =
            PublicKeyAgreement::from_raw_bytes(Curve::X25519, recipient_x.get_public_bytes())
                .unwrap();
        let jwe = authcrypt(
            plaintext.as_bytes(),
            &format!("{sender_did}#key-2"),
            &sender_priv,
            &[(&format!("{recipient_did}#key-2"), &recipient_pub)],
        )
        .unwrap();
        BASE64_URL_SAFE_NO_PAD.encode(jwe.as_bytes())
    }

    /// Build a pickup `delivery` message carrying the given attachments.
    fn delivery_with(attachments: Vec<Attachment>) -> Message {
        let mut b = Message::build(
            "delivery-1".to_string(),
            "https://didcomm.org/messagepickup/3.0/delivery".to_string(),
            json!({}),
        );
        for a in attachments {
            b = b.attachment(a);
        }
        b.finalize()
    }

    /// A batch interleaving valid messages with four kinds of poison —
    /// malformed base64, valid-base64-but-not-utf8, an unsupported attachment
    /// type, and a policy-rejected plaintext — must not panic, error, or abort:
    /// the drain skips each poison attachment and still surfaces the valid
    /// messages that came *before and after* them.
    #[tokio::test]
    async fn poison_messages_are_skipped_and_do_not_stall_the_drain() {
        let (sender_did, sender_x) = peer_with_x25519();
        let (recipient_did, recipient_x) = peer_with_x25519();
        let atm = atm_with_secret(recipient_x.clone()).await;
        let profile = fake_profile();

        // Valid authcrypt messages (must be surfaced), one before and one after
        // the poison, to prove the batch keeps going.
        let good1 = Attachment::base64(authcrypt_b64(
            &sender_did,
            &sender_x,
            &recipient_did,
            &recipient_x,
            "m1",
        ))
        .id("good-1".to_string())
        .finalize();
        let good2 = Attachment::base64(authcrypt_b64(
            &sender_did,
            &sender_x,
            &recipient_did,
            &recipient_x,
            "m2",
        ))
        .id("good-2".to_string())
        .finalize();

        // Poison 1: malformed base64.
        let bad_b64 = Attachment::base64("!!!not-valid-base64!!!".to_string())
            .id("poison-b64".to_string())
            .finalize();
        // Poison 2: valid base64 but not utf8.
        let bad_utf8 = Attachment::base64(BASE64_URL_SAFE_NO_PAD.encode([0xFF, 0xFE, 0xFD]))
            .id("poison-utf8".to_string())
            .finalize();
        // Poison 3: a plaintext the secure default policy rejects.
        let plaintext = DcMessage::build(
            "evil".to_string(),
            "example/v1".to_string(),
            json!({"x": 1}),
        )
        .from(sender_did.clone())
        .to(recipient_did.clone())
        .finalize();
        let poison_plaintext = Attachment::base64(
            BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_string(&plaintext).unwrap().as_bytes()),
        )
        .id("poison-plaintext".to_string())
        .finalize();
        // Poison 4: unsupported attachment type (json, no base64).
        let unsupported = Attachment::json(json!({"not": "base64"}))
            .id("poison-json".to_string())
            .finalize();

        let delivery = delivery_with(vec![
            good1,
            bad_b64,
            bad_utf8,
            poison_plaintext,
            unsupported,
            good2,
        ]);

        let out = MessagePickup {}
            ._handle_delivery(&atm, &profile, &delivery)
            .await
            .expect("the drain must not error on a poison batch");

        // Only the two valid authcrypt messages surface; every poison is skipped.
        let ids: Vec<&str> = out.iter().map(|(m, _)| m.id.as_str()).collect();
        assert_eq!(
            out.len(),
            2,
            "only the valid messages should surface, got ids: {ids:?}"
        );
        assert!(ids.contains(&"good-1"));
        assert!(ids.contains(&"good-2"));
        // The secure default held: everything surfaced is authenticated authcrypt.
        for (_, meta) in &out {
            assert!(
                meta.authenticated,
                "surfaced pickup messages must be authcrypt-authenticated"
            );
        }
    }

    /// An *entirely* poison batch surfaces nothing and still returns `Ok` — a
    /// fully-hostile delivery cannot take the drain (or the pickup loop) down.
    #[tokio::test]
    async fn all_poison_batch_surfaces_nothing_without_error() {
        let (_recipient_did, recipient_x) = peer_with_x25519();
        let atm = atm_with_secret(recipient_x).await;
        let profile = fake_profile();

        let delivery = delivery_with(vec![
            Attachment::base64("###".to_string())
                .id("p1".to_string())
                .finalize(),
            Attachment::json(json!({"x": 1}))
                .id("p2".to_string())
                .finalize(),
        ]);

        let out = MessagePickup {}
            ._handle_delivery(&atm, &profile, &delivery)
            .await
            .expect("all-poison batch must not error");
        assert!(out.is_empty(), "no poison message should surface");
    }

    /// With a poison channel configured, an undeliverable attachment is
    /// broadcast (id + retained raw payload + reason) *before* it is purged,
    /// while a valid message is delivered normally and never reported.
    #[tokio::test]
    async fn poison_messages_are_reported_on_the_channel() {
        let (sender_did, sender_x) = peer_with_x25519();
        let (recipient_did, recipient_x) = peer_with_x25519();

        // ATM with the secure default policy *and* a poison channel.
        let config = ATMConfig::builder()
            .with_poison_message_channel(16)
            .build()
            .unwrap();
        let tdk = Arc::new(
            TDKSharedState::new(TDKConfig::headless().unwrap())
                .await
                .unwrap(),
        );
        tdk.secrets_resolver().insert(recipient_x.clone()).await;
        let atm = ATM::new(config, tdk).await.unwrap();
        let mut rx = atm.get_poison_channel().expect("poison channel configured");
        let profile = fake_profile();

        // One valid authcrypt (delivered, never reported) + one poison plaintext
        // (the secure default rejects the unauthenticated wrapping).
        let good = Attachment::base64(authcrypt_b64(
            &sender_did,
            &sender_x,
            &recipient_did,
            &recipient_x,
            "m1",
        ))
        .id("good-1".to_string())
        .finalize();
        let plaintext = DcMessage::build(
            "evil".to_string(),
            "example/v1".to_string(),
            json!({"x": 1}),
        )
        .from(sender_did.clone())
        .to(recipient_did.clone())
        .finalize();
        let poison = Attachment::base64(
            BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_string(&plaintext).unwrap().as_bytes()),
        )
        .id("poison-1".to_string())
        .finalize();

        let out = MessagePickup {}
            ._handle_delivery(&atm, &profile, &delivery_with(vec![good, poison]))
            .await
            .expect("drain must not error");

        // The good message is delivered.
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0.id, "good-1");

        // Exactly one poison event — for the plaintext — carrying its id, the
        // retained raw payload, and a reason. The good message is not reported.
        let p = rx
            .try_recv()
            .expect("the poison message should be reported");
        assert_eq!(p.attachment_id.as_deref(), Some("poison-1"));
        assert!(
            !p.raw.is_empty(),
            "the raw payload is retained for quarantine"
        );
        assert!(!p.reason.is_empty(), "a rejection reason is included");
        assert!(
            rx.try_recv().is_err(),
            "only the poison message is reported, not the valid one"
        );
    }

    /// The poison channel is purely opt-in: with none configured the drain still
    /// skips/purges poison without error.
    #[tokio::test]
    async fn poison_channel_is_optional() {
        let (_recipient_did, recipient_x) = peer_with_x25519();
        let atm = atm_with_secret(recipient_x).await; // no poison channel
        assert!(atm.get_poison_channel().is_none());
        let profile = fake_profile();

        let delivery = delivery_with(vec![
            Attachment::base64("###".to_string())
                .id("p1".to_string())
                .finalize(),
        ]);
        let out = MessagePickup {}
            ._handle_delivery(&atm, &profile, &delivery)
            .await
            .expect("drain must not error without a poison channel");
        assert!(out.is_empty());
    }

    /// The TSP-aware frames drain reports poison on the channel too: a poison
    /// attachment is yielded as `(None, id)` for the caller to ack *and*
    /// broadcast on the poison channel, while a valid message is delivered as a
    /// `DidComm` frame and never reported.
    #[cfg(feature = "tsp")]
    #[tokio::test]
    async fn frames_drain_reports_poison_on_the_channel() {
        let (sender_did, sender_x) = peer_with_x25519();
        let (recipient_did, recipient_x) = peer_with_x25519();

        let config = ATMConfig::builder()
            .with_poison_message_channel(16)
            .build()
            .unwrap();
        let tdk = Arc::new(
            TDKSharedState::new(TDKConfig::headless().unwrap())
                .await
                .unwrap(),
        );
        tdk.secrets_resolver().insert(recipient_x.clone()).await;
        let atm = ATM::new(config, tdk).await.unwrap();
        let mut rx = atm.get_poison_channel().expect("poison channel configured");

        let good = Attachment::base64(authcrypt_b64(
            &sender_did,
            &sender_x,
            &recipient_did,
            &recipient_x,
            "m1",
        ))
        .id("good-1".to_string())
        .finalize();
        let plaintext = DcMessage::build(
            "evil".to_string(),
            "example/v1".to_string(),
            json!({"x": 1}),
        )
        .from(sender_did.clone())
        .to(recipient_did.clone())
        .finalize();
        let poison = Attachment::base64(
            BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_string(&plaintext).unwrap().as_bytes()),
        )
        .id("poison-1".to_string())
        .finalize();

        let out = MessagePickup {}
            ._handle_delivery_frames(&atm, &delivery_with(vec![good, poison]))
            .await
            .expect("frames drain must not error");

        // Good delivered as a frame; poison yielded as (None, id) for the caller.
        assert_eq!(out.len(), 2);
        assert!(out.iter().any(|(f, id)| id == "good-1" && f.is_some()));
        assert!(out.iter().any(|(f, id)| id == "poison-1" && f.is_none()));

        // The poison frame is also reported on the channel.
        let p = rx.try_recv().expect("the poison frame should be reported");
        assert_eq!(p.attachment_id.as_deref(), Some("poison-1"));
        assert!(!p.raw.is_empty(), "the raw payload is retained");
        assert!(
            rx.try_recv().is_err(),
            "only the poison frame is reported, not the valid one"
        );
    }
}
