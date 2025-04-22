/*!
 * Message Pickup Protocol 3.0
 *
 * NOTE: All Message ID's are SHA256 hashes of the message
 *
 * Do not pass message ID's to the mediator, it cannot see inside messages that it is handling.
 *
 */
use affinidi_messaging_didcomm::{AttachmentData, Message, PackEncryptedOptions, UnpackMetadata};
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
    errors::ATMError, messages::GenericDataStruct, profiles::ATMProfile, transports::{websockets::{websocket::WebSocketCommands, WebSocketResponses}, SendMessageResponse}, ATM
};

#[derive(Default)]
pub struct MessagePickup {}

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
/// Handles the return from a message delivery request
/// returns
/// - StatusReply : No messages available
/// - MessageDelivery : A DIDComm message containing messages
#[derive(Serialize, Deserialize)]
enum DeliveryRequestResponse {
    StatusReply(MessagePickupStatusReply),
    MessageDelivery(String),
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

            let msg = Message::build(
                Uuid::new_v4().into(),
                "https://didcomm.org/messagepickup/3.0/status-request".to_owned(),
                json!({"recipient_did": profile_did}),
            )
            .to(mediator_did.to_string())
            .from(profile_did.to_string())
            .header("return_route".into(), Value::String("all".into()))
            .created_time(now)
            .expires_time(now + 300)
            .finalize();

            let msg_id = msg.id.clone();

            debug!("Status-Request message: {:?}", msg);

            // Pack the message
            let (msg, _) = msg
                .pack_encrypted(
                    mediator_did,
                    Some(profile_did),
                    Some(profile_did),
                    &atm.inner.tdk_common.did_resolver,
                    &atm.inner.tdk_common.secrets_resolver,
                    &PackEncryptedOptions::default(),
                )
                .await
                .map_err(|e| ATMError::MsgSendError(format!("Error packing message: {}", e)))?;

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
                ATMError::MsgReceiveError(format!("Error reading status response: {}", err))
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
            let (profile_did, mediator_did) = profile.dids()?;

            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let msg = Message::build(
                Uuid::new_v4().into(),
                "https://didcomm.org/messagepickup/3.0/live-delivery-change".to_owned(),
                json!({"live_delivery": live_delivery}),
            )
            .header("return_route".into(), Value::String("all".into()))
            .created_time(now)
            .expires_time(now + 300)
            .from(profile_did.into())
            .to(mediator_did.into())
            .finalize();
            let msg_id = msg.id.clone();

            // Pack the message
            let (msg, _) = msg
                .pack_encrypted(
                    mediator_did,
                    Some(profile_did),
                    Some(profile_did),
                    &atm.inner.tdk_common.did_resolver,
                    &atm.inner.tdk_common.secrets_resolver,
                    &PackEncryptedOptions::default(),
                )
                .await
                .map_err(|e| ATMError::MsgSendError(format!("Error packing message: {}", e)))?;

            atm.send_message(profile, &msg, &msg_id, false, false)
                .await?;
            Ok(msg_id)
        }
        .instrument(_span)
        .await
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
                        "Could not send Next command to websocket: {:?}",
                        err
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
                            "Could not send CancelNext command to websocket: {:?}",
                            err
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
                            Ok(Some((msg, meta)))
                        }
                        Err(e) => {
                            warn!("Error receiving message: {:?}", e);
                            Err(ATMError::MsgReceiveError(format!(
                                "Error receiving message: {:?}",
                                e
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
                    "Could not send GetMessage({}) Command to websocket: {:?}", msg_id,
                    err
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
                            "Could not send CancelGetMessage command to websocket: {:?}",
                            err
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
                            Ok(Some((msg, meta)))
                        }
                        Err(e) => {
                            warn!("Error receiving message: {:?}", e);
                            Err(ATMError::MsgReceiveError(format!(
                                "Error receiving message: {:?}",
                                e
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

            let msg = Message::build(
                Uuid::new_v4().into(),
                "https://didcomm.org/messagepickup/3.0/delivery-request".to_owned(),
                serde_json::to_value(body).unwrap(),
            )
            .header("return_route".into(), Value::String("all".into()))
            .to(mediator_did.into())
            .from(profile_did.into())
            .created_time(now)
            .expires_time(now + 300)
            .finalize();

            let msg_id = msg.id.clone();

            debug!("Delivery-Request message: {:?}", msg);

            // Pack the message
            let msg = {
                let (msg, _) = msg
                    .pack_encrypted(
                        mediator_did,
                        Some(profile_did),
                        Some(profile_did),
                        &atm.inner.tdk_common.did_resolver,
                        &atm.inner.tdk_common.secrets_resolver,
                        &PackEncryptedOptions::default(),
                    )
                    .await
                    .map_err(|e| ATMError::MsgSendError(format!("Error packing message: {}", e)))?;

                msg
            };

            match atm
                .send_message(profile, &msg, &msg_id, wait_for_response, false)
                .await?
            {
                SendMessageResponse::Message(message) => self._handle_delivery(atm, &message).await,
                _ => Err(ATMError::MsgReceiveError("No Messages from API".into())),
            }
        }
        .instrument(_span)
        .await
    }

    /// Iterates through each attachment and unpacks each message into an array to return
    pub(crate) async fn _handle_delivery(
        &self,
        atm: &ATM,
        message: &Message,
    ) -> Result<Vec<(Message, UnpackMetadata)>, ATMError> {
        let mut response: Vec<(Message, UnpackMetadata)> = Vec::new();

        if let Some(attachments) = &message.attachments {
            for attachment in attachments {
                match &attachment.data {
                    AttachmentData::Base64 { value } => {
                        let decoded = match BASE64_URL_SAFE_NO_PAD.decode(value.base64.clone()) {
                            Ok(decoded) => match String::from_utf8(decoded) {
                                Ok(decoded) => decoded,
                                Err(e) => {
                                    warn!(
                                        "Error encoding vec[u8] to string: ({:?}). Attachment ID ({:?})",
                                        e, attachment.id
                                    );
                                    continue;
                                }
                            },
                            Err(e) => {
                                warn!(
                                    "Error decoding base64: ({:?}). Attachment ID ({:?})",
                                    e, attachment.id
                                );
                                continue;
                            }
                        };

                        match atm.unpack(&decoded).await {
                            Ok((mut m, u)) => {
                                if let Some(attachment_id) = &attachment.id {
                                    m.id = attachment_id.to_string();
                                }
                                response.push((m, u))
                            }
                            Err(e) => {
                                warn!("Error unpacking message: ({:?})", e);
                                continue;
                            }
                        };
                    }
                    _ => {
                        warn!("Attachment type not supported: {:?}", attachment.data);
                        continue;
                    }
                };
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

            let msg = Message::build(
                Uuid::new_v4().into(),
                "https://didcomm.org/messagepickup/3.0/messages-received".to_owned(),
                json!({"message_id_list": list}),
            )
            .header("return_route".into(), Value::String("all".into()))
            .to(mediator_did.into())
            .from(profile_did.into())
            .created_time(now)
            .expires_time(now + 300)
            .finalize();

            let msg_id = msg.id.clone();

            debug!("messages-received message: {:?}", msg);

            // Pack the message
            let (msg, _) = msg
                .pack_encrypted(
                    mediator_did,
                    Some(profile_did),
                    Some(profile_did),
                    &atm.inner.tdk_common.did_resolver,
                    &atm.inner.tdk_common.secrets_resolver,
                    &PackEncryptedOptions::default(),
                )
                .await
                .map_err(|e| ATMError::MsgSendError(format!("Error packing message: {}", e)))?;

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
                    "Invalid response from API: {}",
                    err
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
}
