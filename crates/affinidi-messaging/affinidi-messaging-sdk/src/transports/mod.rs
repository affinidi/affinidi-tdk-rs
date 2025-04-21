use crate::{
    ATM,
    errors::ATMError,
    messages::{GenericDataStruct, GetMessagesRequest, known::MessageType},
    profiles::ATMProfile,
    protocols::{message_pickup::MessagePickup, routing::Routing},
};
use affinidi_messaging_didcomm::Message;
use serde_json::Value;
use sha256::digest;
use std::{sync::Arc, time::Duration};
use tracing::debug;
use websockets::websocket::WebSocketCommands;

pub mod websockets;

/// WebSocketSendResponse is the response from sending a message over a WebSocket connection
/// message_digest is sha256 digest of the message sent
/// bytes_sent is the number of bytes sent
/// message_id is the id of the message sent
#[derive(Debug)]
pub struct WebSocketSendResponse {
    pub message_digest: String,
    pub bytes_sent: u32,
    pub message_id: String,
}

/// SendMessageResponse is the response from sending a message
/// Allows for returning the response from the API or the WebSocket
/// - RestAPI: The response from the API (JSON Value response)
/// - Message: The response from the WebSocket (DIDComm Message)
/// - EmptyResponse: No response was received or expected
#[derive(Debug)]
pub enum SendMessageResponse {
    RestAPI(Value),
    Message(Message),
    EmptyResponse,
}

impl SendMessageResponse {
    pub fn get_http_response<T>(&self) -> Option<T>
    where
        T: GenericDataStruct,
    {
        match self {
            SendMessageResponse::RestAPI(value) => serde_json::from_value(value.to_owned()).ok(),
            SendMessageResponse::Message(_) => None,
            SendMessageResponse::EmptyResponse => None,
        }
    }
}

impl ATM {
    /// Send a message to a mediator based on a given profile
    /// - profile: The profile to connect to the mediator with
    /// - message: The message to send (already packed as a DIDComm message)
    /// - msg_id: The ID of the message (used for message response pickup)
    /// - wait_for_response: Whether to wait for a message response from the mediator
    /// - auto_delete: Whether to delete the message response after receiving it
    ///   NOTE: If set to false, then you must delete the message elsewhere
    ///
    /// Returns: If wait_for_response is true, the response message from the mediator
    ///          Else Ok(None) - Message sent Successfully
    ///          Else Err - Error sending message    
    ///
    pub async fn send_message(
        &self,
        profile: &Arc<ATMProfile>,
        message: &str,
        msg_id: &str,
        wait_for_response: bool,
        auto_delete: bool,
    ) -> Result<SendMessageResponse, ATMError> {
        let Some(mediator) = &*profile.inner.mediator else {
            return Err(ATMError::ConfigError(
                "No Mediator is configured for this Profile".to_string(),
            ));
        };

        if let Some(channel) = &*mediator.ws_channel_tx.read().await {
            // Send to the WS_Connection task for this profile
            debug!(
                "Profile ({}): Sending message to WebSocket Connection Handler",
                profile.inner.alias
            );

            channel
                .send(WebSocketCommands::SendMessage(message.to_owned()))
                .await
                .map_err(|err| {
                    ATMError::TransportError(format!("Could not send websocket message: {:?}", err))
                })?;

            debug!(
                "Profile ({}): WebSocket Channel notified",
                profile.inner.alias
            );

            if wait_for_response {
                let response = MessagePickup::default()
                    .live_stream_get(self, profile, msg_id, Duration::from_secs(10), true)
                    .await?;

                if let Some((message, _)) = response {
                    let type_ = message.type_.parse::<MessageType>()?;
                    if let MessageType::ProblemReport = type_ {
                        Err(ATMError::from_problem_report(&message))
                    } else {
                        Ok(SendMessageResponse::Message(message))
                    }
                } else {
                    Err(ATMError::MsgSendError("No response from API".into()))
                }
            } else {
                Ok(SendMessageResponse::EmptyResponse)
            }
        } else {
            debug!("Profile ({}): Sending message to API", profile.inner.alias);
            // Send HTTP message
            let a = self.send_didcomm_message(profile, message, true).await?;

            debug!("Response: {:#?}", a);

            if wait_for_response {
                let response = self
                    .get_messages(
                        profile,
                        &GetMessagesRequest {
                            message_ids: vec![digest(message)],
                            delete: auto_delete,
                        },
                    )
                    .await?;

                if let Some(first) = response.success.first() {
                    if let Some(msg) = &first.msg {
                        let unpack = self.unpack(msg).await?;

                        Ok(SendMessageResponse::Message(unpack.0))
                    } else {
                        Err(ATMError::MsgReceiveError(
                            "Received message response, but no actual message".into(),
                        ))
                    }
                } else {
                    Err(ATMError::MsgReceiveError(
                        "No Message retrieved from Mediator".into(),
                    ))
                }
            } else {
                Ok(a)
            }
        }
    }

    /// Takes a packed message, wraps it in a forward envelope and sends it to the target DID
    /// - profile: The profile to send the message from
    /// - anonymous: Whether to send the message anonymously
    /// - message: The packed message to send
    /// - msg_id: The ID of the message (used for message response pickup), if None, then the forwarded message ID is used
    /// - target_did: The DID of the target agent (this is where the message will be sent - typically a mediator)
    /// - next_did: The DID of the next agent to forward the message to
    /// - expires_time: The time at which the message expires if not delivered
    /// - delay_milli: The time to wait before delivering the message
    ///   NOTE: If negative, picks a random delay between 0 and the absolute value
    /// - wait_for_response: Whether to wait for a message response from the mediator
    #[allow(clippy::too_many_arguments)]
    pub async fn forward_and_send_message(
        &self,
        profile: &Arc<ATMProfile>,
        anonymous: bool,
        message: &str,
        msg_id: Option<&str>,
        target_did: &str,
        next_did: &str,
        expires_time: Option<u64>,
        delay_milli: Option<i64>,
        wait_for_response: bool,
    ) -> Result<SendMessageResponse, ATMError> {
        let routing = Routing::default();

        // Wrap the message in a forward message
        let forwarded_message = routing
            .forward_message(
                self,
                profile,
                anonymous,
                message,
                target_did,
                next_did,
                expires_time,
                delay_milli,
            )
            .await?;

        let msg_id = if let Some(msg_id) = msg_id {
            msg_id
        } else {
            forwarded_message.0.as_str()
        };

        self.send_message(
            profile,
            &forwarded_message.1,
            msg_id,
            wait_for_response,
            true,
        )
        .await
    }

    /// send_didcomm_message
    /// - msg: Packed DIDComm message that we want to send
    /// - return_response: Whether to return the response from the API
    pub(crate) async fn send_didcomm_message(
        &self,
        profile: &Arc<ATMProfile>,
        message: &str,
        return_response: bool,
    ) -> Result<SendMessageResponse, ATMError> {
        let mediator_url = {
            let url = profile.get_mediator_rest_endpoint();
            if let Some(url) = url {
                url
            } else {
                return Err(ATMError::MsgSendError(
                    "Profile is missing a valid mediator URL".into(),
                ));
            }
        };

        let (profile_did, mediator_did) = profile.dids()?;
        // Check if authenticated
        let tokens = self
            .get_tdk()
            .authentication
            .authenticate(profile_did.to_string(), mediator_did.to_string(), 3, None)
            .await?;

        let msg = message.to_owned();

        let res = self
            .inner
            .tdk_common
            .client
            .post([&mediator_url, "/inbound"].concat())
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {}", tokens.access_token))
            .body(msg)
            .send()
            .await
            .map_err(|e| ATMError::TransportError(format!("Could not send message: {:?}", e)))?;

        let status = res.status();
        debug!("API response: status({})", status);

        let body = res
            .text()
            .await
            .map_err(|e| ATMError::TransportError(format!("Couldn't get body: {:?}", e)))?;

        if !status.is_success() {
            return Err(ATMError::TransportError(format!(
                "API returned an error: status({}), body({})",
                status, body
            )));
        }
        debug!("body =\n{}", body);
        let http_response: Value = if return_response {
            serde_json::from_str(&body).map_err(|e| {
                ATMError::TransportError(format!("Couldn't parse response: {:?}", e))
            })?
        } else {
            Value::Null
        };

        Ok(SendMessageResponse::RestAPI(http_response))
    }
}
