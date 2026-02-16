use std::{sync::Arc, time::SystemTime};

use affinidi_messaging_didcomm::{Message, PackEncryptedOptions};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha256::digest;
use tracing::{Instrument, Level, debug, span};
use uuid::Uuid;

use crate::{ATM, errors::ATMError, profiles::ATMProfile, transports::SendMessageResponse};

#[derive(Default)]
pub struct TrustPing {}

/// Used to construct the response for a TrustPing message
/// - `message_id` - The ID of the message sent
/// - `message_hash` - The sha256 hash of the message sent
/// - `bytes` - The number of bytes sent
/// - `response` - The response from the endpoint
pub struct TrustPingSent {
    pub message_id: String,
    pub message_hash: String,
    pub bytes: u32,
    pub response: SendMessageResponse,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
struct TrustPingBody {
    response_requested: bool,
}

impl TrustPing {
    /// Sends a DIDComm Trust-Ping message
    /// - `to_did` - The DID to send the ping to
    /// - `signed` - Whether the ping should signed or anonymous?
    /// - `expect_pong` - whether a ping response from endpoint is expected[^note]
    /// - `wait_response` - whether to wait for a response from the endpoint
    ///
    /// Returns: The message ID and sha256 hash of the ping message
    /// [^note]: Anonymous pings cannot expect a response, the SDK will automatically set this to false if anonymous is true
    pub async fn send_ping(
        &self,
        atm: &ATM,
        profile: &Arc<ATMProfile>,
        to_did: &str,
        signed: bool,
        expect_pong: bool,
        wait_response: bool,
    ) -> Result<TrustPingSent, ATMError> {
        let _span = span!(Level::DEBUG, "send_ping",);
        async move {
            debug!(
                "Pinging {}, signed?({}) pong_response_expected?({}) wait_response({})",
                to_did, signed, expect_pong, wait_response
            );

            let (profile_did, _) = profile.dids()?;

            let from_did = if signed { Some(profile_did) } else { None };

            let msg = self.generate_ping_message(from_did, to_did, expect_pong)?;
            let mut msg_info = TrustPingSent {
                message_id: msg.id.clone(),
                message_hash: "".to_string(),
                bytes: 0,
                response: SendMessageResponse::EmptyResponse,
            };

            debug!("Ping message: {:#?}", msg);

            // Pack the message
            let (msg, _) = msg
                .pack_encrypted(
                    to_did,
                    from_did,
                    from_did,
                    &atm.inner.tdk_common.did_resolver,
                    &atm.inner.tdk_common.secrets_resolver,
                    &PackEncryptedOptions::default(),
                )
                .await
                .map_err(|e| ATMError::MsgSendError(format!("Error packing message: {e}")))?;

            debug!("Packed message: {:#?}", msg);

            msg_info.message_hash = digest(&msg).to_string();
            msg_info.bytes = msg.len() as u32;

            msg_info.response = atm
                .send_message(profile, &msg, &msg_info.message_id, wait_response, true)
                .await?;

            Ok(msg_info)
        }
        .instrument(_span)
        .await
    }

    /// Generate a DIDComm PlainText Trust-Ping message
    /// - `from_did` - The DID to send the ping from (anonymous if set to None)
    /// - `to_did` - The DID to send the ping to
    /// - `expect_pong` - whether a ping response from endpoint is expected
    ///
    /// Returns: Plaintext DIDComm Message
    pub fn generate_ping_message(
        &self,
        from_did: Option<&str>,
        to_did: &str,
        expect_pong: bool,
    ) -> Result<Message, ATMError> {
        let _span = span!(Level::DEBUG, "generate_ping_message",).entered();
        debug!(
            "Pinging ({}) from ({:?}) pong_response_expected?({})",
            to_did, from_did, expect_pong
        );

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let expect_pong = if from_did.is_none() && expect_pong {
            debug!("Anonymous pings cannot expect a response, changing to false...");
            false
        } else {
            true
        };

        let mut msg = Message::build(
            Uuid::new_v4().into(),
            "https://didcomm.org/trust-ping/2.0/ping".to_owned(),
            json!(TrustPingBody {
                response_requested: expect_pong
            }),
        )
        .to(to_did.to_owned());

        if let Some(from) = from_did {
            msg = msg.from(from.to_string());
        };
        Ok(msg.created_time(now).expires_time(now + 300).finalize())
    }

    /// Generate a Trust-Ping Pong Response DIDComm PlainText message
    /// - `ping` - The DIDComm Ping Message
    /// - `from_did` - The DID to send the pong from (if None then will be anonymous)
    ///
    /// Returns: Plaintext DIDComm Message
    pub fn generate_pong_message(
        &self,
        ping: &Message,
        from_did: Option<&str>,
    ) -> Result<Message, ATMError> {
        let _span = span!(Level::DEBUG, "generate_pong_message",).entered();
        debug!("Pong response to ({:?}) from ({:?})", ping.to, ping.from);

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let to_did = if let Some(from) = &ping.from {
            from.to_string()
        } else {
            return Err(ATMError::MsgSendError(
                "Anonymous Ping received, can't send a Pong response".to_string(),
            ));
        };

        let mut msg = Message::build(
            Uuid::new_v4().into(),
            "https://didcomm.org/trust-ping/2.0/ping-response".to_owned(),
            serde_json::Value::Null,
        )
        .thid(ping.id.clone())
        .to(to_did);

        if let Some(from_did) = from_did {
            msg = msg.from(from_did.to_string());
        }

        Ok(msg.created_time(now).expires_time(now + 300).finalize())
    }
}

/// Wrapper struct that holds a reference to ATM, enabling the `atm.trust_ping().method()` pattern
pub struct TrustPingOps<'a> {
    pub(crate) atm: &'a ATM,
}

impl<'a> TrustPingOps<'a> {
    /// Sends a DIDComm Trust-Ping message
    /// See [`TrustPing::send_ping`] for full documentation
    pub async fn send_ping(
        &self,
        profile: &Arc<ATMProfile>,
        to_did: &str,
        signed: bool,
        expect_pong: bool,
        wait_response: bool,
    ) -> Result<TrustPingSent, ATMError> {
        TrustPing::default()
            .send_ping(self.atm, profile, to_did, signed, expect_pong, wait_response)
            .await
    }

    /// Generate a DIDComm PlainText Trust-Ping message
    /// See [`TrustPing::generate_ping_message`] for full documentation
    pub fn generate_ping_message(
        &self,
        from_did: Option<&str>,
        to_did: &str,
        expect_pong: bool,
    ) -> Result<Message, ATMError> {
        TrustPing::default().generate_ping_message(from_did, to_did, expect_pong)
    }

    /// Generate a Trust-Ping Pong Response DIDComm PlainText message
    /// See [`TrustPing::generate_pong_message`] for full documentation
    pub fn generate_pong_message(
        &self,
        ping: &Message,
        from_did: Option<&str>,
    ) -> Result<Message, ATMError> {
        TrustPing::default().generate_pong_message(ping, from_did)
    }
}
