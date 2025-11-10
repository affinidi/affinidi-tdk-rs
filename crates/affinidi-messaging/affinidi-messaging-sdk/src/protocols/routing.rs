//! DIDComm Routing Protocol
//! https://identity.foundation/didcomm-messaging/spec/#routing-protocol-20
//!
//! The DIDComm Routing Protocol is used to route messages between agents. It is used to ensure that messages are delivered to the correct agent.
//!

use std::sync::Arc;

use crate::{ATM, errors::ATMError, profiles::ATMProfile};
use affinidi_messaging_didcomm::{Attachment, Message, PackEncryptedOptions};
use base64::prelude::*;
use serde_json::{Number, Value, json};
use tracing::{Instrument, Level, span};
use uuid::Uuid;
#[derive(Default)]
pub struct Routing {}

impl Routing {
    /// Takes a DIDComm message and constructs a new message that can be forwarded to the target DID.
    /// NOTE: You still need to send the actual message
    ///
    /// - atm: The Affinidi Messaging instance
    /// - profile: The profile of the agent forwarding the message
    /// - anonymous: Will not sign or add from fields if true
    /// - message: The message to be forwarded
    /// - target_did: The DID of the target agent (typically a mediator)
    /// - next_did: The DID of the next agent to forward the message to
    /// - expires_time: The time at which the message expires if not delivered
    /// - delay_milli: The time to wait before delivering the message
    ///   NOTE: If negative, picks a random delay between 0 and the absolute value
    ///
    /// Returns:
    ///     (message_id, message)
    #[allow(clippy::too_many_arguments)]
    pub async fn forward_message(
        &self,
        atm: &ATM,
        profile: &Arc<ATMProfile>,
        anonymous: bool,
        message: &str,
        target_did: &str,
        next_did: &str,
        expires_time: Option<u64>,
        delay_milli: Option<i64>,
    ) -> Result<(String, String), ATMError> {
        let _span = span!(Level::DEBUG, "forward_message");

        async move {
            let id = Uuid::new_v4().to_string();

            let attachment = Attachment::base64(BASE64_URL_SAFE_NO_PAD.encode(message)).finalize();

            let mut forwarded = Message::build(
                id.clone(),
                "https://didcomm.org/routing/2.0/forward".to_owned(),
                json!({"next": next_did}),
            )
            .to(target_did.to_owned())
            .attachment(attachment);

            let from_did = if !anonymous {
                forwarded = forwarded.from(profile.inner.did.clone());
                Some(profile.inner.did.as_str())
            } else {
                None
            };

            if let Some(expires_time) = expires_time {
                forwarded = forwarded.expires_time(expires_time);
            }
            if let Some(delay_milli) = delay_milli {
                forwarded = forwarded.header(
                    "delay_milli".to_string(),
                    Value::Number(Number::from(delay_milli)),
                );
            }
            let forwarded = forwarded.finalize();

            // Pack the message
            let (msg, _) = forwarded
                .pack_encrypted(
                    target_did,
                    from_did,
                    from_did,
                    &atm.inner.tdk_common.did_resolver,
                    &atm.inner.tdk_common.secrets_resolver,
                    &PackEncryptedOptions::default(),
                )
                .await
                .map_err(|e| ATMError::MsgSendError(format!("Error packing message: {e}")))?;

            Ok((id, msg))
        }
        .instrument(_span)
        .await
    }
}
