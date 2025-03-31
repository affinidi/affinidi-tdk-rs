use self::protocols::ping;
use crate::{SharedData, database::session::Session};
use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_messaging_didcomm::{
    Message, PackEncryptedMetadata, PackEncryptedOptions, UnpackMetadata,
};
use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_messaging_sdk::messages::known::MessageType as SDKMessageType;
use affinidi_secrets_resolver::SecretsResolver;
use ahash::AHashSet as HashSet;
use protocols::{
    mediator::{accounts, acls, administration},
    message_pickup, routing,
};
use ssi::dids::document::service::Endpoint;
use std::time::SystemTime;

pub mod error_response;
pub mod inbound;
pub mod protocols;
pub(crate) mod store;

struct MessageType(SDKMessageType);

/// Helps with parsing the message type and handling higher level protocols.
/// NOTE:
///   Not all Message Types need to be handled as a protocol.
impl MessageType {
    pub(crate) async fn process(
        &self,
        message: &Message,
        state: &SharedData,
        session: &Session,
        metadata: &UnpackMetadata,
    ) -> Result<ProcessMessageResponse, MediatorError> {
        match self.0 {
            SDKMessageType::MediatorAdministration => {
                administration::process(message, state, session, metadata).await
            }
            SDKMessageType::MediatorAccountManagement => {
                accounts::process(message, state, session, metadata).await
            }
            SDKMessageType::MediatorACLManagement => {
                acls::process(message, state, session, metadata).await
            }
            SDKMessageType::TrustPing => ping::process(message, session),
            SDKMessageType::MessagePickupStatusRequest => {
                message_pickup::status_request(message, state, session).await
            }
            SDKMessageType::MessagePickupStatusResponse => Err(MediatorError::NotImplemented(
                session.session_id.clone(),
                "Mediator does not handle Message Pickup Status responses".into(),
            )),
            SDKMessageType::MessagePickupDeliveryRequest => {
                message_pickup::delivery_request(message, state, session).await
            }
            SDKMessageType::MessagePickupMessagesReceived => {
                message_pickup::messages_received(message, state, session).await
            }
            SDKMessageType::MessagePickupLiveDeliveryChange => {
                message_pickup::toggle_live_delivery(message, state, session).await
            }
            SDKMessageType::AffinidiAuthenticate => Err(MediatorError::NotImplemented(
                session.session_id.clone(),
                "Affinidi Authentication is only handled by the Authorization handler".into(),
            )),
            SDKMessageType::AffinidiAuthenticateRefresh => Err(MediatorError::NotImplemented(
                session.session_id.clone(),
                "Affinidi Authentication is only handled by the Authorization handler".into(),
            )),
            SDKMessageType::ForwardRequest => routing::process(message, state, session).await,
            SDKMessageType::ProblemReport => Err(MediatorError::NotImplemented(
                session.session_id.clone(),
                "Problem Report is only handled by the Error handler".into(),
            )),
            SDKMessageType::Other(_) => Err(MediatorError::NotImplemented(
                session.session_id.clone(),
                "Unknown message type".into(),
            )),
        }
    }
}

/// Type of message wrapper we are dealing with
/// used when storing messages in the database
#[derive(Debug, Default)]
pub enum WrapperType {
    /// to_did, message, expires_at
    Envelope(String, String, u64),
    Message(Message),
    #[default]
    None,
}
#[derive(Debug, Default)]
pub(crate) struct ProcessMessageResponse {
    pub store_message: bool,
    pub force_live_delivery: bool, // Will force a live delivery attempt.
    pub forward_message: bool, // Set to true if the message was forwarded. Means we don't need to store it.
    pub data: WrapperType,
}

/// Options for packing a message
#[derive(Debug)]
pub struct PackOptions {
    /// Protects against DoS attacks by limiting the number of keys per recipient
    pub to_keys_per_recipient_limit: usize,
    /// If true, then will repack the message for the next recipient if possible
    pub forward: bool,
}

impl Default for PackOptions {
    fn default() -> Self {
        PackOptions {
            to_keys_per_recipient_limit: 100,
            forward: true,
        }
    }
}

pub(crate) trait MessageHandler {
    /// Processes an incoming message, determines any additional actions to take
    /// Returns a message to store and deliver if necessary
    async fn process(
        &self,
        state: &SharedData,
        session: &Session,
        metadata: &UnpackMetadata,
    ) -> Result<ProcessMessageResponse, MediatorError>;

    /// Uses the incoming unpack metadata to determine best way to pack the message
    #[allow(clippy::too_many_arguments)]
    async fn pack<S>(
        &self,
        session_id: &str,
        to_did: &str,
        mediator_did: &str,
        metadata: &UnpackMetadata,
        secrets_resolver: &S,
        did_resolver: &DIDCacheClient,
        pack_options: &PackOptions,
        forward_locals: &HashSet<String>,
    ) -> Result<(String, PackEncryptedMetadata), MediatorError>
    where
        S: SecretsResolver;
}

impl MessageHandler for Message {
    async fn process(
        &self,
        state: &SharedData,
        session: &Session,
        metadata: &UnpackMetadata,
    ) -> Result<ProcessMessageResponse, MediatorError> {
        let msg_type = MessageType(self.type_.as_str().parse::<SDKMessageType>().map_err(
            |err| {
                MediatorError::ParseError(
                    session.session_id.clone(),
                    "msg.type".into(),
                    err.to_string(),
                )
            },
        )?);

        // Check if message expired
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if let Some(expires) = self.expires_time {
            if expires <= now {
                return Err(MediatorError::MessageExpired(
                    "-1".into(),
                    expires.to_string(),
                    now.to_string(),
                ));
            }
        }

        msg_type.process(self, state, session, metadata).await
    }

    async fn pack<S>(
        &self,
        session_id: &str,
        to_did: &str,
        mediator_did: &str,
        metadata: &UnpackMetadata,
        secrets_resolver: &S,
        did_resolver: &DIDCacheClient,
        pack_options: &PackOptions,
        forward_locals: &HashSet<String>,
    ) -> Result<(String, PackEncryptedMetadata), MediatorError>
    where
        S: SecretsResolver,
    {
        // Check if this message would route back to the mediator based on potential next hops
        let to_doc = did_resolver.resolve(to_did).await.map_err(|e| {
            MediatorError::DIDError(session_id.into(), to_did.into(), e.to_string())
        })?;
        let mut forward_loopback = to_doc.doc.service.iter().any(|service| {
            if let Some(endpoints) = &service.service_endpoint {
                endpoints.into_iter().any(|endpoint| {
                    let uri = match endpoint {
                        Endpoint::Uri(uri) => uri.to_string(),
                        Endpoint::Map(map) => {
                            if let Some(uri) = map.get("uri") {
                                uri.as_str().unwrap_or_default().to_string()
                            } else {
                                "".to_string()
                            }
                        }
                    };
                    forward_locals.contains(&uri)
                })
            } else {
                false
            }
        });

        // Flip the forward loopback flag if the message is not meant to be forwarded
        forward_loopback = !forward_loopback;

        // If the pack option was not to forward, then force forward loopback to false
        if !pack_options.forward {
            forward_loopback = false;
        }

        if metadata.encrypted {
            // Respond with an encrypted message
            let a = match self
                .pack_encrypted(
                    to_did,
                    self.from.as_deref(),
                    Some(mediator_did),
                    did_resolver,
                    secrets_resolver,
                    &PackEncryptedOptions {
                        to_kids_limit: pack_options.to_keys_per_recipient_limit,
                        forward: forward_loopback,
                        ..PackEncryptedOptions::default()
                    },
                )
                .await
            {
                Ok(msg) => msg,
                Err(e) => {
                    return Err(MediatorError::MessagePackError("-1".into(), e.to_string()));
                }
            };

            Ok(a)
        } else {
            Err(MediatorError::MessagePackError(
                "-1".into(),
                "PACK METHOD NOT IMPLEMENTED".into(),
            ))
        }
    }
}
