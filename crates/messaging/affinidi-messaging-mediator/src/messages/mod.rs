#[cfg(feature = "didcomm")]
use self::protocols::ping;
#[cfg(feature = "didcomm")]
use crate::common::time::unix_timestamp_secs;
#[cfg(feature = "didcomm")]
use crate::didcomm_compat;
#[cfg(feature = "didcomm")]
use crate::messages::protocols::discover_features;
use crate::{SharedData, common::session::Session};
#[cfg(feature = "didcomm")]
use affinidi_did_common::service::Endpoint;
#[cfg(feature = "didcomm")]
use affinidi_did_resolver_cache_sdk::DIDCacheClient;
#[cfg(feature = "didcomm")]
use affinidi_messaging_didcomm::message::Message;
use affinidi_messaging_mediator_common::errors::MediatorError;
#[cfg(feature = "didcomm")]
use affinidi_messaging_sdk::messages::compat::{PackEncryptedMetadata, UnpackMetadata};
use affinidi_messaging_sdk::messages::{
    known::MessageType as SDKMessageType,
    problem_report::{ProblemReport, ProblemReportScope, ProblemReportSorter},
};
#[cfg(feature = "didcomm")]
use affinidi_secrets_resolver::SecretsResolver;
#[cfg(feature = "didcomm")]
use ahash::AHashSet as HashSet;
use http::StatusCode;
#[cfg(feature = "didcomm")]
use protocols::{
    mediator::{accounts, acls, administration},
    message_pickup, routing,
};
#[cfg(feature = "didcomm")]
use serde_json::Value;

#[cfg(feature = "didcomm")]
pub mod error_response;
pub mod inbound;
#[cfg(feature = "didcomm")]
pub mod protocols;
pub(crate) mod store;

#[cfg(feature = "didcomm")]
struct MessageType(SDKMessageType);

/// Helps with parsing the message type and handling higher level protocols.
/// NOTE:
///   Not all Message Types need to be handled as a protocol.
#[cfg(feature = "didcomm")]
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
            SDKMessageType::MessagePickupStatusResponse => Err(MediatorError::problem(
                66,
                &session.session_id,
                Some(message.id.to_string()),
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "me.not_implemented",
                "Mediator does not process Message Pickup status responses",
                vec![],
                StatusCode::NOT_IMPLEMENTED,
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
            SDKMessageType::AffinidiAuthenticate => Err(MediatorError::problem(
                66,
                &session.session_id,
                Some(message.id.to_string()),
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "me.not_implemented",
                "Authentication must use the /authenticate endpoint, not the message handler",
                vec![],
                StatusCode::BAD_REQUEST,
            )),
            SDKMessageType::AffinidiAuthenticateRefresh => Err(MediatorError::problem(
                66,
                &session.session_id,
                Some(message.id.to_string()),
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "me.not_implemented",
                "Authentication refresh must use the /authenticate/refresh endpoint, not the message handler",
                vec![],
                StatusCode::BAD_REQUEST,
            )),
            SDKMessageType::ForwardRequest => {
                routing::process(message, metadata, state, session).await
            }
            SDKMessageType::ProblemReport => Err(MediatorError::problem(
                66,
                &session.session_id,
                Some(message.id.to_string()),
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "me.not_implemented",
                "Mediator does not process inbound Problem Report messages",
                vec![],
                StatusCode::NOT_IMPLEMENTED,
            )),
            SDKMessageType::DiscoverFeaturesQueries => {
                discover_features::process(message, session, state)
            }
            SDKMessageType::DiscoverFeaturesDisclose => Err(MediatorError::problem(
                88,
                &session.session_id,
                Some(message.id.to_string()),
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "me.not_implemented",
                "Mediator does not process Discover Features disclosure responses",
                vec![],
                StatusCode::NOT_IMPLEMENTED,
            )),
            SDKMessageType::Other(ref type_) => Err(MediatorError::problem_with_log(
                66,
                &session.session_id,
                Some(message.id.to_string()),
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "me.not_implemented",
                "Unsupported message type: {1}",
                vec![type_.to_string()],
                StatusCode::NOT_IMPLEMENTED,
                format!("Unsupported message type: {type_}"),
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
    #[cfg(feature = "didcomm")]
    Message(Box<Message>),
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
#[cfg(feature = "didcomm")]
#[derive(Debug)]
pub struct PackOptions {
    /// Protects against DoS attacks by limiting the number of keys per recipient
    pub to_keys_per_recipient_limit: usize,
    /// If true, then will repack the message for the next recipient if possible
    pub forward: bool,
}

#[cfg(feature = "didcomm")]
impl Default for PackOptions {
    fn default() -> Self {
        PackOptions {
            to_keys_per_recipient_limit: 100,
            forward: true,
        }
    }
}

#[cfg(feature = "didcomm")]
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

#[cfg(feature = "didcomm")]
impl MessageHandler for Message {
    async fn process(
        &self,
        state: &SharedData,
        session: &Session,
        metadata: &UnpackMetadata,
    ) -> Result<ProcessMessageResponse, MediatorError> {
        let msg_type = MessageType(self.typ.as_str().parse::<SDKMessageType>().map_err(|err| {
            MediatorError::MediatorError(
                30,
                session.session_id.to_string(),
                Some(self.id.clone()),
                Box::new(ProblemReport::new(
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "message.type.incorrect".into(),
                    "Unexpected message type: {1}. Reason: {2}".into(),
                    vec![self.typ.to_string(), err.to_string()],
                    None,
                )),
                StatusCode::BAD_REQUEST.as_u16(),
                format!("Unexpected message type: {}. Reason: {}", self.typ, err),
            )
        })?);

        // Check if message expired
        let now = unix_timestamp_secs();
        if let Some(expires) = self.expires_time
            && expires <= now
        {
            return Err(MediatorError::MediatorError(
                31,
                session.session_id.to_string(),
                Some(self.id.clone()),
                Box::new(ProblemReport::new(
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "message.expired".into(),
                    "Message has expired: {1}".into(),
                    vec![expires.to_string()],
                    None,
                )),
                StatusCode::BAD_REQUEST.as_u16(),
                "Message has expired".to_string(),
            ));
        }

        msg_type.process(self, state, session, metadata).await
    }

    async fn pack<S>(
        &self,
        session_id: &str,
        to_did: &str,
        _mediator_did: &str,
        metadata: &UnpackMetadata,
        secrets_resolver: &S,
        did_resolver: &DIDCacheClient,
        _pack_options: &PackOptions,
        forward_locals: &HashSet<String>,
    ) -> Result<(String, PackEncryptedMetadata), MediatorError>
    where
        S: SecretsResolver,
    {
        // Check if this message would route back to the mediator based on potential next hops
        let to_doc = did_resolver.resolve(to_did).await.map_err(|e| {
            MediatorError::MediatorError(
                74,
                session_id.to_string(),
                Some(self.id.clone()),
                Box::new(ProblemReport::new(
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "did.resolve".into(),
                    "DID ({1}) couldn't be resolved: {2}".into(),
                    vec![to_did.to_string(), e.to_string()],
                    None,
                )),
                StatusCode::BAD_REQUEST.as_u16(),
                format!("DID ({to_did}) couldn't be resolved: {e}"),
            )
        })?;

        fn check_loopback(endpoint: &Value, forward_locals: &HashSet<String>) -> bool {
            let uri = if let Some(uri) = endpoint.get("uri") {
                if let Some(uri) = uri.as_str() {
                    uri
                } else {
                    return false;
                }
            } else {
                return false;
            };
            forward_locals.contains(uri)
        }

        let _forward_loopback = to_doc.doc.service.iter().any(|service| {
            if let Endpoint::Map(endpoints) = &service.service_endpoint {
                if endpoints.is_array() {
                    endpoints
                        .as_array()
                        .map(|arr| {
                            arr.iter()
                                .any(|endpoint| check_loopback(endpoint, forward_locals))
                        })
                        .unwrap_or(false)
                } else {
                    check_loopback(endpoints, forward_locals)
                }
            } else {
                false
            }
        });

        if metadata.encrypted {
            // Respond with an encrypted message
            let a = match didcomm_compat::pack_encrypted(
                self,
                to_did,
                self.from.as_deref(),
                did_resolver,
                secrets_resolver,
            )
            .await
            {
                Ok(msg) => msg,
                Err(e) => {
                    return Err(MediatorError::MediatorError(
                        47,
                        session_id.to_string(),
                        Some(self.id.clone()),
                        Box::new(ProblemReport::new(
                            ProblemReportSorter::Error,
                            ProblemReportScope::Protocol,
                            "message.pack".into(),
                            "Couldn't pack DIDComm message: {1}".into(),
                            vec![e.to_string()],
                            None,
                        )),
                        StatusCode::BAD_REQUEST.as_u16(),
                        format!("Couldn't pack DIDComm message: {e}"),
                    ));
                }
            };

            Ok(a)
        } else {
            Err(MediatorError::problem(
                66,
                session_id,
                Some(self.id.to_string()),
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "me.not_implemented",
                "Mediator only supports encrypted message packing",
                vec![],
                StatusCode::NOT_IMPLEMENTED,
            ))
        }
    }
}
