/// Refuse delivery without saying why.
///
/// The reasons a message is not delivered to a local recipient — no such
/// account here, the recipient may not receive, its access list blocked this
/// sender, it does not accept anonymous or forwarded messages — are each a fact
/// about *another* DID. Answering them apart lets a sender enumerate which DIDs
/// this mediator serves and probe their access lists, one refusal at a time.
///
/// So every one of them returns this. The specific reason is logged against the
/// session, so an operator keeps full diagnostics and only the sender is told
/// nothing.
///
/// The same reasoning the challenge path already applies, where an unknown DID
/// is refused identically to a blocked one, and the same answer the TSP
/// delivery path gives. Spec Rev 3 §3.7 requires it of TSP; nothing requires it
/// of DIDComm, but the leak is identical and so is the fix, and a mediator that
/// closed it on one protocol and left it open on the other would simply be
/// probed over the other.
///
/// This refuses rather than acknowledging. A uniform *success* would conceal
/// the reason equally well and is the stricter reading of §3.7, but it would
/// tell a sender its message was accepted when it was dropped — the failure
/// R1.1 exists to prevent, and the one this repository treats as the most
/// consequential lie a transport can tell.
///
/// Gated on `didcomm` rather than on both protocols because every supported
/// build has it: `default` includes `didcomm`, and `tsp` is additive on top.
/// A `tsp`-without-`didcomm` build does not compile for unrelated reasons
/// already, so widening this would buy nothing.
#[cfg(feature = "didcomm")]
pub(crate) fn delivery_refused(
    session: &Session,
    message_id: Option<String>,
    reason: &str,
) -> MediatorError {
    tracing::warn!(
        session = %session.session_id,
        reason = %reason,
        "delivery refused; the sender is told only that it was refused"
    );
    MediatorError::problem(
        73,
        &session.session_id,
        message_id,
        ProblemReportSorter::Error,
        ProblemReportScope::Protocol,
        "delivery.refused",
        "Message not accepted for delivery",
        vec![],
        StatusCode::FORBIDDEN,
    )
}

#[cfg(feature = "didcomm")]
use self::protocols::ping;
#[cfg(feature = "didcomm")]
use self::protocols::trust_tasks;
#[cfg(feature = "didcomm")]
use crate::didcomm_compat;
#[cfg(feature = "didcomm")]
use crate::messages::protocols::discover_features;
#[cfg(feature = "didcomm")]
use crate::{SharedData, common::session::Session};
#[cfg(feature = "didcomm")]
use affinidi_did_common::service::Endpoint;
#[cfg(feature = "didcomm")]
use affinidi_did_resolver_cache_sdk::DIDCacheClient;
#[cfg(feature = "didcomm")]
use affinidi_messaging_didcomm::message::Message;
#[cfg(feature = "didcomm")]
use affinidi_messaging_mediator_common::errors::MediatorError;
#[cfg(feature = "didcomm")]
use affinidi_messaging_sdk::messages::compat::{PackEncryptedMetadata, UnpackMetadata};
#[cfg(feature = "didcomm")]
use affinidi_messaging_sdk::messages::{
    known::MessageType as SDKMessageType,
    problem_report::{ProblemReport, ProblemReportScope, ProblemReportSorter},
};
#[cfg(feature = "didcomm")]
use affinidi_secrets_resolver::SecretsResolver;
#[cfg(feature = "didcomm")]
use ahash::AHashSet as HashSet;
#[cfg(feature = "didcomm")]
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
#[cfg(feature = "didcomm-v1")]
pub mod inbound_v1;
#[cfg(feature = "didcomm")]
pub mod protocols;
pub(crate) mod store;
#[cfg(feature = "didcomm-v1")]
pub mod v1_mediation;

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
            SDKMessageType::TrustPing => ping::process(message, session, state.clock.unix_secs()),
            SDKMessageType::TrustTaskEnvelope => {
                trust_tasks::process(message, state, session, metadata).await
            }
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
        let now = state.clock.unix_secs();
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

#[cfg(test)]
#[cfg(feature = "didcomm")]
mod delivery_refusal_tests {
    use super::delivery_refused;
    use crate::common::session::Session;

    fn session() -> Session {
        Session {
            did: "did:example:alice".to_string(),
            session_id: "test-session".to_string(),
            ..Default::default()
        }
    }

    /// Every reason a delivery is refused must look the same to the sender.
    ///
    /// Each reason is a fact about another DID — whether it is hosted here,
    /// what its access list says, whether it accepts anonymous or forwarded
    /// messages. Answering them apart lets a sender enumerate the mediator's
    /// accounts and probe their ACLs one refusal at a time.
    ///
    /// Asserted here because this is where the property lives: every refusal
    /// across the direct, forwarded and v1 paths goes through this one helper,
    /// which ignores its reason when building the response.
    #[test]
    fn every_reason_produces_the_same_response() {
        let reasons = [
            "direct-delivery recipient is not known on this mediator",
            "recipient is not authorized to receive messages through this mediator",
            "delivery blocked by the recipient's access list",
            "recipient is not accepting anonymous messages",
            "recipient is not accepting forwarded messages",
            "no local account is bound to that DIDComm v1 routing key",
        ];

        let rendered: Vec<String> = reasons
            .iter()
            .map(|r| format!("{:?}", delivery_refused(&session(), None, r)))
            .collect();

        for other in &rendered[1..] {
            assert_eq!(
                &rendered[0], other,
                "refusals must be indistinguishable to the sender"
            );
        }

        for reason in reasons {
            assert!(
                !rendered[0].contains(reason),
                "the response leaked the reason: {reason}"
            );
        }
    }

    /// A message id is carried through — it identifies the sender's *own*
    /// message, so returning it reveals nothing about a third party and lets a
    /// legitimate sender correlate the refusal with what it sent.
    #[test]
    fn the_senders_own_message_id_is_still_returned() {
        let with_id = format!(
            "{:?}",
            delivery_refused(&session(), Some("msg-1".to_string()), "any reason")
        );
        assert!(with_id.contains("msg-1"));
    }
}
