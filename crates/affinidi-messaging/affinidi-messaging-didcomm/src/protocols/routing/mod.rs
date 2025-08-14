mod forward;

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_secrets_resolver::SecretsResolver;
use ahash::AHashMap as HashMap;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use ssi::dids::{
    Document,
    document::{Service, service::Endpoint},
};
use tracing::warn;
use uuid::Uuid;

use crate::{
    Attachment, AttachmentData, Message, PackEncryptedOptions,
    document::is_did,
    error::{ErrorKind, Result, ResultExt, err_msg},
    message::{MessagingServiceMetadata, anoncrypt, authcrypt},
};

pub use self::forward::ParsedForward;

pub(crate) const FORWARD_MSG_TYPE: &str = "https://didcomm.org/routing/2.0/forward";

pub(crate) const DIDCOMM_V2_PROFILE: &str = "didcomm/v2";

/// Properties for DIDCommMessagingService
/// (https://identity.foundation/didcomm-messaging/spec/#did-document-service-endpoint).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DIDCommMessagingService {
    pub uri: String,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accept: Option<Vec<String>>,

    #[serde(default)]
    pub routing_keys: Vec<String>,
}

/// Service type must match `DIDCommMessaging`
fn check_service_type(service: &Service) -> Result<()> {
    // Check of the service_endpoint is of type DIDCommMessaging
    if service
        .type_
        .first()
        .map(|t| t == "DIDCommMessaging")
        .is_some()
    {
        Ok(())
    } else {
        Err(err_msg(
            ErrorKind::InvalidState,
            format!(
                "Service ({}) is not type `DIDCommMessaging. Instead it is ({})",
                service.id,
                service.type_.first().unwrap_or(&"".to_string())
            ),
        ))
    }
}

/// Checks if a defined service meets the criteria for a DIDComm v2 service
fn check_service(service: &Service) -> Result<Option<(String, DIDCommMessagingService)>> {
    check_service_type(service)?;

    if let Some(service_endpoint) = &service.service_endpoint {
        // Only accepts DIDComm Version 2 specification
        // Check that this service endpoint supports didcomm/v2

        let endpoint = service_endpoint.into_iter().find(|endpoint| {
            if let Endpoint::Map(value) = endpoint {
                if let Some(accept) = value.get("accept") {
                    let a: Vec<String> = match serde_json::from_value(accept.clone()) {
                        Ok(value) => value,
                        Err(e) => {
                            warn!(
                                "Error parsing accept field ({:?}) on service id({}): {}",
                                accept, service.id, e
                            );
                            return false;
                        }
                    };

                    a.contains(&DIDCOMM_V2_PROFILE.to_string())
                } else {
                    // If accept is not defined, then it is assumed that it accepts all profiles
                    true
                }
            } else {
                false
            }
        });

        if let Some(endpoint) = endpoint {
            let value = match endpoint {
                Endpoint::Map(map) => map,
                _ => {
                    return Err(err_msg(
                        ErrorKind::InvalidState,
                        format!(
                            "Service ({}) has an invalid serviceEndpoint definition",
                            service.id
                        ),
                    ));
                }
            };

            let found_service: DIDCommMessagingService = serde_json::from_value(value.clone())
                .map_err(|_| {
                    err_msg(
                        ErrorKind::InvalidState,
                        format!(
                            "Service ({}) has an invalid serviceEndpoint definition",
                            service.id
                        ),
                    )
                })?;

            Ok(Some((service.id.to_string(), found_service)))
        } else {
            Err(err_msg(
                ErrorKind::IllegalArgument,
                "Service with the specified ID does not accept didcomm/v2 profile",
            ))
        }
    } else {
        // if there is no serviceEndpoint, then we can't proceed

        Err(err_msg(
            ErrorKind::InvalidState,
            format!(
                "Service ({}) has no serviceEndpoint definitions",
                service.id
            ),
        ))
    }
}

/// Returns a Service Endpoint definition if it exists
/// If a service_id is specified, then we look for that explicitly
/// service_id: is a DID URL fragment that refers to a specific service endpoint in the DID document.
///             E.g. did:peer:2...#service-1 should be specified as service_id = "service-1"
///
/// Returns
/// - Ok(None) if no service endpoint can be found and no service_id was given
/// - Ok(DIDCommMessagingService) - service endpoint found
/// - Err(err) - service_id provided, but couldn't find/match to it.
fn find_did_comm_service(
    did_doc: &Document,
    service_id: Option<&str>,
) -> Result<Option<(String, DIDCommMessagingService)>> {
    match service_id {
        Some(service_id) => {
            let service = did_doc.service(service_id).ok_or_else(|| {
                err_msg(
                    ErrorKind::InvalidState,
                    "Service with the specified ID not found in the DID document",
                )
            })?;

            check_service(service)
        }
        None => {
            let service = did_doc
                .service
                .iter()
                .find_map(|service| check_service(service).unwrap_or_default());

            Ok(service)
        }
    }
}

async fn resolve_did_comm_services_chain(
    to: &str,
    service_id: Option<&str>,
    resolver: &DIDCacheClient,
) -> Result<Vec<(String, DIDCommMessagingService)>> {
    let result = resolver.resolve(to).await.map_err(|e| {
        err_msg(
            ErrorKind::DIDNotResolved,
            format!("Couldn't resolve DID({}). Reason: {}", to, e),
        )
    })?;

    let service = find_did_comm_service(&result.doc, service_id)?;

    if service.is_none() {
        return Ok(vec![]);
    }

    let mut service = service.unwrap();

    let mut services = vec![service.clone()];
    let mut service_endpoint = &service.1.uri;

    while is_did(service_endpoint) {
        // Now alternative endpoints recursion is not supported
        // (because it should not be used according to the specification)
        if services.len() > 1 {
            return Err(err_msg(
                ErrorKind::InvalidState,
                "DID doc defines alternative endpoints recursively",
            ));
        }

        let resolved = resolver.resolve(service_endpoint).await.map_err(|e| {
            err_msg(
                ErrorKind::DIDNotResolved,
                format!("Couldn't resolve DID({}). Reason: {}", to, e),
            )
        })?;

        service = find_did_comm_service(&resolved.doc, None)?.ok_or_else(|| {
            err_msg(
                // TODO: Think on introducing a more appropriate error kind
                ErrorKind::InvalidState,
                "Referenced mediator does not provide any DIDCommMessaging services",
            )
        })?;

        services.insert(0, service.clone());
        service_endpoint = &service.1.uri;
    }

    Ok(services)
}

fn generate_message_id() -> String {
    Uuid::new_v4().to_string()
}

fn build_forward_message(
    forwarded_msg: &str,
    next: &str,
    headers: Option<&HashMap<String, Value>>,
) -> Result<String> {
    let body = json!({ "next": next });

    // TODO: Think how to avoid extra deserialization of forwarded_msg here.
    // (This deserializtion is a double work because the whole Forward message with the attachments
    // will then be serialized.)
    let attachment = Attachment::json(
        serde_json::from_str(forwarded_msg)
            .kind(ErrorKind::Malformed, "Unable deserialize forwarded message")?,
    )
    .finalize();

    let mut msg_builder = Message::build(generate_message_id(), FORWARD_MSG_TYPE.to_owned(), body);

    if let Some(headers) = headers {
        for (name, value) in headers {
            msg_builder = msg_builder.header(name.to_owned(), value.to_owned());
        }
    }

    msg_builder = msg_builder.attachment(attachment);

    let msg = msg_builder.finalize();

    serde_json::to_string(&msg).kind(ErrorKind::InvalidState, "Unable serialize forward message")
}

/// Tries to parse plaintext message into `ParsedForward` structure if the message is Forward.
/// (https://identity.foundation/didcomm-messaging/spec/#messages)
///
/// # Parameters
/// - `msg` plaintext message to try to parse into `ParsedForward` structure
///
/// # Returns
/// `Some` with `ParsedForward` structure if `msg` is Forward message, otherwise `None`.
pub fn try_parse_forward<'a>(msg: &'a Message) -> Option<ParsedForward<'a>> {
    if msg.type_ != FORWARD_MSG_TYPE {
        return None;
    }

    let next = match msg.body {
        Value::Object(ref body) => match body.get("next") {
            Some(Value::String(next)) => Some(next),
            _ => None,
        },
        _ => None,
    };

    next?;

    let next = next.unwrap();

    let json_attachment_data = match msg.attachments {
        Some(ref attachments) => match &attachments[..] {
            [attachment, ..] => match &attachment.data {
                AttachmentData::Json { value } => Some(value),
                _ => None,
            },
            _ => None,
        },
        None => None,
    };

    json_attachment_data?;

    let forwarded_msg = &json_attachment_data.unwrap().json;

    Some(ParsedForward {
        msg,
        next: next.clone(),
        forwarded_msg: forwarded_msg.clone(),
    })
}

/// Wraps an anoncrypt or authcrypt message into a Forward onion (nested Forward messages).
/// https://identity.foundation/didcomm-messaging/spec/#messages
///
/// # Parameters
/// - `msg` Anoncrypt or authcrypt message to wrap into Forward onion.
/// - `headers` (optional) Additional headers to each Forward message of the onion.
/// - `to` Recipient (a key identifier or DID) of the message being wrapped into Forward onion.
/// - `routing_keys` Routing keys (each one is a key identifier or DID) to use for encryption of
///   Forward messages in the onion. The keys must be ordered along the route (so in the opposite
///   direction to the wrapping steps).
/// - `enc_alg_anon` Algorithm to use for wrapping into each Forward message of the onion.
/// - `did_resolver` instance of `DIDResolver` to resolve DIDs.
/// - `to_kids_limit` maximum number of kids in a single recipient did.
///
/// # Returns
/// `Result` with the message wrapped into Forward onion or `Error`.
///
/// # Errors
/// - `Malformed` The message to wrap is malformed.
/// - `DIDNotResolved` Issuer DID not found.
/// - `DIDUrlNotFound` Issuer authentication verification method is not found.
/// - `Unsupported` Used crypto or method is unsupported.
/// - `InvalidState` Indicates a library error.
pub async fn wrap_in_forward<T>(
    msg: &str,
    options: &PackEncryptedOptions,
    to: &str,
    sign_by: Option<&str>,
    routing_keys: &[String],
    did_resolver: &DIDCacheClient,
    secrets_resolver: &T,
) -> Result<String>
where
    T: SecretsResolver,
{
    let mut tos = routing_keys.to_vec();

    let mut nexts = tos.clone();
    nexts.remove(0);
    nexts.push(to.to_owned());

    tos.reverse();
    nexts.reverse();

    let mut msg = msg.to_owned();

    for (to_, next_) in tos.iter().zip(nexts.iter()) {
        msg = build_forward_message(&msg, next_, options.forward_headers.as_ref())?;
        if let Some(sign_by) = sign_by {
            msg = authcrypt(
                to,
                sign_by,
                did_resolver,
                secrets_resolver,
                msg.as_bytes(),
                &options.enc_alg_auth,
                &options.enc_alg_anon,
                false,
                options.to_kids_limit,
            )
            .await?
            .0;
        } else {
            msg = anoncrypt(
                to_,
                did_resolver,
                msg.as_bytes(),
                &options.enc_alg_anon,
                options.to_kids_limit,
            )
            .await?
            .0;
        }
    }

    Ok(msg)
}

pub(crate) async fn wrap_in_forward_if_needed<T>(
    msg: &str,
    to: &str,
    sign_by: Option<&str>,
    did_resolver: &DIDCacheClient,
    secrets_resolver: &T,
    options: &PackEncryptedOptions,
) -> Result<Option<(String, MessagingServiceMetadata)>>
where
    T: SecretsResolver,
{
    if !options.forward {
        return Ok(None);
    }

    let services_chain =
        resolve_did_comm_services_chain(to, options.messaging_service.as_deref(), did_resolver)
            .await?;

    if services_chain.is_empty() {
        return Ok(None);
    }

    let mut routing_keys = services_chain[1..]
        .iter()
        .map(|service| service.1.uri.clone())
        .collect::<Vec<_>>();

    routing_keys.append(&mut services_chain.last().unwrap().1.routing_keys.clone());

    if routing_keys.is_empty() {
        return Ok(None);
    }

    let forward_msg = wrap_in_forward(
        msg,
        options,
        to,
        sign_by,
        &routing_keys,
        did_resolver,
        secrets_resolver,
    )
    .await?;

    let messaging_service = MessagingServiceMetadata {
        id: services_chain.last().unwrap().0.clone(),
        service_endpoint: services_chain.first().unwrap().1.uri.clone(),
        routing_keys,
    };

    Ok(Some((forward_msg, messaging_service)))
}
