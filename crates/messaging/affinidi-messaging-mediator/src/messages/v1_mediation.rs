//! DIDComm v1 mediation protocols: coordinate-mediation 1.0 and
//! message-pickup 2.0.
//!
//! Stage 1 taught the mediator to *receive* v1 forwards. This is what lets a
//! wallet set that up for itself and collect what arrives: register routing
//! keys, then poll for messages.
//!
//! # These messages are authenticated; forwards are not
//!
//! A `routing/1.0/forward` is anon-packed by design, so
//! [`crate::messages::inbound_v1`] has no sender to authorise against and leans
//! on the recipient's ACL. Everything here is the opposite: the client
//! **authcrypts** to the mediator, so opening the envelope proves which verkey
//! sent it, and that key is the identity every decision below is made against.
//! There is nothing to spoof — a v1 plaintext has no `from` header to lie in.
//!
//! # Account identity
//!
//! v1 has no DIDs, so the client's account is keyed by the `did:key` derived
//! from its authenticated verkey. Deterministic, needs no extra state, and it
//! is the same identifier Aries uses for a connection's keys.
//!
//! Provisioning deliberately mirrors [`crate::handlers::authenticate::response`]
//! rather than inventing a second policy: an unknown account is created with
//! `global_acl_default`, unless `mediator_acl_mode` is `explicit_allow`, in
//! which case mediation is denied. One admission gate, two entry points.

use affinidi_messaging_didcomm_v1::identity::Verkey;
use affinidi_messaging_didcomm_v1::message::MessageV1;
use affinidi_messaging_didcomm_v1::protocols::coordinate_mediation as cm;
use affinidi_messaging_didcomm_v1::protocols::message_pickup as mp;
use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_messaging_mediator_common::store::types::DeletionAuthority;
use affinidi_messaging_mediator_common::types::messages::{FetchDeletePolicy, FetchOptions};
use affinidi_messaging_sdk::messages::problem_report::{ProblemReportScope, ProblemReportSorter};
use affinidi_messaging_sdk::protocols::mediator::acls::AccessListModeType;
use http::StatusCode;
use sha256::digest;
use tracing::{debug, warn};

use crate::SharedData;
use crate::common::session::Session;

/// Most messages a `delivery-request` may return when it names no `limit`.
///
/// A client that asks for everything still gets a bounded page; it can keep
/// requesting. Matches the store's own default fetch limit.
const DEFAULT_DELIVERY_LIMIT: u32 = 10;

/// Hard cap on a `delivery-request`, whatever `limit` it asks for.
///
/// The request is authenticated but the number is attacker-chosen, and each
/// message is copied into a response the mediator has to build in memory.
const MAX_DELIVERY_LIMIT: u32 = 100;

/// Cap on `message_id_list` in one `messages-received`.
const MAX_ACK_IDS: usize = 100;

/// A v1 request the mediator answers directly, rather than routing.
pub(crate) enum V1Request {
    CoordinateMediation(cm::CoordinateMediation),
    MessagePickup(mp::MessagePickup),
}

impl V1Request {
    /// Classify `msg`, or `None` when it is not a protocol this module serves.
    pub(crate) fn classify(msg: &MessageV1) -> Option<Self> {
        if let Some(kind) = cm::CoordinateMediation::classify(msg) {
            return Some(Self::CoordinateMediation(kind));
        }
        mp::MessagePickup::classify(msg).map(Self::MessagePickup)
    }
}

/// Handle an authenticated v1 protocol message, returning the reply to send
/// back.
///
/// `sender` is the verkey that authenticated the envelope — not anything the
/// message claimed.
pub(crate) async fn handle(
    state: &SharedData,
    session: &Session,
    request: V1Request,
    msg: &MessageV1,
    sender: &Verkey,
) -> Result<MessageV1, MediatorError> {
    let account = client_account(state, session, sender).await?;

    match request {
        V1Request::CoordinateMediation(kind) => {
            coordinate_mediation(state, session, kind, msg, &account).await
        }
        V1Request::MessagePickup(kind) => message_pickup(state, session, kind, msg, &account).await,
    }
}

/// The client's account: the `did:key` for its authenticated verkey, created on
/// first contact under the same policy as first authentication.
struct ClientAccount {
    did: String,
    did_hash: String,
}

async fn client_account(
    state: &SharedData,
    session: &Session,
    sender: &Verkey,
) -> Result<ClientAccount, MediatorError> {
    let did = sender.to_did_key();
    let did_hash = digest(did.as_bytes());

    if !state.database.account_exists(&did_hash).await? {
        // Same gate as `handlers::authenticate::response`: in explicit-allow
        // mode an unknown identity is refused rather than self-registered.
        if state.config.security.mediator_acl_mode == AccessListModeType::ExplicitAllow {
            warn!(
                %did,
                "v1 mediation refused: no account and mediator_acl_mode is explicit_allow"
            );
            return Err(v1_problem(
                session,
                25,
                "authorization.blocked",
                "This mediator does not accept mediation requests from unknown clients".to_string(),
                StatusCode::FORBIDDEN,
            ));
        }

        debug!(%did, "v1 mediation: registering a new account for the client verkey");
        state
            .database
            .account_add(&did_hash, &state.config.security.global_acl_default, None)
            .await?;
    }

    Ok(ClientAccount { did, did_hash })
}

async fn coordinate_mediation(
    state: &SharedData,
    session: &Session,
    kind: cm::CoordinateMediation,
    msg: &MessageV1,
    account: &ClientAccount,
) -> Result<MessageV1, MediatorError> {
    match kind {
        cm::CoordinateMediation::MediateRequest => {
            let identity = state.didcomm_v1_identity().await?;
            let endpoint = mediator_endpoint(state);

            debug!(did = %account.did, "granting v1 mediation");
            cm::mediate_grant(
                &msg.id,
                &endpoint,
                &[identity.verkey()],
                cm::KeyFormat::Base58,
            )
            .map_err(|e| v1_build_error(session, e))
        }

        cm::CoordinateMediation::KeylistUpdate => {
            let updates = cm::parse_keylist_update(msg).map_err(|e| {
                v1_problem(
                    session,
                    37,
                    "message.didcomm_v1.keylist",
                    format!("malformed keylist-update: {e}"),
                    StatusCode::BAD_REQUEST,
                )
            })?;

            let mut results = Vec::with_capacity(updates.len());
            for update in updates {
                let result = apply_keylist_update(state, account, &update).await;
                results.push(cm::KeylistUpdated {
                    recipient_key: update.recipient_key,
                    action: update.action,
                    result,
                });
            }

            cm::keylist_update_response(&msg.id, &results, cm::KeyFormat::Base58)
                .map_err(|e| v1_build_error(session, e))
        }

        cm::CoordinateMediation::KeylistQuery => {
            let keys = state
                .database
                .v1_routing_keys_for(&account.did_hash)
                .await?
                .iter()
                .filter_map(|k| Verkey::from_base58(k).ok())
                .collect::<Vec<_>>();

            cm::keylist(&msg.id, &keys, cm::KeyFormat::Base58)
                .map_err(|e| v1_build_error(session, e))
        }

        // Responses, not requests: a client sending one to the mediator is
        // confused, but it is not an error worth a problem report either.
        cm::CoordinateMediation::MediateGrant
        | cm::CoordinateMediation::MediateDeny
        | cm::CoordinateMediation::KeylistUpdateResponse
        | cm::CoordinateMediation::Keylist => Err(v1_problem(
            session,
            37,
            "message.didcomm_v1.unexpected",
            format!(
                "`{}` is a mediator-to-client message; the mediator does not accept it",
                msg.typ
            ),
            StatusCode::BAD_REQUEST,
        )),

        // `CoordinateMediation` is `#[non_exhaustive]`.
        _ => Err(v1_problem(
            session,
            37,
            "message.didcomm_v1.unsupported",
            format!("unsupported coordinate-mediation message `{}`", msg.typ),
            StatusCode::BAD_REQUEST,
        )),
    }
}

/// Apply one keylist change, reporting the per-key outcome rather than failing
/// the whole batch — RFC 0211 expects a result for every entry.
async fn apply_keylist_update(
    state: &SharedData,
    account: &ClientAccount,
    update: &cm::KeylistUpdate,
) -> cm::KeylistResult {
    let verkey = update.recipient_key.to_base58();

    match update.action {
        cm::KeylistAction::Add => {
            match state.database.v1_routing_key_lookup(&verkey).await {
                // Already ours: nothing to do, and say so rather than claiming
                // to have made a change.
                Ok(Some(owner)) if owner == account.did => cm::KeylistResult::NoChange,
                // Someone else's key. Refusing is the whole point of the
                // exclusive binding — granting it would hand this client
                // another account's inbound traffic.
                Ok(Some(_)) => cm::KeylistResult::ClientError,
                Ok(None) => match state
                    .database
                    .v1_routing_key_bind(&verkey, &account.did)
                    .await
                {
                    Ok(()) => cm::KeylistResult::Success,
                    Err(e) => {
                        warn!(%verkey, error = %e, "v1 keylist add failed");
                        cm::KeylistResult::ServerError
                    }
                },
                Err(e) => {
                    warn!(%verkey, error = %e, "v1 keylist lookup failed");
                    cm::KeylistResult::ServerError
                }
            }
        }

        cm::KeylistAction::Remove => {
            match state.database.v1_routing_key_lookup(&verkey).await {
                Ok(Some(owner)) if owner == account.did => {
                    match state.database.v1_routing_key_unbind(&verkey).await {
                        Ok(true) => cm::KeylistResult::Success,
                        Ok(false) => cm::KeylistResult::NoChange,
                        Err(e) => {
                            warn!(%verkey, error = %e, "v1 keylist remove failed");
                            cm::KeylistResult::ServerError
                        }
                    }
                }
                // Not bound at all — a no-op, not an error.
                Ok(None) => cm::KeylistResult::NoChange,
                // Bound to someone else: refuse, and report it the same way as
                // any other rejected request so this cannot be used to probe
                // which keys other accounts hold.
                Ok(Some(_)) => cm::KeylistResult::ClientError,
                Err(e) => {
                    warn!(%verkey, error = %e, "v1 keylist lookup failed");
                    cm::KeylistResult::ServerError
                }
            }
        }

        // `KeylistAction` is `#[non_exhaustive]`.
        _ => cm::KeylistResult::ClientError,
    }
}

async fn message_pickup(
    state: &SharedData,
    session: &Session,
    kind: mp::MessagePickup,
    msg: &MessageV1,
    account: &ClientAccount,
) -> Result<MessageV1, MediatorError> {
    match kind {
        mp::MessagePickup::StatusRequest => {
            let status = state.database.inbox_status(&account.did_hash).await?;
            mp::status(&msg.id, status.message_count, None, false)
                .map_err(|e| v1_build_error(session, e))
        }

        mp::MessagePickup::DeliveryRequest => {
            let limit = mp::delivery_limit(msg)
                .unwrap_or(DEFAULT_DELIVERY_LIMIT)
                .min(MAX_DELIVERY_LIMIT);

            let fetched = state
                .database
                .fetch_messages(
                    &session.session_id,
                    &account.did_hash,
                    &FetchOptions {
                        limit: limit as usize,
                        start_id: None,
                        // Pickup 2.0 acknowledges separately: deleting on
                        // delivery would lose any message whose delivery was
                        // lost in flight. See the protocol module docs.
                        delete_policy: FetchDeletePolicy::DoNotDelete,
                    },
                )
                .await?;

            let messages: Vec<mp::QueuedMessage> = fetched
                .success
                .iter()
                .filter_map(|element| {
                    // `msg` is optional on the store element; a record without
                    // a body cannot be delivered, and skipping it leaves it
                    // queued rather than acknowledging something never sent.
                    let body = element.msg.as_deref()?;
                    let envelope = serde_json::from_str(body).ok()?;
                    Some(mp::QueuedMessage {
                        id: element.msg_id.clone(),
                        envelope,
                    })
                })
                .collect();

            // Nothing queued → answer with a status, as RFC 0685 specifies;
            // an empty `delivery` would look like a delivery that dropped
            // everything.
            if messages.is_empty() {
                let status = state.database.inbox_status(&account.did_hash).await?;
                return mp::status(&msg.id, status.message_count, None, false)
                    .map_err(|e| v1_build_error(session, e));
            }

            mp::delivery(&msg.id, &messages, None).map_err(|e| v1_build_error(session, e))
        }

        mp::MessagePickup::MessagesReceived => {
            let ids = mp::parse_messages_received(msg).map_err(|e| {
                v1_problem(
                    session,
                    37,
                    "message.didcomm_v1.messages_received",
                    format!("malformed messages-received: {e}"),
                    StatusCode::BAD_REQUEST,
                )
            })?;

            if ids.len() > MAX_ACK_IDS {
                return Err(v1_problem(
                    session,
                    37,
                    "message.didcomm_v1.messages_received",
                    format!(
                        "messages-received lists {} ids, exceeding the maximum of {MAX_ACK_IDS}",
                        ids.len()
                    ),
                    StatusCode::BAD_REQUEST,
                ));
            }

            for id in &ids {
                // `Owner` authority makes the store reject an id the client
                // neither sent nor received, so one client cannot delete
                // another's messages by guessing ids.
                if let Err(e) = state
                    .database
                    .delete_message(
                        id,
                        DeletionAuthority::Owner {
                            did_hash: account.did_hash.clone(),
                        },
                    )
                    .await
                {
                    debug!(%id, error = %e, "v1 messages-received: delete failed");
                }
            }

            let status = state.database.inbox_status(&account.did_hash).await?;
            mp::status(&msg.id, status.message_count, None, false)
                .map_err(|e| v1_build_error(session, e))
        }

        mp::MessagePickup::LiveDeliveryChange => {
            // Live delivery would need a persistent connection to this client.
            // RFC 0685 has a problem-report for exactly this case; answering
            // with a truthful `live_delivery: false` status is the honest
            // alternative to silently accepting and never pushing.
            let status = state.database.inbox_status(&account.did_hash).await?;
            mp::status(&msg.id, status.message_count, None, false)
                .map_err(|e| v1_build_error(session, e))
        }

        // Mediator-to-client messages.
        mp::MessagePickup::Status | mp::MessagePickup::Delivery => Err(v1_problem(
            session,
            37,
            "message.didcomm_v1.unexpected",
            format!(
                "`{}` is a mediator-to-client message; the mediator does not accept it",
                msg.typ
            ),
            StatusCode::BAD_REQUEST,
        )),

        _ => Err(v1_problem(
            session,
            37,
            "message.didcomm_v1.unsupported",
            format!("unsupported message-pickup message `{}`", msg.typ),
            StatusCode::BAD_REQUEST,
        )),
    }
}

/// The endpoint a `mediate-grant` publishes for inbound traffic.
fn mediator_endpoint(state: &SharedData) -> String {
    // The DID document's DIDComm service endpoint is the authoritative answer;
    // fall back to the configured listen address so a development mediator
    // still returns something usable.
    state
        .config
        .mediator_did_document
        .as_ref()
        .and_then(|doc| {
            doc.service
                .iter()
                .find(|s| s.type_.iter().any(|t| t == "DIDCommMessaging"))
                .and_then(|s| s.service_endpoint.get_uri())
        })
        .map(|uri| uri.trim_matches('"').to_string())
        .unwrap_or_else(|| state.config.listen_address.clone())
}

fn v1_build_error(session: &Session, error: impl std::fmt::Display) -> MediatorError {
    v1_problem(
        session,
        37,
        "message.didcomm_v1.build",
        format!("couldn't build the DIDComm v1 reply: {error}"),
        StatusCode::INTERNAL_SERVER_ERROR,
    )
}

fn v1_problem(
    session: &Session,
    code: u16,
    descriptor: &str,
    detail: String,
    status: StatusCode,
) -> MediatorError {
    MediatorError::problem(
        code,
        &session.session_id,
        None,
        ProblemReportSorter::Error,
        ProblemReportScope::Message,
        descriptor,
        "{1}",
        vec![detail],
        status,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn verkey(seed: u8) -> Verkey {
        Verkey::from_bytes([seed; 32])
    }

    #[test]
    fn classifies_both_protocols_and_nothing_else() {
        let request = cm::mediate_request().unwrap();
        assert!(matches!(
            V1Request::classify(&request),
            Some(V1Request::CoordinateMediation(
                cm::CoordinateMediation::MediateRequest
            ))
        ));

        let status = mp::status_request(None).unwrap();
        assert!(matches!(
            V1Request::classify(&status),
            Some(V1Request::MessagePickup(mp::MessagePickup::StatusRequest))
        ));

        let forward = MessageV1::new(
            affinidi_messaging_didcomm_v1::protocols::forward::FORWARD_TYPE,
            json!({}),
        )
        .unwrap();
        assert!(
            V1Request::classify(&forward).is_none(),
            "a forward is routed, not answered"
        );

        let basic = affinidi_messaging_didcomm_v1::protocols::basic_message::BasicMessage::new("x")
            .unwrap()
            .finalize();
        assert!(V1Request::classify(&basic).is_none());
    }

    /// The account identifier must be derived purely from the authenticated
    /// verkey, so two requests from one key always reach the same account and a
    /// different key never does.
    #[test]
    fn account_did_is_derived_from_the_verkey() {
        let a = verkey(1).to_did_key();
        let b = verkey(1).to_did_key();
        let c = verkey(2).to_did_key();

        assert_eq!(a, b, "the same verkey must always yield the same account");
        assert_ne!(a, c);
        assert!(a.starts_with("did:key:z6Mk"));
        assert_eq!(
            Verkey::from_did_key(&a).unwrap(),
            verkey(1),
            "the derivation must be reversible, so a bound key can be read back"
        );
    }

    #[test]
    fn delivery_limits_are_bounded() {
        // Asks for more than the cap → capped.
        let big = mp::delivery_request(10_000, None).unwrap();
        assert_eq!(
            mp::delivery_limit(&big).unwrap().min(MAX_DELIVERY_LIMIT),
            MAX_DELIVERY_LIMIT
        );

        // Asks for nothing → the default, not unbounded.
        let none = MessageV1::new(mp::DELIVERY_REQUEST_TYPE, json!({})).unwrap();
        assert_eq!(
            mp::delivery_limit(&none).unwrap_or(DEFAULT_DELIVERY_LIMIT),
            DEFAULT_DELIVERY_LIMIT
        );

        const { assert!(DEFAULT_DELIVERY_LIMIT <= MAX_DELIVERY_LIMIT) };
    }
}
