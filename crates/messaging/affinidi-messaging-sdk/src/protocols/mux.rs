//! DID multiplexing (`messaging/mux/*/0.1`): one mediator connection carrying
//! many DIDs.
//!
//! A *member* DID lets a *principal* connection carry its traffic by signing a
//! statement with its **authentication** key (a W3C Data Integrity proof,
//! `eddsa-jcs-2022`):
//!
//! - [`sign_grant`]: a stored grant, which survives reconnects until it
//!   expires or is revoked. Send it with
//!   [`TrustTasksOps::mux_grant`](super::trust_tasks::TrustTasksOps::mux_grant).
//! - [`sign_attach`]: bound to one connection's `sessionId` + `muxNonce`
//!   (both from that connection's `ready` event), gone when it closes.
//! - [`sign_revoke_all`]: voids every grant the member issued under an epoch.
//!
//! **Nothing here happens by default.** Every grant and attach is an explicit
//! call with an explicit scope; there is no implicit membership, renewal or
//! re-attach.

use std::time::{SystemTime, UNIX_EPOCH};

use affinidi_did_common::DocumentExt;
use affinidi_messaging_didcomm::message::Message;
use affinidi_secrets_resolver::SecretsResolver;
use affinidi_secrets_resolver::secrets::{KeyType, Secret};
use serde::Serialize;
use serde_json::{Value, json};
use tracing::warn;
use trust_tasks_proof::affinidi::{SignOptions, sign_trust_task};
use trust_tasks_rs::TrustTask;
use uuid::Uuid;

use crate::tasks::messaging::mux;
use crate::{ATM, errors::ATMError};

/// The Trust Tasks DIDComm envelope `type`.
const ENVELOPE_TYPE: &str = "https://trusttasks.org/binding/didcomm/0.1/envelope";
/// `messaging/mux/event` Type URI.
const EVENT_TYPE: &str = "https://trusttasks.org/spec/messaging/mux/event/0.1";
/// `messaging/mux/notice` Type URI.
const NOTICE_TYPE: &str = "https://trusttasks.org/spec/messaging/mux/notice/0.1";

/// The current mux connection's `ready` event: what an attach must be bound
/// to. A new value arrives with every (re)connect; the nonce from an earlier
/// connection is useless on a new one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MuxReady {
    pub session_id: String,
    pub mux_nonce: String,
    pub max_dids_per_connection: Option<u64>,
    pub max_attach_lifetime_seconds: Option<u64>,
    pub max_grant_lifetime_seconds: Option<u64>,
}

impl MuxReady {
    fn from_payload(payload: &Value) -> Option<Self> {
        if payload.get("event").and_then(Value::as_str) != Some("ready") {
            return None;
        }
        let u = |k: &str| payload.get(k).and_then(Value::as_u64);
        Some(Self {
            session_id: payload.get("sessionId")?.as_str()?.to_string(),
            mux_nonce: payload.get("muxNonce")?.as_str()?.to_string(),
            max_dids_per_connection: u("maxDidsPerConnection"),
            max_attach_lifetime_seconds: u("maxAttachLifetimeSeconds"),
            max_grant_lifetime_seconds: u("maxGrantLifetimeSeconds"),
        })
    }
}

/// A `messaging/mux/event` payload (`ready`, `attached`, `detached`,
/// `refused`), as the generated type.
pub type MuxEvent = mux::event::v0_1::Payload;

/// The receive side of a mux connection, installed on the profile's
/// mediator by the websocket transport.
#[derive(Debug)]
pub(crate) struct MuxHandles {
    pub(crate) ready_rx: tokio::sync::watch::Receiver<Option<MuxReady>>,
    pub(crate) events_tx: tokio::sync::broadcast::Sender<MuxEvent>,
}

/// The transport's half of [`MuxHandles`].
#[derive(Debug)]
pub(crate) struct MuxSides {
    pub(crate) ready_tx: tokio::sync::watch::Sender<Option<MuxReady>>,
    pub(crate) events_tx: tokio::sync::broadcast::Sender<MuxEvent>,
}

impl MuxSides {
    /// A new socket means a new mux session: forget the old `ready`.
    pub(crate) fn reset(&self) {
        let _ = self.ready_tx.send(None);
    }

    /// Consume a mux event arriving on the socket. Returns whether the
    /// message was one (and so must not be handed to the application as an
    /// ordinary message).
    pub(crate) fn absorb(&self, message: &Message) -> bool {
        let Some(task) = decode_mux_event(message) else {
            return false;
        };
        let payload = serde_json::to_value(&task.payload).unwrap_or_default();
        if let Some(ready) = MuxReady::from_payload(&payload) {
            let _ = self.ready_tx.send(Some(ready));
        }
        let _ = self.events_tx.send(task.payload);
        true
    }
}

/// Channel capacity for mux events: they are rare control messages.
pub(crate) const MUX_EVENT_CAPACITY: usize = 64;

/// The WebSocket subprotocol that asks the mediator for a mux connection.
pub const MUX_SUBPROTOCOL: &str = "affinidi-mux";

/// What a grant or attach allows the principal to do for the member.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum MuxCapability {
    /// Live delivery of the member's messages.
    Receive,
    /// Message-pickup status / delivery requests for the member.
    Pickup,
    /// Deleting (acknowledging) the member's messages.
    Delete,
    /// Sending as the member over the principal's connection.
    Send,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

fn scope_value(scope: &[MuxCapability]) -> Result<Value, ATMError> {
    if scope.is_empty() {
        // Empty means nothing, never everything (R5.1); the mediator would
        // refuse it, so refuse it here with a clearer message.
        return Err(ATMError::ConfigError(
            "a mux scope must name at least one capability".into(),
        ));
    }
    serde_json::to_value(scope).map_err(|e| ATMError::ConfigError(e.to_string()))
}

/// The member's Ed25519 **authentication** secret: mux statements authorise a
/// principal to act as the member, so only an authentication key may sign
/// one (an assertion key is refused by the mediator).
async fn authentication_secret(atm: &ATM, member_did: &str) -> Result<Secret, ATMError> {
    let doc = atm
        .inner
        .tdk_common
        .did_resolver()
        .resolve(member_did)
        .await
        .map_err(|e| ATMError::DIDError(format!("couldn't resolve {member_did}: {e}")))?
        .doc;
    let resolver = atm.inner.tdk_common.secrets_resolver();
    for kid in doc.find_authentication(None) {
        if let Some(secret) = resolver.get_secret(kid).await
            && secret.get_key_type() == KeyType::Ed25519
        {
            return Ok(secret);
        }
    }
    Err(ATMError::SecretsError(format!(
        "no Ed25519 authentication key for {member_did} in the secrets resolver"
    )))
}

async fn sign(atm: &ATM, member_did: &str, body: Value) -> Result<Value, ATMError> {
    let secret = authentication_secret(atm, member_did).await?;
    sign_trust_task(&body, &secret, SignOptions::new())
        .await
        .map_err(|e| ATMError::MsgSendError(format!("couldn't sign mux statement: {e}")))
}

/// Sign a `muxGrant`: `member_did` lets `principal_did` carry its traffic at
/// `mediator_did`, with `scope`, for `ttl_secs` (the mediator caps it), under
/// the member's current revoke-all `epoch` (0 for a DID that never revoked).
///
/// Returns the signed statement and its `grantId`.
pub async fn sign_grant(
    atm: &ATM,
    member_did: &str,
    principal_did: &str,
    mediator_did: &str,
    scope: &[MuxCapability],
    epoch: u64,
    ttl_secs: u64,
) -> Result<(Value, String), ATMError> {
    let grant_id = Uuid::new_v4().to_string();
    let iat = now();
    let body = json!({
        "type": "muxGrant",
        "issuer": member_did,
        "audience": mediator_did,
        "grantId": grant_id,
        "principal": principal_did,
        "scope": scope_value(scope)?,
        "epoch": epoch,
        "iat": iat,
        "exp": iat + ttl_secs,
    });
    Ok((sign(atm, member_did, body).await?, grant_id))
}

/// Sign a `muxAttach` binding `member_did` to one connection, identified by
/// the `session_id` and `mux_nonce` its `ready` event carried.
#[allow(clippy::too_many_arguments)]
pub async fn sign_attach(
    atm: &ATM,
    member_did: &str,
    principal_did: &str,
    mediator_did: &str,
    session_id: &str,
    mux_nonce: &str,
    scope: &[MuxCapability],
    ttl_secs: u64,
) -> Result<Value, ATMError> {
    let iat = now();
    let body = json!({
        "type": "muxAttach",
        "issuer": member_did,
        "audience": mediator_did,
        "principal": principal_did,
        "sessionId": session_id,
        "muxNonce": mux_nonce,
        "scope": scope_value(scope)?,
        "iat": iat,
        "exp": iat + ttl_secs,
    });
    sign(atm, member_did, body).await
}

/// Sign a `muxRevokeAll` voiding every grant `member_did` issued under
/// `epoch`. This is the hand-over switch: whoever controls the DID now can
/// end every delegation of it in one call.
pub async fn sign_revoke_all(
    atm: &ATM,
    member_did: &str,
    mediator_did: &str,
    epoch: u64,
) -> Result<Value, ATMError> {
    let iat = now();
    let body = json!({
        "type": "muxRevokeAll",
        "issuer": member_did,
        "audience": mediator_did,
        "epoch": epoch,
        "iat": iat,
        "exp": iat + 300,
    });
    sign(atm, member_did, body).await
}

fn decode<P: serde::de::DeserializeOwned>(
    message: &Message,
    type_uri: &str,
) -> Option<TrustTask<P>> {
    if message.typ != ENVELOPE_TYPE
        || message.body.get("type").and_then(Value::as_str) != Some(type_uri)
    {
        return None;
    }
    serde_json::from_value(message.body.clone())
        .inspect_err(
            |e| warn!(r#type = type_uri, error = %e, "dropping a mux document that does not parse"),
        )
        .ok()
}

/// Recognise a `messaging/mux/event` (live: `ready`, `attached`, `detached`,
/// `refused`) among messages arriving on a mux connection.
pub fn decode_mux_event(message: &Message) -> Option<TrustTask<mux::event::v0_1::Payload>> {
    decode(message, EVENT_TYPE)
}

/// Recognise a durable `messaging/mux/notice` (e.g. `grantsSuspended`: the
/// grants it lists must be re-created with a fresh member signature).
pub fn decode_mux_notice(message: &Message) -> Option<TrustTask<mux::notice::v0_1::Payload>> {
    decode(message, NOTICE_TYPE)
}

/// Which DID an unpacked message on a mux connection was for: the DID of the
/// first key it was encrypted to. A dispatcher routes on this (R1.7: one demux
/// owner per socket) so each member's consumer sees only its own messages.
/// `None` for a message encrypted to no key (anoncrypt with no recipient kid
/// is not a thing; plaintext or signed-only messages are).
pub fn mux_recipient(meta: &crate::messages::compat::UnpackMetadata) -> Option<String> {
    meta.encrypted_to_kids
        .first()
        .map(|kid| kid.split('#').next().unwrap_or(kid).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_scope_is_refused_locally() {
        assert!(scope_value(&[]).is_err());
        assert_eq!(
            scope_value(&[MuxCapability::Receive, MuxCapability::Pickup]).unwrap(),
            json!(["receive", "pickup"])
        );
    }

    fn event_message(payload: Value) -> Message {
        let doc = json!({
            "id": "urn:uuid:1", "type": EVENT_TYPE, "issuer": "did:example:m",
            "recipient": "did:example:p", "payload": payload,
        });
        Message::build("m1".to_string(), ENVELOPE_TYPE.to_string(), doc).finalize()
    }

    const NONCE: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    #[tokio::test]
    async fn the_transport_absorbs_events_and_tracks_ready() {
        let (ready_tx, mut ready_rx) = tokio::sync::watch::channel(None);
        let (events_tx, mut events_rx) = tokio::sync::broadcast::channel(4);
        let sides = MuxSides {
            ready_tx,
            events_tx,
        };

        let ready = event_message(json!({
            "event": "ready", "sessionId": "sess", "muxNonce": NONCE,
            "maxDidsPerConnection": 10, "maxAttachLifetimeSeconds": 600,
        }));
        assert!(
            sides.absorb(&ready),
            "a mux event is not an application message"
        );
        ready_rx.changed().await.unwrap();
        let got = ready_rx.borrow().clone().expect("ready recorded");
        assert_eq!(got.session_id, "sess");
        assert_eq!(got.mux_nonce, NONCE);
        assert_eq!(got.max_dids_per_connection, Some(10));
        assert_eq!(
            serde_json::to_value(events_rx.recv().await.unwrap()).unwrap()["event"],
            "ready"
        );

        // An ordinary message passes through untouched.
        let other = Message::build(
            "m2".to_string(),
            "https://didcomm.org/basicmessage/2.0/message".to_string(),
            json!({"content": "hi"}),
        )
        .finalize();
        assert!(!sides.absorb(&other));

        // A new socket forgets the old session's nonce.
        sides.reset();
        assert!(ready_rx.borrow().is_none());
    }

    #[test]
    fn events_are_recognised_by_type() {
        let doc = json!({
            "id": "urn:uuid:1", "type": EVENT_TYPE, "issuer": "did:example:m",
            "recipient": "did:example:p",
            "payload": { "event": "ready", "sessionId": "s",
                         "muxNonce": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" }
        });
        let msg = Message::build("m1".to_string(), ENVELOPE_TYPE.to_string(), doc).finalize();
        let ev = decode_mux_event(&msg).expect("a ready event");
        assert_eq!(serde_json::to_value(&ev.payload).unwrap()["event"], "ready");
        assert!(decode_mux_notice(&msg).is_none());
    }
}
