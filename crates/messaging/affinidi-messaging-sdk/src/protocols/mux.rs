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
//! The mediator also stores durable `messaging/mux/notice` documents in the
//! principal's (or, for `grantsPresent`, the member's) inbox: grants
//! suspended (recreate them), revoked, expiring, or present on a DID. On a mux
//! connection the transport verifies each one and hands it to
//! [`ATMProfile::mux_notices`](crate::profiles::ATMProfile::mux_notices)
//! instead of the ordinary message stream; acknowledge it with
//! [`ack_mux_notice`] once handled, which deletes it. Elsewhere use
//! [`verify_mux_notice`] on a received message. The `ready` event's
//! [`MuxReady::pending_notices`] says how many wait.
//!
//! **Nothing here happens by default.** Every grant and attach is an explicit
//! call with an explicit scope; there is no implicit membership, renewal or
//! re-attach.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use affinidi_did_common::DocumentExt;
use affinidi_messaging_didcomm::message::Message;
use affinidi_secrets_resolver::SecretsResolver;
use affinidi_secrets_resolver::secrets::{KeyType, Secret};
use serde::Serialize;
use serde_json::{Value, json};
use tracing::warn;
use trust_tasks_proof::affinidi::{
    CachedDidResolver, ProofPurposeResolver, SignOptions, Verifier, sign_trust_task,
};
use trust_tasks_rs::TrustTask;
use uuid::Uuid;

use crate::tasks::messaging::mux;
use crate::{ATM, errors::ATMError};

/// The Trust Tasks DIDComm envelope `type`.
const ENVELOPE_TYPE: &str = "https://trusttasks.org/binding/didcomm/0.1/envelope";
/// `messaging/mux/event` Type URI.
pub(crate) const EVENT_TYPE: &str = "https://trusttasks.org/spec/messaging/mux/event/0.1";
/// `messaging/mux/notice` Type URI.
const NOTICE_TYPE: &str = "https://trusttasks.org/spec/messaging/mux/notice/0.1";

/// The current mux connection's `ready` event: what an attach must be bound
/// to. A new value arrives with every (re)connect; the nonce from an earlier
/// connection is useless on a new one.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct MuxReady {
    pub session_id: String,
    pub mux_nonce: String,
    pub max_dids_per_connection: Option<u64>,
    pub max_attach_lifetime_seconds: Option<u64>,
    pub max_grant_lifetime_seconds: Option<u64>,
    /// How many `messaging/mux/notice` documents wait in the principal's
    /// inbox. Non-zero means drain them before trusting the member set.
    /// `None` from a mediator that does not report it.
    pub pending_notices: Option<u64>,
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
            pending_notices: u("pendingNotices"),
        })
    }
}

impl MuxReady {
    /// The `ready` carried by `event`, if it is one with a session id and a
    /// nonce.
    pub fn from_event(event: &MuxEvent) -> Option<Self> {
        Self::from_payload(&serde_json::to_value(event).ok()?)
    }
}

/// A `messaging/mux/event` payload (`ready`, `attached`, `detached`,
/// `refused`), as the generated type.
pub type MuxEvent = mux::event::v0_1::Payload;

/// The kind of a [`MuxEvent`].
pub use mux::event::v0_1::PayloadEvent as MuxEventKind;

/// One member's change in an `attached` or `detached` [`MuxEvent`]
/// (`dids[]`), with its reason (for example `connectionFull`).
pub use mux::event::v0_1::{MemberChange as MuxMemberChange, MemberChangeReason};

/// A `refused` event: the mediator refused an inbound frame on a raw-TSP
/// `tsp-mux` socket and said so in-band instead of closing the socket. Only
/// the refused frame is gone; nothing was stored or delivered for it.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct MuxRefused {
    /// Lowercase hex SHA-256 of the refused frame's exact bytes. Compare with
    /// the id `TspMuxWebSocket::send` returned (`tsp` feature).
    pub frame_id: String,
    /// The mediator's stable refusal code (as the traffic monitor reports it).
    pub code: String,
    /// The frame's sender, when the mediator could read it.
    pub sender: Option<String>,
    /// The frame's receiver, when the mediator could read it.
    pub receiver: Option<String>,
    /// A short explanation, never message content.
    pub reason: Option<String>,
}

impl MuxRefused {
    /// The refusal `event` reports, if it is a well-formed `refused` event.
    pub fn from_event(event: &MuxEvent) -> Option<Self> {
        if event.event != MuxEventKind::Refused {
            return None;
        }
        Some(Self {
            frame_id: event.frame_id.as_ref()?.to_string(),
            code: event.code.as_ref()?.to_string(),
            sender: event.sender.as_ref().map(|d| d.to_string()),
            receiver: event.receiver.as_ref().map(|d| d.to_string()),
            reason: event.reason.as_ref().map(|r| r.to_string()),
        })
    }
}

/// Whether `event` carries what the spec requires of its kind ("Members per
/// kind"); a consumer ignores one that does not. The schema already refuses
/// unknown members; this checks the per-kind required ones.
pub(crate) fn event_is_well_formed(event: &MuxEvent) -> bool {
    match event.event {
        MuxEventKind::Ready => MuxReady::from_event(event).is_some(),
        MuxEventKind::Attached => {
            !event.dids.is_empty()
                && event
                    .dids
                    .iter()
                    .all(|c| c.scope.is_some() && c.delivery_active.is_some())
        }
        MuxEventKind::Detached => !event.dids.is_empty(),
        MuxEventKind::Refused => MuxRefused::from_event(event).is_some(),
    }
}

/// Check a `messaging/mux/event` document before acting on it, once its
/// carrier has shown that `mediator` sent it (authcrypt on DIDComm, the TSP
/// envelope's signature on TSP):
///
/// - its `issuer` is `mediator` and its `recipient` is `principal` (consumer
///   rule 1);
/// - it parses, and carries what its kind requires ("Members per kind");
/// - its Data Integrity `proof`, when it has one, verifies and binds to the
///   issuer. The spec only recommends a proof on events, so one without is
///   accepted on the strength of the connection; one with a proof that does
///   not verify is refused.
///
/// Returns the payload, or why the event must be ignored.
pub async fn verify_mux_event(
    atm: &ATM,
    document: &Value,
    mediator_did: &str,
    principal_did: &str,
) -> Result<MuxEvent, ATMError> {
    check_event(&proof_resolver(atm), document, mediator_did, principal_did).await
}

/// The resolver proofs on mux documents are checked with: the ATM's own
/// (cached) DID resolver.
pub(crate) fn proof_resolver(atm: &ATM) -> Arc<dyn ProofPurposeResolver> {
    Arc::new(CachedDidResolver::new(Arc::new(
        atm.inner.tdk_common.did_resolver().clone(),
    )))
}

pub(crate) async fn check_event(
    resolver: &Arc<dyn ProofPurposeResolver>,
    document: &Value,
    mediator_did: &str,
    principal_did: &str,
) -> Result<MuxEvent, ATMError> {
    let reject = |why: String| Err(ATMError::MsgReceiveError(why));
    if document.get("type").and_then(Value::as_str) != Some(EVENT_TYPE) {
        return reject("not a messaging/mux/event".into());
    }
    if document.get("issuer").and_then(Value::as_str) != Some(mediator_did) {
        return reject(format!(
            "mux event not issued by the mediator {mediator_did}"
        ));
    }
    if document.get("recipient").and_then(Value::as_str) != Some(principal_did) {
        return reject("mux event addressed to someone else".into());
    }
    let task: TrustTask<MuxEvent> = match serde_json::from_value(document.clone()) {
        Ok(t) => t,
        Err(e) => return reject(format!("mux event does not parse: {e}")),
    };
    if !event_is_well_formed(&task.payload) {
        return reject(format!("malformed mux `{}` event", task.payload.event));
    }
    if document.get("proof").is_some()
        && let Err(e) = Verifier::with_resolver(resolver.clone())
            .verify_raw(document)
            .await
    {
        return reject(format!("mux event proof: {e}"));
    }
    Ok(task.payload)
}

/// One member DID on the current mux connection, as its latest `attached`
/// event described it.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct MuxMember {
    pub did: String,
    /// The scope in force for the member.
    pub scope: Vec<MuxCapability>,
    /// Whether the member's live traffic comes over this connection. `false`
    /// while the DID's own direct connection (or a newer connection) takes
    /// it: the member stays in the set, inactive, until an `attached` event
    /// with reason `reactivated`.
    pub delivery_active: bool,
    /// The grant carrying the member; `None` for a session attach.
    pub grant_id: Option<String>,
    /// When the membership lapses unless renewed.
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Why the member last changed (`connect`, `grant`, `attach`,
    /// `reactivated`, or `superseded`).
    pub reason: MemberChangeReason,
}

/// The member set of the current mux connection, kept from its `ready`,
/// `attached` and `detached` events (consumer rule 4). Empty, and not
/// [`ready`](Self::is_ready), until the connection's `ready` arrives; emptied
/// again on every new connection. Nothing carries over from an earlier one.
///
/// When [`MuxReady::pending_notices`] is above zero, drain
/// [`mux_notices`](crate::profiles::ATMProfile::mux_notices) before trusting
/// this set (consumer rule 3).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MuxMembers {
    ready: bool,
    members: BTreeMap<String, MuxMember>,
}

impl MuxMembers {
    /// A connection whose `ready` has arrived and that has no members yet.
    pub(crate) fn connected() -> Self {
        Self {
            ready: true,
            members: BTreeMap::new(),
        }
    }

    /// Whether this connection's `ready` has arrived. Before it no member is
    /// reachable through the connection.
    pub fn is_ready(&self) -> bool {
        self.ready
    }

    /// The member `did`, if it is in the set (active or not).
    pub fn get(&self, did: &str) -> Option<&MuxMember> {
        self.members.get(did)
    }

    /// Whether `did`'s live traffic comes over this connection now: it is a
    /// member and its delivery is active.
    pub fn is_reachable(&self, did: &str) -> bool {
        self.get(did).is_some_and(|m| m.delivery_active)
    }

    /// Every member, in DID order.
    pub fn iter(&self) -> impl Iterator<Item = &MuxMember> {
        self.members.values()
    }

    pub fn len(&self) -> usize {
        self.members.len()
    }

    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// Fold one verified event into the set. Returns whether the set changed.
    ///
    /// - `ready` starts a new connection: the set empties.
    /// - `attached` adds the member, or replaces it with the new scope,
    ///   expiry and delivery state.
    /// - `detached` removes it, except `superseded`, which keeps it inactive
    ///   (producer rule 6). `connectionFull` names a grant that never joined.
    ///
    /// A member event before `ready` is ignored: nothing is reachable on a
    /// connection that has not shown it is a mux connection.
    pub(crate) fn apply(&mut self, event: &MuxEvent) -> bool {
        match event.event {
            MuxEventKind::Ready => {
                let changed = !self.ready || !self.members.is_empty();
                *self = Self::connected();
                changed
            }
            MuxEventKind::Attached if self.ready => {
                for c in &event.dids {
                    let member = MuxMember {
                        did: c.did.to_string(),
                        scope: c
                            .scope
                            .as_ref()
                            .map(|s| s.iter().map(|v| MuxCapability::from(*v)).collect())
                            .unwrap_or_default(),
                        delivery_active: c.delivery_active.unwrap_or(false),
                        grant_id: c.grant_id.as_ref().map(|g| g.to_string()),
                        expires_at: c.expires_at,
                        reason: c.reason,
                    };
                    self.members.insert(member.did.clone(), member);
                }
                true
            }
            MuxEventKind::Detached if self.ready => {
                let mut changed = false;
                for c in &event.dids {
                    let did: &str = &c.did;
                    if c.reason == MemberChangeReason::Superseded {
                        if let Some(m) = self.members.get_mut(did) {
                            m.delivery_active = false;
                            m.reason = c.reason;
                            changed = true;
                        }
                    } else {
                        changed |= self.members.remove(did).is_some();
                    }
                }
                changed
            }
            _ => false,
        }
    }
}

impl From<mux::event::v0_1::MuxScopeValue> for MuxCapability {
    fn from(v: mux::event::v0_1::MuxScopeValue) -> Self {
        use mux::event::v0_1::MuxScopeValue as V;
        match v {
            V::Receive => Self::Receive,
            V::Pickup => Self::Pickup,
            V::Delete => Self::Delete,
            V::Send => Self::Send,
        }
    }
}

/// A `messaging/mux/notice` payload (`grantsSuspended`, `grantsRevoked`,
/// `grantsExpiring`, `grantsPresent`), as the generated type.
pub type MuxNotice = mux::notice::v0_1::Payload;

/// A durable notice delivered on a mux connection, already verified (its
/// proof, and that the profile's mediator issued it). It stays in the inbox
/// until [`ack_mux_notice`] deletes it, so one not acknowledged is delivered
/// again on the next connection (at least once). The same notice may arrive
/// twice: `document.id` identifies it.
#[derive(Clone, Debug)]
pub struct MuxNoticeDelivery {
    /// The signed notice document.
    pub document: TrustTask<MuxNotice>,
    /// The stored message's id at the mediator, for [`ack_mux_notice`].
    pub message_id: String,
}

/// The receive side of a mux connection, installed on the profile's
/// mediator by the websocket transport.
#[derive(Debug)]
pub(crate) struct MuxHandles {
    pub(crate) ready_rx: tokio::sync::watch::Receiver<Option<MuxReady>>,
    pub(crate) members_rx: tokio::sync::watch::Receiver<MuxMembers>,
    pub(crate) events_tx: tokio::sync::broadcast::Sender<MuxEvent>,
    pub(crate) notices_tx: tokio::sync::broadcast::Sender<MuxNoticeDelivery>,
}

/// The transport's half of [`MuxHandles`].
#[derive(Debug)]
pub(crate) struct MuxSides {
    pub(crate) ready_tx: tokio::sync::watch::Sender<Option<MuxReady>>,
    pub(crate) members_tx: tokio::sync::watch::Sender<MuxMembers>,
    pub(crate) events_tx: tokio::sync::broadcast::Sender<MuxEvent>,
    pub(crate) notices_tx: tokio::sync::broadcast::Sender<MuxNoticeDelivery>,
    /// The profile's mediator: the only sender and issuer an event or a
    /// notice is accepted from.
    pub(crate) mediator_did: String,
    /// The profile's DID: the only recipient an event is accepted for.
    pub(crate) principal_did: String,
}

impl MuxSides {
    /// A new socket means a new mux session: forget the old `ready` and the
    /// old member set.
    pub(crate) fn reset(&self) {
        let _ = self.ready_tx.send(None);
        self.members_tx.send_replace(MuxMembers::default());
    }

    /// Consume a mux event arriving on the socket. Returns whether the
    /// message was taken (and so must not be handed to the application as an
    /// ordinary message).
    ///
    /// Only the mediator speaks for the connection: an event document that
    /// was not authcrypted by the profile's mediator is not an event, and
    /// passes through as the ordinary (stored) message it is. One from the
    /// mediator that fails [`check_event`] is dropped: events are never
    /// stored, so there is nothing to delete.
    pub(crate) async fn absorb(
        &self,
        resolver: &Arc<dyn ProofPurposeResolver>,
        message: &Message,
        meta: &crate::messages::compat::UnpackMetadata,
    ) -> bool {
        if message.typ != ENVELOPE_TYPE
            || message.body.get("type").and_then(Value::as_str) != Some(EVENT_TYPE)
        {
            return false;
        }
        if !sent_by(meta, &self.mediator_did) {
            warn!(
                from = ?meta.encrypted_from_kid,
                "a mux event not authcrypted by this profile's mediator; passing it on as an ordinary message"
            );
            return false;
        }
        let event = match check_event(
            resolver,
            &message.body,
            &self.mediator_did,
            &self.principal_did,
        )
        .await
        {
            Ok(e) => e,
            Err(e) => {
                warn!(error = %e, "ignoring a mux event");
                return true;
            }
        };
        if let Some(ready) = MuxReady::from_event(&event) {
            let _ = self.ready_tx.send(Some(ready));
        }
        self.members_tx.send_if_modified(|m| m.apply(&event));
        let _ = self.events_tx.send(event);
        true
    }
}

/// Whether an unpacked message was authcrypted by `did` (its sender key is
/// one of `did`'s). Anoncrypt and plaintext are nobody's.
fn sent_by(meta: &crate::messages::compat::UnpackMetadata, did: &str) -> bool {
    meta.authenticated
        && meta
            .encrypted_from_kid
            .as_deref()
            .is_some_and(|kid| kid.split('#').next() == Some(did))
}

impl MuxSides {
    /// Take a durable notice out of the ordinary message stream: verify it,
    /// then hand it to [`ATMProfile::mux_notices`] subscribers. Returns
    /// whether it was taken. A notice that does not verify, or that nobody
    /// is subscribed to, stays an ordinary message (it is still in the inbox
    /// either way; nothing is deleted here).
    ///
    /// [`ATMProfile::mux_notices`]: crate::profiles::ATMProfile::mux_notices
    pub(crate) async fn take_notice(&self, atm: &ATM, message: &Message, message_id: &str) -> bool {
        if decode_mux_notice(message).is_none() || self.notices_tx.receiver_count() == 0 {
            return false;
        }
        match verify_mux_notice(atm, message, &self.mediator_did).await {
            Ok(document) => self
                .notices_tx
                .send(MuxNoticeDelivery {
                    document,
                    message_id: message_id.to_string(),
                })
                .is_ok(),
            Err(e) => {
                warn!(error = %e, "a mux notice did not verify; passing it on as an ordinary message");
                false
            }
        }
    }
}

/// Channel capacity for mux events: they are rare control messages.
pub(crate) const MUX_EVENT_CAPACITY: usize = 64;

/// The WebSocket subprotocol that asks the mediator for a mux connection
/// (`messaging/mux/event/0.1`, "DIDComm sockets").
pub const MUX_SUBPROTOCOL: &str = "didcomm-mux";

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

/// Verify a received `messaging/mux/notice` before acting on it (spec consumer
/// rule 1): its Data Integrity proof verifies, binds to its `issuer`, and
/// that issuer is `mediator_did`. Returns the typed notice.
pub async fn verify_mux_notice(
    atm: &ATM,
    message: &Message,
    mediator_did: &str,
) -> Result<TrustTask<MuxNotice>, ATMError> {
    verify_notice_with(proof_resolver(atm), message, mediator_did).await
}

async fn verify_notice_with(
    resolver: Arc<dyn ProofPurposeResolver>,
    message: &Message,
    mediator_did: &str,
) -> Result<TrustTask<MuxNotice>, ATMError> {
    let document = decode_mux_notice(message)
        .ok_or_else(|| ATMError::MsgReceiveError("not a messaging/mux/notice".to_string()))?;
    if message.body.get("issuer").and_then(Value::as_str) != Some(mediator_did) {
        return Err(ATMError::MsgReceiveError(format!(
            "mux notice not issued by the mediator {mediator_did}"
        )));
    }
    Verifier::with_resolver(resolver)
        .verify_raw(&message.body)
        .await
        .map_err(|e| ATMError::MsgReceiveError(format!("mux notice proof: {e}")))?;
    Ok(document)
}

/// Acknowledge a handled notice: delete it from the inbox (spec consumer
/// rule 2). Call only after acting on it; until then it is redelivered.
pub async fn ack_mux_notice(
    atm: &ATM,
    profile: &std::sync::Arc<crate::profiles::ATMProfile>,
    delivery: &MuxNoticeDelivery,
) -> Result<(), ATMError> {
    let r = atm
        .delete_messages_direct(
            profile,
            &crate::messages::DeleteMessageRequest {
                message_ids: vec![delivery.message_id.clone()],
            },
        )
        .await?;
    if r.success.iter().any(|id| id == &delivery.message_id) {
        Ok(())
    } else {
        Err(ATMError::MsgSendError(format!(
            "mux notice {} not deleted: {:?}",
            delivery.message_id, r.errors
        )))
    }
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

    fn event_doc(issuer: &str, recipient: &str, payload: Value) -> Value {
        json!({
            "id": "urn:uuid:1", "type": EVENT_TYPE, "issuer": issuer,
            "recipient": recipient, "issuedAt": "2026-11-09T09:00:01Z",
            "payload": payload,
        })
    }

    fn event_message(payload: Value) -> Message {
        envelope(event_doc(MEDIATOR, PRINCIPAL, payload))
    }

    fn envelope(doc: Value) -> Message {
        Message::build("m1".to_string(), ENVELOPE_TYPE.to_string(), doc).finalize()
    }

    const MEDIATOR: &str = "did:example:m";
    const PRINCIPAL: &str = "did:example:p";
    const NONCE: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    /// Unpack metadata for a message authcrypted by `did`.
    fn authcrypted_by(did: &str) -> crate::messages::compat::UnpackMetadata {
        crate::messages::compat::UnpackMetadata {
            encrypted: true,
            authenticated: true,
            encrypted_from_kid: Some(format!("{did}#key-1")),
            ..Default::default()
        }
    }

    async fn resolver() -> Arc<dyn ProofPurposeResolver> {
        use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
        let client = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .unwrap();
        Arc::new(CachedDidResolver::new(Arc::new(client)))
    }

    struct Sides {
        sides: MuxSides,
        ready: tokio::sync::watch::Receiver<Option<MuxReady>>,
        members: tokio::sync::watch::Receiver<MuxMembers>,
        events: tokio::sync::broadcast::Receiver<MuxEvent>,
    }

    fn sides(mediator: &str) -> Sides {
        let (ready_tx, ready) = tokio::sync::watch::channel(None);
        let (members_tx, members) = tokio::sync::watch::channel(MuxMembers::default());
        let (events_tx, events) = tokio::sync::broadcast::channel(16);
        let (notices_tx, _) = tokio::sync::broadcast::channel(4);
        Sides {
            sides: MuxSides {
                ready_tx,
                members_tx,
                events_tx,
                notices_tx,
                mediator_did: mediator.to_string(),
                principal_did: PRINCIPAL.to_string(),
            },
            ready,
            members,
            events,
        }
    }

    fn ready_payload() -> Value {
        json!({
            "event": "ready", "sessionId": "sess", "muxNonce": NONCE,
            "maxDidsPerConnection": 10, "maxAttachLifetimeSeconds": 600,
            "pendingNotices": 2,
        })
    }

    fn attached(did: &str, reason: &str, active: bool) -> Value {
        json!({ "did": did, "reason": reason, "scope": ["receive", "delete"],
                "deliveryActive": active, "grantId": format!("g-{}", &did[12..]) })
    }

    #[tokio::test]
    async fn the_transport_absorbs_events_and_tracks_ready() {
        let r = resolver().await;
        let mut s = sides(MEDIATOR);
        let from_mediator = authcrypted_by(MEDIATOR);

        assert!(
            s.sides
                .absorb(&r, &event_message(ready_payload()), &from_mediator)
                .await,
            "a mux event is not an application message"
        );
        let got = s.ready.borrow().clone().expect("ready recorded");
        assert_eq!(got.session_id, "sess");
        assert_eq!(got.mux_nonce, NONCE);
        assert_eq!(got.max_dids_per_connection, Some(10));
        assert_eq!(got.pending_notices, Some(2));
        assert!(s.members.borrow().is_ready());
        assert_eq!(
            serde_json::to_value(s.events.recv().await.unwrap()).unwrap()["event"],
            "ready"
        );

        // An ordinary message passes through untouched.
        let other = Message::build(
            "m2".to_string(),
            "https://didcomm.org/basicmessage/2.0/message".to_string(),
            json!({"content": "hi"}),
        )
        .finalize();
        assert!(!s.sides.absorb(&r, &other, &from_mediator).await);

        // A new socket forgets the old session's nonce and members.
        s.sides.reset();
        assert!(s.ready.borrow().is_none());
        assert!(!s.members.borrow().is_ready());
    }

    /// Consumer rule 1, and the premise of the spec's proof rule: only the
    /// mediator speaks for the connection. Before this check any peer able
    /// to message the principal could send it a `ready` (a nonce of its
    /// choosing for the next attach) or a `detached`.
    #[tokio::test]
    async fn only_the_mediator_speaks_for_the_connection() {
        let r = resolver().await;
        let mut s = sides(MEDIATOR);
        let ready = event_message(ready_payload());

        // Authcrypted by a peer: an ordinary message, not an event.
        assert!(
            !s.sides
                .absorb(&r, &ready, &authcrypted_by("did:example:peer"))
                .await
        );
        // Anoncrypt names no sender: the same.
        let anon = crate::messages::compat::UnpackMetadata {
            encrypted: true,
            encrypted_to_kids: vec![format!("{PRINCIPAL}#key-1")],
            ..Default::default()
        };
        assert!(!s.sides.absorb(&r, &ready, &anon).await);
        assert!(s.ready.borrow().is_none(), "no ready taken from a peer");

        // From the mediator, but addressed to someone else or naming another
        // issuer: dropped (events are never stored), and not acted on.
        let from_mediator = authcrypted_by(MEDIATOR);
        for doc in [
            event_doc(MEDIATOR, "did:example:other", ready_payload()),
            event_doc("did:example:other", PRINCIPAL, ready_payload()),
        ] {
            assert!(s.sides.absorb(&r, &envelope(doc), &from_mediator).await);
        }
        // Malformed for its kind: an `attached` entry without its scope.
        let bare = event_message(json!({"event": "attached",
            "dids": [{"did": "did:example:work", "reason": "grant"}]}));
        assert!(s.sides.absorb(&r, &bare, &from_mediator).await);
        assert!(s.ready.borrow().is_none());
        assert!(s.events.try_recv().is_err(), "nothing reached mux_events()");
    }

    #[tokio::test]
    async fn an_event_proof_is_checked_when_present() {
        let r = resolver().await;
        let (mediator, secret) = mediator_key();
        let mut s = sides(&mediator);
        let from_mediator = authcrypted_by(&mediator);

        let signed = sign_trust_task(
            &event_doc(&mediator, PRINCIPAL, ready_payload()),
            &secret,
            SignOptions::new(),
        )
        .await
        .unwrap();
        let mut forged = signed.clone();
        forged["payload"]["muxNonce"] = json!("B".repeat(43));
        assert!(s.sides.absorb(&r, &envelope(forged), &from_mediator).await);
        assert!(s.ready.borrow().is_none(), "a proof that fails is refused");

        assert!(s.sides.absorb(&r, &envelope(signed), &from_mediator).await);
        assert_eq!(s.ready.borrow().as_ref().unwrap().mux_nonce, NONCE);
        assert!(s.events.try_recv().is_ok());
    }

    #[tokio::test]
    async fn the_member_set_follows_attached_and_detached() {
        let r = resolver().await;
        let s = sides(MEDIATOR);
        let from_mediator = authcrypted_by(MEDIATOR);
        let absorb = |payload: Value| {
            let (sides, r, m) = (&s.sides, &r, &from_mediator);
            async move { assert!(sides.absorb(r, &event_message(payload), m).await) }
        };
        const WORK: &str = "did:example:work";
        const HOME: &str = "did:example:home";

        // Before `ready` nothing is reachable (DIDComm binding rule 1).
        absorb(json!({"event": "attached", "dids": [attached(WORK, "connect", true)]})).await;
        assert!(s.members.borrow().is_empty());

        absorb(ready_payload()).await;
        absorb(json!({"event": "attached", "dids": [
            attached(WORK, "connect", true), attached(HOME, "connect", false)]}))
        .await;
        {
            let m = s.members.borrow();
            assert_eq!(m.len(), 2);
            assert!(m.is_reachable(WORK));
            assert!(!m.is_reachable(HOME), "inactive while its own socket is up");
            let work = m.get(WORK).unwrap();
            assert_eq!(
                work.scope,
                vec![MuxCapability::Receive, MuxCapability::Delete]
            );
            assert_eq!(work.grant_id.as_deref(), Some("g-work"));
            assert_eq!(work.reason, MemberChangeReason::Connect);
        }

        // Superseded keeps the member, inactive; reactivated restores it.
        absorb(json!({"event": "detached",
            "dids": [{"did": WORK, "reason": "superseded"}]}))
        .await;
        assert!(!s.members.borrow().is_reachable(WORK));
        assert!(s.members.borrow().get(WORK).is_some());
        absorb(json!({"event": "attached", "dids": [attached(WORK, "reactivated", true)]})).await;
        assert!(s.members.borrow().is_reachable(WORK));

        // Any other detach removes it; connectionFull names one never added.
        absorb(json!({"event": "detached", "dids": [
            {"did": WORK, "reason": "revokedByMember", "grantId": "g-work"},
            {"did": "did:example:full", "reason": "connectionFull"}]}))
        .await;
        let m = s.members.borrow().clone();
        assert!(m.get(WORK).is_none());
        assert_eq!(m.iter().map(|m| m.did.as_str()).collect::<Vec<_>>(), [HOME]);

        // A new `ready` is a new connection: nothing carries over.
        absorb(ready_payload()).await;
        assert!(s.members.borrow().is_empty());
        assert!(s.members.borrow().is_ready());
    }

    /// `connectionFull` (spec dtgwg-trust-tasks-tf#1078): a valid grant the
    /// connection had no room for. Before the re-pin the typed event failed
    /// to parse and was dropped, so the principal never learned of it.
    #[tokio::test]
    async fn a_connection_full_detach_parses_and_reaches_mux_events() {
        let r = resolver().await;
        let mut s = sides(MEDIATOR);
        let detached = event_message(json!({
            "event": "detached",
            "dids": [{
                "did": "did:example:work",
                "reason": "connectionFull",
                "grantId": "0b8f6c1e-3a2d-4f5e-9b7c-1d2e3f4a5b6c"
            }]
        }));
        let decoded = decode_mux_event(&detached).expect("a connectionFull detach parses");
        assert_eq!(
            decoded.payload.dids[0].reason,
            mux::event::v0_1::MemberChangeReason::ConnectionFull
        );
        assert!(
            s.sides
                .absorb(&r, &detached, &authcrypted_by(MEDIATOR))
                .await
        );
        let ev = s.events.recv().await.expect("delivered to mux_events()");
        assert_eq!(
            ev.dids[0].reason,
            mux::event::v0_1::MemberChangeReason::ConnectionFull
        );
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

    async fn signed_notice(secret: &Secret, issuer: &str) -> Message {
        let doc = json!({
            "id": "urn:uuid:5b6c7d8e-9f0a-4b1c-8d2e-3f4a5b6c7d01",
            "type": NOTICE_TYPE,
            "issuer": issuer,
            "recipient": "did:example:phone",
            "issuedAt": "2026-11-09T10:42:17Z",
            "payload": {
                "notice": "grantsSuspended",
                "suspensions": [{
                    "did": "did:example:work",
                    "grantIds": ["g1"],
                    "reason": "suspendedUnknownKey",
                    "suspendedAt": "2026-11-09T10:42:17Z"
                }]
            }
        });
        let signed = sign_trust_task(&doc, secret, SignOptions::new())
            .await
            .unwrap();
        Message::build("n1".to_string(), ENVELOPE_TYPE.to_string(), signed).finalize()
    }

    fn mediator_key() -> (String, Secret) {
        let seed = [7u8; 32];
        let mb = Secret::generate_ed25519(None, Some(&seed))
            .get_public_keymultibase()
            .unwrap();
        let did = format!("did:key:{mb}");
        let secret = Secret::generate_ed25519(Some(&format!("{did}#{mb}")), Some(&seed));
        (did, secret)
    }

    #[tokio::test]
    async fn a_notice_is_accepted_only_from_the_mediator_with_a_valid_proof() {
        let resolver = resolver().await;
        let (mediator, secret) = mediator_key();
        let msg = signed_notice(&secret, &mediator).await;

        let n = verify_notice_with(resolver.clone(), &msg, &mediator)
            .await
            .expect("the mediator's signed notice");
        assert_eq!(
            serde_json::to_value(&n.payload).unwrap()["notice"],
            "grantsSuspended"
        );

        // Issued by anyone else: refused, even with a valid proof.
        assert!(
            verify_notice_with(resolver.clone(), &msg, "did:example:other-mediator")
                .await
                .is_err()
        );

        // Tampered after signing: the proof no longer verifies.
        let mut forged = msg.clone();
        forged.body["payload"]["suspensions"][0]["grantIds"] = json!(["g2"]);
        assert!(
            verify_notice_with(resolver.clone(), &forged, &mediator)
                .await
                .is_err()
        );

        // Unsigned: refused.
        let mut unsigned = msg.clone();
        unsigned.body.as_object_mut().unwrap().remove("proof");
        assert!(
            verify_notice_with(resolver.clone(), &unsigned, &mediator)
                .await
                .is_err()
        );
    }
}
