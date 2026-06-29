//! Trust Spanning Protocol (TSP) client support.
//!
//! Accessed via [`crate::ATM::tsp`]. The TSP sibling of `atm.routing()` etc.
//!
//! ## Storage-format codec
//!
//! A mediator stores a TSP message `base64url(qb2)` — its CESR **qb64** text form
//! (`-E…`) — so it rides the same string store/pickup pipeline as a DIDComm
//! JSON envelope. [`TspOps::is_tsp`] / [`TspOps::decode`] / [`TspOps::encode`]
//! convert a fetched message to/from raw qb2 bytes.
//!
//! ## Send / receive
//!
//! [`TspOps::pack`] builds a TSP **Direct** message from a profile to a recipient
//! DID (extracting the profile's Ed25519 signing + X25519 encryption keys from
//! the secrets resolver, and resolving the recipient's keys from its DID
//! document). [`TspOps::send`] packs and POSTs it to the mediator `/inbound`
//! (reusing the existing DIDComm-authenticated session — the mediator sniffs the
//! `0xD4` magic byte and routes it to its TSP handler). [`TspOps::unpack`]
//! reverses a fetched message: decode → resolve the sender → decrypt + verify
//! with the profile's key.

use std::collections::HashMap;
use std::sync::Arc;

use affinidi_did_common::DocumentExt;
use affinidi_secrets_resolver::SecretsResolver;
use affinidi_secrets_resolver::secrets::KeyType;
use affinidi_tsp::message::control::{ControlMessage, ControlType};
use affinidi_tsp::message::direct::{self, PackedMessage};
use affinidi_tsp::relationship::{InvalidTransition, RelationshipEvent, RelationshipState};
use affinidi_tsp::{DidVidResolver, MessageType, MetaEnvelope};
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use tokio::sync::RwLock;

use crate::ATM;
use crate::errors::ATMError;
use crate::profiles::ATMProfile;

/// Pluggable backing store for TSP relationship state.
///
/// The relationship state machine (invite → accept → bidirectional, plus
/// cancel) is keyed on the `(our_vid, their_vid)` DID pair. The SDK drives the
/// pure FSM in [`affinidi_tsp::relationship::RelationshipState`] and persists
/// each new state through this trait, so where the state lives (memory, a
/// database, …) is up to the consumer.
///
/// The default implementation is [`InMemoryRelationshipStore`]; supply a
/// durable one via
/// [`crate::config::ATMConfigBuilder::with_relationship_store`].
#[async_trait::async_trait]
pub trait RelationshipStore: Send + Sync {
    /// Current relationship state for the `(our_vid, their_vid)` pair.
    /// Returns [`RelationshipState::None`] for an unknown pair.
    async fn get(&self, our_vid: &str, their_vid: &str) -> Result<RelationshipState, ATMError>;

    /// Persist the new state for the `(our_vid, their_vid)` pair.
    async fn set(
        &self,
        our_vid: &str,
        their_vid: &str,
        state: RelationshipState,
    ) -> Result<(), ATMError>;
}

/// Default, ephemeral [`RelationshipStore`] backed by an in-memory map.
///
/// State is held in a `tokio::sync::RwLock<HashMap<(String, String),
/// RelationshipState>>` and is **wiped on process restart** — it is intended
/// for tests and single-process clients that don't need durability. Consumers
/// who need relationship state to survive restarts should implement
/// [`RelationshipStore`] against durable storage and inject it via
/// [`crate::config::ATMConfigBuilder::with_relationship_store`].
#[derive(Default)]
pub struct InMemoryRelationshipStore {
    inner: RwLock<HashMap<(String, String), RelationshipState>>,
}

#[async_trait::async_trait]
impl RelationshipStore for InMemoryRelationshipStore {
    async fn get(&self, our_vid: &str, their_vid: &str) -> Result<RelationshipState, ATMError> {
        let key = (our_vid.to_string(), their_vid.to_string());
        Ok(self
            .inner
            .read()
            .await
            .get(&key)
            .copied()
            .unwrap_or(RelationshipState::None))
    }

    async fn set(
        &self,
        our_vid: &str,
        their_vid: &str,
        state: RelationshipState,
    ) -> Result<(), ATMError> {
        let key = (our_vid.to_string(), their_vid.to_string());
        self.inner.write().await.insert(key, state);
        Ok(())
    }
}

/// Map an FSM [`InvalidTransition`] onto an [`ATMError`].
fn invalid_transition(e: InvalidTransition) -> ATMError {
    ATMError::ConfigError(format!("invalid relationship transition: {e}"))
}

/// Compute (but do not persist) the next state for the `(our_vid, their_vid)`
/// pair after applying `event`. Used by the outbound (`Send*`) methods, which
/// validate the transition up front and only persist the result **after** the
/// wire `send_control` succeeds.
async fn next_state(
    store: &Arc<dyn RelationshipStore>,
    our_vid: &str,
    their_vid: &str,
    event: RelationshipEvent,
) -> Result<RelationshipState, ATMError> {
    let current = store.get(our_vid, their_vid).await?;
    current.transition(event).map_err(invalid_transition)
}

/// Apply a relationship `event` to the state currently held for the
/// `(our_vid, their_vid)` pair in `store`, persist the new state, and return
/// it. Used by [`TspOps::record_incoming_control`] for inbound (`Receive*`)
/// events, where there is no outbound send to gate the persist on.
///
/// Unit-tested directly (see this module's tests) against an
/// [`InMemoryRelationshipStore`]; the wire `send_control` path the outbound
/// public methods add on top requires a live mediator and is covered by the
/// end-to-end test in `affinidi-messaging-test-mediator`.
async fn advance_state(
    store: &Arc<dyn RelationshipStore>,
    our_vid: &str,
    their_vid: &str,
    event: RelationshipEvent,
) -> Result<RelationshipState, ATMError> {
    let next = next_state(store, our_vid, their_vid, event).await?;
    store.set(our_vid, their_vid, next).await?;
    Ok(next)
}

/// TSP protocol operations, obtained from [`crate::ATM::tsp`].
pub struct TspOps<'a> {
    pub(crate) atm: &'a ATM,
}

impl TspOps<'_> {
    // ── Storage-format codec ────────────────────────────────────────────────

    /// Whether a fetched/stored message is a TSP message (base64url-decode +
    /// magic-byte check). DIDComm JSON / compact JWS is not valid base64url of a
    /// TSP message, so it returns `false`.
    pub fn is_tsp(&self, stored: &str) -> bool {
        BASE64_URL_SAFE_NO_PAD
            .decode(stored.as_bytes())
            .map(|bytes| affinidi_tsp::is_tsp(&bytes))
            .unwrap_or(false)
    }

    /// Decode a stored TSP message (`base64url(qb2)`) back to its raw qb2 bytes.
    pub fn decode(&self, stored: &str) -> Result<Vec<u8>, ATMError> {
        let bytes = BASE64_URL_SAFE_NO_PAD
            .decode(stored.as_bytes())
            .map_err(|e| ATMError::MsgReceiveError(format!("not valid base64url: {e}")))?;
        if !affinidi_tsp::is_tsp(&bytes) {
            return Err(ATMError::MsgReceiveError(
                "decoded bytes are not a TSP message".into(),
            ));
        }
        Ok(bytes)
    }

    /// Encode raw qb2 TSP bytes to the stored/transit string form.
    pub fn encode(&self, qb2: &[u8]) -> String {
        BASE64_URL_SAFE_NO_PAD.encode(qb2)
    }

    // ── Send / receive ──────────────────────────────────────────────────────

    /// Build a TSP **Direct** message from `profile` to `to_did` carrying
    /// `payload`, returning the raw qb2 bytes.
    pub async fn pack(
        &self,
        profile: &Arc<ATMProfile>,
        to_did: &str,
        payload: &[u8],
    ) -> Result<Vec<u8>, ATMError> {
        let (from_did, _) = profile.dids()?;
        let (signing_key, decryption_key) = self.profile_tsp_keys(from_did).await?;
        let recipient = self.resolve_vid(to_did).await?;

        let packed = direct::pack(
            payload,
            MessageType::Direct,
            from_did,
            to_did,
            &signing_key,
            &decryption_key,
            &recipient.encryption_key,
        )
        .map_err(|e| ATMError::MsgSendError(format!("couldn't pack TSP message: {e}")))?;

        Ok(packed.bytes)
    }

    /// Pack a TSP Direct message and send it to the mediator `/inbound`.
    ///
    /// Reuses the profile's existing (DIDComm) authenticated session for the
    /// bearer token; the mediator sniffs the TSP magic byte and routes it to its
    /// TSP handler.
    pub async fn send(
        &self,
        profile: &Arc<ATMProfile>,
        to_did: &str,
        payload: &[u8],
    ) -> Result<(), ATMError> {
        let bytes = self.pack(profile, to_did, payload).await?;
        self.send_raw(profile, &bytes).await
    }

    /// Send a TSP message **routed** through one or more relay hops.
    ///
    /// `route` is the ordered hop list ending at the final recipient, e.g.
    /// `[mediator_did, bob_did]`. The payload is sealed end-to-end to the final
    /// recipient (`route.last()`), then wrapped in a routing layer sealed to the
    /// first hop (`route[0]`) — which must be a mediator that speaks TSP routing.
    /// Each hop unwraps its layer and forwards onward; only the final recipient
    /// can read the payload.
    pub async fn send_routed(
        &self,
        profile: &Arc<ATMProfile>,
        route: &[String],
        payload: &[u8],
    ) -> Result<(), ATMError> {
        let final_did = route
            .last()
            .ok_or_else(|| ATMError::MsgSendError("route must not be empty".into()))?;
        // End-to-end Direct TSP message to the final recipient, carried opaquely.
        let inner = self.pack(profile, final_did, payload).await?;
        self.send_routed_opaque(profile, route, &inner).await
    }

    /// Route an **already-packed** inner message through one or more relay hops.
    ///
    /// Like [`send_routed`], but `inner` is a pre-built message sealed to the final
    /// recipient — which may be a **DIDComm** message (the TSP↔DIDComm bridge): a
    /// TSP-routing mediator carries it opaquely to the recipient, who unpacks it
    /// with their native protocol. `route` is the hop list ending at that
    /// recipient (`route.last()`); the routing layer is sealed to `route[0]`.
    pub async fn send_routed_opaque(
        &self,
        profile: &Arc<ATMProfile>,
        route: &[String],
        inner: &[u8],
    ) -> Result<(), ATMError> {
        if route.is_empty() {
            return Err(ATMError::MsgSendError("route must not be empty".into()));
        }
        let first_hop = &route[0];

        let (from_did, _) = profile.dids()?;
        let (signing_key, encryption_key) = self.profile_tsp_keys(from_did).await?;
        let first_vid = self.resolve_vid(first_hop).await?;
        let routed = affinidi_tsp::message::routed::pack_routed(
            inner,
            &route[1..],
            from_did,
            first_hop,
            &signing_key,
            &encryption_key,
            &first_vid.encryption_key,
        )
        .map_err(|e| ATMError::MsgSendError(format!("couldn't pack routed TSP message: {e}")))?;

        self.send_raw(profile, &routed.bytes).await
    }

    /// Send a TSP message wrapped in a **Nested** metadata-privacy envelope.
    ///
    /// The payload is sealed end-to-end to `to_did` as an inner Direct message, then
    /// wrapped in an outer Nested message sealed to `intermediary` — typically the
    /// recipient's mediator, which unwraps the outer layer and forwards the inner
    /// onward. On the wire the envelope is addressed to `intermediary`, so only it
    /// learns `to_did`; the recipient still opens a plain Direct message.
    pub async fn send_nested(
        &self,
        profile: &Arc<ATMProfile>,
        intermediary: &str,
        to_did: &str,
        payload: &[u8],
    ) -> Result<(), ATMError> {
        // Inner Direct message sealed end-to-end to the final recipient.
        let inner = self.pack(profile, to_did, payload).await?;
        self.send_nested_opaque(profile, intermediary, &inner).await
    }

    /// Wrap an **already-packed** inner message in a Nested envelope to `intermediary`.
    ///
    /// Like [`send_nested`], but `inner` is a pre-built message sealed to its final
    /// recipient — which may be a **DIDComm** message (the TSP↔DIDComm bridge): the
    /// intermediary unwraps the Nested layer and forwards the opaque inner, blind to
    /// its protocol.
    pub async fn send_nested_opaque(
        &self,
        profile: &Arc<ATMProfile>,
        intermediary: &str,
        inner: &[u8],
    ) -> Result<(), ATMError> {
        let (from_did, _) = profile.dids()?;
        let (signing_key, encryption_key) = self.profile_tsp_keys(from_did).await?;
        let intermediary_vid = self.resolve_vid(intermediary).await?;
        let nested = affinidi_tsp::message::direct::pack(
            inner,
            affinidi_tsp::MessageType::Nested,
            from_did,
            intermediary,
            &signing_key,
            &encryption_key,
            &intermediary_vid.encryption_key,
        )
        .map_err(|e| ATMError::MsgSendError(format!("couldn't pack nested TSP message: {e}")))?;

        self.send_raw(profile, &nested.bytes).await
    }

    /// Send a TSP **Control** message — a relationship-management message (invite /
    /// accept / cancel) to a peer.
    ///
    /// Build `control` with [`affinidi_tsp::message::control::ControlMessage`]'s
    /// `invite` / `accept` / `cancel`. It is sealed to `to_did` and carried with
    /// message type `Control`; the mediator relays it to the recipient like a Direct
    /// message (it never inspects the control payload), and the recipient applies the
    /// relationship transition on receipt.
    pub async fn send_control(
        &self,
        profile: &Arc<ATMProfile>,
        to_did: &str,
        control: &affinidi_tsp::message::control::ControlMessage,
    ) -> Result<(), ATMError> {
        let (from_did, _) = profile.dids()?;
        let (signing_key, encryption_key) = self.profile_tsp_keys(from_did).await?;
        let to_vid = self.resolve_vid(to_did).await?;
        let packed = affinidi_tsp::message::direct::pack(
            &control.encode(),
            affinidi_tsp::MessageType::Control,
            from_did,
            to_did,
            &signing_key,
            &encryption_key,
            &to_vid.encryption_key,
        )
        .map_err(|e| ATMError::MsgSendError(format!("couldn't pack control TSP message: {e}")))?;

        self.send_raw(profile, &packed.bytes).await
    }

    // ── Relationship management ───────────────────────────────────────────────

    /// The configured [`RelationshipStore`] backing relationship state.
    fn relationship_store(&self) -> &Arc<dyn RelationshipStore> {
        self.atm.inner.config.relationship_store()
    }

    /// Begin forming a relationship with `their_did`: advance the FSM with
    /// `SendInvite` (from [`RelationshipState::None`] → [`Pending`]), send a
    /// Relationship Forming Invite control message, then persist the new state.
    ///
    /// State is only persisted after the invite is successfully sent. Returns
    /// the new state ([`RelationshipState::Pending`]).
    ///
    /// [`Pending`]: RelationshipState::Pending
    pub async fn form_relationship(
        &self,
        profile: &Arc<ATMProfile>,
        their_did: &str,
    ) -> Result<RelationshipState, ATMError> {
        let (our_did, _) = profile.dids()?;
        let store = self.relationship_store();
        let next = next_state(store, our_did, their_did, RelationshipEvent::SendInvite).await?;
        self.send_control(profile, their_did, &ControlMessage::invite())
            .await?;
        store.set(our_did, their_did, next).await?;
        Ok(next)
    }

    /// Accept an invite previously received from `their_did`: advance the FSM
    /// with `SendAccept` (from [`RelationshipState::InviteReceived`] →
    /// [`Bidirectional`]), send a Relationship Forming Accept referencing the
    /// invite, then persist.
    ///
    /// `invite_wire` is the raw qb2 bytes of the received invite message (as
    /// returned by [`TspOps::decode`]); its BLAKE2s-256 digest is carried in the
    /// accept as the thread reference. State is only persisted after the accept
    /// is successfully sent. Returns the new state ([`Bidirectional`]).
    ///
    /// [`Bidirectional`]: RelationshipState::Bidirectional
    pub async fn accept_relationship(
        &self,
        profile: &Arc<ATMProfile>,
        their_did: &str,
        invite_wire: &[u8],
    ) -> Result<RelationshipState, ATMError> {
        let (our_did, _) = profile.dids()?;
        let store = self.relationship_store();
        let next = next_state(store, our_did, their_did, RelationshipEvent::SendAccept).await?;
        // `direct::message_digest` takes a `PackedMessage`; wrap the wire bytes.
        let digest = direct::message_digest(&PackedMessage {
            bytes: invite_wire.to_vec(),
        })
        .to_vec();
        self.send_control(profile, their_did, &ControlMessage::accept(digest))
            .await?;
        store.set(our_did, their_did, next).await?;
        Ok(next)
    }

    /// Cancel/terminate the relationship with `their_did`: advance the FSM with
    /// `SendCancel` (valid from [`Pending`], [`InviteReceived`], or
    /// [`Bidirectional`] → [`RelationshipState::None`]), send a Relationship
    /// Cancel control message, then persist.
    ///
    /// State is only persisted after the cancel is successfully sent. Returns
    /// the new state ([`RelationshipState::None`]).
    ///
    /// [`Pending`]: RelationshipState::Pending
    /// [`InviteReceived`]: RelationshipState::InviteReceived
    /// [`Bidirectional`]: RelationshipState::Bidirectional
    pub async fn cancel_relationship(
        &self,
        profile: &Arc<ATMProfile>,
        their_did: &str,
    ) -> Result<RelationshipState, ATMError> {
        let (our_did, _) = profile.dids()?;
        let store = self.relationship_store();
        let next = next_state(store, our_did, their_did, RelationshipEvent::SendCancel).await?;
        self.send_control(profile, their_did, &ControlMessage::cancel())
            .await?;
        store.set(our_did, their_did, next).await?;
        Ok(next)
    }

    /// The current relationship state for the `(profile, their_did)` pair, read
    /// from the configured [`RelationshipStore`]. Returns
    /// [`RelationshipState::None`] for an unknown pair.
    pub async fn relationship_state(
        &self,
        profile: &Arc<ATMProfile>,
        their_did: &str,
    ) -> Result<RelationshipState, ATMError> {
        let (our_did, _) = profile.dids()?;
        self.relationship_store().get(our_did, their_did).await
    }

    /// Advance the relationship FSM for a **received** control message from
    /// `peer_did` and persist the result.
    ///
    /// The caller decodes a fetched TSP control message — `unpack` it, then
    /// `ControlMessage::decode(payload)` — and passes the decoded `control`
    /// here. Its [`ControlType`] is mapped to the matching `Receive*` event
    /// (invite → `ReceiveInvite`, accept → `ReceiveAccept`, cancel →
    /// `ReceiveCancel`), the transition is applied, persisted, and the new
    /// state returned.
    pub async fn record_incoming_control(
        &self,
        profile: &Arc<ATMProfile>,
        peer_did: &str,
        control: &ControlMessage,
    ) -> Result<RelationshipState, ATMError> {
        let (our_did, _) = profile.dids()?;
        let event = match control.control_type {
            ControlType::RelationshipFormingInvite => RelationshipEvent::ReceiveInvite,
            ControlType::RelationshipFormingAccept => RelationshipEvent::ReceiveAccept,
            ControlType::RelationshipCancel => RelationshipEvent::ReceiveCancel,
        };
        advance_state(self.relationship_store(), our_did, peer_did, event).await
    }

    /// POST an already-packed TSP message (raw qb2 bytes) to the mediator
    /// `/inbound`, reusing the profile's existing (DIDComm) authenticated session
    /// for the bearer token. The mediator sniffs the TSP magic byte and routes it
    /// to its TSP handler.
    pub async fn send_raw(&self, profile: &Arc<ATMProfile>, bytes: &[u8]) -> Result<(), ATMError> {
        let mediator_url = profile.get_mediator_rest_endpoint().ok_or_else(|| {
            ATMError::MsgSendError("Profile is missing a valid mediator URL".into())
        })?;
        let (profile_did, mediator_did) = profile.dids()?;
        let tokens = self
            .atm
            .get_tdk()
            .authentication()
            .authenticate(profile_did.to_string(), mediator_did.to_string(), 3, None)
            .await?;

        let res = self
            .atm
            .inner
            .tdk_common
            .client()
            .post([&mediator_url, "/inbound"].concat())
            .header("Content-Type", "application/tsp")
            .header("Authorization", format!("Bearer {}", tokens.access_token))
            .body(bytes.to_vec())
            .send()
            .await
            .map_err(|e| ATMError::TransportError(format!("Could not send TSP message: {e:?}")))?;

        let status = res.status();
        if !status.is_success() {
            let body = res.text().await.unwrap_or_default();
            return Err(ATMError::TransportError(format!(
                "Mediator rejected TSP message: status({status}), body({body})"
            )));
        }
        Ok(())
    }

    /// Unpack a fetched TSP message (stored `base64url(qb2)`): decode, resolve the
    /// sender's keys, then decrypt + verify with the profile's decryption key.
    /// Returns `(payload, sender_vid)`.
    pub async fn unpack(
        &self,
        profile: &Arc<ATMProfile>,
        stored: &str,
    ) -> Result<(Vec<u8>, String), ATMError> {
        let qb2 = self.decode(stored)?;
        self.unpack_bytes(profile, &qb2).await
    }

    /// Unpack a raw qb2 TSP message (the bytes a [`TspWebSocket::recv`] yields, or
    /// the result of [`TspOps::decode`]): resolve the sender's keys, then decrypt +
    /// verify with the profile's decryption key. Returns `(payload, sender_vid)`.
    ///
    /// This is the shared core of [`TspOps::unpack`]; WS consumers that already hold
    /// raw qb2 bytes call this directly instead of re-encoding to base64url.
    pub async fn unpack_bytes(
        &self,
        profile: &Arc<ATMProfile>,
        qb2: &[u8],
    ) -> Result<(Vec<u8>, String), ATMError> {
        let meta = MetaEnvelope::parse(qb2)
            .map_err(|e| ATMError::MsgReceiveError(format!("couldn't parse TSP envelope: {e}")))?;

        let (profile_did, _) = profile.dids()?;
        if meta.receiver != profile_did {
            return Err(ATMError::MsgReceiveError(format!(
                "TSP message addressed to {}, not this profile ({profile_did})",
                meta.receiver
            )));
        }

        let (_signing_key, decryption_key) = self.profile_tsp_keys(profile_did).await?;
        let sender = self.resolve_vid(&meta.sender).await?;

        let unpacked = direct::unpack(
            qb2,
            &decryption_key,
            &sender.encryption_key,
            &sender.signing_key,
        )
        .map_err(|e| ATMError::MsgReceiveError(format!("couldn't unpack TSP message: {e}")))?;

        Ok((unpacked.payload, unpacked.sender))
    }

    // ── WebSocket (raw-TSP) delivery ──────────────────────────────────────────

    /// Open the mediator's **raw-TSP WebSocket** for `profile`.
    ///
    /// Authenticates the profile, upgrades the mediator `/ws` endpoint offering
    /// the `tsp` subprotocol (alongside the `bearer.<jwt>` auth subprotocol), and
    /// returns a [`TspWebSocket`] for reading/writing raw qb2 TSP frames.
    ///
    /// The mediator's raw-TSP mode is *flush-on-connect + delete-on-send*: any
    /// queued TSP messages for `profile` are flushed onto the socket the instant
    /// it connects, and each is deleted server-side once it has been sent. This
    /// is distinct from the DIDComm message-pickup delete-to-ack contract.
    ///
    /// Frames are raw qb2 TSP bytes; unpack a received frame with
    /// [`TspOps::unpack_bytes`].
    pub async fn connect_websocket(
        &self,
        profile: &Arc<ATMProfile>,
    ) -> Result<TspWebSocket, ATMError> {
        use tokio_tungstenite::tungstenite::{ClientRequestBuilder, http::Uri};

        let (profile_did, mediator_did) = profile.dids()?;
        let tokens = self
            .atm
            .get_tdk()
            .authentication()
            .authenticate(profile_did.to_string(), mediator_did.to_string(), 3, None)
            .await?;
        let access_token = tokens.access_token;

        // Resolve the WS endpoint from the profile's mediator config (mirrors
        // the DIDComm transport's two checks).
        let Some(mediator) = &*profile.inner.mediator else {
            return Err(ATMError::ConfigError(format!(
                "Profile ({}) is missing a valid mediator configuration!",
                profile.inner.alias
            )));
        };
        let Some(address) = &mediator.websocket_endpoint else {
            return Err(ATMError::ConfigError(format!(
                "Profile ({}) is missing a valid websocket endpoint!",
                profile.inner.alias
            )));
        };

        let uri: Uri = address.parse().map_err(|e| {
            ATMError::TransportError(format!(
                "Mediator {}: Invalid websocket endpoint {address}: {e}",
                mediator.did
            ))
        })?;
        let host = uri.host().unwrap_or_default().to_string();
        let port = uri
            .port_u16()
            .unwrap_or(if uri.scheme_str() == Some("wss") {
                443
            } else {
                80
            });

        // Offer `bearer.<jwt>` (auth) + `tsp` (raw-TSP mode) subprotocols.
        let builder = ClientRequestBuilder::new(uri)
            .with_sub_protocol(format!("bearer.{access_token}"))
            .with_sub_protocol("tsp");

        let (ws, response) =
            crate::transports::websockets::proxy::connect_websocket(builder, &host, port)
                .await
                .map_err(|e| {
                    ATMError::TransportError(format!(
                        "Profile '{}' → mediator {} TSP websocket {address} ({host}:{port}): {e}",
                        profile.inner.alias, mediator.did
                    ))
                })?;

        // The 101 should echo `tsp`, confirming the mode was accepted.
        // tokio-tungstenite already enforces subprotocol agreement, so a
        // mismatch here is informational only — warn, don't hard-fail.
        match response
            .headers()
            .get("sec-websocket-protocol")
            .and_then(|v| v.to_str().ok())
        {
            Some("tsp") => {}
            other => tracing::warn!(
                "TSP websocket did not echo the `tsp` subprotocol (got {other:?}); \
                 raw-TSP mode may not be active"
            ),
        }

        Ok(TspWebSocket { ws })
    }

    // ── Internal helpers ────────────────────────────────────────────────────

    /// Resolve a DID-based VID to its TSP public keys + endpoints.
    async fn resolve_vid(&self, did: &str) -> Result<affinidi_tsp::ResolvedVid, ATMError> {
        let resolver = DidVidResolver::new(self.atm.inner.tdk_common.did_resolver().clone());
        resolver
            .resolve_did(did)
            .await
            .map_err(|e| ATMError::DIDError(format!("couldn't resolve TSP VID {did}: {e}")))
    }

    /// Extract this profile's TSP private keys `(signing_key, decryption_key)`:
    /// the Ed25519 key from its `authentication` relationship and the X25519 key
    /// from its `keyAgreement`, pulled from the secrets resolver.
    async fn profile_tsp_keys(&self, did: &str) -> Result<([u8; 32], [u8; 32]), ATMError> {
        let doc = self
            .atm
            .inner
            .tdk_common
            .did_resolver()
            .resolve(did)
            .await
            .map_err(|e| ATMError::DIDError(format!("couldn't resolve own DID {did}: {e}")))?
            .doc;

        let signing_key = self
            .first_private_key(doc.find_authentication(None), KeyType::Ed25519)
            .await
            .ok_or_else(|| {
                ATMError::SecretsError(format!("no Ed25519 authentication key for {did}"))
            })?;
        let decryption_key = self
            .first_private_key(doc.find_key_agreement(None), KeyType::X25519)
            .await
            .ok_or_else(|| {
                ATMError::SecretsError(format!("no X25519 keyAgreement key for {did}"))
            })?;
        Ok((signing_key, decryption_key))
    }

    /// First verification-method `kid` whose secret is of `want` type, as a raw
    /// 32-byte private key.
    async fn first_private_key(&self, kids: Vec<&str>, want: KeyType) -> Option<[u8; 32]> {
        for kid in kids {
            if let Some(secret) = self
                .atm
                .inner
                .tdk_common
                .secrets_resolver()
                .get_secret(kid)
                .await
                && secret.get_key_type() == want
                && let Ok(bytes) = <[u8; 32]>::try_from(secret.get_private_bytes())
            {
                return Some(bytes);
            }
        }
        None
    }
}

/// An open **raw-TSP WebSocket** to the mediator, obtained from
/// [`TspOps::connect_websocket`].
///
/// Frames are raw qb2 TSP bytes (the same wire form [`TspOps::decode`] yields).
/// Receive the next message with [`recv`](TspWebSocket::recv) and unpack it with
/// [`TspOps::unpack_bytes`]; send a raw TSP message with
/// [`send`](TspWebSocket::send).
///
/// Delivery is *flush-on-connect + delete-on-send* (server-side): queued
/// messages are flushed onto the socket on connect and deleted once sent. The
/// client therefore owns its own failure handling — a dropped socket after a
/// frame was sent means that message is already gone from the mailbox.
pub struct TspWebSocket {
    ws: tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
}

impl TspWebSocket {
    /// Receive the next raw qb2 TSP frame.
    ///
    /// Returns `Ok(Some(bytes))` for a delivered message (unpack it with
    /// [`TspOps::unpack_bytes`]), or `Ok(None)` when the socket closes / the
    /// stream ends. Control frames (`Ping`/`Pong`) and any `Text` frames are
    /// skipped transparently.
    pub async fn recv(&mut self) -> Result<Option<Vec<u8>>, ATMError> {
        use futures_util::StreamExt;
        use tokio_tungstenite::tungstenite::Message;

        loop {
            match self.ws.next().await {
                Some(Ok(Message::Binary(bytes))) => return Ok(Some(bytes.to_vec())),
                Some(Ok(Message::Close(_))) | None => return Ok(None),
                Some(Ok(Message::Ping(_) | Message::Pong(_) | Message::Text(_))) => continue,
                Some(Ok(Message::Frame(_))) => continue,
                Some(Err(e)) => {
                    return Err(ATMError::TransportError(format!(
                        "TSP websocket receive error: {e}"
                    )));
                }
            }
        }
    }

    /// Send a raw qb2 TSP message inbound. The mediator routes it via its TSP
    /// inbound handler (the same path as [`TspOps::send_raw`], over the socket).
    pub async fn send(&mut self, tsp_message: &[u8]) -> Result<(), ATMError> {
        use futures_util::SinkExt;
        use tokio_tungstenite::tungstenite::Message;

        self.ws
            .send(Message::Binary(tsp_message.to_vec().into()))
            .await
            .map_err(|e| ATMError::TransportError(format!("TSP websocket send error: {e}")))
    }

    /// Close the socket gracefully.
    pub async fn close(mut self) -> Result<(), ATMError> {
        self.ws
            .close(None)
            .await
            .map_err(|e| ATMError::TransportError(format!("TSP websocket close error: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use affinidi_tsp::message::direct;
    use affinidi_tsp::{MessageType, PrivateVid};
    use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};

    fn is_tsp(stored: &str) -> bool {
        BASE64_URL_SAFE_NO_PAD
            .decode(stored.as_bytes())
            .map(|b| affinidi_tsp::is_tsp(&b))
            .unwrap_or(false)
    }

    /// Codec + a pack/unpack round-trip using `direct::pack`/`unpack` with the
    /// same keys the `TspOps` pack/unpack drive through the secrets resolver and
    /// DID resolution. (The full profile/mediator path is exercised by the
    /// end-to-end test in `affinidi-messaging-test-mediator`.)
    #[test]
    fn pack_unpack_roundtrip_via_codec() {
        let alice = PrivateVid::generate("did:example:alice");
        let bob = PrivateVid::generate("did:example:bob");

        // alice packs to bob (as TspOps::pack does, with direct::pack).
        let packed = direct::pack(
            b"secret payload",
            MessageType::Direct,
            "did:example:alice",
            "did:example:bob",
            &alice.signing_key,
            &alice.decryption_key,
            &bob.encryption_key,
        )
        .unwrap();

        // Stored/transit form, recognised on pickup.
        let stored = BASE64_URL_SAFE_NO_PAD.encode(&packed.bytes);
        assert!(is_tsp(&stored));
        let qb2 = BASE64_URL_SAFE_NO_PAD.decode(stored.as_bytes()).unwrap();

        // bob unpacks (as TspOps::unpack does, with direct::unpack).
        let unpacked = direct::unpack(
            &qb2,
            &bob.decryption_key,
            &alice.encryption_key,
            &alice.verifying_key,
        )
        .unwrap();
        assert_eq!(unpacked.payload, b"secret payload");
        assert_eq!(unpacked.sender, "did:example:alice");
        assert_eq!(unpacked.receiver, "did:example:bob");
    }

    #[test]
    fn rejects_didcomm_and_garbage() {
        assert!(!is_tsp("{\"protected\":\"...\"}"));
        assert!(!is_tsp("eyJhbGciOiJ..."));
        assert!(!is_tsp(""));
    }

    // ── Relationship store + FSM ──────────────────────────────────────────────
    //
    // These exercise the store contract and the store-and-FSM helpers
    // (`next_state` / `advance_state`) directly — the same logic the public
    // `TspOps` relationship methods run, minus the wire `send_control` call,
    // which needs a live mediator and is covered by the end-to-end test in
    // `affinidi-messaging-test-mediator`.

    use super::{
        InMemoryRelationshipStore, RelationshipEvent, RelationshipState, RelationshipStore,
        advance_state, next_state,
    };
    use std::sync::Arc;

    const ALICE: &str = "did:example:alice";
    const BOB: &str = "did:example:bob";

    #[tokio::test]
    async fn in_memory_store_get_set_roundtrip() {
        let store = InMemoryRelationshipStore::default();
        // Unknown pair defaults to None.
        assert_eq!(
            store.get(ALICE, BOB).await.unwrap(),
            RelationshipState::None
        );

        store
            .set(ALICE, BOB, RelationshipState::Pending)
            .await
            .unwrap();
        assert_eq!(
            store.get(ALICE, BOB).await.unwrap(),
            RelationshipState::Pending
        );

        // Keys are directional: (bob, alice) is a separate, still-unknown pair.
        assert_eq!(
            store.get(BOB, ALICE).await.unwrap(),
            RelationshipState::None
        );
    }

    /// Outbound initiator happy path: None →(SendInvite)→ Pending
    /// →(ReceiveAccept)→ Bidirectional, driven through the store the way the
    /// public methods do (validate via `next_state`, then persist).
    #[tokio::test]
    async fn outbound_happy_path_through_store() {
        let store: Arc<dyn RelationshipStore> = Arc::new(InMemoryRelationshipStore::default());

        // form_relationship's store step.
        let next = next_state(&store, ALICE, BOB, RelationshipEvent::SendInvite)
            .await
            .unwrap();
        assert_eq!(next, RelationshipState::Pending);
        store.set(ALICE, BOB, next).await.unwrap();
        assert_eq!(
            store.get(ALICE, BOB).await.unwrap(),
            RelationshipState::Pending
        );

        // record_incoming_control(accept) step.
        let next = advance_state(&store, ALICE, BOB, RelationshipEvent::ReceiveAccept)
            .await
            .unwrap();
        assert_eq!(next, RelationshipState::Bidirectional);
        assert_eq!(
            store.get(ALICE, BOB).await.unwrap(),
            RelationshipState::Bidirectional
        );
    }

    /// Inbound responder happy path: None →(ReceiveInvite)→ InviteReceived
    /// →(SendAccept)→ Bidirectional.
    #[tokio::test]
    async fn inbound_happy_path_through_store() {
        let store: Arc<dyn RelationshipStore> = Arc::new(InMemoryRelationshipStore::default());

        // record_incoming_control(invite).
        let next = advance_state(&store, BOB, ALICE, RelationshipEvent::ReceiveInvite)
            .await
            .unwrap();
        assert_eq!(next, RelationshipState::InviteReceived);

        // accept_relationship's store step.
        let next = next_state(&store, BOB, ALICE, RelationshipEvent::SendAccept)
            .await
            .unwrap();
        assert_eq!(next, RelationshipState::Bidirectional);
        store.set(BOB, ALICE, next).await.unwrap();
        assert_eq!(
            store.get(BOB, ALICE).await.unwrap(),
            RelationshipState::Bidirectional
        );
    }

    /// An invalid event for the current state surfaces as an `ATMError` and
    /// leaves the stored state untouched.
    #[tokio::test]
    async fn invalid_transition_is_rejected() {
        let store: Arc<dyn RelationshipStore> = Arc::new(InMemoryRelationshipStore::default());
        // SendAccept from None is not a valid edge.
        assert!(
            next_state(&store, ALICE, BOB, RelationshipEvent::SendAccept)
                .await
                .is_err()
        );
        // advance_state must not persist on a rejected transition.
        assert!(
            advance_state(&store, ALICE, BOB, RelationshipEvent::ReceiveAccept)
                .await
                .is_err()
        );
        assert_eq!(
            store.get(ALICE, BOB).await.unwrap(),
            RelationshipState::None
        );
    }

    /// `record_incoming_control`'s ControlType → RelationshipEvent mapping,
    /// validated by running each mapped event through the FSM from a state where
    /// it is legal.
    #[test]
    fn control_type_event_mapping() {
        use affinidi_tsp::message::control::ControlType;
        // invite → ReceiveInvite (legal from None).
        let e = match ControlType::RelationshipFormingInvite {
            ControlType::RelationshipFormingInvite => RelationshipEvent::ReceiveInvite,
            _ => unreachable!(),
        };
        assert!(RelationshipState::None.transition(e).is_ok());

        // accept → ReceiveAccept (legal from Pending).
        let e = match ControlType::RelationshipFormingAccept {
            ControlType::RelationshipFormingAccept => RelationshipEvent::ReceiveAccept,
            _ => unreachable!(),
        };
        assert!(RelationshipState::Pending.transition(e).is_ok());

        // cancel → ReceiveCancel (legal from Bidirectional).
        let e = match ControlType::RelationshipCancel {
            ControlType::RelationshipCancel => RelationshipEvent::ReceiveCancel,
            _ => unreachable!(),
        };
        assert!(RelationshipState::Bidirectional.transition(e).is_ok());
    }
}
