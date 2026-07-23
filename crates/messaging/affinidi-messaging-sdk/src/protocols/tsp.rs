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
use affinidi_tsp::message::direct;
use affinidi_tsp::relationship::{InvalidTransition, RelationshipEvent, RelationshipState};
use affinidi_tsp::{DidVidResolver, MessageType, MetaEnvelope};
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use tokio::sync::RwLock;

use crate::ATM;
use crate::errors::ATMError;
use crate::profiles::ATMProfile;
use crate::protocols::discover_features::{
    DiscoverFeaturesDisclosure, DiscoverFeaturesQuery, FeatureType, Query,
};
use affinidi_messaging_didcomm::message::Message;

/// DIDComm [Discover Features 2.0](https://identity.foundation/didcomm-messaging/spec/#discover-features-protocol-20)
/// protocol URI that advertises an agent accepts TSP messages.
///
/// Advertise it in the discoverable state (see [`TspOps::advertise_capability`])
/// so a peer can learn our TSP capability proactively; consuming a peer's
/// disclosure that lists it (see [`TspOps::learn_from_disclosure`]) caches the
/// peer as [`TspSupport::Supported`] with source [`CapabilitySource::DiscoverFeatures`].
pub const TSP_DISCOVER_FEATURE_URI: &str = "https://affinidi.com/tsp/1.0";

/// Which wire protocol [`crate::ATM::send_to`] chose for a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SendProtocol {
    /// Sent as a TSP Direct message (`atm.tsp().send`).
    Tsp,
    /// Sent as a DIDComm message (`pack_encrypted` + `send_message`).
    DidComm,
}

/// Policy governing whether [`crate::ATM::send_to`] may pick TSP over DIDComm.
///
/// Set via [`crate::config::ATMConfigBuilder::with_tsp_policy`]. Defaults to
/// [`Off`](TspPolicy::Off), so enabling the `tsp` feature alone changes no
/// send behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum TspPolicy {
    /// Never pick TSP — [`send_to`](crate::ATM::send_to) always sends DIDComm.
    #[default]
    Off,
    /// Pick TSP when the peer is known/derivable to speak it; otherwise fall
    /// back to DIDComm.
    Preferred,
    /// Pick TSP when the peer is known/derivable to speak it; otherwise return
    /// an error instead of falling back to DIDComm.
    Required,
}

/// A peer's known TSP capability — whether its **agent** accepts TSP messages.
///
/// Distinct from a DID-document `TSPTransport` advertisement, which only says
/// the peer's **mediator** speaks TSP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub enum TspSupport {
    /// Not yet known — derive from live signals / negotiate.
    Unknown,
    /// The peer's agent is known to accept TSP.
    Supported,
    /// The peer's agent is known not to accept TSP.
    Unsupported,
}

/// How a [`PeerCapability`] was learned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub enum CapabilitySource {
    /// Derived from a completed TSP relationship (`Bidirectional`).
    Relationship,
    /// Derived from a `TSPTransport` service on the peer's DID document
    /// (a mediator-level, tentative signal).
    DidDocument,
    /// Observed from an inbound TSP message the peer sent us.
    Observed,
    /// Learned from a peer's DIDComm Discover Features 2.0 disclosure that
    /// advertised the TSP capability URI ([`TSP_DISCOVER_FEATURE_URI`]).
    DiscoverFeatures,
    /// Set explicitly by the application.
    Manual,
}

/// A cached per-peer TSP capability record, stored by [`RelationshipStore`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PeerCapability {
    /// Whether the peer's agent accepts TSP.
    pub tsp: TspSupport,
    /// How this record was learned.
    pub source: CapabilitySource,
    /// Unix seconds (against the SDK's configured clock) when learned — used
    /// for the capability TTL.
    pub learned_at_unix: u64,
    /// The peer's mediator DID, when known — used by [`crate::ATM::send_to`] to
    /// route a TSP message to a peer on a *different* mediator (a service-less
    /// `did:key` peer can't advertise this in a DID document, so it is learned
    /// from a routed relationship invite or set out-of-band). `None` means "assume
    /// the peer shares the sender's mediator" (Direct delivery).
    #[serde(default)]
    pub mediator: Option<String>,
}

/// Pluggable backing store for TSP relationship state (and learned per-peer
/// capability).
///
/// The relationship state machine (invite → accept → bidirectional, plus
/// cancel) is keyed on the `(our_vid, their_vid)` DID pair. The SDK drives the
/// pure FSM in [`affinidi_tsp::relationship::RelationshipState`] and persists
/// each new state through this trait, so where the state lives (memory, a
/// database, …) is up to the consumer.
///
/// The same store also caches each peer's learned TSP [`capability`](PeerCapability)
/// (used by [`crate::ATM::send_to`]); the capability methods have default no-op
/// implementations so existing stores keep compiling, and durable stores can
/// override them to persist capability alongside relationship state.
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

    /// Cached TSP capability for the `(our_vid, their_vid)` pair, or `None` if
    /// unknown. Default impl returns `None` (no capability cache);
    /// [`InMemoryRelationshipStore`] and durable stores override it.
    async fn get_capability(
        &self,
        _our_vid: &str,
        _their_vid: &str,
    ) -> Result<Option<PeerCapability>, ATMError> {
        Ok(None)
    }

    /// Persist a learned TSP capability for the `(our_vid, their_vid)` pair.
    /// Default impl is a no-op.
    async fn set_capability(
        &self,
        _our_vid: &str,
        _their_vid: &str,
        _capability: PeerCapability,
    ) -> Result<(), ATMError> {
        Ok(())
    }
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
    capabilities: RwLock<HashMap<(String, String), PeerCapability>>,
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

    async fn get_capability(
        &self,
        our_vid: &str,
        their_vid: &str,
    ) -> Result<Option<PeerCapability>, ATMError> {
        let key = (our_vid.to_string(), their_vid.to_string());
        Ok(self.capabilities.read().await.get(&key).cloned())
    }

    async fn set_capability(
        &self,
        our_vid: &str,
        their_vid: &str,
        capability: PeerCapability,
    ) -> Result<(), ATMError> {
        let key = (our_vid.to_string(), their_vid.to_string());
        self.capabilities.write().await.insert(key, capability);
        Ok(())
    }
}

impl ATM {
    /// Send `message` to `to`, automatically choosing TSP or DIDComm per the
    /// configured [`TspPolicy`] (see [`TspOps::select_protocol`]).
    ///
    /// - **DIDComm**: the message is packed (`pack_encrypted`) and sent to the
    ///   profile's mediator.
    /// - **TSP**: the message is serialised to JSON and sent as a TSP Direct
    ///   message (`atm.tsp().send`), which seals it end-to-end; the recipient
    ///   unpacks the TSP envelope to recover the same JSON [`Message`].
    ///
    /// Returns which [`SendProtocol`] was used. With the default
    /// [`TspPolicy::Off`] this always sends DIDComm, so existing behaviour is
    /// unchanged until an app opts in via
    /// [`with_tsp_policy`](crate::config::ATMConfigBuilder::with_tsp_policy).
    ///
    /// TSP delivery is Direct (via the sender's mediator) when the recipient
    /// shares that mediator. When the recipient's mediator is **known and
    /// different** (learned from a routed relationship invite or set via
    /// [`TspOps::set_peer_mediator`] — the service-less `did:key` case), the
    /// message is instead routed cross-mediator with metadata privacy
    /// ([`TspOps::send_nested_routed`]): the recipient stays hidden from the
    /// sender's mediator.
    ///
    /// [`Message`]: affinidi_messaging_didcomm::message::Message
    pub async fn send_to(
        &self,
        profile: &Arc<ATMProfile>,
        message: &affinidi_messaging_didcomm::message::Message,
        to: &str,
        from: Option<&str>,
        sign_by: Option<&str>,
    ) -> Result<SendProtocol, ATMError> {
        let protocol = self.tsp().select_protocol(profile, to).await?;
        match protocol {
            SendProtocol::Tsp => {
                let payload = serde_json::to_vec(message).map_err(|e| {
                    ATMError::MsgSendError(format!("couldn't serialise message for TSP: {e}"))
                })?;
                // Route cross-mediator (metadata-private) when the peer's mediator
                // is known and differs from ours; otherwise Direct via our mediator.
                let peer_mediator = self
                    .tsp()
                    .peer_capability(profile, to)
                    .await?
                    .and_then(|c| c.mediator);
                let (_, own_mediator) = profile.dids()?;
                match peer_mediator {
                    Some(peer_mediator) if peer_mediator != own_mediator => {
                        let route = [own_mediator.to_string(), peer_mediator];
                        self.tsp()
                            .send_nested_routed(profile, &route, to, &payload)
                            .await?;
                    }
                    _ => {
                        self.tsp().send(profile, to, &payload).await?;
                    }
                }
            }
            SendProtocol::DidComm => {
                // Pack for the recipient, then wrap in a single `forward` to the
                // profile's mediator (`next` = recipient) so it lands in the
                // recipient's mailbox — the standard DIDComm delivery path,
                // mirroring TSP's mediator-relative delivery. v1's single-mediator
                // scope means the recipient shares this mediator.
                let (packed, _meta) = self.pack_encrypted(message, to, from, sign_by).await?;
                let (_, mediator_did) = profile.dids()?;
                let (fwd_id, fwd) = self
                    .routing()
                    .forward_message(profile, false, &packed, mediator_did, to, None, None)
                    .await?;
                self.send_message(profile, &fwd, &fwd_id, false, false)
                    .await?;
            }
        }
        Ok(protocol)
    }
}

/// The outcome of the pure [`classify_protocol`] precedence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProtocolChoice {
    /// Use TSP. `cache` names the source to persist as `Supported`, or `None`
    /// to leave the cache untouched (a tentative signal).
    Tsp { cache: Option<CapabilitySource> },
    /// Use DIDComm.
    DidComm,
    /// No TSP capability under `Required` policy — the caller turns this into an
    /// error.
    Deny,
}

/// Pure protocol-selection precedence, factored out of
/// [`TspOps::select_protocol`] so the full truth table is unit-testable without
/// a live `ATM`. `fresh_cap` is the cached capability (if any, already
/// TTL-filtered); `has_tsp_service` is whether the peer's DID document
/// advertises a `TSPTransport` service.
fn classify_protocol(
    policy: TspPolicy,
    fresh_cap: Option<TspSupport>,
    bidirectional: bool,
    has_tsp_service: bool,
) -> ProtocolChoice {
    if policy == TspPolicy::Off {
        return ProtocolChoice::DidComm;
    }
    // 1. A fresh cached agent-level capability wins.
    match fresh_cap {
        Some(TspSupport::Supported) => return ProtocolChoice::Tsp { cache: None },
        Some(TspSupport::Unsupported) => return deny_or_didcomm(policy),
        _ => {}
    }
    // 2a. A completed relationship is a strong agent-level signal — cache it.
    if bidirectional {
        return ProtocolChoice::Tsp {
            cache: Some(CapabilitySource::Relationship),
        };
    }
    // 2b. A DID-doc `TSPTransport` service is a mediator-level (tentative)
    // signal — attempt TSP but don't cache it as an agent-level capability.
    if has_tsp_service {
        return ProtocolChoice::Tsp { cache: None };
    }
    // 3. No TSP signal.
    deny_or_didcomm(policy)
}

/// Whether a Discover Features 2.0 disclosure advertises the TSP capability URI
/// ([`TSP_DISCOVER_FEATURE_URI`]) as a supported protocol. Factored out of
/// [`TspOps::learn_from_disclosure`] so the match is unit-testable without a live
/// `ATM`.
fn disclosure_advertises_tsp(disclosure: &DiscoverFeaturesDisclosure) -> bool {
    disclosure.disclosures.iter().any(|d| {
        matches!(d.feature_type, FeatureType::Protocol) && d.id == TSP_DISCOVER_FEATURE_URI
    })
}

/// Under `Required`, no-TSP is a denial; otherwise fall back to DIDComm.
fn deny_or_didcomm(policy: TspPolicy) -> ProtocolChoice {
    match policy {
        TspPolicy::Required => ProtocolChoice::Deny,
        _ => ProtocolChoice::DidComm,
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

    /// Send `payload` to `to_did` across mediators with **metadata privacy**:
    /// the inner Direct message is sealed end-to-end to `to_did`, wrapped in a
    /// **Nested** envelope sealed to the recipient's mediator (`route.last()`),
    /// and **routed** through `route`.
    ///
    /// `route` is the hop list `[own_mediator, …, recipient_mediator]`. The sender
    /// posts to its own mediator (`route[0]`), which forwards along the route to
    /// the recipient's mediator; each intermediary sees only the *next hop*, never
    /// `to_did` (it is sealed inside the Nested inner). The recipient's mediator
    /// unwraps the Nested layer and delivers the Direct message to `to_did`
    /// locally — so only the recipient's own mediator learns the recipient, which
    /// is unavoidable for local delivery.
    ///
    /// This is the metadata-private counterpart to [`send_routed`](Self::send_routed),
    /// which carries the recipient as a visible route hop.
    pub async fn send_nested_routed(
        &self,
        profile: &Arc<ATMProfile>,
        route: &[String],
        to_did: &str,
        payload: &[u8],
    ) -> Result<(), ATMError> {
        let intermediary = route
            .last()
            .ok_or_else(|| ATMError::MsgSendError("route must not be empty".into()))?;

        let (from_did, _) = profile.dids()?;
        let (signing_key, decryption_key) = self.profile_tsp_keys(from_did).await?;

        // Inner Direct message sealed end-to-end to the final recipient.
        let recipient = self.resolve_vid(to_did).await?;
        let inner = direct::pack(
            payload,
            MessageType::Direct,
            from_did,
            to_did,
            &signing_key,
            &decryption_key,
            &recipient.encryption_key,
        )
        .map_err(|e| ATMError::MsgSendError(format!("couldn't pack inner TSP message: {e}")))?;

        // Wrap in a Nested envelope sealed to the recipient's mediator, so the
        // recipient's identity is opaque to every earlier hop.
        let intermediary_vid = self.resolve_vid(intermediary).await?;
        let nested = affinidi_tsp::message::routed::pack_nested(
            &inner,
            from_did,
            intermediary,
            &signing_key,
            &decryption_key,
            &intermediary_vid.encryption_key,
        )
        .map_err(|e| ATMError::MsgSendError(format!("couldn't pack nested TSP message: {e}")))?;

        // Route the Nested envelope through the hops to the recipient's mediator.
        self.send_routed_opaque(profile, route, &nested.bytes).await
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

    /// Like [`form_relationship`](Self::form_relationship), but the invite
    /// **advertises this agent's own mediator DID** in its route, so the peer can
    /// learn where to route TSP messages back — needed to reach a cross-mediator
    /// peer (e.g. a service-less `did:key` peer, whose DID document can't carry a
    /// `TSPTransport` service). The peer records it via
    /// [`record_incoming_control`](Self::record_incoming_control).
    ///
    /// Opt-in (SDD decision Q2): the plain
    /// [`form_relationship`](Self::form_relationship) advertises nothing, so your
    /// mediator is only disclosed when you deliberately use this routed form.
    pub async fn form_relationship_routed(
        &self,
        profile: &Arc<ATMProfile>,
        their_did: &str,
    ) -> Result<RelationshipState, ATMError> {
        let (our_did, our_mediator) = profile.dids()?;
        let store = self.relationship_store();
        let next = next_state(store, our_did, their_did, RelationshipEvent::SendInvite).await?;
        self.send_control(
            profile,
            their_did,
            &ControlMessage::invite_routed(vec![our_mediator.to_string()]),
        )
        .await?;
        store.set(our_did, their_did, next).await?;
        Ok(next)
    }

    /// Accept an invite previously received from `their_did`: advance the FSM
    /// with `SendAccept` (from [`RelationshipState::InviteReceived`] →
    /// [`Bidirectional`]), send a Relationship Forming Accept referencing the
    /// invite, then persist.
    ///
    /// `invite_thread_digest` is the received invite's TSP **thread digest** —
    /// the `SHA256` of its plaintext payload frame, which the recipient obtains
    /// by unpacking the invite (see [`TspOps::unpack_control`]). It is carried in
    /// the accept as the `reply` digest, byte-compatible with the reference's
    /// `AcceptRelationship { thread_id }`. State is only persisted after the
    /// accept is successfully sent. Returns the new state ([`Bidirectional`]).
    ///
    /// [`Bidirectional`]: RelationshipState::Bidirectional
    pub async fn accept_relationship(
        &self,
        profile: &Arc<ATMProfile>,
        their_did: &str,
        invite_thread_digest: [u8; 32],
    ) -> Result<RelationshipState, ATMError> {
        let (our_did, _) = profile.dids()?;
        let store = self.relationship_store();
        let next = next_state(store, our_did, their_did, RelationshipEvent::SendAccept).await?;
        self.send_control(
            profile,
            their_did,
            &ControlMessage::accept(invite_thread_digest),
        )
        .await?;
        store.set(our_did, their_did, next).await?;
        // A completed relationship confirms the peer's agent speaks TSP.
        if next == RelationshipState::Bidirectional {
            self.learn_tsp_supported(our_did, their_did, CapabilitySource::Relationship)
                .await?;
        }
        Ok(next)
    }

    /// Cancel/terminate the relationship with `their_did`: advance the FSM with
    /// `SendCancel` (valid from [`Pending`], [`InviteReceived`], or
    /// [`Bidirectional`] → [`RelationshipState::None`]), send a Relationship
    /// Cancel control message, then persist.
    ///
    /// `thread_digest` is the relationship-forming message's thread digest (the
    /// invite's `SHA256` plaintext-frame digest) referenced as the cancel
    /// `reply`, byte-compatible with the reference's `CancelRelationship {
    /// thread_id }`. State is only persisted after the cancel is successfully
    /// sent. Returns the new state ([`RelationshipState::None`]).
    ///
    /// [`Pending`]: RelationshipState::Pending
    /// [`InviteReceived`]: RelationshipState::InviteReceived
    /// [`Bidirectional`]: RelationshipState::Bidirectional
    pub async fn cancel_relationship(
        &self,
        profile: &Arc<ATMProfile>,
        their_did: &str,
        thread_digest: [u8; 32],
    ) -> Result<RelationshipState, ATMError> {
        let (our_did, _) = profile.dids()?;
        let store = self.relationship_store();
        let next = next_state(store, our_did, their_did, RelationshipEvent::SendCancel).await?;
        self.send_control(profile, their_did, &ControlMessage::cancel(thread_digest))
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
        let new_state = advance_state(self.relationship_store(), our_did, peer_did, event).await?;
        // If the peer advertised its mediator in the control's route (a routed
        // invite/accept), cache it so `send_to` can route to this peer on a
        // different mediator. Learned once during the handshake; no-op under
        // `TspPolicy::Off`, like the other capability-learning paths.
        if self.atm.inner.config.tsp_policy() != TspPolicy::Off
            && let Some(peer_mediator) = control.route.first()
        {
            self.set_peer_mediator(profile, peer_did, Some(peer_mediator.clone()))
                .await?;
        }
        // The initiator reaches Bidirectional here (on receiving the accept) —
        // confirm the peer's TSP capability.
        if new_state == RelationshipState::Bidirectional {
            self.learn_tsp_supported(our_did, peer_did, CapabilitySource::Relationship)
                .await?;
        }
        Ok(new_state)
    }

    // ── Protocol selection / capability ───────────────────────────────────────

    /// The cached TSP [`capability`](PeerCapability) for the `(profile, their_did)`
    /// pair, or `None` if unknown or expired (per the configured TTL / clock).
    pub async fn peer_capability(
        &self,
        profile: &Arc<ATMProfile>,
        their_did: &str,
    ) -> Result<Option<PeerCapability>, ATMError> {
        let (our_did, _) = profile.dids()?;
        let cap = self
            .relationship_store()
            .get_capability(our_did, their_did)
            .await?;
        Ok(cap.filter(|c| self.capability_is_fresh(c)))
    }

    /// Explicitly record a peer's TSP [`capability`](PeerCapability) — e.g. the
    /// app learned it out of band. Stamped with the current clock time and
    /// [`CapabilitySource::Manual`].
    pub async fn set_peer_capability(
        &self,
        profile: &Arc<ATMProfile>,
        their_did: &str,
        support: TspSupport,
    ) -> Result<(), ATMError> {
        let (our_did, _) = profile.dids()?;
        let store = self.relationship_store();
        let existing = store.get_capability(our_did, their_did).await?;
        let cap = PeerCapability {
            tsp: support,
            source: CapabilitySource::Manual,
            learned_at_unix: self.atm.inner.config.clock().unix_secs(),
            // Preserve any learned mediator (this call sets support, not routing).
            mediator: existing.and_then(|c| c.mediator),
        };
        store.set_capability(our_did, their_did, cap).await
    }

    /// Record the `mediator` DID that a peer's TSP agent lives behind, so
    /// [`crate::ATM::send_to`] can route a TSP message to a peer on a *different*
    /// mediator (a service-less `did:key` peer can't advertise this in its DID
    /// document). Learned automatically from a routed relationship invite
    /// ([`form_relationship_routed`](Self::form_relationship_routed)); use this to
    /// set it out-of-band. Pass `None` to clear it (assume the shared mediator).
    ///
    /// Preserves any known TSP support level for the peer.
    pub async fn set_peer_mediator(
        &self,
        profile: &Arc<ATMProfile>,
        their_did: &str,
        mediator: Option<String>,
    ) -> Result<(), ATMError> {
        let (our_did, _) = profile.dids()?;
        let store = self.relationship_store();
        let existing = store.get_capability(our_did, their_did).await?;
        let cap = PeerCapability {
            tsp: existing
                .as_ref()
                .map(|c| c.tsp)
                .unwrap_or(TspSupport::Unknown),
            source: existing
                .as_ref()
                .map(|c| c.source)
                .unwrap_or(CapabilitySource::Manual),
            learned_at_unix: self.atm.inner.config.clock().unix_secs(),
            mediator,
        };
        store.set_capability(our_did, their_did, cap).await
    }

    /// Advertise this agent's TSP capability in its Discover Features 2.0
    /// discoverable state, so a peer that queries our supported protocols learns
    /// we accept TSP and can proactively prefer it. Adds
    /// [`TSP_DISCOVER_FEATURE_URI`] to the shared discoverable protocol list
    /// (idempotent).
    ///
    /// Enabling a non-[`Off`](TspPolicy::Off) [`TspPolicy`] auto-advertises this
    /// at SDK construction; call this to advertise at runtime or under `Off`.
    pub async fn advertise_capability(&self) {
        let state = self.atm.inner.config.discover_features.clone();
        let mut features = state.write().await;
        if !features
            .protocols
            .iter()
            .any(|p| p == TSP_DISCOVER_FEATURE_URI)
        {
            features
                .protocols
                .push(TSP_DISCOVER_FEATURE_URI.to_string());
        }
    }

    /// Build a DIDComm Discover Features 2.0 query that asks `to_did` whether it
    /// supports TSP (matches [`TSP_DISCOVER_FEATURE_URI`]). Pack + send it like
    /// any DIDComm message; feed the peer's disclosure response to
    /// [`learn_from_disclosure`](Self::learn_from_disclosure) to populate the
    /// capability cache before the first message.
    pub fn capability_query(&self, from_did: &str, to_did: &str) -> Result<Message, ATMError> {
        self.atm.discover_features().generate_query_message(
            from_did,
            to_did,
            DiscoverFeaturesQuery {
                queries: vec![Query {
                    feature_type: FeatureType::Protocol,
                    match_: TSP_DISCOVER_FEATURE_URI.to_string(),
                }],
            },
        )
    }

    /// Consume a peer's Discover Features 2.0 disclosure: if it advertises the
    /// TSP capability URI, cache the peer as [`TspSupport::Supported`]
    /// (source [`CapabilitySource::DiscoverFeatures`]) so a later
    /// [`send_to`](crate::ATM::send_to) can prefer TSP *before* any relationship
    /// or observed inbound TSP.
    ///
    /// Returns whether the disclosure advertised TSP. A disclosure that omits the
    /// URI is left untouched (not marked `Unsupported`) — a scoped disclosure may
    /// simply not have been queried for it. A no-op under [`TspPolicy::Off`]
    /// (like the other capability-learning paths, tracking is inert unless
    /// protocol selection is enabled).
    pub async fn learn_from_disclosure(
        &self,
        profile: &Arc<ATMProfile>,
        their_did: &str,
        disclosure: &DiscoverFeaturesDisclosure,
    ) -> Result<bool, ATMError> {
        let advertises_tsp = disclosure_advertises_tsp(disclosure);
        if advertises_tsp {
            let (our_did, _) = profile.dids()?;
            self.learn_tsp_supported(our_did, their_did, CapabilitySource::DiscoverFeatures)
                .await?;
        }
        Ok(advertises_tsp)
    }

    /// Whether a cached capability is still within the configured TTL (`None`
    /// TTL = always fresh).
    fn capability_is_fresh(&self, cap: &PeerCapability) -> bool {
        match self.atm.inner.config.tsp_capability_ttl() {
            None => true,
            Some(ttl) => {
                let now = self.atm.inner.config.clock().unix_secs();
                now.saturating_sub(cap.learned_at_unix) <= ttl.as_secs()
            }
        }
    }

    /// Learn that `their_did` speaks TSP and cache it as [`TspSupport::Supported`]
    /// with the given `source`. Called when a relationship completes
    /// ([`CapabilitySource::Relationship`]) or an inbound TSP message is observed
    /// ([`CapabilitySource::Observed`]).
    ///
    /// A no-op when the [`TspPolicy`] is [`Off`](TspPolicy::Off) — capability
    /// tracking is inert unless protocol selection is enabled, so the default
    /// build incurs no extra store writes. Skips the write when a fresh
    /// `Supported` record already exists, so durable stores aren't rewritten on
    /// every received message.
    async fn learn_tsp_supported(
        &self,
        our_did: &str,
        their_did: &str,
        source: CapabilitySource,
    ) -> Result<(), ATMError> {
        if self.atm.inner.config.tsp_policy() == TspPolicy::Off {
            return Ok(());
        }
        let store = self.relationship_store();
        let existing = store.get_capability(our_did, their_did).await?;
        if let Some(cap) = &existing
            && cap.tsp == TspSupport::Supported
            && self.capability_is_fresh(cap)
        {
            return Ok(());
        }
        let cap = PeerCapability {
            tsp: TspSupport::Supported,
            source,
            learned_at_unix: self.atm.inner.config.clock().unix_secs(),
            // Preserve any learned mediator (used for cross-mediator routing).
            mediator: existing.and_then(|c| c.mediator),
        };
        store.set_capability(our_did, their_did, cap).await
    }

    /// Decide which wire protocol to use for a message to `their_did`, per the
    /// configured [`TspPolicy`].
    ///
    /// Gathers the signals ([`peer_capability`](Self::peer_capability), the
    /// relationship state, and — only if those are inconclusive — a DID-doc
    /// `TSPTransport` lookup) and applies the precedence in [`classify_protocol`].
    /// When a `Bidirectional` relationship is the deciding signal, the peer is
    /// cached as [`TspSupport::Supported`]. Under [`TspPolicy::Required`] a
    /// no-TSP outcome is an error rather than a DIDComm fallback.
    pub async fn select_protocol(
        &self,
        profile: &Arc<ATMProfile>,
        their_did: &str,
    ) -> Result<SendProtocol, ATMError> {
        let policy = self.atm.inner.config.tsp_policy();
        if policy == TspPolicy::Off {
            return Ok(SendProtocol::DidComm);
        }

        let (our_did, _) = profile.dids()?;
        let store = self.relationship_store();

        let existing_cap = store
            .get_capability(our_did, their_did)
            .await?
            .filter(|c| self.capability_is_fresh(c));
        let fresh_cap = existing_cap.as_ref().map(|c| c.tsp);
        let bidirectional =
            store.get(our_did, their_did).await? == RelationshipState::Bidirectional;

        // Only resolve the peer's DID document (a network/cache lookup) when the
        // cheap store signals don't already settle it.
        let needs_resolve = !matches!(
            fresh_cap,
            Some(TspSupport::Supported | TspSupport::Unsupported)
        ) && !bidirectional;
        let has_tsp_service = if needs_resolve {
            self.resolve_vid(their_did)
                .await
                .map(|vid| !vid.endpoints.is_empty())
                .unwrap_or(false)
        } else {
            false
        };

        match classify_protocol(policy, fresh_cap, bidirectional, has_tsp_service) {
            ProtocolChoice::Tsp { cache } => {
                if let Some(source) = cache {
                    let cap = PeerCapability {
                        tsp: TspSupport::Supported,
                        source,
                        learned_at_unix: self.atm.inner.config.clock().unix_secs(),
                        mediator: existing_cap.and_then(|c| c.mediator),
                    };
                    store.set_capability(our_did, their_did, cap).await?;
                }
                Ok(SendProtocol::Tsp)
            }
            ProtocolChoice::DidComm => Ok(SendProtocol::DidComm),
            ProtocolChoice::Deny => Err(ATMError::MsgSendError(format!(
                "TspPolicy::Required but no TSP capability is known for {their_did}"
            ))),
        }
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

        // Observing an authenticated inbound TSP message confirms the sender's
        // agent speaks TSP (no-op unless a TSP policy is set).
        self.learn_tsp_supported(profile_did, &unpacked.sender, CapabilitySource::Observed)
            .await?;

        Ok((unpacked.payload, unpacked.sender))
    }

    /// Unpack a fetched TSP **control** message (raw qb2 bytes), returning the
    /// decoded [`ControlMessage`], the sender VID, and the message's TSP
    /// **thread digest** (`SHA256` of its plaintext frame).
    ///
    /// For an invite, the returned `thread_digest` is the value to pass to
    /// [`TspOps::accept_relationship`] (and, later,
    /// [`TspOps::cancel_relationship`]) as the relationship reference.
    pub async fn unpack_control(
        &self,
        profile: &Arc<ATMProfile>,
        qb2: &[u8],
    ) -> Result<(ControlMessage, String, [u8; 32]), ATMError> {
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

        let control = unpacked.control.ok_or_else(|| {
            ATMError::MsgReceiveError("TSP message is not a control message".into())
        })?;
        // An inbound control message is also authenticated inbound TSP — the
        // sender's agent speaks TSP (no-op unless a TSP policy is set).
        self.learn_tsp_supported(profile_did, &unpacked.sender, CapabilitySource::Observed)
            .await?;
        Ok((control, unpacked.sender, unpacked.thread_digest))
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

        // Footgun guard: the mediator permits ONE websocket per DID. If this
        // profile already has a live-stream pickup websocket, opening a second
        // (raw-TSP) socket makes the mediator evict a duplicate channel, and the
        // two sockets flap against each other. A node that needs both DIDComm and
        // TSP should multiplex on the single pickup socket via
        // `MessagePickup::live_stream_next_frame` (or the
        // `affinidi-messaging-didcomm-service` crate), not open this second socket.
        if mediator.ws_channel_tx.read().await.is_some() {
            tracing::warn!(
                "Profile ({}) already has a live-stream websocket; opening a raw-TSP \
                 connect_websocket on the same DID will be evicted by the mediator \
                 (one websocket per DID). For combined DIDComm+TSP receive, multiplex \
                 via message_pickup().live_stream_next_frame instead.",
                profile.inner.alias
            );
        }

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
    /// [`TspOps::unpack_bytes`]). Control frames (`Ping`/`Pong`) and any `Text`
    /// frames are skipped transparently.
    ///
    /// When the socket goes away:
    /// - the peer sent a **close frame** → `Err`, carrying its RFC 6455 code and
    ///   reason. The mediator always states why it closed a socket
    ///   ("replaced by a newer connection", "authentication token expired",
    ///   "streaming task unavailable", …) and that reason is the difference
    ///   between an operator diagnosing the problem and guessing at it. It used
    ///   to be discarded, collapsing every one of those into a bare `Ok(None)`
    ///   that read, to the caller, exactly like "nothing arrived".
    /// - the stream **ended with no close frame** (peer vanished / transport
    ///   died) → `Ok(None)`. There is genuinely nothing to report.
    ///
    /// Either way the socket is finished: polling again cannot produce a
    /// message, so callers should reconnect rather than retry.
    pub async fn recv(&mut self) -> Result<Option<Vec<u8>>, ATMError> {
        use futures_util::StreamExt;
        use tokio_tungstenite::tungstenite::Message;

        loop {
            match self.ws.next().await {
                Some(Ok(Message::Binary(bytes))) => return Ok(Some(bytes.to_vec())),
                Some(Ok(Message::Close(frame))) => {
                    return Err(ATMError::TransportError(match frame {
                        Some(frame) if !frame.reason.is_empty() => format!(
                            "TSP websocket closed by the mediator: {} ({})",
                            frame.reason, frame.code
                        ),
                        Some(frame) => {
                            format!("TSP websocket closed by the mediator: code {}", frame.code)
                        }
                        None => {
                            "TSP websocket closed by the mediator (no reason given)".to_string()
                        }
                    }));
                }
                None => return Ok(None),
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
        CapabilitySource, InMemoryRelationshipStore, PeerCapability, ProtocolChoice,
        RelationshipEvent, RelationshipState, RelationshipStore, TSP_DISCOVER_FEATURE_URI,
        TspPolicy, TspSupport, advance_state, classify_protocol, disclosure_advertises_tsp,
        next_state,
    };
    use crate::errors::ATMError;
    use crate::protocols::discover_features::{
        Disclosure, DiscoverFeaturesDisclosure, FeatureType,
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

    #[tokio::test]
    async fn in_memory_store_capability_roundtrip() {
        let store = InMemoryRelationshipStore::default();
        // Unknown pair → None.
        assert_eq!(store.get_capability(ALICE, BOB).await.unwrap(), None);

        let cap = PeerCapability {
            tsp: TspSupport::Supported,
            source: CapabilitySource::Relationship,
            learned_at_unix: 42,
            mediator: None,
        };
        store.set_capability(ALICE, BOB, cap.clone()).await.unwrap();
        assert_eq!(
            store.get_capability(ALICE, BOB).await.unwrap(),
            Some(cap.clone())
        );

        // Directional + independent of relationship state.
        assert_eq!(store.get_capability(BOB, ALICE).await.unwrap(), None);
        assert_eq!(
            store.get(ALICE, BOB).await.unwrap(),
            RelationshipState::None
        );

        // Default trait impl (no override) is a no-op that reports Unknown.
        struct NoCap;
        #[async_trait::async_trait]
        impl RelationshipStore for NoCap {
            async fn get(&self, _: &str, _: &str) -> Result<RelationshipState, ATMError> {
                Ok(RelationshipState::None)
            }
            async fn set(&self, _: &str, _: &str, _: RelationshipState) -> Result<(), ATMError> {
                Ok(())
            }
        }
        let nocap = NoCap;
        nocap.set_capability(ALICE, BOB, cap).await.unwrap(); // no-op, no error
        assert_eq!(nocap.get_capability(ALICE, BOB).await.unwrap(), None);
    }

    // ── classify_protocol truth table (pure) ──────────────────────────────────

    #[test]
    fn classify_off_is_always_didcomm() {
        for cap in [
            None,
            Some(TspSupport::Supported),
            Some(TspSupport::Unsupported),
        ] {
            for bidi in [false, true] {
                for svc in [false, true] {
                    assert_eq!(
                        classify_protocol(TspPolicy::Off, cap, bidi, svc),
                        ProtocolChoice::DidComm
                    );
                }
            }
        }
    }

    #[test]
    fn classify_cached_supported_wins() {
        // A Supported cache short-circuits before relationship / service checks.
        for policy in [TspPolicy::Preferred, TspPolicy::Required] {
            assert_eq!(
                classify_protocol(policy, Some(TspSupport::Supported), false, false),
                ProtocolChoice::Tsp { cache: None }
            );
        }
    }

    #[test]
    fn classify_cached_unsupported_short_circuits() {
        // Unsupported wins even when a TSPTransport service is present.
        assert_eq!(
            classify_protocol(
                TspPolicy::Preferred,
                Some(TspSupport::Unsupported),
                true,
                true
            ),
            ProtocolChoice::DidComm
        );
        assert_eq!(
            classify_protocol(
                TspPolicy::Required,
                Some(TspSupport::Unsupported),
                true,
                true
            ),
            ProtocolChoice::Deny
        );
    }

    #[test]
    fn classify_relationship_selects_tsp_and_caches() {
        assert_eq!(
            classify_protocol(TspPolicy::Preferred, None, true, false),
            ProtocolChoice::Tsp {
                cache: Some(CapabilitySource::Relationship)
            }
        );
    }

    #[test]
    fn classify_did_doc_service_is_tentative_tsp_no_cache() {
        assert_eq!(
            classify_protocol(TspPolicy::Preferred, None, false, true),
            ProtocolChoice::Tsp { cache: None }
        );
    }

    #[test]
    fn classify_no_signal_falls_back_or_denies() {
        // No signal (e.g. a did:key peer we've never talked to).
        assert_eq!(
            classify_protocol(TspPolicy::Preferred, None, false, false),
            ProtocolChoice::DidComm
        );
        assert_eq!(
            classify_protocol(TspPolicy::Required, None, false, false),
            ProtocolChoice::Deny
        );
        // Unknown cached capability behaves like no cache.
        assert_eq!(
            classify_protocol(
                TspPolicy::Preferred,
                Some(TspSupport::Unknown),
                false,
                false
            ),
            ProtocolChoice::DidComm
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

    // ── Discover Features → capability (pure) ──────────────────────────────────

    fn protocol_disclosure(ids: &[&str]) -> DiscoverFeaturesDisclosure {
        DiscoverFeaturesDisclosure {
            disclosures: ids
                .iter()
                .map(|id| Disclosure {
                    feature_type: FeatureType::Protocol,
                    id: (*id).to_string(),
                    roles: vec![],
                })
                .collect(),
        }
    }

    #[test]
    fn disclosure_with_tsp_uri_is_recognised() {
        let d = protocol_disclosure(&[
            "https://didcomm.org/trust-ping/2.0",
            TSP_DISCOVER_FEATURE_URI,
        ]);
        assert!(disclosure_advertises_tsp(&d));
    }

    #[test]
    fn disclosure_without_tsp_uri_is_not() {
        let d = protocol_disclosure(&["https://didcomm.org/trust-ping/2.0"]);
        assert!(!disclosure_advertises_tsp(&d));
        assert!(!disclosure_advertises_tsp(
            &DiscoverFeaturesDisclosure::default()
        ));
    }

    #[test]
    fn tsp_uri_under_non_protocol_feature_type_is_ignored() {
        // The same string disclosed as a goal code / header must not count as a
        // protocol capability.
        let d = DiscoverFeaturesDisclosure {
            disclosures: vec![
                Disclosure {
                    feature_type: FeatureType::GoalCode,
                    id: TSP_DISCOVER_FEATURE_URI.to_string(),
                    roles: vec![],
                },
                Disclosure {
                    feature_type: FeatureType::Header,
                    id: TSP_DISCOVER_FEATURE_URI.to_string(),
                    roles: vec![],
                },
            ],
        };
        assert!(!disclosure_advertises_tsp(&d));
    }
}
