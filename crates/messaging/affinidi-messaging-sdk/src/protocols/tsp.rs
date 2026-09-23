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
use std::time::Duration;

use affinidi_did_common::DocumentExt;
use affinidi_secrets_resolver::SecretsResolver;
use affinidi_secrets_resolver::secrets::KeyType;
/// Re-exported so a caller can name a control message without depending on
/// `affinidi-tsp` directly.
pub use affinidi_tsp::message::control::ControlMessage;
use affinidi_tsp::message::control::ControlType;
use affinidi_tsp::message::direct;
/// Re-exported so callers can name the states a [`RelationshipStore`] holds
/// without depending on `affinidi-tsp` directly.
pub use affinidi_tsp::relationship::RelationshipState;
use affinidi_tsp::relationship::{InvalidTransition, RelationshipEvent};
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
/// The two digests that identify a relationship, one per uni-directional half
/// (spec Rev 3 §7.2.1).
///
/// "Conceptually, this exchange creates two uni-directional relationships, one
/// (from the requester) can be identified by the Digest, and the other (from
/// the replier) can be identified by the Reply_Digest."
///
/// An endpoint needs both: a cancellation may name either half, and the invite
/// race is broken by comparing our own outstanding invite's digest against the
/// one that arrived.
///
/// `Serialize`/`Deserialize` so a durable [`RelationshipStore`] (e.g.
/// [`PersistentRelationshipStore`]) can persist it — losing the digests across a
/// restart forfeits the §7.2.3 invite-race tiebreak and §7.2.1 cancel matching.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ThreadDigests {
    /// The digest of the invite this endpoint sent or received — the thread id
    /// of the exchange that opened the relationship.
    pub invite: Option<[u8; 32]>,
    /// The digest of the accept that answered it, identifying the other half.
    pub accept: Option<[u8; 32]>,
}

impl ThreadDigests {
    /// Does `digest` name either half of this relationship?
    ///
    /// True when nothing is recorded: an endpoint that has not kept the digests
    /// cannot contradict one, and refusing every cancellation would be worse
    /// than accepting one it cannot check.
    pub fn recognizes(&self, digest: &[u8; 32]) -> bool {
        match (self.invite, self.accept) {
            (None, None) => true,
            (a, b) => [a, b].into_iter().flatten().any(|d| &d == digest),
        }
    }
}

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

    /// The thread digests recorded for the `(our_vid, their_vid)` pair.
    ///
    /// A store that does not keep them returns the default, which recognises
    /// any digest and loses the Rev 3 §7.2.3 invite-race tiebreak — an endpoint
    /// cannot decide which of two invites to keep without its own digest to
    /// compare. Implement this to get the rule.
    async fn thread_digests(
        &self,
        _our_vid: &str,
        _their_vid: &str,
    ) -> Result<ThreadDigests, ATMError> {
        Ok(ThreadDigests::default())
    }

    /// Persist the thread digests for the `(our_vid, their_vid)` pair.
    /// Default impl is a no-op.
    async fn set_thread_digests(
        &self,
        _our_vid: &str,
        _their_vid: &str,
        _digests: ThreadDigests,
    ) -> Result<(), ATMError> {
        Ok(())
    }

    /// The `Reply_Path` an inviting peer supplied — the route its accept is to
    /// travel back over (Rev 3 §7.2.4). Empty when the invite asked for a
    /// direct reply.
    ///
    /// A store that does not keep it returns empty, and an accept then goes
    /// direct. That is a conformance loss, not just a missing optimisation:
    /// §7.2.4 says the responder MUST use the path, and going direct discloses
    /// to the destination — and to observers — an endpoint the route existed to
    /// keep out of view.
    async fn reply_path(&self, _our_vid: &str, _their_vid: &str) -> Result<Vec<String>, ATMError> {
        Ok(Vec::new())
    }

    /// Persist the `Reply_Path` from an invite. Default impl is a no-op.
    async fn set_reply_path(
        &self,
        _our_vid: &str,
        _their_vid: &str,
        _path: Vec<String>,
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
    digests: RwLock<HashMap<(String, String), ThreadDigests>>,
    reply_paths: RwLock<HashMap<(String, String), Vec<String>>>,
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

    async fn thread_digests(
        &self,
        our_vid: &str,
        their_vid: &str,
    ) -> Result<ThreadDigests, ATMError> {
        let key = (our_vid.to_string(), their_vid.to_string());
        Ok(self
            .digests
            .read()
            .await
            .get(&key)
            .copied()
            .unwrap_or_default())
    }

    async fn set_thread_digests(
        &self,
        our_vid: &str,
        their_vid: &str,
        digests: ThreadDigests,
    ) -> Result<(), ATMError> {
        let key = (our_vid.to_string(), their_vid.to_string());
        self.digests.write().await.insert(key, digests);
        Ok(())
    }

    async fn reply_path(&self, our_vid: &str, their_vid: &str) -> Result<Vec<String>, ATMError> {
        let key = (our_vid.to_string(), their_vid.to_string());
        Ok(self
            .reply_paths
            .read()
            .await
            .get(&key)
            .cloned()
            .unwrap_or_default())
    }

    async fn set_reply_path(
        &self,
        our_vid: &str,
        their_vid: &str,
        path: Vec<String>,
    ) -> Result<(), ATMError> {
        let key = (our_vid.to_string(), their_vid.to_string());
        self.reply_paths.write().await.insert(key, path);
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

/// A minimal key/value backend a [`PersistentRelationshipStore`] serialises
/// relationship records into.
///
/// Implement it over whatever durable store a service already runs — the VTA's
/// encrypted fjall keyspace, sled, redb, a SQL table — and the pair-record
/// encoding, the defaults for absent facets and the (de)serialisation all stay
/// in [`PersistentRelationshipStore`], so a consumer writes three trivial
/// methods rather than another copy of the store logic (design note
/// `tsp-relationship-recovery.md`, D1 — "implement it once, not five times").
///
/// Keys are opaque byte strings the store constructs; a backend must return them
/// byte-for-byte and yield `None` for an absent key. Values are already-encoded
/// bytes. The durability boundary is here: a `put` that returns `Ok(())` must
/// survive a process restart, or the store it backs is not durable.
#[async_trait::async_trait]
pub trait RelationshipKv: Send + Sync {
    /// Fetch the bytes stored under `key`, or `None` if absent.
    async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, ATMError>;
    /// Durably store `value` under `key`, replacing any existing value.
    async fn put(&self, key: &[u8], value: &[u8]) -> Result<(), ATMError>;
    /// Remove `key` if present. An absent key is not an error.
    async fn delete(&self, key: &[u8]) -> Result<(), ATMError>;

    /// Return every `(key, value)` whose key starts with `prefix`.
    ///
    /// Used by the idle-eviction sweep (D5/D6) and the proactive startup
    /// reconcile (D9), both of which enumerate stored relationships. The default
    /// yields nothing, so those degrade to no-ops on a backend that cannot scan
    /// rather than failing to compile; a durable backend (fjall, sled, SQL)
    /// implements it over its native prefix iteration.
    async fn scan_prefix(&self, _prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, ATMError> {
        Ok(Vec::new())
    }
}

// Key layout: `PREFIX ‖ facet ‖ len(our_vid) as u32-BE ‖ our_vid ‖ their_vid`.
// The length prefix on `our_vid` makes the boundary unambiguous without relying
// on a separator that a DID might contain, so no two distinct pairs — or the
// same pair under different facets — can ever collide on a key.
const REL_KEY_PREFIX: &[u8] = b"tsp-rel/v1/";
const FACET_STATE: u8 = 1;
const FACET_DIGESTS: u8 = 2;
const FACET_REPLY_PATH: u8 = 3;
const FACET_CAPABILITY: u8 = 4;
const FACET_LAST_ACTIVE: u8 = 5;

fn rel_key(facet: u8, our_vid: &str, their_vid: &str) -> Vec<u8> {
    let mut key =
        Vec::with_capacity(REL_KEY_PREFIX.len() + 1 + 4 + our_vid.len() + their_vid.len());
    key.extend_from_slice(REL_KEY_PREFIX);
    key.push(facet);
    key.extend_from_slice(&(our_vid.len() as u32).to_be_bytes());
    key.extend_from_slice(our_vid.as_bytes());
    key.extend_from_slice(their_vid.as_bytes());
    key
}

/// The key prefix that scans every pair stored under one facet — `rel_key`
/// truncated before the pair, for [`RelationshipKv::scan_prefix`].
fn rel_facet_prefix(facet: u8) -> Vec<u8> {
    let mut prefix = Vec::with_capacity(REL_KEY_PREFIX.len() + 1);
    prefix.extend_from_slice(REL_KEY_PREFIX);
    prefix.push(facet);
    prefix
}

/// Recover `(our_vid, their_vid)` from a `rel_key` of the given `facet`, or
/// `None` if the key is not one (wrong prefix/facet, truncated, or not UTF-8).
/// The inverse of [`rel_key`]; the `u32` length prefix is what makes the split
/// unambiguous.
fn decode_rel_key(facet: u8, key: &[u8]) -> Option<(String, String)> {
    let head = REL_KEY_PREFIX.len() + 1 + 4;
    if key.len() < head || !key.starts_with(REL_KEY_PREFIX) || key[REL_KEY_PREFIX.len()] != facet {
        return None;
    }
    let len_at = REL_KEY_PREFIX.len() + 1;
    let our_len = u32::from_be_bytes(key[len_at..len_at + 4].try_into().ok()?) as usize;
    let our_start = len_at + 4;
    let our_end = our_start.checked_add(our_len)?;
    if our_end > key.len() {
        return None;
    }
    let our = String::from_utf8(key[our_start..our_end].to_vec()).ok()?;
    let their = String::from_utf8(key[our_end..].to_vec()).ok()?;
    Some((our, their))
}

/// A durable [`RelationshipStore`] backed by any [`RelationshipKv`].
///
/// State survives a process restart. The failure this fixes: a Rev 3 §7.2.2
/// gate silently dropping every peer's application traffic after a restart wiped
/// an [`InMemoryRelationshipStore`], because the peers still hold the
/// relationship the restarted endpoint forgot (design note
/// `tsp-relationship-recovery.md`, D1). Inject it with
/// [`crate::config::ATMConfigBuilder::with_relationship_store`] in place of the
/// ephemeral default.
///
/// Each facet the trait keeps — state, thread digests, reply path, capability —
/// is stored under its own key per `(our_vid, their_vid)` pair, mirroring
/// [`InMemoryRelationshipStore`]'s independent maps. Setters therefore never
/// read-modify-write a shared record and cannot lose one field to a concurrent
/// write of another.
pub struct PersistentRelationshipStore<B: RelationshipKv> {
    backend: B,
}

impl<B: RelationshipKv> PersistentRelationshipStore<B> {
    /// Wrap a durable backend. The store is empty only if the backend is; an
    /// existing backend is re-opened with its relationships intact.
    pub fn new(backend: B) -> Self {
        Self { backend }
    }

    /// The underlying backend, for a consumer that shares it with other state.
    pub fn backend(&self) -> &B {
        &self.backend
    }

    async fn load<T: serde::de::DeserializeOwned>(
        &self,
        key: &[u8],
    ) -> Result<Option<T>, ATMError> {
        match self.backend.get(key).await? {
            Some(bytes) => serde_json::from_slice(&bytes).map(Some).map_err(|e| {
                ATMError::SDKError(format!("relationship store: decoding a stored record: {e}"))
            }),
            None => Ok(None),
        }
    }

    async fn save<T: serde::Serialize>(&self, key: &[u8], value: &T) -> Result<(), ATMError> {
        let bytes = serde_json::to_vec(value).map_err(|e| {
            ATMError::SDKError(format!("relationship store: encoding a record: {e}"))
        })?;
        self.backend.put(key, &bytes).await
    }

    /// Record that the relationship with `their_vid` was active at `now_ms`
    /// (design note `tsp-relationship-recovery.md`, D5). A caller stamps this on a
    /// **successful round-trip**, not on a send attempt — a broken relationship
    /// must age out, not refresh itself on every failed retry.
    ///
    /// This is a `PersistentRelationshipStore` extension, not a
    /// [`RelationshipStore`] trait method: idle eviction needs a timestamp, but
    /// the ephemeral store has nothing to evict, so only the durable store
    /// carries it (the C3 decision in the design note).
    pub async fn touch(&self, our_vid: &str, their_vid: &str, now_ms: u64) -> Result<(), ATMError> {
        self.save(&rel_key(FACET_LAST_ACTIVE, our_vid, their_vid), &now_ms)
            .await
    }

    /// When the relationship with `their_vid` was last [`touch`](Self::touch)ed, or
    /// `None` if it never was. Feed it to [`EvictionPolicy::is_idle`] to decide
    /// eviction.
    pub async fn last_active(
        &self,
        our_vid: &str,
        their_vid: &str,
    ) -> Result<Option<u64>, ATMError> {
        self.load(&rel_key(FACET_LAST_ACTIVE, our_vid, their_vid))
            .await
    }

    /// Remove every facet of the relationship with `their_vid` — the whole
    /// record, not just its state. Used by the eviction sweep, and available for
    /// a hard local teardown.
    pub async fn forget(&self, our_vid: &str, their_vid: &str) -> Result<(), ATMError> {
        for facet in [
            FACET_STATE,
            FACET_DIGESTS,
            FACET_REPLY_PATH,
            FACET_CAPABILITY,
            FACET_LAST_ACTIVE,
        ] {
            self.backend
                .delete(&rel_key(facet, our_vid, their_vid))
                .await?;
        }
        Ok(())
    }

    /// Evict every relationship idle beyond `policy` as of `now_ms` — the D5
    /// sweep (design note D6). Scans the last-active facet, and for each pair past
    /// the TTL removes the whole record. Returns the pairs evicted.
    ///
    /// Purely local: evicting a relationship the peer kept is safe — the next
    /// send reads `None`, re-invites, and D2's reconcile has the peer re-accept.
    /// A pair that was never `touch`ed has no last-active entry and so is never
    /// swept by age; that is deliberate, since "never active" is not the same as
    /// "idle since epoch". Requires a [`RelationshipKv::scan_prefix`]; on a
    /// backend without one it evicts nothing.
    pub async fn evict_idle(
        &self,
        now_ms: u64,
        policy: &EvictionPolicy,
    ) -> Result<Vec<(String, String)>, ATMError> {
        let entries = self
            .backend
            .scan_prefix(&rel_facet_prefix(FACET_LAST_ACTIVE))
            .await?;
        let mut evicted = Vec::new();
        for (key, value) in entries {
            let Some((our, their)) = decode_rel_key(FACET_LAST_ACTIVE, &key) else {
                continue;
            };
            // A record that will not decode cannot be aged; leave it rather than
            // guess an age and evict a live relationship.
            let Ok(last_active_ms) = serde_json::from_slice::<u64>(&value) else {
                continue;
            };
            if policy.is_idle(last_active_ms, now_ms) {
                self.forget(&our, &their).await?;
                evicted.push((our, their));
            }
        }
        Ok(evicted)
    }

    /// The `(our_vid, their_vid)` pairs currently `Bidirectional` — the
    /// candidates for a proactive startup reconcile (design note D9), which
    /// re-asserts them before real traffic can fail rather than waiting for a
    /// timeout. Requires a [`RelationshipKv::scan_prefix`]; returns empty without
    /// one.
    pub async fn established_relationships(&self) -> Result<Vec<(String, String)>, ATMError> {
        let entries = self
            .backend
            .scan_prefix(&rel_facet_prefix(FACET_STATE))
            .await?;
        let mut out = Vec::new();
        for (key, value) in entries {
            let Some((our, their)) = decode_rel_key(FACET_STATE, &key) else {
                continue;
            };
            if serde_json::from_slice::<RelationshipState>(&value).ok()
                == Some(RelationshipState::Bidirectional)
            {
                out.push((our, their));
            }
        }
        Ok(out)
    }
}

#[async_trait::async_trait]
impl<B: RelationshipKv> RelationshipStore for PersistentRelationshipStore<B> {
    async fn get(&self, our_vid: &str, their_vid: &str) -> Result<RelationshipState, ATMError> {
        Ok(self
            .load(&rel_key(FACET_STATE, our_vid, their_vid))
            .await?
            .unwrap_or(RelationshipState::None))
    }

    async fn set(
        &self,
        our_vid: &str,
        their_vid: &str,
        state: RelationshipState,
    ) -> Result<(), ATMError> {
        self.save(&rel_key(FACET_STATE, our_vid, their_vid), &state)
            .await
    }

    async fn thread_digests(
        &self,
        our_vid: &str,
        their_vid: &str,
    ) -> Result<ThreadDigests, ATMError> {
        Ok(self
            .load(&rel_key(FACET_DIGESTS, our_vid, their_vid))
            .await?
            .unwrap_or_default())
    }

    async fn set_thread_digests(
        &self,
        our_vid: &str,
        their_vid: &str,
        digests: ThreadDigests,
    ) -> Result<(), ATMError> {
        self.save(&rel_key(FACET_DIGESTS, our_vid, their_vid), &digests)
            .await
    }

    async fn reply_path(&self, our_vid: &str, their_vid: &str) -> Result<Vec<String>, ATMError> {
        Ok(self
            .load(&rel_key(FACET_REPLY_PATH, our_vid, their_vid))
            .await?
            .unwrap_or_default())
    }

    async fn set_reply_path(
        &self,
        our_vid: &str,
        their_vid: &str,
        path: Vec<String>,
    ) -> Result<(), ATMError> {
        self.save(&rel_key(FACET_REPLY_PATH, our_vid, their_vid), &path)
            .await
    }

    async fn get_capability(
        &self,
        our_vid: &str,
        their_vid: &str,
    ) -> Result<Option<PeerCapability>, ATMError> {
        self.load(&rel_key(FACET_CAPABILITY, our_vid, their_vid))
            .await
    }

    async fn set_capability(
        &self,
        our_vid: &str,
        their_vid: &str,
        capability: PeerCapability,
    ) -> Result<(), ATMError> {
        self.save(&rel_key(FACET_CAPABILITY, our_vid, their_vid), &capability)
            .await
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

/// The hop list to seal a routed message over, given that it is posted to
/// `own_mediator`.
///
/// The SDK always hands a routed message to its own mediator, and that mediator
/// only relays a routing layer addressed to itself — anything else it treats as
/// Direct delivery to one of its own accounts, and refuses when the addressee is
/// not one ("recipient is not local"). So a route whose first hop is some other
/// intermediary — the `Reply_Path` a peer on another mediator supplied is the
/// common case — has to be extended with `own_mediator` in front. Rev 3 §7.2.4
/// lets the responder add hops of its own, and the minimal condition it sets is
/// met: our mediator knows how to reach the first hop of the peer's list.
///
/// Unchanged when the route already starts at `own_mediator` (the same-mediator
/// case, byte-identical to before) and when it is a single hop — then `route[0]`
/// is the final recipient, not an intermediary, and the message goes to it
/// through our mediator's Direct delivery as it always has.
fn route_via_own_mediator<'a>(
    own_mediator: &str,
    route: &'a [String],
) -> std::borrow::Cow<'a, [String]> {
    match route.first() {
        Some(first) if route.len() > 1 && first != own_mediator => {
            let mut extended = Vec::with_capacity(route.len() + 1);
            extended.push(own_mediator.to_string());
            extended.extend_from_slice(route);
            std::borrow::Cow::Owned(extended)
        }
        _ => std::borrow::Cow::Borrowed(route),
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

/// Per-request bound on a TSP `/inbound` POST. The shared TDK HTTP client
/// carries no request timeout (it also serves long-lived calls), so without
/// this a POST onto a half-dead connection waits for the OS to give up.
const SEND_RAW_TIMEOUT: Duration = Duration::from_secs(30);

/// Delay before each re-POST of the same bytes after a connection-level
/// failure: two retries, three attempts in all.
const SEND_RAW_RETRY_BACKOFF: &[Duration] =
    &[Duration::from_millis(100), Duration::from_millis(400)];

/// POST packed TSP bytes to a mediator `/inbound`, re-POSTing the **identical
/// bytes** after a connection-level failure (Keyring VTI-39: a pooled
/// keep-alive connection closed by an intermediary under the request surfaced
/// as hyper `IncompleteMessage`, and the reply was lost with nothing retrying
/// it).
///
/// Re-POSTing is safe because the mediator stores a message idempotently on
/// the sha256 of its stored form, and that form is a pure function of these
/// bytes (`deliver_opaque` stores `base64url(qb2)`; `FjallStore::store_message`
/// keys it on `digest(message)`; the memory store and the Redis
/// `store_message` in `conf/atm-functions.lua` short-circuit the same way when
/// the hash is already stored for that recipient). So when the first attempt
/// was in fact stored and only its response was lost, the retry is a no-op.
/// That is also why this never re-seals: a fresh HPKE seal is different bytes
/// and would be stored — and delivered — twice.
///
/// Only failures where no HTTP answer was received are retried. Any status,
/// 4xx or 5xx, is the mediator's answer and is returned as-is.
async fn post_tsp_inbound(
    client: &reqwest::Client,
    url: &str,
    access_token: &str,
    bytes: &[u8],
    backoff: &[Duration],
) -> Result<(), ATMError> {
    let mut attempt = 0;
    let res = loop {
        let sent = client
            .post(url)
            .header("Content-Type", "application/tsp")
            .header("Authorization", format!("Bearer {access_token}"))
            .timeout(SEND_RAW_TIMEOUT)
            .body(bytes.to_vec())
            .send()
            .await;
        match sent {
            Ok(res) => break res,
            Err(e) if attempt < backoff.len() && is_retryable_send_error(&e) => {
                tracing::warn!(
                    attempt = attempt + 1,
                    error = %e,
                    "TSP /inbound POST failed before a response; re-sending the same bytes"
                );
                tokio::time::sleep(backoff[attempt]).await;
                attempt += 1;
            }
            Err(e) => {
                return Err(ATMError::TransportError(format!(
                    "Could not send TSP message: {e:?}"
                )));
            }
        }
    };

    // An accepted message is not re-read: a body that fails to arrive after a
    // 2xx must not turn a delivered message into an error the caller retries.
    if !res.status().is_success() {
        crate::errors::check_response("send TSP message", res).await?;
    }
    Ok(())
}

/// Whether a failed send never got an HTTP answer and may be re-sent: a failed
/// connect, the per-request timeout, or a connection that closed or reset
/// under the request (hyper `IncompleteMessage` / a closed or canceled
/// connection, or an I/O reset, abort, broken pipe or early EOF). Anything else
/// — a request that could not be built, a redirect loop, a body error — is not.
fn is_retryable_send_error(e: &reqwest::Error) -> bool {
    if e.is_status() || e.is_builder() || e.is_redirect() {
        return false;
    }
    if e.is_connect() || e.is_timeout() {
        return true;
    }
    let mut source = std::error::Error::source(e);
    while let Some(err) = source {
        if let Some(h) = err.downcast_ref::<hyper::Error>()
            && (h.is_incomplete_message() || h.is_closed() || h.is_canceled())
        {
            return true;
        }
        if let Some(io) = err.downcast_ref::<std::io::Error>()
            && matches!(
                io.kind(),
                std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::UnexpectedEof
            )
        {
            return true;
        }
        source = err.source();
    }
    false
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

/// What sending an application message to a peer requires first, decided from
/// the relationship state this endpoint holds (design note
/// `tsp-relationship-recovery.md`, D3).
///
/// This is the *local* half of recovery — it acts on the state we hold, which
/// is unambiguous. Detecting that a peer lost *its* half while we still hold
/// [`Bidirectional`](RelationshipState::Bidirectional) is a different problem:
/// §7.2.2 has the peer drop our message silently, so the only signal is a
/// round-trip timeout, which also means "peer down". That is timeout-driven and
/// belongs to the send/outbox layer (design note D4/C2), not to a decision read
/// off local state, so it is deliberately not represented here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendReadiness {
    /// [`Bidirectional`](RelationshipState::Bidirectional): send the payload
    /// directly.
    Ready,
    /// [`None`](RelationshipState::None): no relationship on record — establish
    /// one first. Send an invite; the payload may follow it immediately (§3.6)
    /// rather than wait a round trip, because the invite puts the peer in
    /// [`InviteReceived`](RelationshipState::InviteReceived), which admits it.
    /// This is the recovery path when our own half was lost (a restart onto an
    /// ephemeral store) or never existed.
    Reestablish,
    /// [`Pending`](RelationshipState::Pending) or
    /// [`InviteReceived`](RelationshipState::InviteReceived): a handshake is
    /// already in flight, so §3.6 admits an application message to the peer now —
    /// a peer we invited sits in `InviteReceived`, and a peer that invited us
    /// sits in `Pending`; neither is `None`, so both admit the payload. It can
    /// go without a fresh invite; the relationship completes when the accept
    /// lands.
    HandshakeInFlight,
}

/// Decide what a send needs from the relationship `state`. Pure and total over
/// the four states, so a new state cannot silently fall through to "send
/// anyway".
pub fn readiness_for(state: RelationshipState) -> SendReadiness {
    match state {
        RelationshipState::Bidirectional => SendReadiness::Ready,
        RelationshipState::None => SendReadiness::Reestablish,
        RelationshipState::Pending | RelationshipState::InviteReceived => {
            SendReadiness::HandshakeInFlight
        }
    }
}

/// May a refused `SendInvite` be carried on from, given the readiness read
/// **after** the refusal?
///
/// The question arises only inside
/// [`send_reestablishing`](TspOps::send_reestablishing), whose readiness read
/// and `SendInvite` are two separate awaits on the store: the peer can invite us
/// in between, leaving our half [`InviteReceived`](RelationshipState::InviteReceived),
/// and `SendInvite` is legal only from [`None`](RelationshipState::None). The
/// answer is decided on the *store* rather than on the error, because an
/// [`ATMError`]'s text is not a contract and the state is.
///
/// - Anything but [`Reestablish`](SendReadiness::Reestablish) means a
///   relationship is on record again — the peer invited us while we were
///   preparing to invite it, which is the outcome the invite existed to produce.
///   §3.6 admits the payload over any state but `None`, so carry on.
/// - [`Reestablish`](SendReadiness::Reestablish) means our half is still `None`:
///   the invite failed for its own reasons, nothing has changed, and sending the
///   payload would feed it to the peer's §7.2.2 drop and report success. Surface
///   the error.
///
/// Pure and total, like [`readiness_for`] beside it, and for the same reason:
/// the race it answers lives between two awaits and cannot be staged in a test,
/// so the decision is what gets pinned.
#[must_use]
pub fn invite_refusal_is_benign(after: SendReadiness) -> bool {
    !matches!(after, SendReadiness::Reestablish)
}

/// [`readiness_for`] the state currently held for the `(our_vid, their_vid)`
/// pair in `store`. Reads local state only — no network — so it composes with a
/// durable [`RelationshipStore`]: after a restart the readiness reflects what
/// the store recovered, which is the whole point of persisting it.
async fn readiness_for_pair(
    store: &Arc<dyn RelationshipStore>,
    our_vid: &str,
    their_vid: &str,
) -> Result<SendReadiness, ATMError> {
    Ok(readiness_for(store.get(our_vid, their_vid).await?))
}

/// Backoff schedule for re-establishment retries (design note
/// `tsp-relationship-recovery.md`, D4).
///
/// A mediator or VTA restart makes *every* peer time out at once, so retries
/// are spread — jittered exponential backoff — and **bounded**: §7.2.2's drop is
/// silent, so a round-trip timeout cannot distinguish "the peer lost our
/// relationship" from "the peer is down" (C2), and a peer that is genuinely down
/// must not be re-invited forever.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BackoffPolicy {
    /// Delay before the first retry.
    pub base: Duration,
    /// Ceiling any single delay is capped at.
    pub max: Duration,
    /// Give up after this many attempts. `0` disables recovery entirely.
    pub max_attempts: u32,
}

impl Default for BackoffPolicy {
    fn default() -> Self {
        Self {
            base: Duration::from_secs(1),
            max: Duration::from_secs(60),
            max_attempts: 6,
        }
    }
}

impl BackoffPolicy {
    /// The capped exponential delay for a 0-based `attempt` — `base · 2^attempt`,
    /// saturating, capped at `max` — or `None` once `attempt >= max_attempts`,
    /// which is the signal to give up. Deterministic; apply [`full_jitter`] on
    /// top for the actual wait so a fleet of peers does not retry in lockstep.
    pub fn capped_delay(&self, attempt: u32) -> Option<Duration> {
        if attempt >= self.max_attempts {
            return None;
        }
        let factor = 1u64.checked_shl(attempt).unwrap_or(u64::MAX);
        let millis = (self.base.as_millis() as u64).saturating_mul(factor);
        Some(Duration::from_millis(millis).min(self.max))
    }
}

/// Full jitter (AWS's "Exponential Backoff and Jitter"): spread a retry
/// uniformly over `[0, delay)` by scaling with `frac ∈ [0, 1)`. The caller
/// supplies `frac` from its own RNG, so this stays pure and testable; `frac` is
/// clamped, so an out-of-range value cannot produce a negative or longer wait.
pub fn full_jitter(delay: Duration, frac: f64) -> Duration {
    Duration::from_secs_f64(delay.as_secs_f64() * frac.clamp(0.0, 1.0))
}

/// What to do about a peer whose send timed out (design note D4). Single-flight
/// per peer, bounded by a [`BackoffPolicy`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryAction {
    /// No attempt is in flight and one is due — start re-establishing now.
    Start,
    /// An attempt is already in flight for this peer; coalesce onto it rather
    /// than launch a second (an invite storm against one peer is the failure
    /// this prevents).
    InFlight,
    /// Not yet eligible; re-check after this delay.
    Backoff(Duration),
    /// Attempts exhausted — surface an error and stop retrying this peer.
    GiveUp,
}

/// Per-peer re-establishment bookkeeping (design note D4).
///
/// Pure and clock-injected (`now_ms`), so a coordinator can hold one behind a
/// lock per `(our, their)` pair without pulling wall-clock time or an RNG into
/// the decision — the same shape as the rest of this module's tested cores.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RecoveryState {
    attempts: u32,
    in_flight: bool,
    next_eligible_ms: u64,
}

impl RecoveryState {
    /// A fresh tracker: eligible immediately, nothing in flight.
    pub fn new() -> Self {
        Self::default()
    }

    /// Decide what to do now, and mark an attempt in flight when the answer is
    /// [`RecoveryAction::Start`] — so two callers racing on the same peer get
    /// one `Start` and one `InFlight`, which is the single-flight guarantee.
    pub fn begin(&mut self, now_ms: u64, policy: &BackoffPolicy) -> RecoveryAction {
        if self.in_flight {
            return RecoveryAction::InFlight;
        }
        if self.attempts >= policy.max_attempts {
            return RecoveryAction::GiveUp;
        }
        if now_ms < self.next_eligible_ms {
            return RecoveryAction::Backoff(Duration::from_millis(self.next_eligible_ms - now_ms));
        }
        self.in_flight = true;
        RecoveryAction::Start
    }

    /// A started attempt failed: clear the in-flight flag, count it, and hold the
    /// peer off until `now_ms + delay` (the caller passes the already-jittered
    /// [`BackoffPolicy::capped_delay`]).
    pub fn fail(&mut self, now_ms: u64, delay: Duration) {
        self.in_flight = false;
        self.attempts = self.attempts.saturating_add(1);
        self.next_eligible_ms = now_ms.saturating_add(delay.as_millis() as u64);
    }

    /// The relationship recovered: forget everything, so the peer is treated as
    /// healthy again and a later loss starts a fresh backoff rather than
    /// inheriting an exhausted one.
    pub fn succeed(&mut self) {
        *self = Self::new();
    }

    /// Attempts spent so far (for observability — the drop/recovery metrics of
    /// design note D8).
    pub fn attempts(&self) -> u32 {
        self.attempts
    }
}

/// Idle-eviction policy for relationships (design note
/// `tsp-relationship-recovery.md`, D5) — the original proposal's "if not used
/// for a period of time, remove it".
///
/// Eviction is purely local and needs no coordination with the peer: if we evict
/// a relationship the peer kept, the next send reads `None`
/// ([`SendReadiness::Reestablish`]) and re-invites, and D2's reconcile transition
/// lets the peer accept the re-invite it did not strictly need. The only cost of
/// an over-eager eviction is one extra handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvictionPolicy {
    /// Evict a relationship untouched for at least this long.
    pub ttl: Duration,
}

impl Default for EvictionPolicy {
    /// Seven days — the interval from the original proposal.
    fn default() -> Self {
        Self {
            ttl: Duration::from_secs(7 * 24 * 60 * 60),
        }
    }
}

impl EvictionPolicy {
    /// Whether a relationship last touched at `last_active_ms` is idle as of
    /// `now_ms` — i.e. eligible for eviction. Saturating, so a clock that appears
    /// to move backwards reads as "not idle" rather than underflowing to a huge
    /// age.
    pub fn is_idle(&self, last_active_ms: u64, now_ms: u64) -> bool {
        now_ms.saturating_sub(last_active_ms) >= self.ttl.as_millis() as u64
    }
}

/// A snapshot of a [`RecoveryCoordinator`]'s counters (design note D8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RecoveryMetrics {
    /// Recovery attempts started (each a `Start` from [`RecoveryCoordinator::begin`]).
    pub attempts: u64,
    /// Attempts that ended in a recovered relationship.
    pub successes: u64,
    /// Peers given up on after exhausting the backoff — the alarm signal that a
    /// peer is durably unreachable, not merely mid-recovery.
    pub give_ups: u64,
}

/// Async single-flight recovery coordinator (design note D6).
///
/// Holds one [`RecoveryState`] per `(our, their)` pair behind a lock, driven by
/// a [`BackoffPolicy`] and a caller-supplied clock, and keeps the [`RecoveryMetrics`]
/// counters (D8). It turns the pure D4 decision into the thing a runtime calls:
/// on a round-trip timeout the runtime calls [`begin`](Self::begin); on
/// `Start` it runs one recovery ([`TspOps::reset_relationship`] →
/// [`TspOps::send_reestablishing`]) and reports the outcome with
/// [`settle_success`](Self::settle_success) / [`settle_failure`](Self::settle_failure).
/// A second timeout for the same peer while one is in flight gets `InFlight` and
/// coalesces — no invite storm against a single peer.
pub struct RecoveryCoordinator {
    policy: BackoffPolicy,
    states: tokio::sync::Mutex<HashMap<(String, String), RecoveryState>>,
    attempts: std::sync::atomic::AtomicU64,
    successes: std::sync::atomic::AtomicU64,
    give_ups: std::sync::atomic::AtomicU64,
}

impl RecoveryCoordinator {
    /// A coordinator with the given backoff policy and no peers tracked yet.
    pub fn new(policy: BackoffPolicy) -> Self {
        Self {
            policy,
            states: tokio::sync::Mutex::new(HashMap::new()),
            attempts: std::sync::atomic::AtomicU64::new(0),
            successes: std::sync::atomic::AtomicU64::new(0),
            give_ups: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Decide whether to (re)establish the relationship with `their` from `our`
    /// now — see [`RecoveryAction`]. `Start` marks an attempt in flight (and
    /// counts it); a racing caller gets `InFlight`.
    pub async fn begin(&self, our: &str, their: &str, now_ms: u64) -> RecoveryAction {
        use std::sync::atomic::Ordering::Relaxed;
        let key = (our.to_string(), their.to_string());
        let mut states = self.states.lock().await;
        let action = states.entry(key).or_default().begin(now_ms, &self.policy);
        match action {
            RecoveryAction::Start => {
                self.attempts.fetch_add(1, Relaxed);
            }
            RecoveryAction::GiveUp => {
                self.give_ups.fetch_add(1, Relaxed);
            }
            _ => {}
        }
        action
    }

    /// Report that a started attempt recovered the relationship: clears the
    /// peer's backoff so a later loss starts fresh.
    pub async fn settle_success(&self, our: &str, their: &str) {
        let key = (our.to_string(), their.to_string());
        if let Some(state) = self.states.lock().await.get_mut(&key) {
            state.succeed();
        }
        self.successes
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Report that a started attempt failed: hold the peer off for `delay` before
    /// the next `Start`.
    pub async fn settle_failure(&self, our: &str, their: &str, now_ms: u64, delay: Duration) {
        let key = (our.to_string(), their.to_string());
        self.states
            .lock()
            .await
            .entry(key)
            .or_default()
            .fail(now_ms, delay);
    }

    /// The delay to wait before retrying `attempt` (0-based), jittered — a
    /// convenience over [`BackoffPolicy::capped_delay`] + [`full_jitter`] using
    /// this coordinator's policy. `None` once attempts are exhausted.
    pub fn retry_delay(&self, attempt: u32, jitter_frac: f64) -> Option<Duration> {
        self.policy
            .capped_delay(attempt)
            .map(|d| full_jitter(d, jitter_frac))
    }

    /// A snapshot of the recovery counters (design note D8).
    pub fn metrics(&self) -> RecoveryMetrics {
        use std::sync::atomic::Ordering::Relaxed;
        RecoveryMetrics {
            attempts: self.attempts.load(Relaxed),
            successes: self.successes.load(Relaxed),
            give_ups: self.give_ups.load(Relaxed),
        }
    }
}

/// Per-peer inbound-invite rate limiter (design note D7).
///
/// D2 makes accepting an invite cheap and makes a re-invite reset a live
/// relationship to `InviteReceived`; this bounds how often one peer can make us
/// do that, so an authenticated peer cannot flood invites to keep a relationship
/// perpetually mid-handshake. It is *not* admission control (that stays the
/// application's decision on the invite) and it does not gate control messages
/// the FSM needs — only how often a *fresh* invite from an already-known peer is
/// acted on. Pure and clock-injected.
pub struct InviteRateLimiter {
    min_interval: Duration,
    last_accepted_ms: tokio::sync::Mutex<HashMap<(String, String), u64>>,
}

impl InviteRateLimiter {
    /// Accept at most one invite per `min_interval` from a given peer.
    pub fn new(min_interval: Duration) -> Self {
        Self {
            min_interval,
            last_accepted_ms: tokio::sync::Mutex::new(HashMap::new()),
        }
    }

    /// May we act on an invite from `their` to `our` at `now_ms`? Records the
    /// time and returns `true` when allowed; returns `false` (without updating)
    /// when the previous accept was under `min_interval` ago.
    pub async fn allow(&self, our: &str, their: &str, now_ms: u64) -> bool {
        let key = (our.to_string(), their.to_string());
        let mut map = self.last_accepted_ms.lock().await;
        let interval = self.min_interval.as_millis() as u64;
        match map.get(&key) {
            Some(&last) if now_ms.saturating_sub(last) < interval => false,
            _ => {
                map.insert(key, now_ms);
                true
            }
        }
    }
}

/// What an inbound control message did to relationship state, and what it asks
/// of this endpoint next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncomingControl {
    /// The relationship state after applying the message.
    pub state: RelationshipState,
    /// Rev 3 §7.3 answer to a cancellation is still owed, and the caller has to
    /// send it.
    ///
    /// A cancellation of a relationship held in both directions is answered
    /// with a cancellation of our own. [`TspOps::record_incoming_control`]
    /// sends that answer itself, so this is `false` once it has gone out — the
    /// state is `None` by then, and a caller that answered anyway through
    /// [`TspOps::cancel_relationship`] would only be refused. It is `true` only
    /// when the answer was due and could not be sent; retry it with
    /// [`TspOps::answer_cancellation`], naming the digest the peer's
    /// cancellation carried (`ControlMessage::reply`).
    ///
    /// `false` for every other control message.
    pub reply_expected: bool,
    /// The `Reply_Path` an invite carried — the route its accept is to travel
    /// back over (§7.2.4). Empty for a direct invite and for every other
    /// control message.
    ///
    /// [`TspOps::accept_relationship`] uses the stored copy of this without
    /// being asked; it is reported here so a caller can see the route rather
    /// than having to infer it.
    pub reply_path: Vec<String>,
}

/// What an inbound TSP frame turned out to be.
///
/// A receiver cannot tell a control message from an application one without
/// opening it — the kind lives in the encrypted payload, not the envelope — so
/// anything that must treat them differently needs to unpack once and be told,
/// rather than guess and unpack twice.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum InboundTsp {
    /// An application message for the upper layer.
    Application {
        /// The decrypted payload.
        payload: Vec<u8>,
        /// The sender's VID.
        sender: String,
    },
    /// An upper-layer control message (`XCTL`).
    ///
    /// Carried exactly like an application message and opaque to TSP, but the
    /// sender marked it as control for the layer above rather than as user
    /// data, and that distinction is the only thing the separate type code
    /// exists to convey. Handing it over as [`Self::Application`] would throw
    /// away the one bit of information it carries.
    UpperLayerControl {
        /// The decrypted payload.
        payload: Vec<u8>,
        /// The sender's VID.
        sender: String,
    },
    /// A padding-only message (`XPAD`), carrying nothing.
    ///
    /// §9.4: "The receiver SHOULD silently discard padding messages." It exists
    /// to make traffic analysis harder — a message whose entire content is
    /// filler, so an observer cannot tell a conversation's shape from the
    /// pattern of what crosses the wire.
    ///
    /// Reported rather than swallowed inside the SDK because a caller that
    /// fetched it still has to delete it from the mailbox, and one that cannot
    /// see it would leave it there forever. "Silently" constrains what reaches
    /// the application and what goes back to the sender, not whether the
    /// receiving code is told it arrived.
    Padding {
        /// The sender's VID.
        sender: String,
    },
    /// A relationship control message: an invite, an accept or a cancellation.
    Control {
        /// The decoded control payload. Boxed: a control message is several
        /// times the size of an application one, and an unboxed variant would
        /// make every inbound frame pay for it.
        control: Box<ControlMessage>,
        /// The sender's VID.
        sender: String,
        /// This message's `TSP_Digest` — the value an accept must echo back.
        thread_digest: [u8; 32],
    },
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
    ///
    /// Delegates to [`crate::tsp_wire::looks_like_tsp`], which is available in
    /// every build. Classification deliberately does not live behind the `tsp`
    /// feature — see that module for why — and having one implementation is
    /// what keeps the gated and ungated answers from disagreeing about the same
    /// frame.
    pub fn is_tsp(&self, stored: &str) -> bool {
        crate::tsp_wire::looks_like_tsp(stored)
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
        let (signing_key, _) = self.profile_tsp_keys(from_did).await?;
        let recipient = self.resolve_vid(to_did).await?;

        let packed = direct::pack(
            payload,
            MessageType::Direct,
            from_did,
            to_did,
            &signing_key,
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

    /// Route an **already-packed** TSP message through one or more relay hops.
    ///
    /// Like [`send_routed`], but `inner` is a pre-built TSP message sealed to the
    /// final recipient — a nested message, say, that the caller built itself.
    /// `route` is the hop list ending at that recipient (`route.last()`); the
    /// routing layer is sealed to `route[0]`.
    ///
    /// `inner` must be a TSP message. Spec Rev 3 §9.4 carries a routed inner raw
    /// as an `Encoded_TSP_Message`, where Rev 2 wrapped it in a `B` var-data
    /// field. That wrapper is what let this method carry an arbitrary
    /// non-TSP blob — the TSP↔DIDComm bridge — and Rev 3 removes it.
    pub async fn send_routed_opaque(
        &self,
        profile: &Arc<ATMProfile>,
        route: &[String],
        inner: &[u8],
    ) -> Result<(), ATMError> {
        if route.is_empty() {
            return Err(ATMError::MsgSendError("route must not be empty".into()));
        }

        // A routed inner is carried raw under Rev 3 §9.4, so it must be a TSP
        // message — which is always quadlet-aligned. Fail here, where the caller
        // can see why, rather than deep in the CESR encoder.
        if !inner.len().is_multiple_of(3) {
            return Err(ATMError::MsgSendError(format!(
                "a routed inner must be a TSP message and is therefore quadlet-aligned, but this \
                 one is {} bytes; carrying an arbitrary non-TSP inner relied on the Rev 2 \
                 var-data wrapper that Rev 3 removed",
                inner.len()
            )));
        }

        let (from_did, own_mediator) = profile.dids()?;
        // `send_raw` always posts to this profile's own mediator, so the routing
        // layer has to be addressed to it. A route that starts somewhere else —
        // the reply path a peer on another mediator supplied, say — gets our
        // mediator put in front (see `route_via_own_mediator`).
        let route = route_via_own_mediator(own_mediator, route);
        let route = route.as_ref();
        let first_hop = &route[0];

        let (signing_key, _) = self.profile_tsp_keys(from_did).await?;
        let first_vid = self.resolve_vid(first_hop).await?;
        let routed = affinidi_tsp::message::routed::pack_routed(
            inner,
            &route[1..],
            from_did,
            first_hop,
            &signing_key,
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
    /// Like [`send_nested`], but `inner` is a pre-built TSP message sealed to its
    /// final recipient. The intermediary unwraps the Nested layer and forwards
    /// the inner without opening it.
    ///
    /// `inner` must be a TSP message. Rev 3 §9.4 carries a nested inner raw as an
    /// `Encoded_TSP_Message`; the Rev 2 var-data wrapper that let this carry an
    /// arbitrary non-TSP blob — the TSP↔DIDComm bridge — is gone.
    pub async fn send_nested_opaque(
        &self,
        profile: &Arc<ATMProfile>,
        intermediary: &str,
        inner: &[u8],
    ) -> Result<(), ATMError> {
        let (from_did, _) = profile.dids()?;
        let (signing_key, _) = self.profile_tsp_keys(from_did).await?;
        let intermediary_vid = self.resolve_vid(intermediary).await?;
        let nested = affinidi_tsp::message::direct::pack(
            inner,
            affinidi_tsp::MessageType::Nested,
            from_did,
            intermediary,
            &signing_key,
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
        let (signing_key, _) = self.profile_tsp_keys(from_did).await?;

        // Inner Direct message sealed end-to-end to the final recipient.
        let recipient = self.resolve_vid(to_did).await?;
        let inner = direct::pack(
            payload,
            MessageType::Direct,
            from_did,
            to_did,
            &signing_key,
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
    ///
    /// When `to_did`'s mediator is known (learned from a routed invite, or set
    /// with [`set_peer_mediator`](Self::set_peer_mediator)) and is not ours, a
    /// Direct message cannot reach it — our mediator delivers Direct only to its
    /// own accounts — so the control message is routed
    /// `[own_mediator, peer_mediator, to_did]` instead, as
    /// [`ATM::send_to`](crate::ATM::send_to) does for application messages. The
    /// returned digest is the same either way: it is the inner message's.
    pub async fn send_control(
        &self,
        profile: &Arc<ATMProfile>,
        to_did: &str,
        control: &affinidi_tsp::message::control::ControlMessage,
    ) -> Result<[u8; 32], ATMError> {
        if let Some(route) = self.cross_mediator_route(profile, to_did).await? {
            return self
                .send_control_routed(profile, to_did, control, &route)
                .await;
        }
        let (from_did, _) = profile.dids()?;
        let (signing_key, _) = self.profile_tsp_keys(from_did).await?;
        let to_vid = self.resolve_vid(to_did).await?;
        let packed = affinidi_tsp::message::direct::pack(
            &control.encode(),
            affinidi_tsp::MessageType::Control,
            from_did,
            to_did,
            &signing_key,
            &to_vid.encryption_key,
        )
        .map_err(|e| ATMError::MsgSendError(format!("couldn't pack control TSP message: {e}")))?;

        self.send_raw(profile, &packed.bytes).await?;
        // The digest is the thread id of the exchange this message opens, and
        // the caller records it: an invite's is what the Rev 3 §7.2.3 race
        // tiebreak compares against, and what a cancellation later names.
        Ok(packed.thread_digest)
    }

    /// Send a control message to `to_did` over `route` instead of directly.
    ///
    /// Used for the accept that answers an invite carrying a `Reply_Path`
    /// (Rev 3 §7.2.4). The control message is sealed end-to-end to `to_did`
    /// and carried opaquely by the intermediaries, so what they relay is
    /// indistinguishable from any other routed message.
    ///
    /// `route` is the path as the inviter supplied it, and §5.3.3 has it ending
    /// at the inviter's own VID rather than its intermediary's. §7.2.4 allows a
    /// responder to prepend hops of its own — "the minimal required condition
    /// is that the last intermediary in `B`'s hop list knows how to reach the
    /// first hop in `A`'s list" — and when the path starts at a mediator other
    /// than ours, ours is prepended ([`send_routed_opaque`] does it), because
    /// the message is posted to our own mediator and it must be the first hop.
    /// When the inviter shares our mediator the path is used exactly as given.
    ///
    /// [`send_routed_opaque`]: Self::send_routed_opaque
    async fn send_control_routed(
        &self,
        profile: &Arc<ATMProfile>,
        to_did: &str,
        control: &affinidi_tsp::message::control::ControlMessage,
        route: &[String],
    ) -> Result<[u8; 32], ATMError> {
        let (from_did, _) = profile.dids()?;
        let (signing_key, _) = self.profile_tsp_keys(from_did).await?;
        let to_vid = self.resolve_vid(to_did).await?;
        let inner = affinidi_tsp::message::direct::pack(
            &control.encode(),
            affinidi_tsp::MessageType::Control,
            from_did,
            to_did,
            &signing_key,
            &to_vid.encryption_key,
        )
        .map_err(|e| ATMError::MsgSendError(format!("couldn't pack control TSP message: {e}")))?;

        self.send_routed_opaque(profile, route, &inner.bytes)
            .await?;
        Ok(inner.thread_digest)
    }

    // ── Relationship management ───────────────────────────────────────────────

    /// The configured [`RelationshipStore`] backing relationship state.
    fn relationship_store(&self) -> &Arc<dyn RelationshipStore> {
        self.atm.inner.config.relationship_store()
    }

    /// The route to `their_did` when its mediator is known and is not ours:
    /// `[peer_mediator, their_did]`, which [`send_routed_opaque`] then extends
    /// with our own mediator in front. `None` when the peer's mediator is
    /// unknown or is our own, where a Direct message is what reaches it.
    ///
    /// [`send_routed_opaque`]: Self::send_routed_opaque
    async fn cross_mediator_route(
        &self,
        profile: &Arc<ATMProfile>,
        their_did: &str,
    ) -> Result<Option<Vec<String>>, ATMError> {
        let (_, own_mediator) = profile.dids()?;
        let peer_mediator = self
            .peer_capability(profile, their_did)
            .await?
            .and_then(|c| c.mediator);
        Ok(match peer_mediator {
            Some(peer_mediator) if peer_mediator != own_mediator => {
                Some(vec![peer_mediator, their_did.to_string()])
            }
            _ => None,
        })
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
        let digest = self
            .send_control(profile, their_did, &ControlMessage::invite())
            .await?;
        store.set(our_did, their_did, next).await?;
        store
            .set_thread_digests(
                our_did,
                their_did,
                ThreadDigests {
                    invite: Some(digest),
                    accept: None,
                },
            )
            .await?;
        Ok(next)
    }

    /// Send a message under the **libsodium sealed box** (Rev 3 §8.3) instead of
    /// HPKE-Base.
    ///
    /// For a peer that has not migrated. §8 keeps this scheme for
    /// implementations that already had it and tells new ones otherwise —
    /// "implementors SHOULD consider migrating to the HPKE option specified in
    /// this document. We MAY remove this option in the future" — so [`send`] is
    /// the default and this is a per-peer compatibility decision.
    ///
    /// Nothing has to be agreed in advance: the receiver reads the scheme off
    /// the ciphertext field's code, and [`unpack`] accepts either.
    ///
    /// [`send`]: Self::send
    /// [`unpack`]: Self::unpack
    pub async fn send_sealed_box(
        &self,
        profile: &Arc<ATMProfile>,
        their_did: &str,
        payload: &[u8],
    ) -> Result<(), ATMError> {
        let (our_did, _) = profile.dids()?;
        let (signing_key, _) = self.profile_tsp_keys(our_did).await?;
        let their_vid = self.resolve_vid(their_did).await?;

        let packed = affinidi_tsp::message::direct::pack_sealed_box(
            payload,
            affinidi_tsp::MessageType::Direct,
            our_did,
            their_did,
            &signing_key,
            &their_vid.encryption_key,
        )
        .map_err(|e| ATMError::MsgSendError(format!("couldn't pack a sealed-box message: {e}")))?;

        self.send_raw(profile, &packed.bytes).await
    }

    /// Send an upper-layer control message (`XCTL`) carrying `payload`.
    ///
    /// Travels exactly like an application message and is gated the same way;
    /// TSP does not interpret the payload either way. The difference is the
    /// label: the receiver gets [`InboundTsp::UpperLayerControl`] rather than
    /// [`InboundTsp::Application`], so a protocol layered on top of TSP can
    /// keep its own signalling apart from user data without inventing a
    /// convention inside the payload.
    ///
    /// Not to be confused with [`send_control`](Self::send_control), which
    /// carries TSP's *own* relationship messages — invites, accepts and
    /// cancellations.
    pub async fn send_generic_control(
        &self,
        profile: &Arc<ATMProfile>,
        their_did: &str,
        payload: &[u8],
    ) -> Result<(), ATMError> {
        let (our_did, _) = profile.dids()?;
        let (signing_key, _) = self.profile_tsp_keys(our_did).await?;
        let their_vid = self.resolve_vid(their_did).await?;

        let packed = affinidi_tsp::message::direct::pack(
            payload,
            affinidi_tsp::MessageType::GenericControl,
            our_did,
            their_did,
            &signing_key,
            &their_vid.encryption_key,
        )
        .map_err(|e| {
            ATMError::MsgSendError(format!("couldn't pack an upper-layer control message: {e}"))
        })?;

        self.send_raw(profile, &packed.bytes).await
    }

    /// Send a padding-only message (`XPAD`) — content-free traffic, sized by
    /// `padding`.
    ///
    /// §11 notes that "timing, size, and frequency survive encryption, nesting,
    /// and routing alike": an observer of a hop learns when a relationship is
    /// busy even when it learns nothing else. A message with no content still
    /// occupies all three, so these let an endpoint spend them deliberately
    /// rather than leaking the shape of a real conversation.
    ///
    /// The other use is §7.4.3. An endpoint that rotated because its keys may
    /// have been compromised sends one to each peer, because "a peer holding
    /// stale key state will fail to verify it and will therefore obtain the new
    /// key state, whereas a peer that receives nothing has no occasion to". It
    /// is signed with the new keys, so an adversary holding the old ones cannot
    /// produce it.
    ///
    /// The receiver discards it silently — [`InboundTsp::Padding`] — so nothing
    /// reaches the peer's application and no reply comes back. A padding
    /// message that provoked a response would defeat its own purpose.
    pub async fn send_padding(
        &self,
        profile: &Arc<ATMProfile>,
        their_did: &str,
        padding: &affinidi_tsp::Padding,
    ) -> Result<(), ATMError> {
        let (our_did, _) = profile.dids()?;
        let (signing_key, _) = self.profile_tsp_keys(our_did).await?;
        let their_vid = self.resolve_vid(their_did).await?;

        let packed = affinidi_tsp::message::direct::pack_padding_message(
            our_did,
            their_did,
            &signing_key,
            &their_vid.encryption_key,
            padding,
        )
        .map_err(|e| ATMError::MsgSendError(format!("couldn't pack a padding message: {e}")))?;

        self.send_raw(profile, &packed.bytes).await
    }

    /// Introduce a new VID over an existing relationship, opening a second one
    /// beside it (Rev 3 §7.2.5, parallel relationship forming).
    ///
    /// `profile` and `their_did` are the relationship the introduction travels
    /// over; `new_profile` is the VID being introduced, and its key signs the
    /// introduction so the peer can check that whoever controls it agreed.
    ///
    /// The peer replies from a new VID of its own, to `new_profile`'s VID —
    /// §7.2.5 puts the accept between the new pair rather than over the
    /// original relationship — so the state this advances is the new pair's,
    /// not the existing one's. The existing relationship is only the channel.
    ///
    /// Why do this rather than form a fresh relationship: the peer learns the
    /// new identifier over a channel it already trusts, so there is no
    /// out-of-band introduction to secure. §11 notes an out-of-band
    /// introduction has no authenticity of its own and "a party able to
    /// interfere with that channel could substitute a VID of its own".
    pub async fn form_parallel_relationship(
        &self,
        profile: &Arc<ATMProfile>,
        their_did: &str,
        new_profile: &Arc<ATMProfile>,
    ) -> Result<RelationshipState, ATMError> {
        let (our_did, _) = profile.dids()?;
        let (new_did, _) = new_profile.dids()?;

        let existing = self.relationship_store().get(our_did, their_did).await?;
        if existing == RelationshipState::None {
            return Err(ATMError::MsgSendError(format!(
                "cannot introduce {new_did} to {their_did}: no relationship to introduce it over"
            )));
        }

        let (signing_key, _) = self.profile_tsp_keys(our_did).await?;
        let (new_signing_key, _) = self.profile_tsp_keys(new_did).await?;
        let their_vid = self.resolve_vid(their_did).await?;

        // The invite is pending between our new VID and the peer we sent it to.
        //
        // Not the pair it will end up forming: §7.2.5 has the peer pick VID_b1
        // and reply `[VID_b1, VID_a1, …]`, and we cannot know VID_b1 until that
        // reply arrives. `record_parallel_accept` moves the pending invite onto
        // the real pair once the accept names it.
        let store = self.relationship_store();
        let next = next_state(store, new_did, their_did, RelationshipEvent::SendInvite).await?;

        let packed = affinidi_tsp::message::direct::pack_referral_invite(
            &ControlMessage::invite_referral(new_did),
            our_did,
            their_did,
            &signing_key,
            &new_signing_key,
            &their_vid.encryption_key,
        )
        .map_err(|e| ATMError::MsgSendError(format!("couldn't pack referral invite: {e}")))?;

        self.send_raw(profile, &packed.bytes).await?;

        store.set(new_did, their_did, next).await?;
        store
            .set_thread_digests(
                new_did,
                their_did,
                ThreadDigests {
                    invite: Some(packed.thread_digest),
                    accept: None,
                },
            )
            .await?;
        Ok(next)
    }

    /// Record the accept that completes a parallel relationship (§7.2.5).
    ///
    /// The reply to an introduction comes from a VID that did not exist when the
    /// introduction was sent — §7.2.5 has the peer pick `VID_b1` and reply
    /// `[VID_b1, VID_a1, …]` — so the pending invite was filed against
    /// `invited_peer`, the VID we sent the introduction to. This moves it onto
    /// the pair the accept actually names and applies it.
    ///
    /// `new_profile` is the VID we introduced and `their_new_did` the sender of
    /// the accept. The accept's echoed digest must match the introduction's, or
    /// this rejects it: without that check any VID could answer an introduction
    /// it never received, and the peer's choice of `VID_b1` is otherwise
    /// unconstrained — there is nothing else here to tie the reply to the
    /// exchange it claims to belong to.
    pub async fn record_parallel_accept(
        &self,
        new_profile: &Arc<ATMProfile>,
        their_new_did: &str,
        invited_peer: &str,
        accept: &ControlMessage,
    ) -> Result<IncomingControl, ATMError> {
        let (new_did, _) = new_profile.dids()?;
        let store = self.relationship_store();

        let pending = store.thread_digests(new_did, invited_peer).await?;
        let expected = pending.invite.ok_or_else(|| {
            ATMError::MsgReceiveError(format!(
                "TSP accept from {their_new_did} rejected: {new_did} has no introduction \
                 outstanding to {invited_peer}"
            ))
        })?;
        if accept.reply != Some(expected) {
            return Err(ATMError::MsgReceiveError(format!(
                "TSP accept from {their_new_did} rejected: it does not echo the digest of the \
                 introduction {new_did} sent to {invited_peer}"
            )));
        }

        // Carry the pending invite over to the pair the accept names, so the
        // ordinary accept handling below sees the state it expects.
        if store.get(new_did, their_new_did).await? == RelationshipState::None {
            store
                .set(new_did, their_new_did, RelationshipState::Pending)
                .await?;
            store
                .set_thread_digests(new_did, their_new_did, pending)
                .await?;
        }

        self.record_incoming_control(new_profile, their_new_did, accept)
            .await
    }

    /// Accept an introduction, completing a parallel relationship (§7.2.5).
    ///
    /// `new_profile` is our own new VID and `their_new_did` the VID the peer
    /// introduced. §7.2.5 puts this accept between the new pair —
    /// `[VID_b1, VID_a1, …]` — rather than over the relationship the invite
    /// arrived on, so it is sent from `new_profile` and addressed to the
    /// introduced VID.
    ///
    /// `invite_thread_digest` is the digest of the invite that carried the
    /// introduction, from [`unpack_control`](Self::unpack_control).
    pub async fn accept_parallel_relationship(
        &self,
        new_profile: &Arc<ATMProfile>,
        their_new_did: &str,
        invite_thread_digest: [u8; 32],
    ) -> Result<RelationshipState, ATMError> {
        let (new_did, _) = new_profile.dids()?;
        let store = self.relationship_store();

        // Record the introduction now. `record_incoming_control` could not:
        // the invite arrived before this VID was chosen, so there was no pair
        // to record it against. This is the first moment both halves exist.
        if store.get(new_did, their_new_did).await? == RelationshipState::None {
            store
                .set(new_did, their_new_did, RelationshipState::InviteReceived)
                .await?;
            store
                .set_thread_digests(
                    new_did,
                    their_new_did,
                    ThreadDigests {
                        invite: Some(invite_thread_digest),
                        accept: None,
                    },
                )
                .await?;
        }

        // From here it is an ordinary accept between the new pair, which is the
        // whole of what §7.2.5 changes.
        self.accept_relationship(new_profile, their_new_did, invite_thread_digest)
            .await
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
            // §5.3.3: a hop list ends at the destination's own VID, not its
            // intermediary's — so the path back to us is our mediator, then us.
            // Rev 2 advertised only the mediator, which left the exit ambiguous.
            &ControlMessage::invite_routed(vec![our_mediator.to_string(), our_did.to_string()]),
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
        let accept = ControlMessage::accept(invite_thread_digest);

        // §7.2.4: "If the `Reply_Path` is present, then `B` MUST use the routed
        // path specified by `Reply_Path` to send the `TSP_RFA` message". Sending
        // direct would disclose to the inviter, and to anyone watching, an
        // endpoint the route exists to keep out of view — so the path is
        // honoured here rather than left to the caller to remember.
        //
        // With no reply path, `send_control` still routes the accept when the
        // inviter's mediator is known and is not ours.
        let reply_path = store.reply_path(our_did, their_did).await?;
        let digest = if reply_path.is_empty() {
            self.send_control(profile, their_did, &accept).await?
        } else {
            self.send_control_routed(profile, their_did, &accept, &reply_path)
                .await?
        };

        store.set(our_did, their_did, next).await?;
        // The accept's own digest identifies the other direction (§7.2.1).
        let mut digests = store.thread_digests(our_did, their_did).await?;
        digests.accept = Some(digest);
        store
            .set_thread_digests(our_did, their_did, digests)
            .await?;
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

    /// Answer a peer's cancellation (Rev 3 §7.3) with one of our own, naming
    /// `relationship_digest` — the digest the peer's cancellation named.
    ///
    /// §7.3 has an endpoint that held the relationship in both directions reply
    /// with a `TSP_RFD` and then forget it. By the time anyone can answer,
    /// [`record_incoming_control`](Self::record_incoming_control) has already
    /// applied `ReceiveCancel` and the relationship is gone, so this sends the
    /// cancellation **without** running the state machine — which is exactly
    /// why [`cancel_relationship`](Self::cancel_relationship) cannot be used
    /// for it (`SendCancel` is not a transition out of `None`).
    ///
    /// `record_incoming_control` calls this itself. It is public so a caller
    /// told [`IncomingControl::reply_expected`] (the answer could not be sent)
    /// can retry.
    ///
    /// Refused unless the stored state for the pair is
    /// [`RelationshipState::None`]: a relationship still held is cancelled with
    /// `cancel_relationship`, which also forgets it. Returns the answer's own
    /// thread digest.
    pub async fn answer_cancellation(
        &self,
        profile: &Arc<ATMProfile>,
        their_did: &str,
        relationship_digest: [u8; 32],
    ) -> Result<[u8; 32], ATMError> {
        let (our_did, _) = profile.dids()?;
        let state = self.relationship_store().get(our_did, their_did).await?;
        if state != RelationshipState::None {
            return Err(ATMError::MsgSendError(format!(
                "no §7.3 answer to send: {our_did} still holds a relationship with {their_did} \
                 ({state:?}); cancel it with cancel_relationship"
            )));
        }
        self.send_control(
            profile,
            their_did,
            &ControlMessage::cancel(relationship_digest),
        )
        .await
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

    /// What a send to `their_did` would need first, read from the current
    /// relationship — see [`SendReadiness`] (design note
    /// `tsp-relationship-recovery.md`, D3). A caller can branch on this itself;
    /// [`send_reestablishing`](Self::send_reestablishing) is the ready-made send
    /// that acts on it.
    pub async fn send_readiness(
        &self,
        profile: &Arc<ATMProfile>,
        their_did: &str,
    ) -> Result<SendReadiness, ATMError> {
        let (our_did, _) = profile.dids()?;
        readiness_for_pair(self.relationship_store(), our_did, their_did).await
    }

    /// Send `payload` to `their_did` over `route`, (re)establishing the
    /// relationship first when this endpoint has lost or never had it — the
    /// recovery-aware send (design note `tsp-relationship-recovery.md`, D3).
    ///
    /// This is what a service calls instead of [`send_routed`](Self::send_routed)
    /// so that a peer restart cannot turn its traffic into silent §7.2.2 drops:
    ///
    /// - [`Ready`](SendReadiness::Ready): the relationship is live — send
    ///   directly.
    /// - [`HandshakeInFlight`](SendReadiness::HandshakeInFlight): an invite is
    ///   already outstanding in one direction; §3.6 lets the payload follow it,
    ///   so send directly without a second invite.
    /// - [`Reestablish`](SendReadiness::Reestablish): no relationship on record —
    ///   send an invite ([`form_relationship_routed`](Self::form_relationship_routed)),
    ///   then the payload immediately after (§3.6). The peer records the invite,
    ///   which admits the payload that follows, so recovery costs one round trip
    ///   rather than invite → wait-for-accept → send.
    ///
    /// It handles the case where *our* half was lost or never formed. It does
    /// **not** handle the peer having lost *its* half while we still read
    /// `Bidirectional`: that shows up only as a round-trip timeout (§7.2.2's drop
    /// is silent) and is the send/outbox layer's job to detect and retry
    /// (design note D4). Here `Ready` sends once and returns.
    ///
    /// # The peer may invite us mid-sequence
    ///
    /// The readiness read and the invite's `SendInvite` transition are two
    /// separate awaits on the relationship store, and the peer can move our half
    /// between them: its own invite arrives, `None` + `ReceiveInvite` leaves us
    /// [`InviteReceived`](RelationshipState::InviteReceived), and `SendInvite` is
    /// legal only from [`None`](RelationshipState::None). The invite is then
    /// refused with `invalid transition: SendInvite in state InviteReceived`.
    ///
    /// That is not a failed send. It is the outcome the invite existed to
    /// produce, reached from the other side — a relationship is on record again,
    /// and [`admits_application_message`](RelationshipState::admits_application_message)
    /// is true for every state but `None`, so the payload can go. Returning the
    /// error instead loses it, and loses it worst where this method matters
    /// most: two endpoints repairing the same broken relationship at once is
    /// what a mediator restart or a peer redeploy produces, so the collision is
    /// commonest exactly when recovery is.
    ///
    /// So a refused invite is answered by **re-reading the store** rather than by
    /// inspecting the error — [`invite_refusal_is_benign`] is the decision, and
    /// is pure so it can be tested without a mediator. Our half no longer `None`
    /// means carry on to the payload; still `None` means the invite failed for
    /// its own reasons (no route, no key, the mediator refused it) and that error
    /// stands. The payload is sent exactly once either way.
    pub async fn send_reestablishing(
        &self,
        profile: &Arc<ATMProfile>,
        their_did: &str,
        route: &[String],
        payload: &[u8],
    ) -> Result<(), ATMError> {
        if self.send_readiness(profile, their_did).await? == SendReadiness::Reestablish
            // Sends the invite and moves us to `Pending`; the payload below rides
            // after it (§3.6) rather than waiting for the accept.
            && let Err(e) = self.form_relationship_routed(profile, their_did).await
        {
            let after = self.send_readiness(profile, their_did).await?;
            if !invite_refusal_is_benign(after) {
                return Err(e);
            }
            tracing::debug!(
                %their_did,
                ?after,
                "a re-establishing invite was refused because the peer re-formed the \
                 relationship first; sending the payload over it (§3.6)",
            );
        }
        self.send_routed(profile, route, payload).await
    }

    /// Force the local relationship with `their_did` back to `None`, clearing its
    /// thread digests — the "stale local half" reset (design note
    /// `tsp-relationship-recovery.md`, D4).
    ///
    /// Use it when a send over a relationship we read as `Bidirectional` times
    /// out with no reply. §7.2.2's drop is silent, so a round-trip timeout is the
    /// only sign the *peer* may have lost its half while we still hold ours; and
    /// re-inviting needs `SendInvite`, which is valid only from `None`. After
    /// this, [`send_reestablishing`](Self::send_reestablishing) sees
    /// [`SendReadiness::Reestablish`] and re-invites.
    ///
    /// Safe against a false positive (the timeout was merely the network): if the
    /// peer *did* keep the relationship, our fresh invite arrives over its live
    /// one and D2's reconcile transition (`Bidirectional` + `ReceiveInvite` →
    /// `InviteReceived`) has it re-accept rather than error. So an unnecessary
    /// reset self-heals — which is what lets D4 act on an ambiguous timeout at
    /// all.
    pub async fn reset_relationship(
        &self,
        profile: &Arc<ATMProfile>,
        their_did: &str,
    ) -> Result<(), ATMError> {
        let (our_did, _) = profile.dids()?;
        let store = self.relationship_store();
        store
            .set(our_did, their_did, RelationshipState::None)
            .await?;
        store
            .set_thread_digests(our_did, their_did, ThreadDigests::default())
            .await?;
        Ok(())
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
    ) -> Result<IncomingControl, ATMError> {
        let (our_did, _) = profile.dids()?;
        let event = match control.control_type {
            ControlType::RelationshipFormingInvite => RelationshipEvent::ReceiveInvite,
            ControlType::RelationshipFormingAccept => RelationshipEvent::ReceiveAccept,
            ControlType::RelationshipCancel => RelationshipEvent::ReceiveCancel,
        };

        // §7.2.5: an invite may introduce a new VID, carrying that VID's own
        // signature. Check it before anything else. Unverified, the referral is
        // only a claim that the sender *wishes* to introduce the VID — it says
        // nothing about whether that VID's controller agreed — and acting on
        // one is how an endpoint gets talked into a relationship with an
        // identifier nobody vouched for.
        //
        // The check needs the introduced VID's key, which means resolving it;
        // that is why `affinidi-tsp` cannot do this itself and leaves it here.
        if let Some(referral) = control.referral.as_ref() {
            let introduced = self.resolve_vid(&referral.new_vid).await.map_err(|e| {
                ATMError::MsgReceiveError(format!(
                    "TSP referral from {peer_did} discarded: could not resolve the introduced \
                     VID {}: {e}",
                    referral.new_vid
                ))
            })?;
            affinidi_tsp::message::direct::verify_referral(
                // The SDK packs referrals under HPKE-Base, so that is the
                // digest algorithm the signature covers.
                affinidi_tsp::message::direct::PkaeScheme::HpkeBase,
                control,
                peer_did,
                &introduced.signing_key,
            )
            .map_err(|e| {
                ATMError::MsgReceiveError(format!(
                    "TSP referral from {peer_did} discarded: {} did not sign the introduction: {e}",
                    referral.new_vid
                ))
            })?;
        }

        let store = self.relationship_store();
        let prior = store.get(our_did, peer_did).await?;

        // A referral invite advances nothing here, and cannot.
        //
        // §7.2.5 has it arrive on one relationship while proposing another: the
        // pair it forms is our *new* VID and the introduced one, and we have not
        // chosen our new VID yet at this point — that is the decision the
        // introduction asks us to make. Advancing the relationship it arrived on
        // would be wrong twice over: that relationship is not the one being
        // formed, and it is already established, so there is no invite for it to
        // receive.
        //
        // So the introduction is recorded when it is acted on, by
        // `accept_parallel_relationship`, which is the first moment both
        // identities exist. Here it is only verified and reported.
        if control.referral.is_some() {
            return Ok(IncomingControl {
                state: prior,
                reply_expected: false,
                reply_path: control.route.clone(),
            });
        }

        let mut digests = store.thread_digests(our_did, peer_did).await?;

        // Rev 3 §7.2.3, the invite race. Both endpoints may invite each other
        // for the same VID pair at once. Both keep the invite whose digest is
        // lexicographically lower and discard the other, so the two sides
        // converge on one exchange and one thread id instead of each believing
        // it opened the relationship.
        if control.control_type == ControlType::RelationshipFormingInvite
            && prior == RelationshipState::Pending
            && let (Some(ours), Some(theirs)) = (digests.invite, control.digest)
        {
            if ours.as_slice() < theirs.as_slice() {
                return Err(ATMError::MsgReceiveError(format!(
                    "TSP invite from {peer_did} discarded: our own invite has the lower digest"
                )));
            }
            // Theirs wins: adopt it in place of the invite we sent.
            store
                .set(our_did, peer_did, RelationshipState::InviteReceived)
                .await?;
            store
                .set_thread_digests(
                    our_did,
                    peer_did,
                    ThreadDigests {
                        invite: Some(theirs),
                        accept: None,
                    },
                )
                .await?;
            store
                .set_reply_path(our_did, peer_did, control.route.clone())
                .await?;
            return Ok(IncomingControl {
                state: RelationshipState::InviteReceived,
                reply_expected: false,
                reply_path: control.route.clone(),
            });
        }

        // Rev 3 §7.3 gives a cancellation three cases, distinguished by what we
        // hold. One naming a relationship we do not hold at all — or naming a
        // digest that is not either half of the one we do hold — is ignored
        // rather than answered, so it cannot be used to probe which
        // relationships exist. The other two — forget it, or answer and forget
        // it — are handled below.
        if control.control_type == ControlType::RelationshipCancel {
            if prior == RelationshipState::None {
                return Err(ATMError::MsgReceiveError(format!(
                    "TSP cancellation from {peer_did} discarded: no relationship with {our_did}"
                )));
            }
            if let Some(named) = control.reply.as_ref()
                && !digests.recognizes(named)
            {
                return Err(ATMError::MsgReceiveError(format!(
                    "TSP cancellation from {peer_did} discarded: names an unrecognised relationship"
                )));
            }
        }

        // What the relationship was known by, for the §7.3 answer below — the
        // record is cleared before it is sent.
        let cancelled_digest = digests.invite.or(digests.accept);
        let new_state = advance_state(store, our_did, peer_did, event).await?;

        // Record the digests as the handshake produces them: the invite's
        // identifies this direction, the accept's the other (§7.2.1).
        match control.control_type {
            ControlType::RelationshipFormingInvite => {
                digests.invite = control.digest;
                store.set_thread_digests(our_did, peer_did, digests).await?;
                // §7.2.4: the accept MUST travel back over the path the invite
                // supplied, so it is kept rather than left to the caller to
                // notice — a responder that forgets it silently goes direct.
                store
                    .set_reply_path(our_did, peer_did, control.route.clone())
                    .await?;
            }
            ControlType::RelationshipFormingAccept => {
                digests.accept = control.digest;
                store.set_thread_digests(our_did, peer_did, digests).await?;
            }
            ControlType::RelationshipCancel => {
                store
                    .set_thread_digests(our_did, peer_did, ThreadDigests::default())
                    .await?;
                store.set_reply_path(our_did, peer_did, Vec::new()).await?;
            }
        }
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

        // §7.3: a cancellation of a relationship we held in both directions is
        // answered with a cancellation of our own. It is sent here, not left to
        // the caller: there is no policy in it — nothing to accept or refuse —
        // and by the time a caller could act the relationship is already gone,
        // so `cancel_relationship` refuses to send it (`SendCancel` from
        // `None`). Every consumer that was left to answer it got that error and
        // the peer was never answered (Keyring VTI-38).
        //
        // It names the relationship the peer's cancellation named, so both
        // sides agree which one was torn down. A send that fails does not undo
        // the recording — the relationship is gone either way — and is reported
        // through `reply_expected` so the caller can retry.
        let mut reply_expected = false;
        if control.control_type == ControlType::RelationshipCancel
            && prior == RelationshipState::Bidirectional
        {
            let named = control.reply.or(cancelled_digest);
            match named {
                Some(named) => {
                    if let Err(e) = self.answer_cancellation(profile, peer_did, named).await {
                        tracing::warn!(
                            peer = %peer_did,
                            error = %e,
                            "could not send the TSP §7.3 answer to a cancellation; the \
                             relationship is forgotten regardless",
                        );
                        reply_expected = true;
                    }
                }
                // Unreachable for a decoded cancellation — `reply` is its one
                // required field — but a relationship with no digest on either
                // side leaves nothing to name, so there is nothing to answer.
                None => tracing::warn!(
                    peer = %peer_did,
                    "TSP cancellation named no relationship and none was recorded; no §7.3 \
                     answer sent",
                ),
            }
        }

        Ok(IncomingControl {
            state: new_state,
            reply_expected,
            reply_path: match control.control_type {
                ControlType::RelationshipFormingInvite => control.route.clone(),
                _ => Vec::new(),
            },
        })
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
        // `advertises_tsp`, not `!endpoints.is_empty()`: a *mediated* peer
        // publishes no transport URL of its own — its `TSPTransport` service
        // names its mediator's DID — so testing the URL list alone reads as "no
        // TSP" for exactly the peers TSP reaches through a mediator.
        let has_tsp_service = if needs_resolve {
            self.resolve_vid(their_did)
                .await
                .map(|vid| vid.advertises_tsp())
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
    ///
    /// A connection-level failure (a pooled keep-alive connection closed under
    /// the request, a reset, a refused connect, the per-request timeout) is
    /// retried twice more with the **same bytes**; the mediator stores a message
    /// idempotently on its hash, so a retry of a POST that was in fact stored is
    /// a no-op. The message is never re-sealed, which would defeat that. An HTTP status is an answer and is never
    /// retried.
    pub async fn send_raw(&self, profile: &Arc<ATMProfile>, bytes: &[u8]) -> Result<(), ATMError> {
        let mediator_url = profile.get_mediator_rest_endpoint().ok_or_else(|| {
            ATMError::MsgSendError("Profile is missing a valid mediator URL".into())
        })?;
        let (profile_did, mediator_did) = profile.dids()?;
        // Authenticated once: the retries below are sub-second, well inside the
        // access token's lifetime, and a connection-level failure says nothing
        // about the token. A token the mediator does refuse comes back as a 401
        // status, which is an answer and is not retried here.
        let tokens = self
            .atm
            .get_tdk()
            .authentication()
            .authenticate(profile_did.to_string(), mediator_did.to_string(), 3, None)
            .await?;

        post_tsp_inbound(
            self.atm.inner.tdk_common.client(),
            &[&mediator_url, "/inbound"].concat(),
            &tokens.access_token,
            bytes,
            SEND_RAW_RETRY_BACKOFF,
        )
        .await
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

        let unpacked = self
            .unpack_with_fresh_key_state(profile_did, &meta.sender, qb2)
            .await?;

        // Rev 3 §7.2.2: an application message from a VID we hold no
        // relationship with is dropped. "It is not permissible that one
        // endpoint which has learned a VID of the other simply starts with an
        // application level message without first having an exchange of TSP
        // control messages."
        //
        // Any recorded relationship admits one, not only a completed one:
        // receiving an invite records the inbound half, and §3.6 lets a sender
        // pack user data alongside its invite rather than wait a round trip.
        if self.atm.inner.config.tsp_relationship_gating() {
            let state = self
                .relationship_store()
                .get(profile_did, &unpacked.sender)
                .await?;
            if !state.admits_application_message() {
                // D8: the alarm the original incident lacked — a peer arriving
                // with a relationship this endpoint has lost.
                self.atm.inner.config.record_relationship_drop();
                return Err(ATMError::MsgReceiveError(format!(
                    "TSP message from {} discarded: no relationship with {profile_did}",
                    unpacked.sender
                )));
            }
        }

        // Observing an authenticated inbound TSP message confirms the sender's
        // agent speaks TSP (no-op unless a TSP policy is set).
        self.learn_tsp_supported(profile_did, &unpacked.sender, CapabilitySource::Observed)
            .await?;

        // A padding message has no payload, and this signature has no way to
        // say so: returning it would hand the caller an empty `Vec` that looks
        // exactly like a real message the peer sent with no content. Refusing
        // is the honest answer, and `unpack_message` is the API that can
        // actually express the distinction.
        if unpacked.message_type == affinidi_tsp::MessageType::PaddingOnly {
            return Err(ATMError::MsgReceiveError(format!(
                "TSP padding message from {} carries no payload; use unpack_message to \
                 handle padding",
                unpacked.sender
            )));
        }

        Ok((unpacked.payload, unpacked.sender))
    }

    /// Unpack a fetched TSP message and report which kind it is.
    ///
    /// For a caller that handles both — a service listener taking whatever
    /// arrives on one socket — where [`unpack`](Self::unpack) and
    /// [`unpack_control`](Self::unpack_control) each assume the kind in advance.
    ///
    /// An application message is subject to the Rev 3 §7.2.2 relationship gate;
    /// a control message is not, since the exchange that forms a relationship
    /// cannot itself require one.
    pub async fn unpack_message(
        &self,
        profile: &Arc<ATMProfile>,
        qb2: &[u8],
    ) -> Result<InboundTsp, ATMError> {
        let meta = MetaEnvelope::parse(qb2)
            .map_err(|e| ATMError::MsgReceiveError(format!("couldn't parse TSP envelope: {e}")))?;

        let (profile_did, _) = profile.dids()?;
        if meta.receiver != profile_did {
            return Err(ATMError::MsgReceiveError(format!(
                "TSP message addressed to {}, not this profile ({profile_did})",
                meta.receiver
            )));
        }

        let unpacked = self
            .unpack_with_fresh_key_state(profile_did, &meta.sender, qb2)
            .await?;

        self.learn_tsp_supported(profile_did, &unpacked.sender, CapabilitySource::Observed)
            .await?;

        if let Some(control) = unpacked.control {
            return Ok(InboundTsp::Control {
                control: Box::new(control),
                sender: unpacked.sender,
                thread_digest: unpacked.thread_digest,
            });
        }

        // A padding message carries nothing, so it is neither gated nor
        // delivered — §9.4 has the receiver discard it silently. It is still
        // named, so the caller can clear it from the mailbox.
        if unpacked.message_type == affinidi_tsp::MessageType::PaddingOnly {
            return Ok(InboundTsp::Padding {
                sender: unpacked.sender,
            });
        }

        // §7.2.2, as in `unpack_bytes`: an application message from a VID we
        // hold no relationship with is discarded.
        if self.atm.inner.config.tsp_relationship_gating() {
            let state = self
                .relationship_store()
                .get(profile_did, &unpacked.sender)
                .await?;
            if !state.admits_application_message() {
                self.atm.inner.config.record_relationship_drop(); // D8
                return Err(ATMError::MsgReceiveError(format!(
                    "TSP message from {} discarded: no relationship with {profile_did}",
                    unpacked.sender
                )));
            }
        }

        // `XCTL` and `XSCS` travel identically and are gated identically; only
        // the label the sender attached differs, and it is preserved here.
        if unpacked.message_type == affinidi_tsp::MessageType::GenericControl {
            return Ok(InboundTsp::UpperLayerControl {
                payload: unpacked.payload,
                sender: unpacked.sender,
            });
        }

        Ok(InboundTsp::Application {
            payload: unpacked.payload,
            sender: unpacked.sender,
        })
    }

    /// Unpack a fetched TSP **control** message (raw qb2 bytes), returning the
    /// decoded [`ControlMessage`], the sender VID, and the message's TSP
    /// **thread digest** — the Rev 3 `TSP_Digest` carried in the message and
    /// verified on unpack.
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

        let unpacked = self
            .unpack_with_fresh_key_state(profile_did, &meta.sender, qb2)
            .await?;

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
        self.connect_websocket_inner(profile, false).await
    }

    /// Open the mediator's raw-TSP WebSocket in **delete-to-ack** mode
    /// (subprotocol `tsp-ack`).
    ///
    /// Identical to [`connect_websocket`](Self::connect_websocket) except that
    /// the mediator does not delete a message when it writes it to the socket.
    /// It keeps it until this client acknowledges, via
    /// [`TspWebSocket::ack`], which you call once the frame is safely in your
    /// hands.
    ///
    /// Use this whenever losing a message matters. Plain `connect_websocket`
    /// is at-most-once past the socket write: a successful write means the
    /// frame reached the mediator's local sink, so a connection that dies
    /// before your process reads it takes the message with it — the mediator
    /// has already forgotten it.
    ///
    /// The trade is the usual one. Anything sent but not acked when the
    /// connection drops is redelivered on the next connect, so a consumer
    /// **must be idempotent**: it may see a frame twice. Within a single
    /// connection the mediator will not re-send an un-acked frame.
    pub async fn connect_websocket_acked(
        &self,
        profile: &Arc<ATMProfile>,
    ) -> Result<TspWebSocket, ATMError> {
        self.connect_websocket_inner(profile, true).await
    }

    async fn connect_websocket_inner(
        &self,
        profile: &Arc<ATMProfile>,
        ack: bool,
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

        // Offer `bearer.<jwt>` (auth) + the raw-TSP mode subprotocol(s).
        //
        // `tsp` is offered BEFORE `tsp-ack`, and the order is load-bearing.
        //
        // A mediator that predates `tsp-ack` echoes the client's subprotocol
        // list back unchanged, so it would happily echo `tsp-ack` without
        // implementing it — and we would believe we had delete-to-ack while it
        // deleted on send, silently losing the very guarantee we asked for.
        //
        // Selection takes the first client-listed protocol the server also
        // offers. An older mediator offers back our own list and so selects our
        // first entry, `tsp`; a mediator that supports the mode narrows its
        // offer to `tsp-ack` and so selects that despite it being second. Only
        // a mediator that implements delete-to-ack can answer `tsp-ack`, which
        // is what makes the echoed value trustworthy.
        let builder =
            ClientRequestBuilder::new(uri).with_sub_protocol(format!("bearer.{access_token}"));
        let builder = if ack {
            builder
                .with_sub_protocol("tsp")
                .with_sub_protocol("tsp-ack")
        } else {
            builder.with_sub_protocol("tsp")
        };

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
        let echoed = response
            .headers()
            .get("sec-websocket-protocol")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let acked = match echoed.as_deref() {
            Some("tsp-ack") => true,
            Some("tsp") => {
                // A downgrade is silent otherwise, and silently losing the
                // delivery guarantee you asked for is exactly the failure this
                // mode exists to prevent — say so loudly.
                if ack {
                    tracing::warn!(
                        "requested `tsp-ack` but the mediator echoed `tsp`: it predates \
                         delete-to-ack, so delivery on this socket is at-most-once past \
                         the write and `ack()` will not be honoured"
                    );
                }
                false
            }
            other => {
                tracing::warn!(
                    "TSP websocket did not echo a known subprotocol (got {other:?}); \
                     raw-TSP mode may not be active"
                );
                false
            }
        };

        Ok(TspWebSocket {
            ws,
            ack_mode: acked,
            atm: self.atm.clone(),
            profile: profile.clone(),
        })
    }

    // ── Internal helpers ────────────────────────────────────────────────────

    /// Resolve a DID-based VID to its TSP public keys + endpoints.
    /// Force a re-resolution of `did`, returning to its provenance chain rather
    /// than the cached document.
    ///
    /// Rev 3 §7.4.2 makes the cached value precisely what may have gone stale,
    /// so the cache entry is evicted before resolving. Unlike the synchronous
    /// resolver in `affinidi-tsp`, the SDK is async and can do the work rather
    /// than only signalling that it is needed.
    async fn refresh_vid(&self, did: &str) -> Result<affinidi_tsp::ResolvedVid, ATMError> {
        self.atm.inner.tdk_common.did_resolver().remove(did).await;
        self.resolve_vid(did).await
    }

    /// Re-resolve `did` unless its per-peer rate limit is in force.
    ///
    /// `Ok(None)` means the limit is in force and nothing was attempted; the
    /// caller proceeds on the key state it already holds. §7.4.2 bounds this
    /// because re-resolution can be provoked by a message that has not been
    /// authenticated, and resolution is more expensive than the message
    /// provoking it, so the cost would otherwise land on the peer's
    /// infrastructure rather than on this endpoint.
    async fn refresh_key_state(
        &self,
        did: &str,
        now_ms: u64,
    ) -> Result<Option<affinidi_tsp::ResolvedVid>, ATMError> {
        let policy = self.atm.inner.config.tsp_key_state_policy();
        if !self
            .atm
            .inner
            .tsp_key_state
            .may_resolve(did, policy.resolution_rate_limit, now_ms)
        {
            return Ok(None);
        }
        self.atm.inner.tsp_key_state.record_resolved(did, now_ms);
        self.refresh_vid(did).await.map(Some)
    }

    /// Verify and decrypt `qb2` from `sender_vid`, applying the key-state
    /// freshness rules of Rev 3 §7.4.2 on the way.
    ///
    /// Two occasions refresh the sender's key state, both only where this
    /// endpoint resolves key state for itself and holds a relationship with the
    /// sender:
    ///
    /// * a message arriving after a silence longer than the re-verification
    ///   threshold is not acted on until the key state has been refreshed —
    ///   the case that matters under compromise, since stale key state is
    ///   internally consistent, so a message signed with a compromised key
    ///   verifies and gives no warning;
    /// * a verification failure is retried once after a refresh, since the
    ///   failure may be a rotation not yet observed.
    ///
    /// Outside a relationship neither applies and a failure is discarded at
    /// once, or anyone could make this endpoint resolve by sending it noise.
    async fn unpack_with_fresh_key_state(
        &self,
        profile_did: &str,
        sender_vid: &str,
        qb2: &[u8],
    ) -> Result<affinidi_tsp::message::direct::UnpackedMessage, ATMError> {
        let (_signing_key, decryption_key) = self.profile_tsp_keys(profile_did).await?;
        let policy = self.atm.inner.config.tsp_key_state_policy();
        let now_ms = self.atm.inner.config.clock().unix_millis() as u64;

        let established = self
            .relationship_store()
            .get(profile_did, sender_vid)
            .await?
            .admits_application_message();
        let watching = policy.self_resolving && established;

        let mut sender = self.resolve_vid(sender_vid).await?;

        if watching
            && self.atm.inner.tsp_key_state.silent_longer_than(
                sender_vid,
                policy.reverification_threshold,
                now_ms,
            )
        {
            match self.refresh_key_state(sender_vid, now_ms).await {
                Ok(Some(fresh)) => sender = fresh,
                // Rate-limited: this peer's allowance is spent, so proceed on
                // the key state we hold.
                Ok(None) => {}
                Err(e) => {
                    return Err(ATMError::MsgReceiveError(format!(
                        "key state for {sender_vid} could not be confirmed after a silence: {e}"
                    )));
                }
            }
        }

        let unpacked = match direct::unpack(qb2, &decryption_key, &sender.signing_key) {
            Ok(unpacked) => unpacked,
            Err(first_error) => {
                if !watching {
                    return Err(ATMError::MsgReceiveError(format!(
                        "couldn't unpack TSP message: {first_error}"
                    )));
                }
                match self.refresh_key_state(sender_vid, now_ms).await {
                    Ok(Some(fresh)) => direct::unpack(qb2, &decryption_key, &fresh.signing_key)
                        .map_err(|e| {
                            ATMError::MsgReceiveError(format!("couldn't unpack TSP message: {e}"))
                        })?,
                    // No refresh was possible, so the original failure stands.
                    _ => {
                        return Err(ATMError::MsgReceiveError(format!(
                            "couldn't unpack TSP message: {first_error}"
                        )));
                    }
                }
            }
        };

        // The message verified, so the key state behind it is confirmed now.
        self.atm.inner.tsp_key_state.record_seen(sender_vid, now_ms);
        Ok(unpacked)
    }

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
    /// Whether the mediator agreed to `tsp-ack` (delete-to-ack). False for a
    /// plain `tsp` socket, including when a `tsp-ack` request was downgraded by
    /// an older mediator.
    ack_mode: bool,
    /// Held so [`ack`](TspWebSocket::ack) can reach the delete path; the ack
    /// travels over the SDK's ordinary authenticated deletion channel, not over
    /// this socket.
    atm: ATM,
    profile: Arc<ATMProfile>,
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

    /// Whether this socket negotiated `tsp-ack` (delete-to-ack delivery).
    ///
    /// False on a plain `tsp` socket **and** when a `tsp-ack` request was
    /// downgraded by a mediator that predates the mode — check this if you need
    /// to know whether the guarantee you asked for is actually in force.
    pub fn is_acked(&self) -> bool {
        self.ack_mode
    }

    /// Acknowledge a frame returned by [`recv`](TspWebSocket::recv), releasing
    /// the mediator's copy.
    ///
    /// Call this once the frame is safely handled — persisted, dispatched,
    /// whatever "received" means for you — not merely once it has been read off
    /// the socket. Everything not acked when the connection drops is
    /// redelivered on the next connect, which is the entire point: that window
    /// is what makes this at-least-once instead of at-most-once.
    ///
    /// The message id is derived, not transmitted: the mediator keys deletion on
    /// `sha256` of the stored body, and the stored body for a TSP message is the
    /// base64url encoding of exactly these bytes. So the ack needs no id from
    /// the mediator and no change to the frame format.
    ///
    /// Deletion is queued on the SDK's background deletion handler, so this does
    /// not block on a round trip.
    ///
    /// Returns an error on a socket that did not negotiate `tsp-ack` — there,
    /// the mediator deleted the message when it sent it and there is nothing to
    /// acknowledge. Guard with [`is_acked`](TspWebSocket::is_acked) in code that
    /// handles both modes.
    pub async fn ack(&self, qb2: &[u8]) -> Result<(), ATMError> {
        if !self.ack_mode {
            return Err(ATMError::ConfigError(
                "ack() on a socket that did not negotiate `tsp-ack`: the mediator already \
                 deleted this message when it sent it. Open the socket with \
                 `connect_websocket_acked` to use delete-to-ack."
                    .into(),
            ));
        }
        let stored = BASE64_URL_SAFE_NO_PAD.encode(qb2);
        let message_id = sha256::digest(stored.as_str());
        self.atm
            .delete_message_background(&self.profile, &message_id)
            .await
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
    use super::{ControlMessage, ThreadDigests};
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
            &bob.encryption_key,
        )
        .unwrap();

        // Stored/transit form, recognised on pickup.
        let stored = BASE64_URL_SAFE_NO_PAD.encode(&packed.bytes);
        assert!(is_tsp(&stored));
        let qb2 = BASE64_URL_SAFE_NO_PAD.decode(stored.as_bytes()).unwrap();

        // bob unpacks (as TspOps::unpack does, with direct::unpack).
        let unpacked = direct::unpack(&qb2, &bob.decryption_key, &alice.verifying_key).unwrap();
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
        BackoffPolicy, CapabilitySource, EvictionPolicy, InMemoryRelationshipStore,
        InviteRateLimiter, PeerCapability, PersistentRelationshipStore, ProtocolChoice,
        RecoveryAction, RecoveryCoordinator, RecoveryState, RelationshipEvent, RelationshipKv,
        RelationshipState, RelationshipStore, SendReadiness, TSP_DISCOVER_FEATURE_URI, TspPolicy,
        TspSupport, advance_state, classify_protocol, disclosure_advertises_tsp, full_jitter,
        invite_refusal_is_benign, next_state, readiness_for, readiness_for_pair,
        route_via_own_mediator,
    };
    use crate::errors::ATMError;
    use crate::protocols::discover_features::{
        Disclosure, DiscoverFeaturesDisclosure, FeatureType,
    };
    use std::sync::Arc;
    use std::time::Duration;

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

    // ---- Rev 3 §7.2.2 / §7.3, at the SDK layer ----

    /// §7.2.2 gates on *any* recorded relationship, not only a completed one.
    /// An invite records the inbound half, and §3.6 lets a sender pack user
    /// data alongside its invite rather than wait a round trip, so gating on
    /// `Bidirectional` alone would drop messages the specification expects.
    #[tokio::test]
    async fn gating_admits_any_recorded_relationship() {
        let store: Arc<dyn RelationshipStore> = Arc::new(InMemoryRelationshipStore::default());

        // A stranger is refused.
        assert!(
            !store
                .get(BOB, ALICE)
                .await
                .unwrap()
                .admits_application_message()
        );

        // Receiving an invite is enough.
        advance_state(&store, BOB, ALICE, RelationshipEvent::ReceiveInvite)
            .await
            .unwrap();
        assert!(
            store
                .get(BOB, ALICE)
                .await
                .unwrap()
                .admits_application_message()
        );

        // As is having sent one.
        let store2: Arc<dyn RelationshipStore> = Arc::new(InMemoryRelationshipStore::default());
        advance_state(&store2, ALICE, BOB, RelationshipEvent::SendInvite)
            .await
            .unwrap();
        assert!(
            store2
                .get(ALICE, BOB)
                .await
                .unwrap()
                .admits_application_message()
        );
    }

    /// §7.3: a cancellation removes a half-formed relationship, and the state
    /// machine has a transition for it — an inviter may withdraw before being
    /// answered.
    #[tokio::test]
    async fn a_cancellation_removes_a_half_formed_relationship() {
        let store: Arc<dyn RelationshipStore> = Arc::new(InMemoryRelationshipStore::default());

        advance_state(&store, BOB, ALICE, RelationshipEvent::ReceiveInvite)
            .await
            .unwrap();
        let next = advance_state(&store, BOB, ALICE, RelationshipEvent::ReceiveCancel)
            .await
            .unwrap();

        assert_eq!(next, RelationshipState::None);
        assert_eq!(
            store.get(BOB, ALICE).await.unwrap(),
            RelationshipState::None
        );
    }

    /// §7.3: the reply expectation follows the state held *before* the
    /// cancellation — bidirectional is answered, one-sided is not.
    #[tokio::test]
    async fn only_a_bidirectional_cancellation_expects_a_reply() {
        for (prior, expected) in [
            (RelationshipState::Bidirectional, true),
            (RelationshipState::InviteReceived, false),
            (RelationshipState::Pending, false),
        ] {
            let store: Arc<dyn RelationshipStore> = Arc::new(InMemoryRelationshipStore::default());
            store.set(BOB, ALICE, prior).await.unwrap();

            let held = store.get(BOB, ALICE).await.unwrap();
            let reply_expected = held == RelationshipState::Bidirectional;
            assert_eq!(reply_expected, expected, "prior state {prior:?}");

            advance_state(&store, BOB, ALICE, RelationshipEvent::ReceiveCancel)
                .await
                .unwrap();
            assert_eq!(
                store.get(BOB, ALICE).await.unwrap(),
                RelationshipState::None
            );
        }
    }

    // ---- Rev 3 §7.2.1 / §7.2.3: thread digests and the invite race ----

    /// §7.2.1: a relationship has two digests, one per uni-directional half,
    /// and a cancellation may name either. A store that keeps neither cannot
    /// contradict a digest, so it recognises any — refusing every cancellation
    /// would be worse than accepting one it cannot check.
    #[test]
    fn thread_digests_recognize_either_half() {
        let invite = [0x11u8; 32];
        let accept = [0x22u8; 32];
        let other = [0x33u8; 32];

        let both = ThreadDigests {
            invite: Some(invite),
            accept: Some(accept),
        };
        assert!(both.recognizes(&invite));
        assert!(both.recognizes(&accept));
        assert!(!both.recognizes(&other));

        let one = ThreadDigests {
            invite: Some(invite),
            accept: None,
        };
        assert!(one.recognizes(&invite));
        assert!(!one.recognizes(&other));

        // Nothing recorded: anything is recognised.
        assert!(ThreadDigests::default().recognizes(&other));
    }

    #[tokio::test]
    async fn the_store_round_trips_thread_digests() {
        let store: Arc<dyn RelationshipStore> = Arc::new(InMemoryRelationshipStore::default());
        assert_eq!(
            store.thread_digests(ALICE, BOB).await.unwrap(),
            ThreadDigests::default()
        );

        let digests = ThreadDigests {
            invite: Some([7u8; 32]),
            accept: Some([9u8; 32]),
        };
        store.set_thread_digests(ALICE, BOB, digests).await.unwrap();
        assert_eq!(store.thread_digests(ALICE, BOB).await.unwrap(), digests);

        // Per pair, so the reverse direction is its own record.
        assert_eq!(
            store.thread_digests(BOB, ALICE).await.unwrap(),
            ThreadDigests::default()
        );
    }

    /// §7.2.3: both endpoints keep the invite whose digest is lexicographically
    /// lower. The rule has to be symmetric — run from each side of the same
    /// pair, the two must agree on which invite survives, or they end up with
    /// two half-relationships and two thread ids.
    #[test]
    fn the_race_tiebreak_is_symmetric() {
        let lower = [0x01u8; 32];
        let higher = [0x02u8; 32];

        // The endpoint holding the lower digest keeps its own.
        let keeps_own = lower.as_slice() < higher.as_slice();
        assert!(keeps_own);

        // The endpoint holding the higher digest adopts the one that arrived.
        let adopts_theirs = higher.as_slice() >= lower.as_slice();
        assert!(adopts_theirs);

        // Exactly one of the two keeps its own, whichever way round they are.
        for (ours, theirs) in [(lower, higher), (higher, lower)] {
            let we_keep_ours = ours.as_slice() < theirs.as_slice();
            let they_keep_theirs = theirs.as_slice() < ours.as_slice();
            assert_ne!(
                we_keep_ours, they_keep_theirs,
                "exactly one side keeps its own invite"
            );
        }
    }

    // ---- Rev 3 §7.2.4: relationship forming over a routed path ----

    #[tokio::test]
    async fn the_store_round_trips_a_reply_path() {
        let store: Arc<dyn RelationshipStore> = Arc::new(InMemoryRelationshipStore::default());
        assert!(store.reply_path(BOB, ALICE).await.unwrap().is_empty());

        let path = vec!["did:example:m1".to_string(), ALICE.to_string()];
        store
            .set_reply_path(BOB, ALICE, path.clone())
            .await
            .unwrap();
        assert_eq!(store.reply_path(BOB, ALICE).await.unwrap(), path);

        // Per pair and per direction.
        assert!(store.reply_path(ALICE, BOB).await.unwrap().is_empty());
    }

    /// Keyring VTI-41: a reply path that starts at the inviter's mediator is
    /// sent from a different mediator. The message is posted to our own
    /// mediator, which relays only a routing layer addressed to itself, so ours
    /// goes in front (§7.2.4 lets the responder add hops).
    #[test]
    fn a_route_starting_at_another_mediator_gets_ours_prepended() {
        let own = "did:example:mediator-b";
        let route = vec!["did:example:mediator-a".to_string(), ALICE.to_string()];

        let sent = route_via_own_mediator(own, &route);
        assert_eq!(
            sent.as_ref(),
            [
                own.to_string(),
                "did:example:mediator-a".to_string(),
                ALICE.to_string()
            ]
        );
    }

    /// The same-mediator case is untouched: a route that already starts at our
    /// mediator is sent exactly as given, so what goes on the wire is
    /// byte-identical to before.
    #[test]
    fn a_route_starting_at_our_mediator_is_left_alone() {
        let own = "did:example:mediator-a";
        let route = vec![own.to_string(), ALICE.to_string()];

        let sent = route_via_own_mediator(own, &route);
        assert!(matches!(sent, std::borrow::Cow::Borrowed(_)));
        assert_eq!(sent.as_ref(), route.as_slice());
    }

    /// A one-hop route names the final recipient, not an intermediary, so there
    /// is nothing to put a mediator in front of. And an empty one is the
    /// caller's error to report, not this function's to repair.
    #[test]
    fn a_single_hop_or_empty_route_is_left_alone() {
        let own = "did:example:mediator-a";
        let single = vec![BOB.to_string()];
        assert_eq!(
            route_via_own_mediator(own, &single).as_ref(),
            single.as_slice()
        );
        assert!(route_via_own_mediator(own, &[]).is_empty());
    }

    /// §5.3.3: a hop list ends at the destination's own VID, not its
    /// intermediary's. A reply path is a hop list, so an invite that asks for a
    /// routed reply names the mediator *and* the inviter — Rev 2 advertised
    /// only the mediator, which left the exit ambiguous.
    #[test]
    fn a_routed_invite_names_the_inviter_as_the_exit() {
        let mediator = "did:example:mediator".to_string();
        let inviter = "did:example:alice".to_string();
        let control = ControlMessage::invite_routed(vec![mediator.clone(), inviter.clone()]);

        assert_eq!(control.route, vec![mediator, inviter.clone()]);
        assert_eq!(
            control.route.last(),
            Some(&inviter),
            "the path must end at the inviter, so the exit delivers to it"
        );
    }

    /// A reply path survives the invite's wire encoding: it is the `-J` field
    /// of the `XRFI` payload, so it has to come back out of a packed message.
    #[test]
    fn a_reply_path_round_trips_through_the_wire() {
        let alice = PrivateVid::generate("did:example:alice");
        let bob = PrivateVid::generate("did:example:bob");
        let path = vec![
            "did:example:mediator".to_string(),
            "did:example:alice".to_string(),
        ];

        let packed = direct::pack(
            &ControlMessage::invite_routed(path.clone()).encode(),
            MessageType::Control,
            "did:example:alice",
            "did:example:bob",
            &alice.signing_key,
            &bob.encryption_key,
        )
        .unwrap();

        let unpacked =
            direct::unpack(&packed.bytes, &bob.decryption_key, &alice.verifying_key).unwrap();
        let control = unpacked.control.expect("an invite decodes to a control");
        assert_eq!(control.route, path);
    }

    /// An invite with no reply path leaves the field empty, and the accept then
    /// goes direct — the `-JAA` case.
    #[test]
    fn a_direct_invite_carries_no_reply_path() {
        let alice = PrivateVid::generate("did:example:alice");
        let bob = PrivateVid::generate("did:example:bob");

        let packed = direct::pack(
            &ControlMessage::invite().encode(),
            MessageType::Control,
            "did:example:alice",
            "did:example:bob",
            &alice.signing_key,
            &bob.encryption_key,
        )
        .unwrap();

        let unpacked =
            direct::unpack(&packed.bytes, &bob.decryption_key, &alice.verifying_key).unwrap();
        assert!(unpacked.control.unwrap().route.is_empty());
    }

    // ---- D1: durable relationship store (tsp-relationship-recovery.md) ----

    /// A shareable in-memory [`RelationshipKv`] standing in for a real durable
    /// backend. Cloning shares the same map, so dropping a store and building a
    /// new one over a clone models a process restart against the same on-disk
    /// store — without a real backend the test would only re-prove the map.
    #[derive(Clone, Default)]
    struct SharedMemKv(
        std::sync::Arc<tokio::sync::Mutex<std::collections::HashMap<Vec<u8>, Vec<u8>>>>,
    );

    #[async_trait::async_trait]
    impl RelationshipKv for SharedMemKv {
        async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, ATMError> {
            Ok(self.0.lock().await.get(key).cloned())
        }
        async fn put(&self, key: &[u8], value: &[u8]) -> Result<(), ATMError> {
            self.0.lock().await.insert(key.to_vec(), value.to_vec());
            Ok(())
        }
        async fn delete(&self, key: &[u8]) -> Result<(), ATMError> {
            self.0.lock().await.remove(key);
            Ok(())
        }
        async fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, ATMError> {
            Ok(self
                .0
                .lock()
                .await
                .iter()
                .filter(|(k, _)| k.starts_with(prefix))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect())
        }
    }

    const A: &str = ALICE;
    const B: &str = BOB;

    /// Every facet the trait keeps round-trips through the durable store.
    #[tokio::test]
    async fn persistent_store_round_trips_all_facets() {
        let store = PersistentRelationshipStore::new(SharedMemKv::default());

        store
            .set(A, B, RelationshipState::Bidirectional)
            .await
            .unwrap();
        let digests = ThreadDigests {
            invite: Some([7u8; 32]),
            accept: Some([9u8; 32]),
        };
        store.set_thread_digests(A, B, digests).await.unwrap();
        store
            .set_reply_path(A, B, vec!["did:example:mediator".to_string()])
            .await
            .unwrap();
        let cap = PeerCapability {
            tsp: TspSupport::Supported,
            source: CapabilitySource::Relationship,
            learned_at_unix: 1234,
            mediator: Some("did:example:mediator".to_string()),
        };
        store.set_capability(A, B, cap.clone()).await.unwrap();

        assert_eq!(
            store.get(A, B).await.unwrap(),
            RelationshipState::Bidirectional
        );
        assert_eq!(store.thread_digests(A, B).await.unwrap(), digests);
        assert_eq!(
            store.reply_path(A, B).await.unwrap(),
            vec!["did:example:mediator"]
        );
        assert_eq!(store.get_capability(A, B).await.unwrap(), Some(cap));
    }

    /// The whole point of D1: an established relationship survives a restart. A
    /// new store built over the same backend still holds `Bidirectional` — so
    /// the peer's next application message is admitted, not dropped at the
    /// §7.2.2 gate.
    #[tokio::test]
    async fn persistent_store_survives_a_restart() {
        let backend = SharedMemKv::default();

        // First "process": drive the relationship to complete and record its
        // digests, then drop the store.
        {
            let store = PersistentRelationshipStore::new(backend.clone());
            store
                .set(A, B, RelationshipState::Bidirectional)
                .await
                .unwrap();
            store
                .set_thread_digests(
                    A,
                    B,
                    ThreadDigests {
                        invite: Some([1u8; 32]),
                        accept: Some([2u8; 32]),
                    },
                )
                .await
                .unwrap();
        }

        // Restart: a fresh store over the same on-disk backend.
        let restarted = PersistentRelationshipStore::new(backend);
        assert_eq!(
            restarted.get(A, B).await.unwrap(),
            RelationshipState::Bidirectional,
            "a durable store must not forget the relationship across a restart"
        );
        assert!(
            restarted
                .get(A, B)
                .await
                .unwrap()
                .admits_application_message(),
            "the peer's traffic must still be admitted after the restart"
        );
        assert_eq!(
            restarted.thread_digests(A, B).await.unwrap().invite,
            Some([1u8; 32]),
            "digests must survive too, or the §7.2.3 tiebreak is lost after a restart"
        );
    }

    /// An unknown pair reads as the neutral defaults — never an error.
    #[tokio::test]
    async fn persistent_store_defaults_for_an_unknown_pair() {
        let store = PersistentRelationshipStore::new(SharedMemKv::default());
        assert_eq!(store.get(A, B).await.unwrap(), RelationshipState::None);
        assert_eq!(
            store.thread_digests(A, B).await.unwrap(),
            ThreadDigests::default()
        );
        assert!(store.reply_path(A, B).await.unwrap().is_empty());
        assert_eq!(store.get_capability(A, B).await.unwrap(), None);
    }

    /// Length-prefixed keys keep pairs and facets from colliding even when the
    /// DIDs share substrings across the `our`/`their` boundary — `("a","bc")`
    /// must not read `("ab","c")`'s state.
    #[tokio::test]
    async fn persistent_store_keys_do_not_collide() {
        let store = PersistentRelationshipStore::new(SharedMemKv::default());
        store
            .set("a", "bc", RelationshipState::Bidirectional)
            .await
            .unwrap();
        store
            .set("ab", "c", RelationshipState::Pending)
            .await
            .unwrap();
        assert_eq!(
            store.get("a", "bc").await.unwrap(),
            RelationshipState::Bidirectional
        );
        assert_eq!(
            store.get("ab", "c").await.unwrap(),
            RelationshipState::Pending
        );
        // A facet is likewise scoped: setting a capability must not shadow state.
        assert_eq!(
            store.get("a", "bc").await.unwrap(),
            RelationshipState::Bidirectional
        );
    }

    /// It is a drop-in for the ephemeral default: usable behind
    /// `Arc<dyn RelationshipStore>`, the type `with_relationship_store` takes.
    #[tokio::test]
    async fn persistent_store_is_a_dyn_relationship_store() {
        let store: Arc<dyn RelationshipStore> =
            Arc::new(PersistentRelationshipStore::new(SharedMemKv::default()));
        store
            .set(A, B, RelationshipState::InviteReceived)
            .await
            .unwrap();
        assert_eq!(
            store.get(A, B).await.unwrap(),
            RelationshipState::InviteReceived
        );
    }

    // ---- D3: recovery-aware send readiness (tsp-relationship-recovery.md) ----

    /// The pure decision is total and correct over every state.
    #[test]
    fn readiness_for_maps_every_state() {
        assert_eq!(
            readiness_for(RelationshipState::Bidirectional),
            SendReadiness::Ready
        );
        assert_eq!(
            readiness_for(RelationshipState::None),
            SendReadiness::Reestablish
        );
        assert_eq!(
            readiness_for(RelationshipState::Pending),
            SendReadiness::HandshakeInFlight
        );
        assert_eq!(
            readiness_for(RelationshipState::InviteReceived),
            SendReadiness::HandshakeInFlight
        );
    }

    /// Only `None` asks to re-establish — a handshake already in flight must not
    /// be restarted, and a live relationship must not re-invite.
    #[test]
    fn only_a_missing_relationship_triggers_reestablish() {
        for state in [
            RelationshipState::Bidirectional,
            RelationshipState::Pending,
            RelationshipState::InviteReceived,
        ] {
            assert_ne!(
                readiness_for(state),
                SendReadiness::Reestablish,
                "{state:?} must not re-invite"
            );
        }
    }

    /// The collision `send_reestablishing` has to survive: the peer invited us
    /// between our readiness read and our `SendInvite`, so the invite was refused
    /// and our half now reads `InviteReceived`. A relationship is on record, §3.6
    /// admits the payload over it, and the send carries on.
    ///
    /// Pinned here rather than end-to-end because the race lives between two
    /// awaits — there is no point at which a test can put the peer's invite.
    #[test]
    fn a_peer_invite_landing_mid_reestablish_is_carried_on_from() {
        assert!(invite_refusal_is_benign(SendReadiness::HandshakeInFlight));
    }

    /// The peer went further and the handshake completed under us. Still on
    /// record, still sendable — more so.
    #[test]
    fn a_completed_relationship_is_carried_on_from() {
        assert!(invite_refusal_is_benign(SendReadiness::Ready));
    }

    /// Nothing on record after the refusal, so the invite genuinely failed.
    /// Sending the payload here would feed it to the peer's §7.2.2 drop and
    /// report success, so the error has to stand.
    #[test]
    fn a_half_still_absent_means_the_invite_really_failed() {
        assert!(!invite_refusal_is_benign(SendReadiness::Reestablish));
    }

    /// The two decisions must not drift apart: exactly the readiness that asks
    /// for an invite is the one that makes a refusal fatal.
    #[test]
    fn benign_refusal_is_the_complement_of_asking_to_reestablish() {
        for state in [
            RelationshipState::Bidirectional,
            RelationshipState::None,
            RelationshipState::Pending,
            RelationshipState::InviteReceived,
        ] {
            let readiness = readiness_for(state);
            assert_eq!(
                invite_refusal_is_benign(readiness),
                readiness != SendReadiness::Reestablish,
                "{state:?}"
            );
        }
    }

    /// D1 × D3: readiness is read off the store, so a durable store makes a send
    /// after a restart take the `Ready` path — no needless re-invite — while a
    /// pair the store never knew takes `Reestablish`.
    #[tokio::test]
    async fn readiness_follows_the_durable_store_across_a_restart() {
        let backend = SharedMemKv::default();
        {
            let store: Arc<dyn RelationshipStore> =
                Arc::new(PersistentRelationshipStore::new(backend.clone()));
            store
                .set(A, B, RelationshipState::Bidirectional)
                .await
                .unwrap();
        }

        // Restart: a fresh store over the same backend.
        let store: Arc<dyn RelationshipStore> = Arc::new(PersistentRelationshipStore::new(backend));

        // The recovered relationship sends directly — the whole reason to persist.
        assert_eq!(
            readiness_for_pair(&store, A, B).await.unwrap(),
            SendReadiness::Ready
        );
        // A peer we have no record of re-establishes before sending.
        assert_eq!(
            readiness_for_pair(&store, A, "did:example:carol")
                .await
                .unwrap(),
            SendReadiness::Reestablish
        );
    }

    // ---- D4: bounded, jittered, single-flight recovery (tsp-relationship-recovery.md) ----

    /// The delay grows exponentially from `base`, is capped at `max`, and stops
    /// (`None`) once attempts are exhausted.
    #[test]
    fn backoff_is_exponential_capped_and_bounded() {
        let policy = BackoffPolicy {
            base: Duration::from_secs(1),
            max: Duration::from_secs(10),
            max_attempts: 6,
        };
        assert_eq!(policy.capped_delay(0), Some(Duration::from_secs(1)));
        assert_eq!(policy.capped_delay(1), Some(Duration::from_secs(2)));
        assert_eq!(policy.capped_delay(2), Some(Duration::from_secs(4)));
        // 2^3 = 8 s, still under the cap.
        assert_eq!(policy.capped_delay(3), Some(Duration::from_secs(8)));
        // 2^4 = 16 s → capped at 10 s.
        assert_eq!(policy.capped_delay(4), Some(Duration::from_secs(10)));
        assert_eq!(policy.capped_delay(5), Some(Duration::from_secs(10)));
        // Exhausted.
        assert_eq!(policy.capped_delay(6), None);
        assert_eq!(policy.capped_delay(99), None);
    }

    /// A huge attempt count cannot overflow the shift or the multiply.
    #[test]
    fn backoff_saturates_rather_than_overflows() {
        let policy = BackoffPolicy {
            base: Duration::from_secs(1),
            max: Duration::from_secs(30),
            max_attempts: 1000,
        };
        // 2^500 would overflow; it saturates and caps instead of panicking.
        assert_eq!(policy.capped_delay(500), Some(Duration::from_secs(30)));
    }

    /// Full jitter maps `frac ∈ [0,1)` onto `[0, delay)`, and clamps out-of-range
    /// input so it can never lengthen the wait or go negative.
    #[test]
    fn full_jitter_spreads_within_bounds() {
        let d = Duration::from_secs(8);
        assert_eq!(full_jitter(d, 0.0), Duration::ZERO);
        assert_eq!(full_jitter(d, 0.5), Duration::from_secs(4));
        assert_eq!(full_jitter(d, 1.0), d);
        // Out of range clamps, never exceeds `delay` or goes negative.
        assert_eq!(full_jitter(d, 2.0), d);
        assert_eq!(full_jitter(d, -1.0), Duration::ZERO);
    }

    /// Single-flight: a fresh peer starts, a concurrent begin coalesces, and a
    /// failure holds the peer off for the backoff before the next start.
    #[test]
    fn recovery_is_single_flight_then_backs_off() {
        let policy = BackoffPolicy {
            base: Duration::from_secs(1),
            max: Duration::from_secs(10),
            max_attempts: 3,
        };
        let mut st = RecoveryState::new();

        // First timeout for this peer → start an attempt.
        assert_eq!(st.begin(0, &policy), RecoveryAction::Start);
        // A second caller while it is in flight coalesces, not a second invite.
        assert_eq!(st.begin(0, &policy), RecoveryAction::InFlight);

        // The attempt fails; hold off for the (jittered) backoff.
        st.fail(0, Duration::from_secs(2));
        match st.begin(1_000, &policy) {
            RecoveryAction::Backoff(d) => assert_eq!(d, Duration::from_secs(1)),
            other => panic!("expected Backoff, got {other:?}"),
        }
        // Once eligible, it starts again.
        assert_eq!(st.begin(2_000, &policy), RecoveryAction::Start);
    }

    /// Attempts are bounded: after `max_attempts` failures the peer is given up,
    /// so a genuinely-down peer is not re-invited forever (C2).
    #[test]
    fn recovery_gives_up_after_max_attempts() {
        let policy = BackoffPolicy {
            base: Duration::from_secs(1),
            max: Duration::from_secs(10),
            max_attempts: 2,
        };
        let mut st = RecoveryState::new();

        assert_eq!(st.begin(0, &policy), RecoveryAction::Start);
        st.fail(0, Duration::ZERO);
        assert_eq!(st.begin(0, &policy), RecoveryAction::Start);
        st.fail(0, Duration::ZERO);
        // Two attempts spent → give up, no matter how much time passes.
        assert_eq!(st.begin(1_000_000, &policy), RecoveryAction::GiveUp);
        assert_eq!(st.attempts(), 2);
    }

    /// A success clears the backoff, so a later loss starts fresh rather than
    /// inheriting an exhausted counter.
    #[test]
    fn recovery_success_resets_the_backoff() {
        let policy = BackoffPolicy {
            base: Duration::from_secs(1),
            max: Duration::from_secs(10),
            max_attempts: 2,
        };
        let mut st = RecoveryState::new();
        st.begin(0, &policy);
        st.fail(0, Duration::from_secs(5));
        st.begin(5_000, &policy); // second (final) attempt
        st.succeed();
        // Fresh again: eligible immediately, no attempts spent.
        assert_eq!(st.attempts(), 0);
        assert_eq!(st.begin(5_001, &policy), RecoveryAction::Start);
    }

    // ---- D5: idle eviction (tsp-relationship-recovery.md) ----

    /// The default TTL is the seven days of the original proposal, and `is_idle`
    /// is a saturating age comparison across the boundary.
    #[test]
    fn eviction_is_idle_past_the_ttl() {
        let policy = EvictionPolicy::default();
        assert_eq!(policy.ttl, Duration::from_secs(7 * 24 * 60 * 60));

        let day_ms = 24 * 60 * 60 * 1000u64;
        // Touched now, checked six days later — still active.
        assert!(!policy.is_idle(0, 6 * day_ms));
        // Exactly seven days — idle (>= boundary).
        assert!(policy.is_idle(0, 7 * day_ms));
        // Eight days — idle.
        assert!(policy.is_idle(0, 8 * day_ms));
        // A backwards clock reads as not-idle rather than underflowing to a huge
        // age that would evict a just-touched relationship.
        assert!(!policy.is_idle(10 * day_ms, day_ms));
    }

    /// `touch` / `last_active` round-trip through the durable store and survive a
    /// restart, so the idle clock is not reset by a bounce (which would stop
    /// anything from ever ageing out).
    #[tokio::test]
    async fn last_active_persists_across_a_restart() {
        let backend = SharedMemKv::default();
        {
            let store = PersistentRelationshipStore::new(backend.clone());
            assert_eq!(store.last_active(A, B).await.unwrap(), None);
            store.touch(A, B, 1_700_000_000_000).await.unwrap();
        }
        // Restart over the same backend.
        let store = PersistentRelationshipStore::new(backend);
        assert_eq!(
            store.last_active(A, B).await.unwrap(),
            Some(1_700_000_000_000)
        );

        // And it drives the eviction decision.
        let policy = EvictionPolicy {
            ttl: Duration::from_secs(60),
        };
        let last = store.last_active(A, B).await.unwrap().unwrap();
        assert!(!policy.is_idle(last, last + 59_000));
        assert!(policy.is_idle(last, last + 60_000));
    }

    // ---- D6: eviction sweep + single-flight coordinator (tsp-relationship-recovery.md) ----

    const C: &str = "did:example:carol";

    /// The sweep forgets only pairs past the TTL, leaving the rest — and it can
    /// decode `(our, their)` back out of the scanned keys (the length-prefix
    /// round-trip).
    #[tokio::test]
    async fn evict_idle_sweeps_only_idle_pairs() {
        let store = PersistentRelationshipStore::new(SharedMemKv::default());
        let ttl = Duration::from_secs(60);

        // An old pair and a fresh one, both established.
        for (their, active_at) in [(B, 0u64), (C, 100_000u64)] {
            store
                .set(A, their, RelationshipState::Bidirectional)
                .await
                .unwrap();
            store.touch(A, their, active_at).await.unwrap();
        }

        // At now = 100_000, B is 100 s idle (past 60 s), C was just touched.
        let evicted = store
            .evict_idle(100_000, &EvictionPolicy { ttl })
            .await
            .unwrap();
        assert_eq!(evicted, vec![(A.to_string(), B.to_string())]);

        // B is gone (all facets), C survives.
        assert_eq!(store.get(A, B).await.unwrap(), RelationshipState::None);
        assert_eq!(store.last_active(A, B).await.unwrap(), None);
        assert_eq!(
            store.get(A, C).await.unwrap(),
            RelationshipState::Bidirectional
        );
    }

    /// A pair never `touch`ed has no last-active entry and is never age-swept.
    #[tokio::test]
    async fn evict_idle_ignores_never_touched_pairs() {
        let store = PersistentRelationshipStore::new(SharedMemKv::default());
        store
            .set(A, B, RelationshipState::Bidirectional)
            .await
            .unwrap();
        let evicted = store
            .evict_idle(
                u64::MAX,
                &EvictionPolicy {
                    ttl: Duration::from_secs(1),
                },
            )
            .await
            .unwrap();
        assert!(evicted.is_empty());
        assert_eq!(
            store.get(A, B).await.unwrap(),
            RelationshipState::Bidirectional
        );
    }

    /// `forget` removes every facet of one pair.
    #[tokio::test]
    async fn forget_removes_the_whole_record() {
        let store = PersistentRelationshipStore::new(SharedMemKv::default());
        store
            .set(A, B, RelationshipState::Bidirectional)
            .await
            .unwrap();
        store
            .set_thread_digests(
                A,
                B,
                ThreadDigests {
                    invite: Some([1u8; 32]),
                    accept: None,
                },
            )
            .await
            .unwrap();
        store.touch(A, B, 5).await.unwrap();

        store.forget(A, B).await.unwrap();
        assert_eq!(store.get(A, B).await.unwrap(), RelationshipState::None);
        assert_eq!(
            store.thread_digests(A, B).await.unwrap(),
            ThreadDigests::default()
        );
        assert_eq!(store.last_active(A, B).await.unwrap(), None);
    }

    /// The coordinator is single-flight per peer, backs off after a failure,
    /// resets on success, and counts what happened (D8 metrics).
    #[tokio::test]
    async fn recovery_coordinator_single_flight_backoff_and_metrics() {
        let coord = RecoveryCoordinator::new(BackoffPolicy {
            base: Duration::from_secs(1),
            max: Duration::from_secs(10),
            max_attempts: 3,
        });

        assert_eq!(coord.begin(A, B, 0).await, RecoveryAction::Start);
        // Concurrent begin for the same peer coalesces.
        assert_eq!(coord.begin(A, B, 0).await, RecoveryAction::InFlight);
        // A different peer is independent.
        assert_eq!(coord.begin(A, C, 0).await, RecoveryAction::Start);

        coord.settle_failure(A, B, 0, Duration::from_secs(1)).await;
        match coord.begin(A, B, 500).await {
            RecoveryAction::Backoff(d) => assert_eq!(d, Duration::from_millis(500)),
            other => panic!("expected Backoff, got {other:?}"),
        }
        assert_eq!(coord.begin(A, B, 1000).await, RecoveryAction::Start);
        coord.settle_success(A, B).await;
        // After success the peer starts fresh.
        assert_eq!(coord.begin(A, B, 2000).await, RecoveryAction::Start);

        let m = coord.metrics();
        assert_eq!(m.successes, 1);
        assert!(m.attempts >= 3);
    }

    /// Attempts are bounded: past the cap the coordinator returns `GiveUp` and
    /// counts it (the D8 alarm that a peer is durably unreachable).
    #[tokio::test]
    async fn recovery_coordinator_gives_up_and_counts() {
        let coord = RecoveryCoordinator::new(BackoffPolicy {
            base: Duration::from_secs(1),
            max: Duration::from_secs(10),
            max_attempts: 1,
        });
        assert_eq!(coord.begin(A, B, 0).await, RecoveryAction::Start);
        coord.settle_failure(A, B, 0, Duration::ZERO).await;
        assert_eq!(coord.begin(A, B, 1_000_000).await, RecoveryAction::GiveUp);
        assert_eq!(coord.metrics().give_ups, 1);
    }

    // ---- D9: proactive reconcile candidates ----

    /// Only `Bidirectional` relationships are offered for a startup reconcile —
    /// a half-open handshake is already in flight and must not be restarted.
    #[tokio::test]
    async fn established_relationships_lists_bidirectional_only() {
        let store = PersistentRelationshipStore::new(SharedMemKv::default());
        store
            .set(A, B, RelationshipState::Bidirectional)
            .await
            .unwrap();
        store.set(A, C, RelationshipState::Pending).await.unwrap();
        store
            .set(A, "did:example:dave", RelationshipState::Bidirectional)
            .await
            .unwrap();

        let mut got = store.established_relationships().await.unwrap();
        got.sort();
        assert_eq!(
            got,
            vec![
                (A.to_string(), B.to_string()), // did:example:bob
                (A.to_string(), "did:example:dave".to_string()),
            ]
        );
    }

    // ---- D7: inbound-invite rate limiting ----

    /// One accepted invite per `min_interval` per peer; a flood in between is
    /// refused without moving the clock forward.
    #[tokio::test]
    async fn invite_rate_limiter_enforces_min_interval() {
        let limiter = InviteRateLimiter::new(Duration::from_secs(10));
        assert!(limiter.allow(A, B, 0).await); // first invite
        assert!(!limiter.allow(A, B, 5_000).await); // 5 s later — too soon
        assert!(!limiter.allow(A, B, 9_999).await); // still under 10 s
        assert!(limiter.allow(A, B, 10_000).await); // exactly 10 s — allowed
        // A different peer is tracked independently.
        assert!(limiter.allow(A, C, 5_000).await);
    }
}

/// `post_tsp_inbound` against a raw local HTTP/1.1 server that misbehaves the
/// way an intermediary does (Keyring VTI-39).
#[cfg(test)]
mod send_raw_retry_tests {
    use super::post_tsp_inbound;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    const OK: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n";
    const FAST: &[Duration] = &[Duration::from_millis(1), Duration::from_millis(1)];

    /// Read one HTTP/1.1 request (headers + `content-length` body) and return
    /// its body, or `None` when the peer closed first.
    async fn read_request(sock: &mut TcpStream) -> Option<Vec<u8>> {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        let head_end = loop {
            if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break i + 4;
            }
            let n = sock.read(&mut chunk).await.ok()?;
            if n == 0 {
                return None;
            }
            buf.extend_from_slice(&chunk[..n]);
        };
        let head = String::from_utf8_lossy(&buf[..head_end]).to_ascii_lowercase();
        let len: usize = head
            .lines()
            .find_map(|l| l.strip_prefix("content-length:"))
            .map(|v| v.trim().parse().unwrap())
            .unwrap_or(0);
        while buf.len() < head_end + len {
            let n = sock.read(&mut chunk).await.ok()?;
            if n == 0 {
                return None;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        Some(buf[head_end..head_end + len].to_vec())
    }

    /// The VTI-39 shape: the first request on a keep-alive connection is
    /// answered, the second is read in full and then the connection is closed
    /// without a response (hyper `IncompleteMessage`). The retry, on a fresh
    /// connection, is answered. Every body must be the same bytes.
    #[tokio::test]
    async fn retries_same_bytes_after_keepalive_connection_closed_mid_request() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/inbound", listener.local_addr().unwrap());
        let bodies = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let connections = Arc::new(Mutex::new(0usize));

        let (b, c) = (bodies.clone(), connections.clone());
        tokio::spawn(async move {
            // Connection 1: answer one request, then drop the next mid-flight.
            let (mut sock, _) = listener.accept().await.unwrap();
            *c.lock().unwrap() += 1;
            let body = read_request(&mut sock).await.unwrap();
            b.lock().unwrap().push(body);
            sock.write_all(OK).await.unwrap();
            let body = read_request(&mut sock).await.unwrap();
            b.lock().unwrap().push(body);
            drop(sock);
            // Connection 2: the retry.
            let (mut sock, _) = listener.accept().await.unwrap();
            *c.lock().unwrap() += 1;
            let body = read_request(&mut sock).await.unwrap();
            b.lock().unwrap().push(body);
            sock.write_all(OK).await.unwrap();
            // Hold the connection open so the client reads the response.
            let _ = read_request(&mut sock).await;
        });

        let client = reqwest::Client::new();
        post_tsp_inbound(&client, &url, "tok", b"warm-up", FAST)
            .await
            .expect("first request is answered");
        let sealed = b"\xf8sealed-tsp-bytes".to_vec();
        post_tsp_inbound(&client, &url, "tok", &sealed, FAST)
            .await
            .expect("the retry after the dropped connection is answered");

        let bodies = bodies.lock().unwrap();
        assert_eq!(bodies.len(), 3, "warm-up, dropped attempt, retry");
        assert_eq!(bodies[1], sealed);
        assert_eq!(bodies[2], sealed, "the retry re-sends the identical bytes");
        assert_eq!(*connections.lock().unwrap(), 2);
    }

    /// Every attempt dropped: gives up after the backoff runs out (three
    /// attempts) with a transport error rather than looping.
    #[tokio::test]
    async fn gives_up_after_bounded_retries() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/inbound", listener.local_addr().unwrap());
        let attempts = Arc::new(Mutex::new(0usize));
        let a = attempts.clone();
        tokio::spawn(async move {
            loop {
                let (mut sock, _) = listener.accept().await.unwrap();
                if read_request(&mut sock).await.is_some() {
                    *a.lock().unwrap() += 1;
                }
                drop(sock);
            }
        });

        let err = post_tsp_inbound(&reqwest::Client::new(), &url, "tok", b"x", FAST)
            .await
            .expect_err("every attempt is dropped");
        assert!(matches!(err, crate::errors::ATMError::TransportError(_)));
        assert_eq!(*attempts.lock().unwrap(), 3);
    }

    /// A 5xx is the mediator's answer: returned once, never re-sent.
    #[tokio::test]
    async fn does_not_retry_an_http_status() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/inbound", listener.local_addr().unwrap());
        let attempts = Arc::new(Mutex::new(0usize));
        let a = attempts.clone();
        tokio::spawn(async move {
            loop {
                let (mut sock, _) = listener.accept().await.unwrap();
                while read_request(&mut sock).await.is_some() {
                    *a.lock().unwrap() += 1;
                    sock.write_all(
                        b"HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\n\r\n",
                    )
                    .await
                    .unwrap();
                }
            }
        });

        post_tsp_inbound(&reqwest::Client::new(), &url, "tok", b"x", FAST)
            .await
            .expect_err("503 is an error");
        assert_eq!(*attempts.lock().unwrap(), 1);
    }
}
