//! # affinidi-tsp
//!
//! Trust Spanning Protocol (TSP) implementation for the Affinidi TDK.
//!
//! TSP is a ToIP Layer 2 protocol that provides authenticated, encrypted
//! messaging between Verifiable Identifiers (VIDs). It uses HPKE-Base for
//! encryption, Ed25519 for signing, and CESR for encoding, per the TSP
//! specification Rev 3.
//!
//! ## Quick Start
//!
//! ```rust
//! use affinidi_tsp::{TspAgent, vid::PrivateVid};
//!
//! // Create an agent
//! let agent = TspAgent::new();
//!
//! // Generate identities
//! let alice = PrivateVid::generate("did:example:alice");
//! let bob = PrivateVid::generate("did:example:bob");
//!
//! // Register identities
//! let bob_public = bob.to_resolved();
//! agent.add_private_vid(alice);
//! agent.add_verified_vid(bob_public);
//!
//! // Send a message (after establishing a relationship)
//! // let packed = agent.send("did:example:alice", "did:example:bob", b"Hello!")?;
//! ```
//!
//! ## Repeated messages
//!
//! [`TspAgent::receive`] refuses a copy of an invite it has already acted on
//! for that VID pair, so a repeated invite cannot reopen an established
//! relationship. An application message carries no identifier or sequence
//! number to check, so `receive` returns the same payload each time it is
//! handed the same message: a consumer that must act once deduplicates it.

#[cfg(feature = "messaging-core")]
pub mod adapter;
pub mod crypto;
pub mod error;
pub mod keystate;
pub mod message;
pub mod relationship;
pub mod store;
pub mod vid;

pub use error::TspError;
pub use keystate::{KeyStatePolicy, ManualClock, SystemClock};
pub use message::MessageType;
pub use message::direct::{Padding, pack_padding_message, pack_signed_only};
pub use message::meta::{MetaEnvelope, TSP_MAGIC_BYTE, is_tsp};
pub use message::routed::{MAX_HOPS, RouteStep};
pub use relationship::{RelationshipPolicy, RelationshipState};
pub use vid::resolver::VidResolver;
#[cfg(feature = "did-resolver")]
pub use vid::{DidVidResolver, TSP_SERVICE_TYPE};
pub use vid::{PrivateVid, ResolvedVid};

use keystate::{Clock, KeyStateTracker, RefreshStatus};
use message::control::ControlMessage;
use message::direct::{self, PackedMessage};
use relationship::RelationshipEvent;
use store::TspStore;
use vid::resolver::DelegatingVidResolver;

/// High-level TSP agent for sending and receiving messages.
///
/// The agent manages local identities (private VIDs), known remote identities,
/// and relationship state. It provides a simple API for the full TSP lifecycle:
///
/// 1. Create/register identities
/// 2. Form relationships (RFI/RFA handshake)
/// 3. Send and receive encrypted, authenticated messages
pub struct TspAgent {
    pub(crate) store: TspStore,
    pub(crate) resolver: DelegatingVidResolver,
    pub(crate) relationship_policy: RelationshipPolicy,
    pub(crate) key_state_policy: KeyStatePolicy,
    pub(crate) key_state: KeyStateTracker,
    pub(crate) clock: Box<dyn Clock>,
}

impl TspAgent {
    /// Create a new TSP agent with an in-memory store and resolver.
    pub fn new() -> Self {
        Self {
            store: TspStore::new(),
            resolver: DelegatingVidResolver::new(),
            relationship_policy: RelationshipPolicy::default(),
            key_state_policy: KeyStatePolicy::default(),
            key_state: KeyStateTracker::new(),
            clock: Box::new(keystate::SystemClock),
        }
    }

    /// Set how this endpoint keeps a peer's key state fresh (Rev 3 §7.4.2).
    pub fn with_key_state_policy(mut self, policy: KeyStatePolicy) -> Self {
        self.key_state_policy = policy;
        self
    }

    /// Replace the VID resolver used for DID-shaped VIDs.
    ///
    /// The builder form of [`TspAgent::with_did_resolver`], for chaining onto
    /// an agent that already has other settings.
    pub fn with_resolver(mut self, resolver: Box<dyn VidResolver>) -> Self {
        self.resolver = DelegatingVidResolver::new().with_did_resolver(resolver);
        self
    }

    /// Replace the clock the freshness rules measure against. For tests.
    pub fn with_clock(mut self, clock: Box<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// Set whether inbound application messages are gated on an existing
    /// relationship (Rev 3 §7.2.2). Defaults to [`RelationshipPolicy::Gated`];
    /// a node that is not an endpoint — an intermediary — sets `Ungated`.
    pub fn with_relationship_policy(mut self, policy: RelationshipPolicy) -> Self {
        self.relationship_policy = policy;
        self
    }

    /// Create a TSP agent with a custom DID resolver for DID-based VIDs.
    pub fn with_did_resolver(did_resolver: Box<dyn VidResolver>) -> Self {
        Self {
            store: TspStore::new(),
            resolver: DelegatingVidResolver::new().with_did_resolver(did_resolver),
            relationship_policy: RelationshipPolicy::default(),
            key_state_policy: KeyStatePolicy::default(),
            key_state: KeyStateTracker::new(),
            clock: Box::new(keystate::SystemClock),
        }
    }

    // --- Identity management ---

    /// Register a private VID (an identity this agent controls).
    pub fn add_private_vid(&self, vid: PrivateVid) {
        let resolved = vid.to_resolved();
        self.resolver.insert(resolved);
        self.store.add_private_vid(vid);
    }

    /// Register a remote VID (a known external identity).
    pub fn add_verified_vid(&self, vid: ResolvedVid) {
        self.resolver.insert(vid.clone());
        self.store.add_remote_vid(vid);
    }

    /// Generate and register a new private VID.
    pub fn create_vid(&self, id: impl Into<String>) -> ResolvedVid {
        let vid = PrivateVid::generate(id);
        let resolved = vid.to_resolved();
        self.add_private_vid(vid);
        resolved
    }

    // --- Relationship management ---

    /// Get the relationship state between two VIDs.
    pub fn relationship_state(&self, our_vid: &str, their_vid: &str) -> RelationshipState {
        self.store.relationship_state(our_vid, their_vid)
    }

    /// Build and pack a Relationship Forming Invite (RFI).
    ///
    /// This sends a control message to initiate a relationship. The invite's
    /// thread digest (`SHA256` of its plaintext frame) is remembered so a later
    /// accept can be correlated, and is used as the cancel reference.
    pub fn send_relationship_invite(
        &self,
        our_vid: &str,
        their_vid: &str,
    ) -> Result<PackedMessage, TspError> {
        let control = ControlMessage::invite();
        let packed = self.pack_control(our_vid, their_vid, &control)?;

        self.store
            .transition_relationship(our_vid, their_vid, RelationshipEvent::SendInvite)?;
        // Remember the invite's thread digest to correlate the accept and to
        // reference on cancel.
        self.store
            .set_thread_digest(our_vid, their_vid, packed.thread_digest);

        Ok(packed)
    }

    /// Build and pack a Relationship Forming Accept (RFA).
    ///
    /// The accept's `reply` is the thread digest of the invite being accepted
    /// — the `thread_digest` of the received invite (see
    /// [`ReceivedMessage::thread_digest`]), which the FSM remembers when it
    /// transitions to [`RelationshipState::InviteReceived`]. The accept's own
    /// thread digest then becomes the relationship reference for cancel.
    pub fn send_relationship_accept(
        &self,
        our_vid: &str,
        their_vid: &str,
    ) -> Result<PackedMessage, TspError> {
        let invite_digest = self
            .store
            .thread_digest(our_vid, their_vid)
            .ok_or_else(|| {
                TspError::Relationship(format!("no invite on record from {their_vid} to accept"))
            })?;
        let control = ControlMessage::accept(invite_digest);
        let packed = self.pack_control(our_vid, their_vid, &control)?;

        self.store
            .transition_relationship(our_vid, their_vid, RelationshipEvent::SendAccept)?;
        // The accept's own digest identifies the other half. The inviter
        // records it on receipt; the accepter must too, or a cancellation that
        // names this half (§7.2.1 allows either) is refused as unrecognised.
        self.store
            .set_reply_thread_digest(our_vid, their_vid, packed.thread_digest);

        Ok(packed)
    }

    /// Build and pack a Relationship Cancel (RFD).
    ///
    /// The cancel's `reply` references the relationship-forming message's thread
    /// digest (the remembered invite digest); if none is on record (e.g. a
    /// degenerate teardown) a zero digest is used.
    pub fn send_relationship_cancel(
        &self,
        our_vid: &str,
        their_vid: &str,
    ) -> Result<PackedMessage, TspError> {
        let reply = self
            .store
            .thread_digest(our_vid, their_vid)
            .unwrap_or([0u8; 32]);
        let control = ControlMessage::cancel(reply);
        let packed = self.pack_control(our_vid, their_vid, &control)?;

        self.store
            .transition_relationship(our_vid, their_vid, RelationshipEvent::SendCancel)?;
        self.store.clear_thread_digest(our_vid, their_vid);
        self.forget_key_state_if_unrelated(their_vid);

        Ok(packed)
    }

    // --- Messaging ---

    /// Pack (seal + sign) a direct message.
    ///
    /// Requires a `Bidirectional` relationship with the recipient.
    pub fn send(
        &self,
        our_vid: &str,
        their_vid: &str,
        payload: &[u8],
    ) -> Result<PackedMessage, TspError> {
        // Check relationship
        let state = self.store.relationship_state(our_vid, their_vid);
        if !state.can_send() {
            return Err(TspError::Relationship(format!(
                "cannot send: relationship with {their_vid} is {state:?}, not Bidirectional"
            )));
        }

        self.pack_message(our_vid, their_vid, payload, MessageType::Direct)
    }

    /// Unpack (verify + decrypt) a received message.
    ///
    /// Returns the decrypted payload along with sender/receiver metadata.
    /// For control messages, also updates the relationship state.
    ///
    /// An invite whose thread digest has already been acted on for this pair
    /// is refused with [`TspError::Discarded`] (or, re-sent while it is still
    /// the invite awaiting our decision, accepted as a no-op). An application
    /// message is returned each time it is received; deduplicating it is the
    /// caller's job.
    pub fn receive(&self, our_vid: &str, wire: &[u8]) -> Result<ReceivedMessage, TspError> {
        // Parse envelope to get sender VID (before full unpack)
        let (envelope, _) = message::envelope::Envelope::decode(wire)?;

        if envelope.receiver != our_vid {
            return Err(TspError::InvalidMessage(format!(
                "message addressed to {}, not {our_vid}",
                envelope.receiver
            )));
        }

        // Look up keys
        let our_private = self.store.get_private_vid(our_vid)?;

        let established = self
            .store
            .relationship_state(our_vid, &envelope.sender)
            .admits_application_message();
        let now_ms = self.clock.now_ms();

        // §7.4.2, first occasion: a message arriving after a silence longer
        // than the re-verification threshold is not acted on until the peer's
        // key state has been refreshed. This is the case that matters under
        // compromise — stale key state is internally consistent, so a message
        // signed with a compromised key verifies and gives no warning.
        let mut sender_resolved = self.resolver.resolve(&envelope.sender)?;
        if self.key_state_policy.self_resolving
            && established
            && self.key_state.silent_longer_than(
                &envelope.sender,
                self.key_state_policy.reverification_threshold,
                now_ms,
            )
        {
            sender_resolved = self.confirm_key_state_after_silence(&envelope.sender, now_ms)?;
        }

        // Unpack. §7.4.2, second occasion: a verification failure inside an
        // established relationship may be a rotation we have not observed, so
        // the VID is re-resolved and the verification retried once before the
        // message is discarded. Outside a relationship it is discarded at once
        // — otherwise anyone could make us resolve by sending us noise.
        let unpacked = match direct::unpack(
            wire,
            &our_private.decryption_key,
            &sender_resolved.signing_key,
        ) {
            Ok(unpacked) => unpacked,
            Err(first_error) => {
                if !(self.key_state_policy.self_resolving && established) {
                    return Err(first_error);
                }
                match self.refresh_key_state(&envelope.sender, now_ms) {
                    Ok(KeyStateRefresh::Fresh(fresh)) => {
                        direct::unpack(wire, &our_private.decryption_key, &fresh.signing_key)?
                    }
                    // No refresh was possible, so the original failure stands.
                    Ok(KeyStateRefresh::RateLimited) => return Err(first_error),
                    Err(_) => return Err(first_error),
                }
            }
        };

        // The message verified, so the key state behind it is confirmed now.
        // Silence is only measured inside a relationship, so only those
        // senders are recorded (here, or below once a control message has
        // formed one); the tracker grows with relationships rather than with
        // every sender whose message verifies.
        if established {
            self.key_state.record_seen(&envelope.sender, now_ms);
        }

        // Handle control messages
        if unpacked.message_type == MessageType::Control {
            let control = unpacked
                .control
                .clone()
                .ok_or_else(|| TspError::InvalidMessage("control message has no payload".into()))?;
            let outcome =
                self.handle_control(our_vid, &unpacked.sender, &control, unpacked.thread_digest)?;
            if !established
                && self
                    .store
                    .relationship_state(our_vid, &envelope.sender)
                    .admits_application_message()
            {
                self.key_state.record_seen(&envelope.sender, now_ms);
            }

            return Ok(ReceivedMessage {
                payload: unpacked.payload,
                sender: unpacked.sender,
                receiver: unpacked.receiver,
                message_type: unpacked.message_type,
                thread_digest: unpacked.thread_digest,
                control: Some(control),
                outcome,
            });
        }

        // §7.2.2: an application message from a VID we hold no relationship
        // with is dropped. An exchange begins with control messages, and this
        // enforces that ordering — it is not admission control, which stays a
        // decision the application makes when it sees the invite.
        if self.relationship_policy == RelationshipPolicy::Gated
            && !self
                .store
                .relationship_state(our_vid, &unpacked.sender)
                .admits_application_message()
        {
            return Err(TspError::Discarded(format!(
                "application message from {} with no relationship to {our_vid}",
                unpacked.sender
            )));
        }

        Ok(ReceivedMessage {
            payload: unpacked.payload,
            sender: unpacked.sender,
            receiver: unpacked.receiver,
            message_type: unpacked.message_type,
            thread_digest: unpacked.thread_digest,
            control: None,
            outcome: ControlOutcome::None,
        })
    }

    // --- Routed / nested messaging (§5.3 / §5.5) ---

    /// Send a message to `final_vid` routed through `intermediaries` (in order).
    ///
    /// The payload is sealed end-to-end to `final_vid` (so intermediaries cannot
    /// read it), then wrapped in a routed layer addressed to the first
    /// intermediary. Each intermediary calls [`TspAgent::forward_routed`] to
    /// advance the message. With an empty `intermediaries` list this is an
    /// ordinary direct send.
    ///
    /// Requires a `Bidirectional` relationship with `final_vid` (the inner is a
    /// direct message); resolution of every hop's keys is via the agent resolver.
    pub fn send_routed(
        &self,
        our_vid: &str,
        final_vid: &str,
        intermediaries: &[&str],
        payload: &[u8],
    ) -> Result<PackedMessage, TspError> {
        // Inner: end-to-end sealed to the final recipient.
        let inner = self.pack_message(our_vid, final_vid, payload, MessageType::Direct)?;

        if intermediaries.is_empty() {
            return Ok(inner);
        }

        // Route is the intermediaries followed by the final recipient, so the
        // last intermediary forwards the inner directly to `final_vid`.
        let mut route: Vec<String> = intermediaries[1..].iter().map(|s| s.to_string()).collect();
        route.push(final_vid.to_string());

        let first_hop = intermediaries[0];
        let our_private = self.store.get_private_vid(our_vid)?;
        let first_resolved = self.resolver.resolve(first_hop)?;

        message::routed::pack_routed(
            &inner.bytes,
            &route,
            our_vid,
            first_hop,
            &our_private.signing_key,
            &first_resolved.encryption_key,
        )
    }

    /// Wrap an already-packed message inside a nested outer message addressed to
    /// `intermediary_vid`, for metadata privacy (§5.5). The intermediary can
    /// open the outer but not the opaque inner.
    pub fn send_nested(
        &self,
        our_vid: &str,
        intermediary_vid: &str,
        inner: &PackedMessage,
    ) -> Result<PackedMessage, TspError> {
        let our_private = self.store.get_private_vid(our_vid)?;
        let intermediary = self.resolver.resolve(intermediary_vid)?;
        message::routed::pack_nested(
            inner,
            our_vid,
            intermediary_vid,
            &our_private.signing_key,
            &intermediary.encryption_key,
        )
    }

    /// Process a routed message addressed to `our_vid` as an intermediary:
    /// open our routing layer, then either re-seal the remaining route to the
    /// next intermediary, or hand the opaque inner to the final recipient.
    pub fn forward_routed(&self, our_vid: &str, wire: &[u8]) -> Result<ForwardOutcome, TspError> {
        // Parse the envelope to authenticate the previous hop (the sender).
        let (envelope, _) = message::envelope::Envelope::decode(wire)?;
        if envelope.receiver != our_vid {
            return Err(TspError::InvalidMessage(format!(
                "routed message addressed to {}, not {our_vid}",
                envelope.receiver
            )));
        }
        let our_private = self.store.get_private_vid(our_vid)?;
        let prev = self.resolver.resolve(&envelope.sender)?;
        let unpacked = direct::unpack(wire, &our_private.decryption_key, &prev.signing_key)?;

        // The message kind lives in the encrypted payload (the cleartext envelope
        // reports a Direct placeholder), so verify it after unpacking.
        if unpacked.message_type != MessageType::Routed {
            return Err(TspError::InvalidMessage(format!(
                "expected a Routed message, got {:?}",
                unpacked.message_type
            )));
        }

        match message::routed::next_hop(&unpacked)? {
            // Last intermediary: deliver the opaque inner to the final recipient.
            message::routed::RouteStep::Forward {
                next,
                remaining,
                inner,
            } if remaining.is_empty() => Ok(ForwardOutcome::Deliver {
                to: next,
                message: inner,
            }),
            // Re-seal the remaining route to the next intermediary.
            message::routed::RouteStep::Forward {
                next,
                remaining,
                inner,
            } => {
                let next_resolved = self.resolver.resolve(&next)?;
                let relayed = message::routed::pack_routed(
                    &inner,
                    &remaining,
                    our_vid,
                    &next,
                    &our_private.signing_key,
                    &next_resolved.encryption_key,
                )?;
                Ok(ForwardOutcome::Relay {
                    to: next,
                    message: relayed,
                })
            }
            // Empty route: the inner is for us to consume.
            message::routed::RouteStep::Deliver { inner } => Ok(ForwardOutcome::Deliver {
                to: our_vid.to_string(),
                message: inner,
            }),
        }
    }

    // --- Internal helpers ---

    fn pack_message(
        &self,
        our_vid: &str,
        their_vid: &str,
        payload: &[u8],
        msg_type: MessageType,
    ) -> Result<PackedMessage, TspError> {
        let our_private = self.store.get_private_vid(our_vid)?;
        let their_resolved = self.resolver.resolve(their_vid)?;

        direct::pack(
            payload,
            msg_type,
            our_vid,
            their_vid,
            &our_private.signing_key,
            &their_resolved.encryption_key,
        )
    }

    fn pack_control(
        &self,
        our_vid: &str,
        their_vid: &str,
        control: &ControlMessage,
    ) -> Result<PackedMessage, TspError> {
        let payload = control.encode();
        self.pack_message(our_vid, their_vid, &payload, MessageType::Control)
    }

    /// Apply a received control message to the relationship FSM, correlating it
    /// to the relationship-forming message via the thread digest.
    ///
    /// `thread_digest` is the `SHA256` of the received message's plaintext frame
    /// (for an invite it is the value the accepter must echo back as `reply`).
    /// The key state to verify a message from `vid` against, after a silence
    /// longer than the re-verification threshold (§7.4.2), or a `Discarded`
    /// error when it cannot be confirmed.
    ///
    /// Confirmed means a refresh succeeded, or, after one failed, the
    /// resolver has since re-resolved the VID from its provenance chain
    /// ([`VidResolver::completed_refresh`], which is how a `DidVidResolver`
    /// re-resolved with `resolve_did` is picked up). The rate limit bounds how
    /// often we resolve; it does not stand in for a confirmation. Inside the
    /// limit:
    ///
    /// * after a refresh that succeeded, the state we hold is that refresh's,
    ///   so it is used;
    /// * while a refresh is in flight on another thread, the message is
    ///   discarded rather than held: this agent is synchronous and has no
    ///   queue to hold it in, and the sender's retry will find the outcome;
    /// * after a refresh that failed, the message is discarded until the next
    ///   attempt, which comes later after each failure in a row (see
    ///   [`keystate::KeyStateTracker::next_resolution_at_ms`]).
    fn confirm_key_state_after_silence(
        &self,
        vid: &str,
        now_ms: u64,
    ) -> Result<ResolvedVid, TspError> {
        if matches!(
            self.key_state.refresh_status(vid),
            RefreshStatus::Failed { .. }
        ) && let Some(resolved) = self.resolver.completed_refresh(vid)
        {
            self.key_state.record_confirmed_after_failed_refresh(vid);
            return Ok(resolved);
        }

        match self.refresh_key_state(vid, now_ms) {
            Ok(KeyStateRefresh::Fresh(fresh)) => Ok(fresh),
            Ok(KeyStateRefresh::RateLimited) => {
                let next_in_ms = self
                    .key_state
                    .next_resolution_at_ms(vid, self.key_state_policy.resolution_rate_limit)
                    .saturating_sub(now_ms);
                match self.key_state.refresh_status(vid) {
                    RefreshStatus::Succeeded => self.resolver.resolve(vid),
                    RefreshStatus::InFlight => Err(TspError::Discarded(format!(
                        "key state for {vid} is not confirmed after a silence: a refresh is in \
                         progress; send again once it completes"
                    ))),
                    RefreshStatus::Failed { consecutive } => Err(TspError::Discarded(format!(
                        "key state for {vid} is not confirmed after a silence: the last refresh \
                         failed ({consecutive} in a row); next refresh allowed in {next_in_ms} ms"
                    ))),
                    RefreshStatus::NeverAttempted => Err(TspError::Discarded(format!(
                        "key state for {vid} is not confirmed after a silence"
                    ))),
                }
            }
            Err(e) => Err(TspError::Discarded(format!(
                "key state for {vid} could not be confirmed after a silence: the refresh \
                 failed: {e}"
            ))),
        }
    }

    /// Re-resolve `vid`, subject to the per-peer rate limit.
    ///
    /// `RateLimited` means no resolution was attempted. §7.4.2 bounds
    /// resolution because it can be provoked by an unauthenticated message,
    /// and resolution is more expensive than the message provoking it, so the
    /// cost would otherwise fall on the peer's infrastructure. Checking the
    /// limit and stamping the attempt is one step, and the outcome is recorded
    /// against this attempt only, so a slow older refresh cannot overwrite a
    /// newer one's result.
    fn refresh_key_state(&self, vid: &str, now_ms: u64) -> Result<KeyStateRefresh, TspError> {
        let Some(token) = self.key_state.try_begin_refresh(
            vid,
            self.key_state_policy.resolution_rate_limit,
            now_ms,
        ) else {
            return Ok(KeyStateRefresh::RateLimited);
        };
        match self.resolver.refresh(vid) {
            Ok(fresh) => {
                self.key_state.record_refresh_succeeded(&token);
                Ok(KeyStateRefresh::Fresh(fresh))
            }
            Err(e) => {
                self.key_state.record_refresh_failed(&token);
                Err(e)
            }
        }
    }

    /// How many refreshes of `peer_vid`'s key state have failed in a row
    /// since the last one that succeeded (or since the resolver re-resolved
    /// it, see [`VidResolver::completed_refresh`]).
    ///
    /// A refresh runs after a silence longer than the re-verification
    /// threshold, and on a verification failure inside a relationship. Only
    /// the first kind gates messages: while it is unconfirmed, messages from
    /// `peer_vid` that arrive after the silence are discarded. A failure of
    /// the second kind can be provoked by any message that names `peer_vid`
    /// as its sender, so a non-zero count on its own does not mean messages
    /// are being discarded; it does mean the resolver could not reach the
    /// peer's provenance chain.
    pub fn key_state_refresh_failures(&self, peer_vid: &str) -> u32 {
        self.key_state.consecutive_refresh_failures(peer_vid)
    }

    /// Drop the key-state bookkeeping for `their_vid` once no local VID holds
    /// a relationship with it.
    fn forget_key_state_if_unrelated(&self, their_vid: &str) {
        let related = self.store.list_private_vids().iter().any(|our_vid| {
            self.store.relationship_state(our_vid, their_vid) != RelationshipState::None
        });
        if !related {
            self.key_state.forget(their_vid);
        }
    }

    fn handle_control(
        &self,
        our_vid: &str,
        their_vid: &str,
        control: &ControlMessage,
        thread_digest: [u8; 32],
    ) -> Result<ControlOutcome, TspError> {
        use message::control::ControlType;

        let state = self.store.relationship_state(our_vid, their_vid);

        match control.control_type {
            ControlType::RelationshipFormingInvite => {
                // A copy of an invite already acted on. Every invite carries a
                // fresh nonce, so a peer re-forming the relationship sends one
                // with a new digest; a digest seen before is the same message
                // again and is no reason to reopen the relationship. Re-sent
                // while we are still deciding on it, it is the no-op it always
                // was; in any other state it is refused and changes nothing.
                if self
                    .store
                    .has_seen_invite(our_vid, their_vid, &thread_digest)
                {
                    if state == RelationshipState::InviteReceived
                        && self.store.thread_digest(our_vid, their_vid) == Some(thread_digest)
                    {
                        return Ok(ControlOutcome::None);
                    }
                    return Err(TspError::Discarded(format!(
                        "invite from {their_vid} was already received; a repeated copy does \
                         not reopen the relationship"
                    )));
                }

                // §7.2.3, the invite race. Both endpoints may invite each other
                // for the same VID pair at once. Both keep the invite whose
                // digest is lexicographically lower and discard the other, so
                // the two sides converge on one exchange and one thread id
                // rather than each believing it opened the relationship.
                if state == RelationshipState::Pending {
                    let ours = self.store.thread_digest(our_vid, their_vid);
                    if let Some(ours) = ours {
                        if ours.as_slice() < thread_digest.as_slice() {
                            // The losing invite is settled too: a later copy of
                            // it, arriving once the race is over, must not
                            // reopen the relationship ours formed.
                            self.store
                                .record_seen_invite(our_vid, their_vid, thread_digest);
                            return Err(TspError::Discarded(format!(
                                "invite race with {their_vid}: ours has the lower digest, \
                                 keeping it"
                            )));
                        }
                        // Theirs wins: adopt it, replacing the invite we sent.
                        self.store.set_relationship_state(
                            our_vid,
                            their_vid,
                            RelationshipState::InviteReceived,
                        );
                        self.store
                            .set_thread_digest(our_vid, their_vid, thread_digest);
                        self.store
                            .record_seen_invite(our_vid, their_vid, thread_digest);
                        return Ok(ControlOutcome::None);
                    }
                }

                self.store.transition_relationship(
                    our_vid,
                    their_vid,
                    RelationshipEvent::ReceiveInvite,
                )?;
                // Remember the invite's digest: our accept echoes it back, and
                // a cancellation names the relationship by it.
                self.store
                    .set_thread_digest(our_vid, their_vid, thread_digest);
                self.store
                    .record_seen_invite(our_vid, their_vid, thread_digest);
            }
            ControlType::RelationshipFormingAccept => {
                // The accept's first digest is the invite it answers.
                let reply = control.require_reply()?;
                if let Some(expected) = self.store.thread_digest(our_vid, their_vid)
                    && reply != &expected
                {
                    return Err(TspError::Discarded(format!(
                        "accept from {their_vid} answers an invite we did not send"
                    )));
                }
                self.store.transition_relationship(
                    our_vid,
                    their_vid,
                    RelationshipEvent::ReceiveAccept,
                )?;
                // The accept's own digest identifies the other direction; a
                // cancellation may name either half (§7.2.1).
                self.store
                    .set_reply_thread_digest(our_vid, their_vid, thread_digest);
            }
            ControlType::RelationshipCancel => {
                // §7.3. What we do depends on what we hold:
                //
                //   nothing            -> ignore the cancellation entirely
                //   one direction only -> remove it, send no reply
                //   bidirectional      -> reply with a cancellation, then remove
                //
                // A cancellation naming a relationship we do not recognise is
                // ignored rather than answered, so it cannot be used to probe
                // which relationships we hold.
                if state == RelationshipState::None {
                    return Err(TspError::Discarded(format!(
                        "cancellation from {their_vid} names no relationship we hold"
                    )));
                }
                if let Some(named) = control.reply.as_ref()
                    && !self.store.recognizes_digest(our_vid, their_vid, named)
                {
                    return Err(TspError::Discarded(format!(
                        "cancellation from {their_vid} names an unrecognised relationship"
                    )));
                }

                let reply_expected = state == RelationshipState::Bidirectional;
                self.store.transition_relationship(
                    our_vid,
                    their_vid,
                    RelationshipEvent::ReceiveCancel,
                )?;
                self.store.clear_thread_digest(our_vid, their_vid);
                self.forget_key_state_if_unrelated(their_vid);
                if reply_expected {
                    return Ok(ControlOutcome::ReplyToCancellation);
                }
            }
        }

        Ok(ControlOutcome::None)
    }
}

impl Default for TspAgent {
    fn default() -> Self {
        Self::new()
    }
}

/// What [`TspAgent::refresh_key_state`] did.
enum KeyStateRefresh {
    /// The VID was resolved again and this is its current key state.
    Fresh(ResolvedVid),
    /// The rate limit is in force, so nothing was resolved.
    RateLimited,
}

/// What a control message asks of the receiving endpoint beyond updating state.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum ControlOutcome {
    /// Nothing further to do.
    #[default]
    None,
    /// The peer cancelled a relationship we held in both directions, so §7.3
    /// asks us to answer with a cancellation of our own before forgetting it.
    ReplyToCancellation,
}

/// A received and unpacked TSP message.
#[derive(Debug, Clone)]
pub struct ReceivedMessage {
    /// The decrypted payload bytes.
    pub payload: Vec<u8>,
    /// The sender's VID.
    pub sender: String,
    /// The receiver's VID.
    pub receiver: String,
    /// The message type.
    pub message_type: MessageType,
    /// The TSP thread digest. For an invite this is the value an accept must
    /// echo back; for an accept, this message's own digest.
    pub thread_digest: [u8; 32],
    /// If this is a control message, the parsed control payload.
    pub control: Option<ControlMessage>,
    /// What the message asks of this endpoint beyond a state change — see
    /// [`ControlOutcome`]. Always [`ControlOutcome::None`] for a non-control
    /// message.
    pub outcome: ControlOutcome,
}

/// The result of forwarding a routed message at an intermediary
/// ([`TspAgent::forward_routed`]).
#[derive(Debug, Clone)]
pub enum ForwardOutcome {
    /// A re-sealed routed layer to relay onward to the next intermediary.
    Relay {
        /// The next intermediary's VID (the new envelope receiver).
        to: String,
        /// The packed routed layer to send to `to`.
        message: PackedMessage,
    },
    /// The opaque inner message to deliver to the final recipient (last hop).
    Deliver {
        /// The final recipient's VID.
        to: String,
        /// The opaque inner message bytes (sealed to the final recipient).
        message: Vec<u8>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_agents() -> (TspAgent, TspAgent, String, String) {
        let alice_agent = TspAgent::new();
        let bob_agent = TspAgent::new();

        let alice_vid = PrivateVid::generate("did:example:alice");
        let bob_vid = PrivateVid::generate("did:example:bob");

        let alice_public = alice_vid.to_resolved();
        let bob_public = bob_vid.to_resolved();

        // Alice knows Bob, Bob knows Alice
        alice_agent.add_private_vid(alice_vid);
        alice_agent.add_verified_vid(bob_public.clone());

        bob_agent.add_private_vid(bob_vid);
        bob_agent.add_verified_vid(alice_public);

        (
            alice_agent,
            bob_agent,
            "did:example:alice".to_string(),
            "did:example:bob".to_string(),
        )
    }

    #[test]
    fn routed_through_two_intermediaries() {
        let alice = TspAgent::new();
        let m1 = TspAgent::new();
        let m2 = TspAgent::new();
        let bob = TspAgent::new();

        let alice_v = PrivateVid::generate("did:example:alice");
        let m1_v = PrivateVid::generate("did:example:m1");
        let m2_v = PrivateVid::generate("did:example:m2");
        let bob_v = PrivateVid::generate("did:example:bob");
        let (a, m1p, m2p, b) = (
            alice_v.to_resolved(),
            m1_v.to_resolved(),
            m2_v.to_resolved(),
            bob_v.to_resolved(),
        );

        // Each party knows the VIDs it must resolve along the route.
        alice.add_private_vid(alice_v);
        alice.add_verified_vid(m1p.clone()); // first hop
        alice.add_verified_vid(b.clone()); // final (inner seal)

        m1.add_private_vid(m1_v);
        m1.add_verified_vid(a.clone()); // previous hop
        m1.add_verified_vid(m2p.clone()); // next hop

        m2.add_private_vid(m2_v);
        m2.add_verified_vid(m1p.clone()); // previous hop
        m2.add_verified_vid(b.clone()); // final

        bob.add_private_vid(bob_v);
        bob.add_verified_vid(a.clone()); // inner sender

        // Alice routes a message to Bob through m1 then m2.
        let layer1 = alice
            .send_routed(
                "did:example:alice",
                "did:example:bob",
                &["did:example:m1", "did:example:m2"],
                b"hi bob",
            )
            .unwrap();

        // m1 relays to m2.
        let layer2 = match m1.forward_routed("did:example:m1", &layer1.bytes).unwrap() {
            ForwardOutcome::Relay { to, message } => {
                assert_eq!(to, "did:example:m2");
                message
            }
            other => panic!("m1 expected Relay, got {other:?}"),
        };

        // m2 is the last hop: it delivers the opaque inner to bob.
        let inner = match m2.forward_routed("did:example:m2", &layer2.bytes).unwrap() {
            ForwardOutcome::Deliver { to, message } => {
                assert_eq!(to, "did:example:bob");
                message
            }
            other => panic!("m2 expected Deliver, got {other:?}"),
        };

        // §7.2.2 gates application messages on an existing relationship, so
        // the endpoints form one before the routed exchange — as they would in
        // practice, over the same route.
        bob.store.set_relationship_state(
            "did:example:bob",
            "did:example:alice",
            RelationshipState::Bidirectional,
        );

        // Bob recovers the plaintext; only he could (the inner was sealed to him).
        let received = bob.receive("did:example:bob", &inner).unwrap();
        assert_eq!(received.payload, b"hi bob");
        assert_eq!(received.sender, "did:example:alice");
        assert_eq!(received.message_type, MessageType::Direct);
    }

    #[test]
    fn full_relationship_handshake() {
        let (alice, bob, alice_id, bob_id) = setup_agents();

        // Alice sends RFI to Bob
        let rfi = alice.send_relationship_invite(&alice_id, &bob_id).unwrap();
        assert_eq!(
            alice.relationship_state(&alice_id, &bob_id),
            RelationshipState::Pending
        );

        // Bob receives the RFI
        let received = bob.receive(&bob_id, &rfi.bytes).unwrap();
        assert_eq!(received.message_type, MessageType::Control);
        assert_eq!(
            bob.relationship_state(&bob_id, &alice_id),
            RelationshipState::InviteReceived
        );

        // Bob sends RFA back to Alice
        let rfa = bob.send_relationship_accept(&bob_id, &alice_id).unwrap();
        assert_eq!(
            bob.relationship_state(&bob_id, &alice_id),
            RelationshipState::Bidirectional
        );

        // Alice receives the RFA
        alice.receive(&alice_id, &rfa.bytes).unwrap();
        assert_eq!(
            alice.relationship_state(&alice_id, &bob_id),
            RelationshipState::Bidirectional
        );
    }

    #[test]
    fn send_after_handshake() {
        let (alice, bob, alice_id, bob_id) = setup_agents();

        // Establish relationship
        let rfi = alice.send_relationship_invite(&alice_id, &bob_id).unwrap();
        bob.receive(&bob_id, &rfi.bytes).unwrap();
        let rfa = bob.send_relationship_accept(&bob_id, &alice_id).unwrap();
        alice.receive(&alice_id, &rfa.bytes).unwrap();

        // Now Alice can send a message
        let msg = alice.send(&alice_id, &bob_id, b"Hello Bob!").unwrap();

        let received = bob.receive(&bob_id, &msg.bytes).unwrap();
        assert_eq!(received.payload, b"Hello Bob!");
        assert_eq!(received.sender, alice_id);
        assert_eq!(received.message_type, MessageType::Direct);
    }

    #[test]
    fn send_without_relationship_fails() {
        let (alice, _bob, alice_id, bob_id) = setup_agents();

        let result = alice.send(&alice_id, &bob_id, b"premature message");
        assert!(result.is_err());
    }

    #[test]
    fn relationship_cancel() {
        let (alice, bob, alice_id, bob_id) = setup_agents();

        // Establish relationship
        let rfi = alice.send_relationship_invite(&alice_id, &bob_id).unwrap();
        bob.receive(&bob_id, &rfi.bytes).unwrap();
        let rfa = bob.send_relationship_accept(&bob_id, &alice_id).unwrap();
        alice.receive(&alice_id, &rfa.bytes).unwrap();

        // Alice cancels
        let cancel = alice.send_relationship_cancel(&alice_id, &bob_id).unwrap();
        assert_eq!(
            alice.relationship_state(&alice_id, &bob_id),
            RelationshipState::None
        );

        // Bob receives cancel
        bob.receive(&bob_id, &cancel.bytes).unwrap();
        assert_eq!(
            bob.relationship_state(&bob_id, &alice_id),
            RelationshipState::None
        );
    }

    #[test]
    fn create_vid_helper() {
        let agent = TspAgent::new();
        let resolved = agent.create_vid("did:example:test");
        assert_eq!(resolved.id, "did:example:test");

        // Should be resolvable
        let found = agent.resolver.resolve("did:example:test").unwrap();
        assert_eq!(found.id, "did:example:test");
    }

    #[test]
    fn wrong_recipient_rejects() {
        let (alice, _bob, alice_id, bob_id) = setup_agents();

        let rfi = alice.send_relationship_invite(&alice_id, &bob_id).unwrap();

        // Try to receive as Alice (but message is for Bob)
        let result = alice.receive(&alice_id, &rfi.bytes);
        assert!(result.is_err());
    }

    // ---- Rev 3 §7.2.2 / §7.2.3 / §7.3 protocol behaviour ----

    /// Build two agents that know each other's VIDs but hold no relationship.
    fn two_strangers() -> (TspAgent, TspAgent) {
        let alice = TspAgent::new();
        let bob = TspAgent::new();
        let a = PrivateVid::generate("did:example:alice");
        let b = PrivateVid::generate("did:example:bob");
        let (ap, bp) = (a.to_resolved(), b.to_resolved());
        alice.add_private_vid(a);
        alice.add_verified_vid(bp.clone());
        bob.add_private_vid(b);
        bob.add_verified_vid(ap.clone());
        (alice, bob)
    }

    /// §7.2.2: an application message from a VID we hold no relationship with
    /// is dropped. "It is not permissible that one endpoint which has learned a
    /// VID of the other simply starts with an application level message."
    #[test]
    fn an_application_message_without_a_relationship_is_dropped() {
        let (alice, bob) = two_strangers();
        // Built with the internal packer: our own `send` refuses to produce
        // this, so it stands in for a sender that does not follow the rule.
        let packed = alice
            .pack_message(
                "did:example:alice",
                "did:example:bob",
                b"unsolicited",
                MessageType::Direct,
            )
            .unwrap();

        let err = bob.receive("did:example:bob", &packed.bytes).unwrap_err();
        assert!(matches!(err, TspError::Discarded(_)), "got {err:?}");
    }

    /// An invite records the inbound half, which admits the messages that
    /// follow it — §3.6 lets a sender pack user data with its invite rather
    /// than wait a round trip.
    #[test]
    fn an_invite_admits_the_messages_that_follow_it() {
        let (alice, bob) = two_strangers();

        let invite = alice
            .send_relationship_invite("did:example:alice", "did:example:bob")
            .unwrap();
        bob.receive("did:example:bob", &invite.bytes).unwrap();

        // §3.6 lets a sender put user data alongside its invite rather than
        // wait a round trip, so this is packed directly rather than via `send`,
        // which waits for the relationship to complete.
        let packed = alice
            .pack_message(
                "did:example:alice",
                "did:example:bob",
                b"now allowed",
                MessageType::Direct,
            )
            .unwrap();
        let got = bob.receive("did:example:bob", &packed.bytes).unwrap();
        assert_eq!(got.payload, b"now allowed");
    }

    /// A node that is not an endpoint — an intermediary — can opt out.
    #[test]
    fn an_ungated_agent_accepts_a_message_from_a_stranger() {
        let alice = TspAgent::new();
        let bob = TspAgent::new().with_relationship_policy(RelationshipPolicy::Ungated);
        let a = PrivateVid::generate("did:example:alice");
        let b = PrivateVid::generate("did:example:bob");
        alice.add_private_vid(a.clone());
        alice.add_verified_vid(b.to_resolved());
        bob.add_private_vid(b);
        bob.add_verified_vid(a.to_resolved());

        let packed = alice
            .pack_message(
                "did:example:alice",
                "did:example:bob",
                b"ungated",
                MessageType::Direct,
            )
            .unwrap();
        let got = bob.receive("did:example:bob", &packed.bytes).unwrap();
        assert_eq!(got.payload, b"ungated");
    }

    /// §7.2.3: when both endpoints invite each other at once, both keep the
    /// invite whose digest is lexicographically lower. Run from both sides of
    /// the same pair of invites, so the two agents converge on one exchange.
    #[test]
    fn the_invite_race_is_broken_the_same_way_on_both_sides() {
        let (alice, bob) = two_strangers();

        let a_invite = alice
            .send_relationship_invite("did:example:alice", "did:example:bob")
            .unwrap();
        let b_invite = bob
            .send_relationship_invite("did:example:bob", "did:example:alice")
            .unwrap();

        let a_lower = a_invite.thread_digest.as_slice() < b_invite.thread_digest.as_slice();

        let alice_got = alice.receive("did:example:alice", &b_invite.bytes);
        let bob_got = bob.receive("did:example:bob", &a_invite.bytes);

        if a_lower {
            // Alice keeps her own and discards Bob's; Bob adopts Alice's.
            assert!(matches!(alice_got, Err(TspError::Discarded(_))));
            assert!(bob_got.is_ok());
            assert_eq!(
                bob.store
                    .thread_digest("did:example:bob", "did:example:alice"),
                Some(a_invite.thread_digest)
            );
        } else {
            assert!(matches!(bob_got, Err(TspError::Discarded(_))));
            assert!(alice_got.is_ok());
            assert_eq!(
                alice
                    .store
                    .thread_digest("did:example:alice", "did:example:bob"),
                Some(b_invite.thread_digest)
            );
        }
    }

    /// Alice invites Bob and Bob accepts; returns the invite's wire bytes.
    fn establish_returning_invite(alice: &TspAgent, bob: &TspAgent) -> Vec<u8> {
        let invite = alice
            .send_relationship_invite("did:example:alice", "did:example:bob")
            .unwrap();
        bob.receive("did:example:bob", &invite.bytes).unwrap();
        let accept = bob
            .send_relationship_accept("did:example:bob", "did:example:alice")
            .unwrap();
        alice.receive("did:example:alice", &accept.bytes).unwrap();
        invite.bytes
    }

    #[test]
    fn a_repeated_invite_does_not_reopen_an_established_relationship() {
        let (alice, bob) = two_strangers();
        let invite = establish_returning_invite(&alice, &bob);

        let again = bob.receive("did:example:bob", &invite);
        assert!(matches!(again, Err(TspError::Discarded(_))), "{again:?}");
        assert_eq!(
            bob.relationship_state("did:example:bob", "did:example:alice"),
            RelationshipState::Bidirectional
        );
        assert!(
            bob.send("did:example:bob", "did:example:alice", b"still live")
                .is_ok()
        );
    }

    #[test]
    fn the_losing_invite_of_a_race_does_not_reopen_the_relationship_later() {
        let (alice, bob) = two_strangers();
        let a_invite = alice
            .send_relationship_invite("did:example:alice", "did:example:bob")
            .unwrap();
        let b_invite = bob
            .send_relationship_invite("did:example:bob", "did:example:alice")
            .unwrap();
        let (winner, loser, winner_vid, loser_vid, losing_invite, winning_invite) =
            if a_invite.thread_digest.as_slice() < b_invite.thread_digest.as_slice() {
                (
                    &alice,
                    &bob,
                    "did:example:alice",
                    "did:example:bob",
                    b_invite,
                    a_invite,
                )
            } else {
                (
                    &bob,
                    &alice,
                    "did:example:bob",
                    "did:example:alice",
                    a_invite,
                    b_invite,
                )
            };

        assert!(matches!(
            winner.receive(winner_vid, &losing_invite.bytes),
            Err(TspError::Discarded(_))
        ));
        loser.receive(loser_vid, &winning_invite.bytes).unwrap();
        let accept = loser
            .send_relationship_accept(loser_vid, winner_vid)
            .unwrap();
        winner.receive(winner_vid, &accept.bytes).unwrap();
        assert_eq!(
            winner.relationship_state(winner_vid, loser_vid),
            RelationshipState::Bidirectional
        );

        let late = winner.receive(winner_vid, &losing_invite.bytes);
        assert!(matches!(late, Err(TspError::Discarded(_))), "{late:?}");
        assert_eq!(
            winner.relationship_state(winner_vid, loser_vid),
            RelationshipState::Bidirectional
        );
    }

    #[test]
    fn a_repeated_invite_while_deciding_is_still_a_no_op() {
        let (alice, bob) = two_strangers();
        let invite = alice
            .send_relationship_invite("did:example:alice", "did:example:bob")
            .unwrap();
        bob.receive("did:example:bob", &invite.bytes).unwrap();

        let again = bob.receive("did:example:bob", &invite.bytes).unwrap();
        assert_eq!(again.message_type, MessageType::Control);
        assert_eq!(
            bob.relationship_state("did:example:bob", "did:example:alice"),
            RelationshipState::InviteReceived
        );
        assert!(
            bob.send_relationship_accept("did:example:bob", "did:example:alice")
                .is_ok()
        );
    }

    #[test]
    fn an_invite_from_before_a_re_establishment_does_not_reopen_the_relationship() {
        let (alice, bob) = two_strangers();
        let first_invite = establish_returning_invite(&alice, &bob);

        // Alice loses her half and re-forms the relationship with a new invite.
        alice.store.set_relationship_state(
            "did:example:alice",
            "did:example:bob",
            RelationshipState::None,
        );
        alice
            .store
            .clear_thread_digest("did:example:alice", "did:example:bob");
        establish_returning_invite(&alice, &bob);

        let stale = bob.receive("did:example:bob", &first_invite);
        assert!(matches!(stale, Err(TspError::Discarded(_))), "{stale:?}");
        assert_eq!(
            bob.relationship_state("did:example:bob", "did:example:alice"),
            RelationshipState::Bidirectional
        );
    }

    #[test]
    fn an_invite_from_a_cancelled_relationship_is_not_acted_on_again() {
        let (alice, bob) = two_strangers();
        let invite = establish_returning_invite(&alice, &bob);
        bob.send_relationship_cancel("did:example:bob", "did:example:alice")
            .unwrap();

        let stale = bob.receive("did:example:bob", &invite);
        assert!(matches!(stale, Err(TspError::Discarded(_))), "{stale:?}");
        assert_eq!(
            bob.relationship_state("did:example:bob", "did:example:alice"),
            RelationshipState::None
        );
    }

    /// Drive Alice and Bob to a live `Bidirectional` relationship in both
    /// directions. Returns the two agents; Alice was the original inviter.
    fn establish(alice: &TspAgent, bob: &TspAgent) {
        let invite = alice
            .send_relationship_invite("did:example:alice", "did:example:bob")
            .unwrap();
        bob.receive("did:example:bob", &invite.bytes).unwrap();
        let accept = bob
            .send_relationship_accept("did:example:bob", "did:example:alice")
            .unwrap();
        alice.receive("did:example:alice", &accept.bytes).unwrap();
        assert_eq!(
            alice.relationship_state("did:example:alice", "did:example:bob"),
            RelationshipState::Bidirectional
        );
        assert_eq!(
            bob.relationship_state("did:example:bob", "did:example:alice"),
            RelationshipState::Bidirectional
        );
    }

    /// D2 (`tsp-relationship-recovery.md`): the reconcile handshake, end to end
    /// with real crypto.
    ///
    /// The asymmetric-loss case the FSM could not previously handle: the sender
    /// lost its half (restart with an ephemeral store), the receiver still holds
    /// the relationship. The sender re-invites; the receiver takes the new
    /// `Bidirectional ──[receive RFI]──► InviteReceived` edge and re-accepts,
    /// and application traffic flows again — with no operator action.
    #[test]
    fn a_lost_half_is_recovered_by_re_inviting_the_peer_that_kept_it() {
        let (alice, bob) = two_strangers();
        establish(&alice, &bob);

        // Bob restarts onto an ephemeral store: his half is wiped. Alice still
        // holds `Bidirectional`. This is exactly the state that made every
        // message Bob sent get dropped at Alice's §7.2.2 gate — except here Bob
        // cannot even send, because `can_send()` is false on `None`.
        bob.store.set_relationship_state(
            "did:example:bob",
            "did:example:alice",
            RelationshipState::None,
        );
        bob.store
            .clear_thread_digest("did:example:bob", "did:example:alice");
        assert!(
            bob.send("did:example:bob", "did:example:alice", b"blocked")
                .is_err(),
            "a wiped half must refuse to send until re-established"
        );

        // Recovery: Bob (who knows locally he has no relationship) re-invites.
        let reinvite = bob
            .send_relationship_invite("did:example:bob", "did:example:alice")
            .unwrap();

        // Alice receives an RFI over a relationship she believes is live. Before
        // D2 this returned `InvalidTransition` and recovery deadlocked; now she
        // reopens to re-accept.
        alice.receive("did:example:alice", &reinvite.bytes).unwrap();
        assert_eq!(
            alice.relationship_state("did:example:alice", "did:example:bob"),
            RelationshipState::InviteReceived
        );

        let reaccept = alice
            .send_relationship_accept("did:example:alice", "did:example:bob")
            .unwrap();
        bob.receive("did:example:bob", &reaccept.bytes).unwrap();

        // Both halves live again.
        assert_eq!(
            alice.relationship_state("did:example:alice", "did:example:bob"),
            RelationshipState::Bidirectional
        );
        assert_eq!(
            bob.relationship_state("did:example:bob", "did:example:alice"),
            RelationshipState::Bidirectional
        );

        // And traffic flows both ways — the whole point of recovery.
        let from_bob = bob
            .send("did:example:bob", "did:example:alice", b"recovered")
            .unwrap();
        let got = alice.receive("did:example:alice", &from_bob.bytes).unwrap();
        assert_eq!(got.payload, b"recovered");

        let from_alice = alice
            .send("did:example:alice", "did:example:bob", b"and back")
            .unwrap();
        let got = bob.receive("did:example:bob", &from_alice.bytes).unwrap();
        assert_eq!(got.payload, b"and back");
    }

    /// The reconcile can carry its payload in the same round trip: §3.6 lets the
    /// re-inviter bundle application data with its RFI, and the peer that kept
    /// the relationship accepts it immediately on reopening — recovery costs one
    /// round trip, not an invite/accept/resend three.
    #[test]
    fn a_reconcile_invite_delivers_its_bundled_payload_immediately() {
        let (alice, bob) = two_strangers();
        establish(&alice, &bob);

        // Bob loses his half.
        bob.store.set_relationship_state(
            "did:example:bob",
            "did:example:alice",
            RelationshipState::None,
        );
        bob.store
            .clear_thread_digest("did:example:bob", "did:example:alice");

        // Bob re-invites, then — per §3.6 — sends the payload straight after,
        // without waiting for Alice's accept.
        let reinvite = bob
            .send_relationship_invite("did:example:bob", "did:example:alice")
            .unwrap();
        let bundled = bob
            .pack_message(
                "did:example:bob",
                "did:example:alice",
                b"data with the invite",
                MessageType::Direct,
            )
            .unwrap();

        // Alice reopens on the invite, then admits the payload that follows it.
        alice.receive("did:example:alice", &reinvite.bytes).unwrap();
        let got = alice.receive("did:example:alice", &bundled.bytes).unwrap();
        assert_eq!(got.payload, b"data with the invite");
    }

    /// §7.3: a cancellation naming a relationship the receiver does not hold is
    /// ignored rather than answered, so it cannot be used to probe which
    /// relationships exist.
    #[test]
    fn a_cancellation_for_an_unknown_relationship_is_ignored() {
        let (alice, bob) = two_strangers();
        // A cancellation naming a relationship neither side holds. Built
        // directly, since the helper derives the digest from stored state.
        let cancel = alice
            .pack_control(
                "did:example:alice",
                "did:example:bob",
                &ControlMessage::cancel([0x11; 32]),
            )
            .unwrap();

        let err = bob.receive("did:example:bob", &cancel.bytes).unwrap_err();
        assert!(matches!(err, TspError::Discarded(_)), "got {err:?}");
    }

    /// §7.3: cancelling a relationship held in both directions asks the
    /// receiver to answer with a cancellation of its own before forgetting it.
    #[test]
    fn cancelling_a_bidirectional_relationship_expects_a_reply() {
        let (alice, bob) = two_strangers();

        let invite = alice
            .send_relationship_invite("did:example:alice", "did:example:bob")
            .unwrap();
        let received = bob.receive("did:example:bob", &invite.bytes).unwrap();
        let accept = bob
            .send_relationship_accept("did:example:bob", "did:example:alice")
            .unwrap();
        alice.receive("did:example:alice", &accept.bytes).unwrap();
        let _ = received;

        assert_eq!(
            bob.relationship_state("did:example:bob", "did:example:alice"),
            RelationshipState::Bidirectional
        );

        let cancel = alice
            .send_relationship_cancel("did:example:alice", "did:example:bob")
            .unwrap();
        let got = bob.receive("did:example:bob", &cancel.bytes).unwrap();

        assert_eq!(got.outcome, ControlOutcome::ReplyToCancellation);
        assert_eq!(
            bob.relationship_state("did:example:bob", "did:example:alice"),
            RelationshipState::None
        );
    }

    /// §7.2.1: a cancellation may name either half. The accepter recognises
    /// one naming its own accept's digest, not only the invite's.
    #[test]
    fn the_accepter_recognises_a_cancellation_naming_its_accept() {
        let (alice, bob) = two_strangers();

        let invite = alice
            .send_relationship_invite("did:example:alice", "did:example:bob")
            .unwrap();
        bob.receive("did:example:bob", &invite.bytes).unwrap();
        let accept = bob
            .send_relationship_accept("did:example:bob", "did:example:alice")
            .unwrap();
        alice.receive("did:example:alice", &accept.bytes).unwrap();

        let cancel = alice
            .pack_control(
                "did:example:alice",
                "did:example:bob",
                &ControlMessage::cancel(accept.thread_digest),
            )
            .unwrap();
        let got = bob.receive("did:example:bob", &cancel.bytes).unwrap();

        assert_eq!(got.outcome, ControlOutcome::ReplyToCancellation);
        assert_eq!(
            bob.relationship_state("did:example:bob", "did:example:alice"),
            RelationshipState::None
        );
    }

    /// A cancellation of a half-formed relationship removes it without a reply.
    #[test]
    fn cancelling_a_one_sided_relationship_expects_no_reply() {
        let (alice, bob) = two_strangers();

        let invite = alice
            .send_relationship_invite("did:example:alice", "did:example:bob")
            .unwrap();
        bob.receive("did:example:bob", &invite.bytes).unwrap();

        let cancel = alice
            .send_relationship_cancel("did:example:alice", "did:example:bob")
            .unwrap();
        let got = bob.receive("did:example:bob", &cancel.bytes).unwrap();

        assert_eq!(got.outcome, ControlOutcome::None);
        assert_eq!(
            bob.relationship_state("did:example:bob", "did:example:alice"),
            RelationshipState::None
        );
    }

    // ---- Rev 3 §7.4.2 key-state freshness ----

    /// A resolver that counts how often each VID was re-resolved, and can be
    /// told to hand back a different key state on the next refresh — standing
    /// in for a peer that has rotated.
    #[derive(Debug, Default)]
    struct CountingResolver {
        current: std::sync::RwLock<std::collections::HashMap<String, ResolvedVid>>,
        rotated: std::sync::RwLock<std::collections::HashMap<String, ResolvedVid>>,
        refreshes: std::sync::atomic::AtomicUsize,
        refresh_fails: std::sync::atomic::AtomicBool,
        completed: std::sync::RwLock<std::collections::HashMap<String, ResolvedVid>>,
        #[allow(clippy::type_complexity)]
        block:
            std::sync::Mutex<Option<(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>)>>,
    }

    impl CountingResolver {
        fn insert(&self, vid: ResolvedVid) {
            self.current.write().unwrap().insert(vid.id.clone(), vid);
        }
        fn stage_rotation(&self, vid: ResolvedVid) {
            self.rotated.write().unwrap().insert(vid.id.clone(), vid);
        }
        fn refreshes(&self) -> usize {
            self.refreshes.load(std::sync::atomic::Ordering::SeqCst)
        }
        /// Make every refresh fail while still answering `resolve` from what
        /// it holds, as a caching resolver does when its source is down.
        fn set_refresh_fails(&self, fails: bool) {
            self.refresh_fails
                .store(fails, std::sync::atomic::Ordering::SeqCst);
        }
        /// Stand in for an async re-resolution that finished after a failed
        /// refresh.
        fn complete_refresh_with(&self, vid: ResolvedVid) {
            self.completed.write().unwrap().insert(vid.id.clone(), vid);
        }
        /// The next refresh signals `entered`, then waits for `release`.
        fn block_next_refresh(
            &self,
            entered: std::sync::mpsc::Sender<()>,
            release: std::sync::mpsc::Receiver<()>,
        ) {
            *self.block.lock().unwrap() = Some((entered, release));
        }
    }

    impl VidResolver for CountingResolver {
        fn resolve(&self, vid: &str) -> Result<ResolvedVid, TspError> {
            self.current
                .read()
                .unwrap()
                .get(vid)
                .cloned()
                .ok_or_else(|| TspError::VidNotFound(vid.to_string()))
        }

        fn refresh(&self, vid: &str) -> Result<ResolvedVid, TspError> {
            self.refreshes
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let block = self.block.lock().unwrap().take();
            if let Some((entered, release)) = block {
                entered.send(()).unwrap();
                release.recv().unwrap();
            }
            if self.refresh_fails.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(TspError::DidResolution(format!(
                    "{vid}: source unavailable"
                )));
            }
            if let Some(rotated) = self.rotated.write().unwrap().remove(vid) {
                self.current
                    .write()
                    .unwrap()
                    .insert(vid.to_string(), rotated.clone());
                return Ok(rotated);
            }
            self.resolve(vid)
        }

        fn completed_refresh(&self, vid: &str) -> Option<ResolvedVid> {
            self.completed.read().unwrap().get(vid).cloned()
        }
    }

    /// Bob, holding a relationship with Alice, resolving key state himself,
    /// with a clock and resolver the test drives.
    fn bob_with_resolver() -> (TspAgent, std::sync::Arc<ManualClock>) {
        let clock = std::sync::Arc::new(ManualClock::new());
        let bob = TspAgent::new().with_clock(Box::new(clock.clone()));
        (bob, clock)
    }

    /// §7.4.2: a verification failure inside an established relationship may be
    /// a rotation not yet observed, so the VID is re-resolved and the
    /// verification retried once before the message is discarded.
    #[test]
    fn a_rotation_is_recovered_by_retrying_once() {
        let alice_old = PrivateVid::generate("did:example:alice");
        let alice_new = PrivateVid::generate("did:example:alice");
        let b = PrivateVid::generate("did:example:bob");

        // Bob holds Alice's *old* key state; the resolver has the new one ready.
        let resolver = std::sync::Arc::new(CountingResolver::default());
        resolver.insert(alice_old.to_resolved());
        resolver.insert(b.to_resolved());
        resolver.stage_rotation(alice_new.to_resolved());

        let (bob, _clock) = bob_with_resolver();
        let bob = bob.with_resolver(Box::new(resolver.clone()));
        bob.add_private_vid(b.clone());
        bob.store.set_relationship_state(
            "did:example:bob",
            "did:example:alice",
            RelationshipState::Bidirectional,
        );

        // Alice signs with her new key, which Bob does not yet know.
        let alice = TspAgent::new();
        alice.add_private_vid(alice_new.clone());
        alice.add_verified_vid(b.to_resolved());
        let packed = alice
            .pack_message(
                "did:example:alice",
                "did:example:bob",
                b"after rotation",
                MessageType::Direct,
            )
            .unwrap();

        let got = bob.receive("did:example:bob", &packed.bytes).unwrap();
        assert_eq!(got.payload, b"after rotation");
        assert_eq!(resolver.refreshes(), 1, "exactly one retry");
    }

    /// Outside a relationship a failure is discarded at once — otherwise
    /// anyone could make the endpoint resolve by sending it noise.
    #[test]
    fn a_failure_outside_a_relationship_does_not_resolve() {
        let alice_old = PrivateVid::generate("did:example:alice");
        let alice_new = PrivateVid::generate("did:example:alice");
        let b = PrivateVid::generate("did:example:bob");

        let resolver = std::sync::Arc::new(CountingResolver::default());
        resolver.insert(alice_old.to_resolved());
        resolver.stage_rotation(alice_new.to_resolved());

        let (bob, _clock) = bob_with_resolver();
        let bob = bob.with_resolver(Box::new(resolver.clone()));
        bob.add_private_vid(b.clone());
        // No relationship recorded.

        let alice = TspAgent::new();
        alice.add_private_vid(alice_new);
        alice.add_verified_vid(b.to_resolved());
        let packed = alice
            .pack_message(
                "did:example:alice",
                "did:example:bob",
                b"noise",
                MessageType::Direct,
            )
            .unwrap();

        assert!(bob.receive("did:example:bob", &packed.bytes).is_err());
        assert_eq!(resolver.refreshes(), 0, "must not resolve for a stranger");
    }

    /// §7.4.2: resolution of any one peer is rate limited, because it can be
    /// provoked by messages the endpoint has not authenticated.
    #[test]
    fn repeated_failures_resolve_only_once_within_the_rate_limit() {
        let alice_real = PrivateVid::generate("did:example:alice");
        let alice_wrong = PrivateVid::generate("did:example:alice");
        let b = PrivateVid::generate("did:example:bob");

        let resolver = std::sync::Arc::new(CountingResolver::default());
        resolver.insert(alice_wrong.to_resolved()); // Bob's view never becomes right
        let (bob, clock) = bob_with_resolver();
        let bob = bob.with_resolver(Box::new(resolver.clone()));
        bob.add_private_vid(b.clone());
        bob.store.set_relationship_state(
            "did:example:bob",
            "did:example:alice",
            RelationshipState::Bidirectional,
        );

        let alice = TspAgent::new();
        alice.add_private_vid(alice_real);
        alice.add_verified_vid(b.to_resolved());

        for _ in 0..5 {
            let packed = alice
                .pack_message(
                    "did:example:alice",
                    "did:example:bob",
                    b"never verifies",
                    MessageType::Direct,
                )
                .unwrap();
            assert!(bob.receive("did:example:bob", &packed.bytes).is_err());
        }
        assert_eq!(
            resolver.refreshes(),
            1,
            "five failures inside the limit must provoke one resolution"
        );

        // Past the limit, one more is allowed.
        clock.advance(std::time::Duration::from_secs(61));
        let packed = alice
            .pack_message(
                "did:example:alice",
                "did:example:bob",
                b"never verifies",
                MessageType::Direct,
            )
            .unwrap();
        assert!(bob.receive("did:example:bob", &packed.bytes).is_err());
        assert_eq!(resolver.refreshes(), 2);
    }

    /// §7.4.2: a message arriving after a silence longer than the
    /// re-verification threshold prompts a refresh before it is acted on.
    #[test]
    fn a_message_after_a_long_silence_refreshes_first() {
        let a = PrivateVid::generate("did:example:alice");
        let b = PrivateVid::generate("did:example:bob");

        let resolver = std::sync::Arc::new(CountingResolver::default());
        resolver.insert(a.to_resolved());

        let (bob, clock) = bob_with_resolver();
        let bob = bob.with_resolver(Box::new(resolver.clone()));
        bob.add_private_vid(b.clone());
        bob.store.set_relationship_state(
            "did:example:bob",
            "did:example:alice",
            RelationshipState::Bidirectional,
        );

        let alice = TspAgent::new();
        alice.add_private_vid(a);
        alice.add_verified_vid(b.to_resolved());
        let send = || {
            alice
                .pack_message(
                    "did:example:alice",
                    "did:example:bob",
                    b"hello",
                    MessageType::Direct,
                )
                .unwrap()
        };

        // First message: no prior record, so no silence to measure.
        bob.receive("did:example:bob", &send().bytes).unwrap();
        assert_eq!(resolver.refreshes(), 0);

        // Well inside the threshold.
        clock.advance(std::time::Duration::from_secs(60));
        bob.receive("did:example:bob", &send().bytes).unwrap();
        assert_eq!(resolver.refreshes(), 0);

        // Past it.
        clock.advance(std::time::Duration::from_secs(60 * 60 * 25));
        bob.receive("did:example:bob", &send().bytes).unwrap();
        assert_eq!(resolver.refreshes(), 1, "a dormant relationship resuming");
    }

    /// Bob in a relationship with Alice, who has been silent past the
    /// re-verification threshold, with a resolver whose refreshes the test
    /// can make fail. Returns a closure that packs a message from Alice.
    fn bob_after_a_silence() -> (
        TspAgent,
        std::sync::Arc<ManualClock>,
        std::sync::Arc<CountingResolver>,
        impl Fn() -> PackedMessage,
    ) {
        let a = PrivateVid::generate("did:example:alice");
        let b = PrivateVid::generate("did:example:bob");

        let resolver = std::sync::Arc::new(CountingResolver::default());
        resolver.insert(a.to_resolved());

        let (bob, clock) = bob_with_resolver();
        let bob = bob.with_resolver(Box::new(resolver.clone()));
        bob.add_private_vid(b.clone());
        bob.store.set_relationship_state(
            "did:example:bob",
            "did:example:alice",
            RelationshipState::Bidirectional,
        );

        let alice = TspAgent::new();
        alice.add_private_vid(a);
        alice.add_verified_vid(b.to_resolved());
        let send = move || {
            alice
                .pack_message(
                    "did:example:alice",
                    "did:example:bob",
                    b"hello",
                    MessageType::Direct,
                )
                .unwrap()
        };

        bob.receive("did:example:bob", &send().bytes).unwrap();
        clock.advance(std::time::Duration::from_secs(60 * 60 * 25));
        (bob, clock, resolver, send)
    }

    /// After a silence, a refresh that fails leaves the key state unconfirmed,
    /// and it stays unconfirmed until a refresh succeeds: messages inside the
    /// rate limit are discarded too, not verified against the key we held.
    #[test]
    fn after_a_failed_refresh_messages_wait_for_a_successful_one() {
        let (bob, clock, resolver, send) = bob_after_a_silence();
        resolver.set_refresh_fails(true);

        let err = bob.receive("did:example:bob", &send().bytes).unwrap_err();
        assert!(matches!(err, TspError::Discarded(_)), "got {err:?}");
        assert_eq!(resolver.refreshes(), 1);
        assert_eq!(bob.key_state_refresh_failures("did:example:alice"), 1);

        for _ in 0..3 {
            clock.advance(std::time::Duration::from_secs(10));
            let err = bob.receive("did:example:bob", &send().bytes).unwrap_err();
            assert!(
                matches!(&err, TspError::Discarded(m) if m.contains("not confirmed")),
                "got {err:?}"
            );
        }
        assert_eq!(
            resolver.refreshes(),
            1,
            "the rate limit still bounds resolution"
        );

        resolver.set_refresh_fails(false);
        clock.advance(std::time::Duration::from_secs(31));
        let got = bob.receive("did:example:bob", &send().bytes).unwrap();
        assert_eq!(got.payload, b"hello");
        assert_eq!(resolver.refreshes(), 2);
        assert_eq!(bob.key_state_refresh_failures("did:example:alice"), 0);
    }

    /// Consecutive failed refreshes lengthen the wait before the next one,
    /// to a bound, and a success resets it.
    #[test]
    fn failed_refreshes_are_retried_with_a_bounded_backoff() {
        let (bob, clock, resolver, send) = bob_after_a_silence();
        resolver.set_refresh_fails(true);

        assert!(bob.receive("did:example:bob", &send().bytes).is_err());
        clock.advance(std::time::Duration::from_secs(60));
        assert!(bob.receive("did:example:bob", &send().bytes).is_err());
        assert_eq!(resolver.refreshes(), 2);
        assert_eq!(bob.key_state_refresh_failures("did:example:alice"), 2);

        // Two failures in a row: the next attempt waits two limits.
        clock.advance(std::time::Duration::from_secs(60));
        assert!(bob.receive("did:example:bob", &send().bytes).is_err());
        assert_eq!(resolver.refreshes(), 2);
        clock.advance(std::time::Duration::from_secs(60));
        resolver.set_refresh_fails(false);
        bob.receive("did:example:bob", &send().bytes).unwrap();
        assert_eq!(resolver.refreshes(), 3);
        assert_eq!(bob.key_state_refresh_failures("did:example:alice"), 0);
    }

    /// The fail-closed rule does not cost a peer anything after a refresh that
    /// worked: a message that fails to verify after a successful refresh does
    /// not stop the next good one inside the rate limit.
    #[test]
    fn after_a_successful_refresh_the_rate_limit_proceeds_on_the_fresh_state() {
        let (bob, clock, resolver, send) = bob_after_a_silence();

        let stranger = TspAgent::new();
        stranger.add_private_vid(PrivateVid::generate("did:example:alice"));
        stranger.add_verified_vid(bob.resolver.resolve("did:example:bob").unwrap());
        let wrongly_signed = stranger
            .pack_message(
                "did:example:alice",
                "did:example:bob",
                b"hello",
                MessageType::Direct,
            )
            .unwrap();
        assert!(
            bob.receive("did:example:bob", &wrongly_signed.bytes)
                .is_err()
        );
        assert_eq!(resolver.refreshes(), 1);

        clock.advance(std::time::Duration::from_secs(5));
        bob.receive("did:example:bob", &send().bytes).unwrap();
        assert_eq!(resolver.refreshes(), 1);
    }

    /// The documented pattern with a `DidVidResolver`: its `refresh` always
    /// evicts and fails, and the application re-resolves with `resolve_did`.
    /// After that the key state counts as confirmed, so the peer is not shut
    /// out for good after one silence; before it, messages are discarded.
    #[cfg(feature = "did-resolver")]
    #[tokio::test]
    async fn a_did_resolver_refreshed_by_resolve_did_confirms_key_state() {
        use affinidi_did_resolver_cache_sdk::DIDCacheClient;
        use affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder;
        use affinidi_encoding::{ED25519_PUB, encode_multikey};

        let mut a = PrivateVid::generate("placeholder");
        a.id = format!("did:key:{}", encode_multikey(ED25519_PUB, &a.verifying_key));
        let alice_did = a.id.clone();
        let b = PrivateVid::generate("did:example:bob");

        let client = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .unwrap();
        let resolver = std::sync::Arc::new(DidVidResolver::new(client));
        resolver.resolve_did(&alice_did).await.unwrap();

        let (bob, clock) = bob_with_resolver();
        let bob = bob.with_resolver(Box::new(resolver.clone()));
        bob.add_private_vid(b.clone());
        bob.store.set_relationship_state(
            "did:example:bob",
            &alice_did,
            RelationshipState::Bidirectional,
        );

        let alice = TspAgent::new();
        alice.add_private_vid(a);
        alice.add_verified_vid(b.to_resolved());
        let send = || {
            alice
                .pack_message(&alice_did, "did:example:bob", b"hello", MessageType::Direct)
                .unwrap()
        };

        bob.receive("did:example:bob", &send().bytes).unwrap();
        clock.advance(std::time::Duration::from_secs(60 * 60 * 25));

        let err = bob.receive("did:example:bob", &send().bytes).unwrap_err();
        assert!(matches!(err, TspError::Discarded(_)), "got {err:?}");
        assert!(
            bob.receive("did:example:bob", &send().bytes).is_err(),
            "evicted and not yet re-resolved"
        );

        resolver.resolve_did(&alice_did).await.unwrap();
        clock.advance(std::time::Duration::from_secs(1));
        let got = bob.receive("did:example:bob", &send().bytes).unwrap();
        assert_eq!(got.payload, b"hello");
        assert_eq!(bob.key_state_refresh_failures(&alice_did), 0);

        // Past the rate limit, later messages are fine too: the silence is
        // over, so no further refresh (and eviction) is due.
        clock.advance(std::time::Duration::from_secs(120));
        bob.receive("did:example:bob", &send().bytes).unwrap();
    }

    /// The same with a VID that was also registered locally
    /// (`add_verified_vid`): the re-resolved value replaces the local copy,
    /// rather than the old key being used.
    #[test]
    fn a_completed_refresh_replaces_a_locally_registered_copy() {
        let alice_old = PrivateVid::generate("did:example:alice");
        let alice_new = PrivateVid::generate("did:example:alice");

        let resolver = std::sync::Arc::new(CountingResolver::default());
        resolver.insert(alice_old.to_resolved());
        let (bob, _clock) = bob_with_resolver();
        let bob = bob.with_resolver(Box::new(resolver.clone()));
        bob.add_verified_vid(alice_old.to_resolved());

        resolver.set_refresh_fails(true);
        assert!(bob.resolver.refresh("did:example:alice").is_err());
        assert!(
            bob.resolver
                .completed_refresh("did:example:alice")
                .is_none()
        );

        resolver.complete_refresh_with(alice_new.to_resolved());
        let completed = bob.resolver.completed_refresh("did:example:alice").unwrap();
        assert_eq!(completed.signing_key, alice_new.verifying_key);
        assert_eq!(
            bob.resolver
                .resolve("did:example:alice")
                .unwrap()
                .signing_key,
            alice_new.verifying_key
        );
    }

    /// While one thread's refresh is in flight, a concurrent message after the
    /// silence is discarded with a reason that says so, and does not start a
    /// second refresh.
    #[test]
    fn a_message_during_an_in_flight_refresh_says_so() {
        let (bob, _clock, resolver, send) = bob_after_a_silence();
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        resolver.block_next_refresh(entered_tx, release_rx);

        let first = send();
        let second = send();
        std::thread::scope(|scope| {
            let slow = scope.spawn(|| bob.receive("did:example:bob", &first.bytes));
            entered_rx.recv().unwrap();

            let err = bob.receive("did:example:bob", &second.bytes).unwrap_err();
            assert!(
                matches!(&err, TspError::Discarded(m) if m.contains("in progress")),
                "got {err:?}"
            );

            release_tx.send(()).unwrap();
            slow.join().unwrap().unwrap();
        });
        assert_eq!(resolver.refreshes(), 1);
    }

    /// A sender with no relationship is not tracked, so the tracker grows with
    /// relationships, not with every sender whose message verifies.
    #[test]
    fn senders_without_a_relationship_are_not_tracked() {
        let a = PrivateVid::generate("did:example:alice");
        let b = PrivateVid::generate("did:example:bob");
        let bob = TspAgent::new().with_relationship_policy(RelationshipPolicy::Ungated);
        bob.add_private_vid(b.clone());
        bob.add_verified_vid(a.to_resolved());

        let alice = TspAgent::new();
        alice.add_private_vid(a);
        alice.add_verified_vid(b.to_resolved());
        let packed = alice
            .pack_message(
                "did:example:alice",
                "did:example:bob",
                b"hello",
                MessageType::Direct,
            )
            .unwrap();
        bob.receive("did:example:bob", &packed.bytes).unwrap();
        assert!(!bob.key_state.silent_longer_than(
            "did:example:alice",
            std::time::Duration::ZERO,
            u64::MAX
        ));
    }

    /// Cancelling the only relationship with a peer drops its key-state
    /// bookkeeping.
    #[test]
    fn cancelling_the_last_relationship_forgets_the_peers_key_state() {
        let (bob, _clock, _resolver, _send) = bob_after_a_silence();
        assert!(bob.key_state.silent_longer_than(
            "did:example:alice",
            std::time::Duration::ZERO,
            u64::MAX
        ));

        bob.send_relationship_cancel("did:example:bob", "did:example:alice")
            .unwrap();
        assert!(!bob.key_state.silent_longer_than(
            "did:example:alice",
            std::time::Duration::ZERO,
            u64::MAX
        ));
    }

    /// An endpoint that does not resolve key state itself takes no action of
    /// its own — §7.4.1, where the VID implementation maintains it.
    #[test]
    fn a_non_self_resolving_endpoint_never_refreshes() {
        let a = PrivateVid::generate("did:example:alice");
        let b = PrivateVid::generate("did:example:bob");

        let resolver = std::sync::Arc::new(CountingResolver::default());
        resolver.insert(a.to_resolved());

        let (bob, clock) = bob_with_resolver();
        let bob = bob
            .with_resolver(Box::new(resolver.clone()))
            .with_key_state_policy(KeyStatePolicy {
                self_resolving: false,
                ..Default::default()
            });
        bob.add_private_vid(b.clone());
        bob.store.set_relationship_state(
            "did:example:bob",
            "did:example:alice",
            RelationshipState::Bidirectional,
        );

        let alice = TspAgent::new();
        alice.add_private_vid(a);
        alice.add_verified_vid(b.to_resolved());
        let packed = alice
            .pack_message(
                "did:example:alice",
                "did:example:bob",
                b"hello",
                MessageType::Direct,
            )
            .unwrap();
        bob.receive("did:example:bob", &packed.bytes).unwrap();

        clock.advance(std::time::Duration::from_secs(60 * 60 * 24 * 30));
        let packed = alice
            .pack_message(
                "did:example:alice",
                "did:example:bob",
                b"hello",
                MessageType::Direct,
            )
            .unwrap();
        bob.receive("did:example:bob", &packed.bytes).unwrap();

        assert_eq!(resolver.refreshes(), 0);
    }

    /// §5.3.3: "The final entry in the hop list is the destination's own VID
    /// with its intermediary, rather than the intermediary's VID in that
    /// relationship." Rev 2 put the intermediary's there.
    ///
    /// The identifier exposed to the source and to every intermediary along the
    /// route is therefore one the destination chose, and an intermediary can
    /// change the VIDs it uses without invalidating routing information its
    /// clients have already shared.
    #[test]
    fn a_route_ends_in_the_destinations_vid_not_the_exits() {
        let alice = TspAgent::new();
        let m1 = TspAgent::new();
        let m2 = TspAgent::new();

        let a = PrivateVid::generate("did:example:alice");
        let m1v = PrivateVid::generate("did:example:m1");
        let m2v = PrivateVid::generate("did:example:m2");
        let bv = PrivateVid::generate("did:example:bob");

        alice.add_private_vid(a);
        alice.add_verified_vid(m1v.to_resolved());
        alice.add_verified_vid(bv.to_resolved());
        m1.add_private_vid(m1v.clone());
        m1.add_verified_vid(alice.resolver.resolve("did:example:alice").unwrap());
        m1.add_verified_vid(m2v.to_resolved());
        m2.add_private_vid(m2v.clone());
        m2.add_verified_vid(m1v.to_resolved());
        m2.add_verified_vid(bv.to_resolved());

        let layer1 = alice
            .send_routed(
                "did:example:alice",
                "did:example:bob",
                &["did:example:m1", "did:example:m2"],
                b"hi bob",
            )
            .unwrap();

        // The route carried to the first hop ends in Bob's VID, not m2's.
        let at_m1 = m1.forward_routed("did:example:m1", &layer1.bytes).unwrap();
        let layer2 = match at_m1 {
            ForwardOutcome::Relay { to, message } => {
                assert_eq!(to, "did:example:m2");
                message
            }
            other => panic!("expected Relay, got {other:?}"),
        };

        // m2 is the exit, and what it delivers to is the destination's VID —
        // the last hop-list entry — rather than a VID of its own.
        match m2.forward_routed("did:example:m2", &layer2.bytes).unwrap() {
            ForwardOutcome::Deliver { to, .. } => assert_eq!(to, "did:example:bob"),
            other => panic!("expected Deliver, got {other:?}"),
        }
    }
}
