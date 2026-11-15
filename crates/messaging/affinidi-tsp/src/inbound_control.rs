//! The one place a received relationship control message — an invite, an
//! accept or a cancellation — is applied to relationship state (#1168).
//!
//! [`receive`](crate::receive) opens and verifies a message; this applies the
//! [`ControlMessage`] it carried. Both [`TspAgent`](crate::TspAgent) (over its
//! in-memory [`TspStore`](crate::store::TspStore)) and the messaging SDK (over its durable
//! `RelationshipStore`) run [`apply_control`], each through a
//! [`ControlStore`] over its own storage. Like the receive path it is async
//! and generic, so the agent's synchronous store completes it in one poll.
//!
//! What it does, in order:
//!
//! * **§7.2.5 referrals.** An invite introducing a new VID is checked against
//!   that VID's own signature before anything else, and refused when the
//!   introduced VID cannot be resolved or did not sign. A verified referral
//!   changes nothing here: the relationship it proposes is between a VID the
//!   receiver has yet to choose and the introduced one, so it is reported
//!   ([`AppliedControl::referral`]) for the receiver to act on.
//! * **Repeated invites.** A copy of the invite still being decided on is a
//!   no-op; a copy of one already acted on (current, from before a
//!   re-formation or cancellation, or the loser of a race) is refused, since a
//!   signed invite verifies as long as its sender's key does.
//! * **§7.2.3 the invite race**: both sides keep the invite with the lower
//!   digest.
//! * **§7.3 cancellations** naming no relationship held, or an unrecognised
//!   one, are refused, not answered, so they cannot probe which relationships
//!   exist. A cancellation of a relationship held in both directions owes an
//!   answer ([`AppliedControl::cancellation_answer`]), which the caller sends.
//! * **Duplicate accepts** for a relationship already held are idempotent; an
//!   accept answering an invite this endpoint did not send is refused.
//! * **§7.2.4 reply paths**: an invite's `Reply_Path` is recorded, for the
//!   accept to travel back over.
//! * **Crash-safe write order**: the state first, then the thread digests,
//!   then the reply path, and the invite history last — a process that stops
//!   part way leaves a redelivered copy of the invite to be recorded again,
//!   not refused as already seen.
//! * **Key state is kept** across a cancellation. The freshness bookkeeping
//!   (last seen, refresh failures and their back-off) for a peer is not
//!   dropped when a relationship with it ends, so cancelling and re-forming a
//!   relationship cannot reset a refresh back-off. It grows with the peers
//!   this endpoint has held a relationship with, as the invite history does.
//!
//! Every refusal is [`TspError::Discarded`] (Rev 3 §3.7: discard silently, send
//! nothing back); an invalid state transition is [`TspError::Relationship`].

use std::future::Future;

use serde::{Deserialize, Serialize};

use crate::error::TspError;
use crate::keystate::KeyStateTracker;
use crate::message::control::{ControlMessage, ControlType};
use crate::message::direct::{PkaeScheme, verify_referral};
use crate::receive::AsyncVidResolver;
use crate::relationship::{RelationshipEvent, RelationshipState};

/// The two thread digests a relationship is known by (Rev 3 §7.2.1).
///
/// "The relationship in the inviter-to-replier direction can be identified by
/// the Digest of the invite, and the relationship in the replier-to-inviter
/// direction (… the replier) can be identified by the Reply_Digest."
///
/// An endpoint needs both: a cancellation may name either half, and the invite
/// race is broken by comparing our own outstanding invite's digest against the
/// one that arrived.
///
/// `Serialize`/`Deserialize` so a durable store can persist it — losing the
/// digests across a restart forfeits the §7.2.3 invite-race tiebreak and
/// §7.2.1 cancel matching.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

/// Which invite-history operation failed, for
/// [`ControlStore::history_unavailable`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HistoryOp {
    /// [`ControlStore::has_seen_invite`]: the invite was treated as new.
    Read,
    /// [`ControlStore::record_seen_invite`]: a later copy of the invite will
    /// not be recognised.
    Record,
}

/// The relationship state [`apply_control`] reads and writes.
///
/// Implemented by [`TspStore`](crate::store::TspStore) for
/// [`TspAgent`](crate::TspAgent), and by the messaging SDK over its
/// `RelationshipStore`.
pub trait ControlStore: Send + Sync {
    /// The state of the relationship between `our_vid` and `their_vid`.
    fn state(
        &self,
        our_vid: &str,
        their_vid: &str,
    ) -> impl Future<Output = Result<RelationshipState, TspError>> + Send;

    /// Persist the state of the relationship.
    fn set_state(
        &self,
        our_vid: &str,
        their_vid: &str,
        state: RelationshipState,
    ) -> impl Future<Output = Result<(), TspError>> + Send;

    /// The thread digests recorded for the relationship. A store that keeps
    /// none returns the default, which recognises any digest and loses the
    /// invite-race tiebreak.
    fn thread_digests(
        &self,
        our_vid: &str,
        their_vid: &str,
    ) -> impl Future<Output = Result<ThreadDigests, TspError>> + Send;

    /// Persist the thread digests for the relationship.
    fn set_thread_digests(
        &self,
        our_vid: &str,
        their_vid: &str,
        digests: ThreadDigests,
    ) -> impl Future<Output = Result<(), TspError>> + Send;

    /// Persist the `Reply_Path` an invite carried (§7.2.4), empty for a direct
    /// reply or once the relationship is cancelled.
    fn set_reply_path(
        &self,
        our_vid: &str,
        their_vid: &str,
        path: Vec<String>,
    ) -> impl Future<Output = Result<(), TspError>> + Send;

    /// Has an invite with this thread digest from `their_vid` already been
    /// acted on for the pair?
    fn has_seen_invite(
        &self,
        our_vid: &str,
        their_vid: &str,
        digest: &[u8; 32],
    ) -> impl Future<Output = Result<bool, TspError>> + Send;

    /// Remember that the invite with this digest has been acted on. Keep a
    /// bounded number per pair, most recent first, across cancellations.
    fn record_seen_invite(
        &self,
        our_vid: &str,
        their_vid: &str,
        digest: [u8; 32],
    ) -> impl Future<Output = Result<(), TspError>> + Send;

    /// The invite history could not be read or written. [`apply_control`]
    /// carries on — refusing would drop a genuine invite, or lose a message
    /// already acted on — and reports the failure here so it is not silent.
    /// The default does nothing; a store that can fail logs it.
    fn history_unavailable(&self, _their_vid: &str, _op: HistoryOp, _error: &TspError) {}
}

/// What [`apply_control`] needs besides the message.
pub struct ControlContext<'a, R: ?Sized, S: ?Sized> {
    /// Resolves an introduced VID's key, to check a §7.2.5 referral.
    pub resolver: &'a R,
    /// The relationship state.
    pub store: &'a S,
    /// Per-peer freshness bookkeeping: a control message that forms a
    /// relationship starts the peer's silence measurement.
    pub key_state: &'a KeyStateTracker,
    /// The current time, in the tracker's milliseconds.
    pub now_ms: u64,
}

/// What applying a control message did, and what it asks of the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AppliedControl {
    /// The relationship state before the message.
    pub prior: RelationshipState,
    /// The relationship state after it.
    pub state: RelationshipState,
    /// Whether the message drove the state machine (as opposed to being a
    /// no-op copy, a duplicate accept, a verified referral, or the winning
    /// invite of a race adopted in place of ours).
    pub transitioned: bool,
    /// Rev 3 §7.3: the peer cancelled a relationship held in both directions,
    /// so a cancellation of our own is owed, naming this digest (the one the
    /// peer's cancellation named). The relationship is already forgotten; the
    /// caller sends the answer without running the state machine.
    pub cancellation_answer: Option<[u8; 32]>,
    /// The `Reply_Path` an invite carried (§7.2.4), recorded in the store;
    /// empty for a direct invite and every other control message.
    pub reply_path: Vec<String>,
    /// For a verified §7.2.5 referral, the VID it introduces. Nothing was
    /// applied: forming the proposed relationship is the receiver's decision.
    pub referral: Option<String>,
}

impl AppliedControl {
    fn unchanged(prior: RelationshipState) -> Self {
        Self {
            prior,
            state: prior,
            transitioned: false,
            cancellation_answer: None,
            reply_path: Vec::new(),
            referral: None,
        }
    }
}

fn discarded(message: String) -> TspError {
    TspError::Discarded(message)
}

/// Apply `control`, received from `their_vid` by `our_vid` and already
/// verified as `their_vid`'s, to the relationship state in `ctx.store`. See
/// the [module docs](self) for the rules.
pub async fn apply_control<R, S>(
    ctx: &ControlContext<'_, R, S>,
    our_vid: &str,
    their_vid: &str,
    control: &ControlMessage,
) -> Result<AppliedControl, TspError>
where
    R: AsyncVidResolver + ?Sized,
    S: ControlStore + ?Sized,
{
    let store = ctx.store;
    let event = match control.control_type {
        ControlType::RelationshipFormingInvite => RelationshipEvent::ReceiveInvite,
        ControlType::RelationshipFormingAccept => RelationshipEvent::ReceiveAccept,
        ControlType::RelationshipCancel => RelationshipEvent::ReceiveCancel,
    };

    // §7.2.5: unverified, a referral is only a claim that the sender wishes to
    // introduce the VID, and says nothing about whether its controller agreed.
    if let Some(referral) = control.referral.as_ref() {
        let introduced = ctx.resolver.resolve(&referral.new_vid).await.map_err(|e| {
            discarded(format!(
                "referral from {their_vid} discarded: could not resolve the introduced VID {}: \
                 {e}",
                referral.new_vid
            ))
        })?;
        // Referrals are packed under HPKE-Base, so that is the digest
        // algorithm the signature covers.
        verify_referral(
            PkaeScheme::HpkeBase,
            control,
            their_vid,
            &introduced.signing_key,
        )
        .map_err(|e| {
            discarded(format!(
                "referral from {their_vid} discarded: {} did not sign the introduction: {e}",
                referral.new_vid
            ))
        })?;
        // It arrived on one relationship while proposing another, between a
        // VID we have not chosen yet and the introduced one: advancing the
        // relationship it arrived on would be wrong.
        let prior = store.state(our_vid, their_vid).await?;
        return Ok(AppliedControl {
            reply_path: control.route.clone(),
            referral: Some(referral.new_vid.clone()),
            ..AppliedControl::unchanged(prior)
        });
    }

    let prior = store.state(our_vid, their_vid).await?;
    let mut digests = store.thread_digests(our_vid, their_vid).await?;

    if control.control_type == ControlType::RelationshipFormingInvite
        && let Some(digest) = control.digest
    {
        // A copy of the invite we are still deciding on: nothing to apply. Not
        // driving `ReceiveInvite` matters — an accept of this invite may land
        // between our read and a transition, which would then reopen what the
        // accept formed. Re-recording completes a first copy interrupted part
        // way.
        if prior == RelationshipState::InviteReceived && digests.invite == Some(digest) {
            store
                .set_reply_path(our_vid, their_vid, control.route.clone())
                .await?;
            record_seen_invite(store, our_vid, their_vid, digest).await;
            return Ok(AppliedControl {
                reply_path: control.route.clone(),
                ..AppliedControl::unchanged(prior)
            });
        }
        // A copy of an invite already acted on. A peer re-forming the
        // relationship sends a new invite with a new nonce and digest.
        if is_repeated_invite(store, our_vid, their_vid, prior, &digests, &digest).await {
            return Err(discarded(format!(
                "invite from {their_vid} discarded: it was already received, and a repeated \
                 copy does not reopen the relationship"
            )));
        }
    }

    // §7.2.3, the invite race: both sides keep the invite whose digest is
    // lexicographically lower, so they converge on one exchange.
    if control.control_type == ControlType::RelationshipFormingInvite
        && prior == RelationshipState::Pending
        && let (Some(ours), Some(theirs)) = (digests.invite, control.digest)
    {
        if ours.as_slice() < theirs.as_slice() {
            // The losing invite is settled too: a copy arriving once the race
            // is over must not reopen the relationship ours forms.
            record_seen_invite(store, our_vid, their_vid, theirs).await;
            return Err(discarded(format!(
                "invite from {their_vid} discarded: our own invite has the lower digest"
            )));
        }
        // Theirs wins: adopt it in place of the invite we sent.
        store
            .set_state(our_vid, their_vid, RelationshipState::InviteReceived)
            .await?;
        store
            .set_thread_digests(
                our_vid,
                their_vid,
                ThreadDigests {
                    invite: Some(theirs),
                    accept: None,
                },
            )
            .await?;
        store
            .set_reply_path(our_vid, their_vid, control.route.clone())
            .await?;
        record_seen_invite(store, our_vid, their_vid, theirs).await;
        return Ok(AppliedControl {
            state: RelationshipState::InviteReceived,
            reply_path: control.route.clone(),
            ..AppliedControl::unchanged(prior)
        });
    }

    // §7.3: a cancellation naming no relationship we hold, or naming neither
    // half of the one we do, is ignored rather than answered.
    if control.control_type == ControlType::RelationshipCancel {
        if prior == RelationshipState::None {
            return Err(discarded(format!(
                "cancellation from {their_vid} discarded: no relationship with {our_vid}"
            )));
        }
        if let Some(named) = control.reply.as_ref()
            && !digests.recognizes(named)
        {
            return Err(discarded(format!(
                "cancellation from {their_vid} discarded: names an unrecognised relationship"
            )));
        }
    }

    if control.control_type == ControlType::RelationshipFormingAccept {
        // A second accept for a relationship already complete — re-sent, or
        // delivered twice by a relay — changes nothing. One answering some
        // other invite falls through and is refused.
        if is_duplicate_accept(prior, &digests, control.reply, control.digest) {
            return Ok(AppliedControl::unchanged(prior));
        }
        // The accept's `Reply_Digest` is the invite it answers; one that
        // answers an invite we did not send is not ours to act on.
        let reply = control.require_reply()?;
        if let Some(expected) = digests.invite
            && reply != &expected
        {
            return Err(discarded(format!(
                "accept from {their_vid} discarded: it answers an invite we did not send"
            )));
        }
    }

    // What the relationship was known by, for the §7.3 answer — the record is
    // cleared before the answer is due.
    let cancelled_digest = digests.invite.or(digests.accept);
    let state = prior.transition(event).map_err(|e| {
        TspError::Relationship(format!(
            "invalid relationship transition: {e} ({our_vid} → {their_vid})"
        ))
    })?;
    store.set_state(our_vid, their_vid, state).await?;
    // The receive path measures silence only inside a relationship, so a
    // control message that just formed one starts the measurement.
    if !prior.admits_application_message() && state.admits_application_message() {
        ctx.key_state.record_seen(their_vid, ctx.now_ms);
    }

    // Record the digests as the handshake produces them: the invite's
    // identifies this direction, the accept's the other (§7.2.1).
    let mut reply_path = Vec::new();
    match control.control_type {
        ControlType::RelationshipFormingInvite => {
            digests.invite = control.digest;
            store
                .set_thread_digests(our_vid, their_vid, digests)
                .await?;
            // §7.2.4: the accept MUST travel back over the path the invite
            // supplied.
            store
                .set_reply_path(our_vid, their_vid, control.route.clone())
                .await?;
            reply_path = control.route.clone();
            // Last, once the invite is fully recorded: if the process stops
            // before this, a redelivered copy is recorded again, not refused.
            if let Some(digest) = control.digest {
                record_seen_invite(store, our_vid, their_vid, digest).await;
            }
        }
        ControlType::RelationshipFormingAccept => {
            digests.accept = control.digest;
            store
                .set_thread_digests(our_vid, their_vid, digests)
                .await?;
        }
        ControlType::RelationshipCancel => {
            store
                .set_thread_digests(our_vid, their_vid, ThreadDigests::default())
                .await?;
            store.set_reply_path(our_vid, their_vid, Vec::new()).await?;
        }
    }

    // §7.3: a cancellation of a relationship held in both directions is
    // answered with one of our own, naming what the peer's named. A decoded
    // cancellation always names one (`reply` is its one required field).
    let cancellation_answer = (control.control_type == ControlType::RelationshipCancel
        && prior == RelationshipState::Bidirectional)
        .then(|| control.reply.or(cancelled_digest))
        .flatten();

    Ok(AppliedControl {
        prior,
        state,
        transitioned: true,
        cancellation_answer,
        reply_path,
        referral: None,
    })
}

/// Is an inbound accept a repeat for a relationship we already hold?
///
/// Only from `Bidirectional`, and only when the accept belongs to this
/// relationship: it echoes the invite we recorded (`reply`) or is the accept
/// we recorded (`digest`). A store with no digests recognises any, as
/// [`ThreadDigests::recognizes`] does.
pub fn is_duplicate_accept(
    prior: RelationshipState,
    digests: &ThreadDigests,
    reply: Option<[u8; 32]>,
    digest: Option<[u8; 32]>,
) -> bool {
    prior == RelationshipState::Bidirectional
        && [reply, digest]
            .into_iter()
            .flatten()
            .any(|d| digests.recognizes(&d))
}

/// Is an inbound invite one this endpoint has already acted on?
///
/// The invite the relationship currently records counts once the
/// relationship is `Bidirectional` (a copy while it is still being decided on
/// is handled before this is asked). Earlier invites come from the store's
/// history. A history that cannot be read is reported and the invite treated
/// as new: the worst that does is ask about an invite again, where refusing
/// would drop a genuine one.
async fn is_repeated_invite<S: ControlStore + ?Sized>(
    store: &S,
    our_vid: &str,
    their_vid: &str,
    prior: RelationshipState,
    digests: &ThreadDigests,
    digest: &[u8; 32],
) -> bool {
    if digests.invite.as_ref() == Some(digest) {
        return prior == RelationshipState::Bidirectional;
    }
    match store.has_seen_invite(our_vid, their_vid, digest).await {
        Ok(seen) => seen,
        Err(e) => {
            store.history_unavailable(their_vid, HistoryOp::Read, &e);
            false
        }
    }
}

/// Add an invite to the history, reporting rather than returning a failure:
/// by now the invite has been acted on (or refused), so failing would only
/// lose the message.
async fn record_seen_invite<S: ControlStore + ?Sized>(
    store: &S,
    our_vid: &str,
    their_vid: &str,
    digest: [u8; 32],
) {
    if let Err(e) = store.record_seen_invite(our_vid, their_vid, digest).await {
        store.history_unavailable(their_vid, HistoryOp::Record, &e);
    }
}

impl ControlStore for crate::store::TspStore {
    fn state(
        &self,
        our_vid: &str,
        their_vid: &str,
    ) -> impl Future<Output = Result<RelationshipState, TspError>> + Send {
        std::future::ready(Ok(self.relationship_state(our_vid, their_vid)))
    }

    fn set_state(
        &self,
        our_vid: &str,
        their_vid: &str,
        state: RelationshipState,
    ) -> impl Future<Output = Result<(), TspError>> + Send {
        self.set_relationship_state(our_vid, their_vid, state);
        std::future::ready(Ok(()))
    }

    fn thread_digests(
        &self,
        our_vid: &str,
        their_vid: &str,
    ) -> impl Future<Output = Result<ThreadDigests, TspError>> + Send {
        std::future::ready(Ok(ThreadDigests {
            invite: self.thread_digest(our_vid, their_vid),
            accept: self.reply_thread_digest(our_vid, their_vid),
        }))
    }

    fn set_thread_digests(
        &self,
        our_vid: &str,
        their_vid: &str,
        digests: ThreadDigests,
    ) -> impl Future<Output = Result<(), TspError>> + Send {
        self.clear_thread_digest(our_vid, their_vid);
        if let Some(invite) = digests.invite {
            self.set_thread_digest(our_vid, their_vid, invite);
        }
        if let Some(accept) = digests.accept {
            self.set_reply_thread_digest(our_vid, their_vid, accept);
        }
        std::future::ready(Ok(()))
    }

    fn set_reply_path(
        &self,
        our_vid: &str,
        their_vid: &str,
        path: Vec<String>,
    ) -> impl Future<Output = Result<(), TspError>> + Send {
        crate::store::TspStore::set_reply_path(self, our_vid, their_vid, path);
        std::future::ready(Ok(()))
    }

    fn has_seen_invite(
        &self,
        our_vid: &str,
        their_vid: &str,
        digest: &[u8; 32],
    ) -> impl Future<Output = Result<bool, TspError>> + Send {
        std::future::ready(Ok(crate::store::TspStore::has_seen_invite(
            self, our_vid, their_vid, digest,
        )))
    }

    fn record_seen_invite(
        &self,
        our_vid: &str,
        their_vid: &str,
        digest: [u8; 32],
    ) -> impl Future<Output = Result<(), TspError>> + Send {
        crate::store::TspStore::record_seen_invite(self, our_vid, their_vid, digest);
        std::future::ready(Ok(()))
    }
}
