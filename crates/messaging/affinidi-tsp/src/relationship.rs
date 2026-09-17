//! TSP relationship state machine.
//!
//! Unlike DIDComm where relationships are implicit, TSP has an explicit
//! relationship lifecycle with control messages:
//!
//! ```text
//! None ──[send RFI]──► Pending ──[receive RFA]──► Bidirectional
//!  │                      │                            │
//!  │   [receive RFI]      │   [receive RFD]            │ [send/receive RFD]
//!  ▼                      ▼                            ▼
//! InviteReceived    None (reset)                  None (reset)
//!  │
//!  │   [send RFA]
//!  ▼
//! Bidirectional
//! ```
//!
//! Re-establishment (`tsp-relationship-recovery.md`, D2): a peer that lost its
//! half re-sends an RFI over a relationship the other side still holds. That
//! side takes `Bidirectional ──[receive RFI]──► InviteReceived` and re-accepts,
//! repairing the peer's half. A re-sent RFI while `InviteReceived` is idempotent.

use serde::{Deserialize, Serialize};

/// Whether this agent enforces the relationship gating rule of Rev 3 §7.2.2.
///
/// The rule addresses an *endpoint*: "If an endpoint receives an application
/// message destined to one of its legitimate VIDs, but it has not established a
/// relationship from the source VID in the message to its own VID, it SHOULD
/// drop the message." It enforces protocol ordering — an exchange begins with
/// control messages — rather than admission control, which stays a local
/// decision the application makes when it sees the invite.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum RelationshipPolicy {
    /// Drop an application message from a VID we hold no relationship with.
    /// The default, and what §7.2.2 asks of an endpoint.
    #[default]
    Gated,
    /// Accept application messages whatever the relationship state.
    ///
    /// For a node that is not an endpoint in the specification's sense — an
    /// intermediary relaying on behalf of others, which by §5 handles messages
    /// for relationships it is not a party to.
    Ungated,
}

/// The state of a TSP relationship between two VIDs.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RelationshipState {
    /// No relationship exists.
    #[default]
    None,
    /// We sent a Relationship Forming Invite, awaiting acceptance.
    Pending,
    /// We received a Relationship Forming Invite, awaiting our decision.
    InviteReceived,
    /// Relationship is established (both parties have agreed).
    Bidirectional,
}

impl RelationshipState {
    /// Can we send a message in this state?
    pub fn can_send(&self) -> bool {
        matches!(self, RelationshipState::Bidirectional)
    }

    /// Does this state admit an inbound *application* message under §7.2.2?
    ///
    /// Any recorded relationship does, not only a completed one. Receiving an
    /// invite records the inbound half, and §3.6 lets a sender pack user data
    /// with its invite rather than wait a round trip — so gating on
    /// `Bidirectional` alone would drop messages the spec expects to arrive.
    pub fn admits_application_message(&self) -> bool {
        !matches!(self, RelationshipState::None)
    }

    /// Apply a state transition.
    pub fn transition(self, event: RelationshipEvent) -> Result<Self, InvalidTransition> {
        match (self, event) {
            // From None
            (RelationshipState::None, RelationshipEvent::SendInvite) => {
                Ok(RelationshipState::Pending)
            }
            (RelationshipState::None, RelationshipEvent::ReceiveInvite) => {
                Ok(RelationshipState::InviteReceived)
            }

            // From Pending
            (RelationshipState::Pending, RelationshipEvent::ReceiveAccept) => {
                Ok(RelationshipState::Bidirectional)
            }
            (RelationshipState::Pending, RelationshipEvent::ReceiveCancel) => {
                Ok(RelationshipState::None)
            }
            (RelationshipState::Pending, RelationshipEvent::SendCancel) => {
                Ok(RelationshipState::None)
            }

            // From InviteReceived
            (RelationshipState::InviteReceived, RelationshipEvent::SendAccept) => {
                Ok(RelationshipState::Bidirectional)
            }
            (RelationshipState::InviteReceived, RelationshipEvent::SendCancel) => {
                Ok(RelationshipState::None)
            }
            // A re-sent invite while we are still deciding. Idempotent: the peer
            // retransmitted its RFI (a lost accept, a slow link), so we stay
            // awaiting our decision. `handle_control` overwrites the recorded
            // thread digest to the latest invite, so the accept we eventually
            // send answers the invite the peer still remembers.
            (RelationshipState::InviteReceived, RelationshipEvent::ReceiveInvite) => {
                Ok(RelationshipState::InviteReceived)
            }
            // The inviter withdrew before we answered. §7.3 removes the
            // relationship in this direction; §7.4 covers the mirror case,
            // where we are the one declining.
            (RelationshipState::InviteReceived, RelationshipEvent::ReceiveCancel) => {
                Ok(RelationshipState::None)
            }

            // From Bidirectional
            (RelationshipState::Bidirectional, RelationshipEvent::SendCancel) => {
                Ok(RelationshipState::None)
            }
            (RelationshipState::Bidirectional, RelationshipEvent::ReceiveCancel) => {
                Ok(RelationshipState::None)
            }
            // Re-establishment (design note `tsp-relationship-recovery.md`, D2).
            // We hold the relationship as complete, but the peer has sent a fresh
            // RFI — the only reason it would is that it lost its half (restart
            // with an ephemeral store, cache eviction, redeploy) and is rebuilding
            // the exchange. There is no separate "re-establish" control message in
            // TSP; a re-invite over a live relationship *is* the signal.
            //
            // We drop back to `InviteReceived` and re-accept: our accept (an RFA)
            // is what repairs the peer's lost inbound half, so there is no shorter
            // path back to `Bidirectional`. The window is safe — `can_send()` is
            // briefly false, but our sends were being dropped by the peer's §7.2.2
            // gate anyway, and `admits_application_message()` stays true, so a
            // payload the peer bundles with its invite (§3.6) is still accepted.
            //
            // The invite is authenticated (it passed unpack + signature verify),
            // so only the real peer can trigger this. Rate-limiting inbound
            // invites so a flood cannot repeatedly reset a live relationship is a
            // layer up (design note D7), not the FSM's job.
            (RelationshipState::Bidirectional, RelationshipEvent::ReceiveInvite) => {
                Ok(RelationshipState::InviteReceived)
            }

            // Invalid transition
            (state, event) => Err(InvalidTransition { state, event }),
        }
    }
}

/// Events that drive relationship state transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelationshipEvent {
    /// We are sending a Relationship Forming Invite.
    SendInvite,
    /// We received a Relationship Forming Invite.
    ReceiveInvite,
    /// We are sending a Relationship Forming Accept.
    SendAccept,
    /// We received a Relationship Forming Accept.
    ReceiveAccept,
    /// We are sending a Relationship Cancel.
    SendCancel,
    /// We received a Relationship Cancel.
    ReceiveCancel,
}

/// Error for invalid state transitions.
#[derive(Debug, Clone)]
pub struct InvalidTransition {
    pub state: RelationshipState,
    pub event: RelationshipEvent,
}

impl std::fmt::Display for InvalidTransition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "invalid transition: {:?} in state {:?}",
            self.event, self.state
        )
    }
}

impl std::error::Error for InvalidTransition {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_outbound_flow() {
        let state = RelationshipState::None;
        let state = state.transition(RelationshipEvent::SendInvite).unwrap();
        assert_eq!(state, RelationshipState::Pending);

        let state = state.transition(RelationshipEvent::ReceiveAccept).unwrap();
        assert_eq!(state, RelationshipState::Bidirectional);
        assert!(state.can_send());
    }

    #[test]
    fn full_inbound_flow() {
        let state = RelationshipState::None;
        let state = state.transition(RelationshipEvent::ReceiveInvite).unwrap();
        assert_eq!(state, RelationshipState::InviteReceived);
        assert!(!state.can_send());

        let state = state.transition(RelationshipEvent::SendAccept).unwrap();
        assert_eq!(state, RelationshipState::Bidirectional);
        assert!(state.can_send());
    }

    #[test]
    fn cancel_from_pending() {
        let state = RelationshipState::Pending;
        let state = state.transition(RelationshipEvent::ReceiveCancel).unwrap();
        assert_eq!(state, RelationshipState::None);
    }

    #[test]
    fn cancel_from_bidirectional() {
        let state = RelationshipState::Bidirectional;
        let state = state.transition(RelationshipEvent::SendCancel).unwrap();
        assert_eq!(state, RelationshipState::None);
    }

    #[test]
    fn reject_invite() {
        let state = RelationshipState::InviteReceived;
        let state = state.transition(RelationshipEvent::SendCancel).unwrap();
        assert_eq!(state, RelationshipState::None);
    }

    #[test]
    fn invalid_double_invite() {
        let state = RelationshipState::Pending;
        assert!(state.transition(RelationshipEvent::SendInvite).is_err());
    }

    #[test]
    fn invalid_accept_without_invite() {
        let state = RelationshipState::None;
        assert!(state.transition(RelationshipEvent::SendAccept).is_err());
    }

    #[test]
    fn none_cannot_send() {
        assert!(!RelationshipState::None.can_send());
    }

    #[test]
    fn pending_cannot_send() {
        assert!(!RelationshipState::Pending.can_send());
    }

    #[test]
    fn default_is_none() {
        assert_eq!(RelationshipState::default(), RelationshipState::None);
    }

    // ---- D2: re-establishment (tsp-relationship-recovery.md) ----

    /// The reconcile edge: the side that still holds the relationship receives a
    /// fresh RFI from a peer that lost its half, and drops back to
    /// `InviteReceived` so it can re-accept. This is the transition that used to
    /// be `InvalidTransition` and deadlocked recovery.
    #[test]
    fn receiving_an_invite_while_bidirectional_reopens_for_reaccept() {
        let state = RelationshipState::Bidirectional;
        let state = state.transition(RelationshipEvent::ReceiveInvite).unwrap();
        assert_eq!(state, RelationshipState::InviteReceived);
        // Cannot send until we re-accept, but still admits the peer's bundled
        // §3.6 payload.
        assert!(!state.can_send());
        assert!(state.admits_application_message());

        // Re-accepting completes the repair.
        let state = state.transition(RelationshipEvent::SendAccept).unwrap();
        assert_eq!(state, RelationshipState::Bidirectional);
        assert!(state.can_send());
    }

    /// A retransmitted RFI while we are still deciding is idempotent.
    #[test]
    fn receiving_a_repeat_invite_while_invite_received_is_idempotent() {
        let state = RelationshipState::InviteReceived;
        let state = state.transition(RelationshipEvent::ReceiveInvite).unwrap();
        assert_eq!(state, RelationshipState::InviteReceived);
    }

    /// Re-establishment must not open a shortcut past accept: receiving an
    /// invite never lands directly in `Bidirectional`.
    #[test]
    fn reestablish_still_requires_an_accept() {
        for start in [
            RelationshipState::Bidirectional,
            RelationshipState::InviteReceived,
            RelationshipState::None,
        ] {
            let next = start.transition(RelationshipEvent::ReceiveInvite).unwrap();
            assert_ne!(
                next,
                RelationshipState::Bidirectional,
                "receiving an invite from {start:?} skipped the accept"
            );
        }
    }
}
