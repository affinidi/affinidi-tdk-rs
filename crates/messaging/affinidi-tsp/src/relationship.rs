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

use serde::{Deserialize, Serialize};

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

            // From Bidirectional
            (RelationshipState::Bidirectional, RelationshipEvent::SendCancel) => {
                Ok(RelationshipState::None)
            }
            (RelationshipState::Bidirectional, RelationshipEvent::ReceiveCancel) => {
                Ok(RelationshipState::None)
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
}
