//! Authenticated session types — backend-agnostic.
//!
//! `Session`, `SessionState`, and `SessionClaims` describe the
//! mediator's auth context: a JWT-authenticated DID with its ACLs,
//! account role, expiry, and refresh-token hash. They live here
//! (rather than in `database/session.rs` next to the Redis impl)
//! because the JWT auth middleware impls `FromRequestParts` on
//! `Session` — the orphan rule prevents implementing a foreign trait
//! on a foreign type, so this struct must be local to the mediator
//! crate. The shape mirrors
//! [`affinidi_messaging_mediator_common::store::types::Session`]; bidirectional
//! `From` impls bridge the two at the trait/handler boundary.

use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_messaging_sdk::protocols::mediator::{accounts::AccountType, acls::MediatorACLSet};
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display, Formatter};
use tracing::warn;

/// JWT claims embedded in session tokens issued after authentication.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionClaims {
    /// Audience (the mediator identifier).
    pub aud: String,
    /// Subject (the authenticated DID).
    pub sub: String,
    /// Unique session identifier.
    pub session_id: String,
    /// Expiration time as a Unix timestamp.
    pub exp: u64,
}

/// Lifecycle state of an authentication session.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum SessionState {
    /// Initial state before any interaction.
    #[default]
    Unknown,
    /// A challenge has been sent to the client, awaiting response.
    ChallengeSent,
    /// The client has successfully authenticated.
    Authenticated,
    /// The session has been blocked (e.g., due to policy violation).
    Blocked,
}

impl TryFrom<&String> for SessionState {
    type Error = MediatorError;

    fn try_from(value: &String) -> Result<Self, Self::Error> {
        match value.as_str() {
            "ChallengeSent" => Ok(Self::ChallengeSent),
            "Authenticated" => Ok(Self::Authenticated),
            _ => {
                warn!("Unknown SessionState: ({})", value);
                Err(MediatorError::SessionError(
                    20,
                    "NA".into(),
                    format!("Unknown session state: ({value})"),
                ))
            }
        }
    }
}

impl Display for SessionState {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// An authentication session, linking a DID to its auth state and permissions.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Session {
    /// Unique session identifier (not serialized; populated from the
    /// backend's session key on read).
    #[serde(skip)]
    pub session_id: String,
    /// Random challenge string sent to the client for DID-based authentication.
    pub challenge: String,
    /// Current lifecycle state of this session.
    pub state: SessionState,
    /// The DID associated with this session.
    pub did: String,
    /// SHA-256 hash of the DID, used as the storage key component.
    pub did_hash: String,
    /// Whether the session has been fully authenticated.
    pub authenticated: bool,
    /// Access control permissions granted to this session.
    pub acls: MediatorACLSet,
    /// Account role type (e.g., standard user, admin).
    pub account_type: AccountType,
    /// Unix timestamp when this session expires.
    pub expires_at: u64,
    /// Hash of the most recently issued refresh token.
    pub refresh_token_hash: Option<String>,
}

// ─── Conversions to / from the trait-layer Session ──────────────────────────

impl From<affinidi_messaging_mediator_common::store::types::SessionState> for SessionState {
    fn from(s: affinidi_messaging_mediator_common::store::types::SessionState) -> Self {
        use affinidi_messaging_mediator_common::store::types::SessionState as S;
        match s {
            S::Unknown => Self::Unknown,
            S::ChallengeSent => Self::ChallengeSent,
            S::Authenticated => Self::Authenticated,
            S::Blocked => Self::Blocked,
        }
    }
}

impl From<SessionState> for affinidi_messaging_mediator_common::store::types::SessionState {
    fn from(s: SessionState) -> Self {
        use affinidi_messaging_mediator_common::store::types::SessionState as S;
        match s {
            SessionState::Unknown => S::Unknown,
            SessionState::ChallengeSent => S::ChallengeSent,
            SessionState::Authenticated => S::Authenticated,
            SessionState::Blocked => S::Blocked,
        }
    }
}

impl From<affinidi_messaging_mediator_common::store::types::Session> for Session {
    fn from(s: affinidi_messaging_mediator_common::store::types::Session) -> Self {
        Self {
            session_id: s.session_id,
            challenge: s.challenge,
            state: s.state.into(),
            did: s.did,
            did_hash: s.did_hash,
            authenticated: s.authenticated,
            acls: s.acls,
            account_type: s.account_type,
            expires_at: s.expires_at,
            refresh_token_hash: s.refresh_token_hash,
        }
    }
}

impl From<Session> for affinidi_messaging_mediator_common::store::types::Session {
    fn from(s: Session) -> Self {
        Self {
            session_id: s.session_id,
            challenge: s.challenge,
            state: s.state.into(),
            did: s.did,
            did_hash: s.did_hash,
            authenticated: s.authenticated,
            acls: s.acls,
            account_type: s.account_type,
            expires_at: s.expires_at,
            refresh_token_hash: s.refresh_token_hash,
        }
    }
}

impl Session {
    /// Borrowed conversion to the trait-layer session type. Avoids the
    /// allocation of going through `From` when only the trait-layer
    /// shape is needed transiently.
    pub fn to_store_session(&self) -> affinidi_messaging_mediator_common::store::types::Session {
        affinidi_messaging_mediator_common::store::types::Session {
            session_id: self.session_id.clone(),
            challenge: self.challenge.clone(),
            state: self.state.into(),
            did: self.did.clone(),
            did_hash: self.did_hash.clone(),
            authenticated: self.authenticated,
            acls: self.acls.clone(),
            account_type: self.account_type.clone(),
            expires_at: self.expires_at,
            refresh_token_hash: self.refresh_token_hash.clone(),
        }
    }
}
