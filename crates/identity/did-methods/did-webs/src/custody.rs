//! What has to be kept between one event and the next.
//!
//! A `did:webs` identifier is not finished when it is created. Rotating it
//! later requires the keys that the inception event *committed to by digest* —
//! and a digest cannot be reversed, so those keys are not recoverable from the
//! published artifacts. Lose them and the identifier can never rotate again.
//!
//! Two things must survive, and they belong in different places:
//!
//! * the **salt**, from which every key is derived. This is the secret. It
//!   belongs wherever the application keeps secrets — `affinidi-secrets-resolver`
//!   in this workspace — and this crate never persists it.
//! * the **state**: which derivation generations are in play, the sequence
//!   number, the last event's SAID. None of it is secret, and it can sit beside
//!   the key event log.
//!
//! [`KeyCustody`] is the second of those. The salt is passed alongside it and
//! immediately used, never stored.

use affinidi_keri::hab::HabState;
use serde::{Deserialize, Serialize};

/// The non-secret half of what an identifier needs to continue.
///
/// Persist this with the artifacts. Keep the salt somewhere else.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct KeyCustody {
    /// The KERI identifier state — generations, sequence number, last SAID.
    pub state: HabState,
}

impl KeyCustody {
    /// Wrap identifier state for persistence.
    pub fn new(state: HabState) -> Self {
        Self { state }
    }

    /// The AID this custody record belongs to.
    pub fn aid(&self) -> &str {
        &self.state.prefix
    }
}
