/*!
 * TDK Profiles.
 *
 * A `TDKProfile` is the serialisable representation of an identity profile —
 * an alias, a DID, an optional mediator, and the secrets backing the DID's
 * keys. Profiles are stored on disk via
 * [`crate::environments::TDKEnvironments`].
 *
 * # Secrets handling
 *
 * `TDKProfile.secrets` is `pub(crate)` to discourage long-lived plaintext
 * exposure. Read via [`TDKProfile::secrets`] (borrow) or drain via
 * [`TDKProfile::take_secrets`] when handing them to a `SecretsResolver`.
 */

use affinidi_secrets_resolver::secrets::Secret;
use serde::{Deserialize, Serialize};

/// Serialisable identity profile.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TDKProfile {
    /// Friendly name for the profile (Alice, Bob, etc).
    pub alias: String,

    /// DID for this profile.
    pub did: String,

    /// DID of the mediator for this profile (if any).
    /// If this is `None` and the profile DID does not self-resolve to a
    /// mediator service endpoint, the default DIDComm mediator from the
    /// active `TDKEnvironment` is used. If neither is set, messaging will
    /// fail for this profile.
    pub mediator: Option<String>,

    /// Secrets backing the profile's keys. Persisted to/from disk during
    /// environment-file IO; transferred to the runtime
    /// [`affinidi_secrets_resolver::ThreadedSecretsResolver`] via
    /// [`TDKProfile::take_secrets`] or [`crate::TDKSharedState::add_profile`].
    /// Field is `pub(crate)` to discourage incidental retention; use the
    /// accessor methods.
    #[serde(default)]
    pub(crate) secrets: Vec<Secret>,
}

impl TDKProfile {
    /// Create a new `TDKProfile`.
    pub fn new(alias: &str, did: &str, mediator: Option<&str>, secrets: Vec<Secret>) -> Self {
        TDKProfile {
            alias: alias.to_string(),
            did: did.to_string(),
            mediator: mediator.map(|s| s.to_string()),
            secrets,
        }
    }

    /// Borrow the profile's secrets without taking ownership.
    pub fn secrets(&self) -> &[Secret] {
        &self.secrets
    }

    /// Drain the profile's secrets, leaving an empty `Vec`.
    ///
    /// Prefer this over [`secrets`](Self::secrets) when handing the
    /// secrets to a `SecretsResolver` — clearing the in-memory copy
    /// shortens the plaintext lifetime.
    pub fn take_secrets(&mut self) -> Vec<Secret> {
        std::mem::take(&mut self.secrets)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_populates_fields() {
        let p = TDKProfile::new("alice", "did:example:1", Some("did:web:m"), vec![]);
        assert_eq!(p.alias, "alice");
        assert_eq!(p.did, "did:example:1");
        assert_eq!(p.mediator.as_deref(), Some("did:web:m"));
        assert!(p.secrets().is_empty());
    }

    #[test]
    fn take_secrets_drains() {
        let s = Secret::generate_ed25519(Some("kid"), Some(&[1u8; 32]));
        let mut p = TDKProfile::new("a", "did:example:1", None, vec![s.clone()]);
        assert_eq!(p.secrets().len(), 1);
        let drained = p.take_secrets();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].id, s.id);
        assert!(p.secrets().is_empty());
    }

    #[test]
    fn serde_roundtrips_with_no_secrets() {
        let p = TDKProfile::new("alice", "did:example:1", Some("did:web:m"), vec![]);
        let json = serde_json::to_string(&p).unwrap();
        let back: TDKProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(back.alias, p.alias);
        assert_eq!(back.did, p.did);
        assert_eq!(back.mediator, p.mediator);
        assert!(back.secrets().is_empty());
    }
}
