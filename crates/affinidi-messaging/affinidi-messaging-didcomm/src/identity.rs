//! Identity types for DIDComm — local identity management.
//!
//! Mirrors the TSP's PrivateVid/ResolvedVid pattern but adapted for
//! DIDComm's variable key types (key agreement + signing).

use crate::crypto::key_agreement::{Curve, PrivateKeyAgreement, PublicKeyAgreement};
/// A local identity with private keys for DIDComm operations.
#[derive(Debug)]
pub struct PrivateIdentity {
    /// The DID for this identity
    pub did: String,
    /// Key agreement key ID (DID URL fragment)
    pub key_agreement_kid: String,
    /// Key agreement private key
    pub key_agreement_private: PrivateKeyAgreement,
    /// Signing key ID (DID URL fragment), if signing is supported
    pub signing_kid: Option<String>,
    /// Ed25519 signing private key (32 bytes), if available
    pub signing_private: Option<[u8; 32]>,
}

impl PrivateIdentity {
    /// Create a new identity with generated keys.
    ///
    /// Generates an X25519 key agreement key and an Ed25519 signing key.
    pub fn generate(did: impl Into<String>) -> Self {
        let did = did.into();
        let ka_kid = format!("{did}#key-agreement-1");
        let sig_kid = format!("{did}#key-signing-1");

        let ka_private = PrivateKeyAgreement::generate(Curve::X25519);
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);

        Self {
            did,
            key_agreement_kid: ka_kid,
            key_agreement_private: ka_private,
            signing_kid: Some(sig_kid),
            signing_private: Some(signing_key.to_bytes()),
        }
    }

    /// Create a new identity with a specific curve for key agreement.
    pub fn generate_with_curve(did: impl Into<String>, curve: Curve) -> Self {
        let did = did.into();
        let ka_kid = format!("{did}#key-agreement-1");
        let sig_kid = format!("{did}#key-signing-1");

        let ka_private = PrivateKeyAgreement::generate(curve);
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);

        Self {
            did,
            key_agreement_kid: ka_kid,
            key_agreement_private: ka_private,
            signing_kid: Some(sig_kid),
            signing_private: Some(signing_key.to_bytes()),
        }
    }

    /// Get the public key agreement key.
    pub fn public_key_agreement(&self) -> PublicKeyAgreement {
        self.key_agreement_private.public_key()
    }

    /// Get the Ed25519 verifying key bytes (if available).
    pub fn verifying_key(&self) -> Option<[u8; 32]> {
        self.signing_private.map(|sk| {
            crate::crypto::signing::public_key_from_private(&sk)
        })
    }

    /// Create a resolved identity (public-only) from this private identity.
    pub fn to_resolved(&self) -> ResolvedIdentity {
        ResolvedIdentity {
            did: self.did.clone(),
            key_agreement_kid: self.key_agreement_kid.clone(),
            key_agreement_public: self.public_key_agreement(),
            signing_kid: self.signing_kid.clone(),
            verifying_key: self.verifying_key(),
        }
    }
}

/// A resolved (public-only) identity — represents a remote party.
///
/// This is what you get after resolving a DID document.
#[derive(Debug, Clone)]
pub struct ResolvedIdentity {
    /// The DID
    pub did: String,
    /// Key agreement key ID
    pub key_agreement_kid: String,
    /// Key agreement public key
    pub key_agreement_public: PublicKeyAgreement,
    /// Signing key ID (if available)
    pub signing_kid: Option<String>,
    /// Ed25519 verifying key (if available)
    pub verifying_key: Option<[u8; 32]>,
}

impl ResolvedIdentity {
    /// Create from explicit values (e.g., after DID resolution).
    pub fn new(
        did: String,
        key_agreement_kid: String,
        key_agreement_public: PublicKeyAgreement,
    ) -> Self {
        Self {
            did,
            key_agreement_kid,
            key_agreement_public,
            signing_kid: None,
            verifying_key: None,
        }
    }
}

/// A mediator/relay endpoint for message forwarding.
#[derive(Debug, Clone)]
pub struct Mediator {
    /// The mediator's DID
    pub did: String,
    /// Key agreement key ID for wrapping forward messages
    pub key_agreement_kid: String,
    /// Key agreement public key
    pub key_agreement_public: PublicKeyAgreement,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_identity() {
        let id = PrivateIdentity::generate("did:example:alice");
        assert_eq!(id.did, "did:example:alice");
        assert!(id.signing_private.is_some());
        assert!(id.verifying_key().is_some());

        let resolved = id.to_resolved();
        assert_eq!(resolved.did, id.did);
        assert!(resolved.verifying_key.is_some());
    }

    #[test]
    fn generate_with_p256() {
        let id = PrivateIdentity::generate_with_curve("did:example:bob", Curve::P256);
        assert_eq!(id.key_agreement_private.curve(), Curve::P256);
    }
}
