//! Verifiable Identifier (VID) types for TSP.
//!
//! A VID is a superset of DIDs — any DID is a valid VID, but VIDs can also be
//! other cryptographically verifiable identifiers (KERI AIDs, raw keys, etc.).

pub mod resolver;

#[cfg(feature = "did-resolver")]
pub mod did_resolver;
#[cfg(feature = "did-resolver")]
pub use did_resolver::{DidVidResolver, TSP_SERVICE_TYPE};

use serde::{Deserialize, Serialize};
use url::Url;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::TspError;

/// A resolved VID with its associated public keys and endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedVid {
    /// The VID string identifier.
    pub id: String,
    /// Ed25519 public verification key (32 bytes).
    pub signing_key: [u8; 32],
    /// X25519 public encryption key (32 bytes).
    pub encryption_key: [u8; 32],
    /// Transport URLs this VID can be reached at directly — the `serviceEndpoint`
    /// of every `TSPTransport` service that names an HTTP-family URL.
    ///
    /// Only URLs a sender can actually POST to land here. A `TSPTransport`
    /// endpoint that names a DID is *not* a transport URL and is kept in
    /// [`mediators`](Self::mediators) instead.
    #[serde(default)]
    pub endpoints: Vec<Url>,
    /// DIDs this VID delegates its transport to — the `serviceEndpoint` of every
    /// `TSPTransport` service that names a DID rather than a URL.
    ///
    /// This is the "I am mediated" advertisement: the VID publishes *who* carries
    /// its traffic, and the transport URL lives in that DID's own document, one
    /// resolve away. A sender resolves the named DID and uses the URL it
    /// publishes. Kept apart from [`endpoints`](Self::endpoints) because a DID is
    /// not something a transport can connect to — `did:` is a valid URL scheme,
    /// so a DID that is allowed to pass as an endpoint reaches the HTTP client
    /// intact and fails there, at the far end of the delivery path.
    #[serde(default)]
    pub mediators: Vec<String>,
}

impl ResolvedVid {
    /// Whether the document advertises TSP transport at all — a direct URL or a
    /// mediator DID.
    ///
    /// This is the "does this peer speak TSP" signal; a mediated VID advertises
    /// no URL of its own, so testing [`endpoints`](Self::endpoints) alone reads
    /// as "no TSP" for exactly the peers that are reachable over it.
    pub fn advertises_tsp(&self) -> bool {
        !self.endpoints.is_empty() || !self.mediators.is_empty()
    }
}

/// A private VID with signing and decryption keys.
///
/// This is the local identity — it holds private keys needed to send
/// (sign + authenticate) and receive (decrypt) TSP messages.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PrivateVid {
    /// The VID string identifier.
    #[zeroize(skip)]
    pub id: String,
    /// Ed25519 private signing key (32 bytes).
    pub signing_key: [u8; 32],
    /// X25519 private decryption key (32 bytes).
    pub decryption_key: [u8; 32],
    /// Ed25519 public verification key (32 bytes).
    #[zeroize(skip)]
    pub verifying_key: [u8; 32],
    /// X25519 public encryption key (32 bytes).
    #[zeroize(skip)]
    pub encryption_key: [u8; 32],
    /// Service endpoints.
    #[zeroize(skip)]
    pub endpoints: Vec<Url>,
}

impl std::fmt::Debug for PrivateVid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivateVid")
            .field("id", &self.id)
            .field("signing_key", &"[REDACTED]")
            .field("decryption_key", &"[REDACTED]")
            .finish()
    }
}

impl PrivateVid {
    /// Create a new PrivateVid with generated keys.
    pub fn generate(id: impl Into<String>) -> Self {
        use ed25519_dalek::SigningKey;
        use x25519_dalek::{PublicKey, StaticSecret};

        let ed_sk = SigningKey::generate(&mut rand_10::rng());
        let ed_pk = ed_sk.verifying_key().to_bytes();

        let x_sk = StaticSecret::random_from_rng(&mut rand_10::rng());
        let x_pk = PublicKey::from(&x_sk);

        PrivateVid {
            id: id.into(),
            signing_key: ed_sk.to_bytes(),
            decryption_key: x_sk.to_bytes(),
            verifying_key: ed_pk,
            encryption_key: x_pk.to_bytes(),
            endpoints: Vec::new(),
        }
    }

    /// Create a PrivateVid from existing key material.
    pub fn from_keys(
        id: impl Into<String>,
        signing_key: [u8; 32],
        decryption_key: [u8; 32],
    ) -> Self {
        use x25519_dalek::{PublicKey, StaticSecret};

        let verifying_key = crate::crypto::signing::public_key_from_private(&signing_key);
        let x_sk = StaticSecret::from(decryption_key);
        let encryption_key = PublicKey::from(&x_sk).to_bytes();

        PrivateVid {
            id: id.into(),
            signing_key,
            decryption_key,
            verifying_key,
            encryption_key,
            endpoints: Vec::new(),
        }
    }

    /// Set the service endpoints for this VID.
    pub fn with_endpoints(mut self, endpoints: Vec<Url>) -> Self {
        self.endpoints = endpoints;
        self
    }

    /// Get the public resolved VID for sharing with others.
    ///
    /// `mediators` is empty: a `PrivateVid` is local key material plus the
    /// transport URLs it was handed, and whether the identity is mediated is a
    /// property of its published document, not of the keys.
    pub fn to_resolved(&self) -> ResolvedVid {
        ResolvedVid {
            id: self.id.clone(),
            signing_key: self.verifying_key,
            encryption_key: self.encryption_key,
            endpoints: self.endpoints.clone(),
            mediators: Vec::new(),
        }
    }
}

/// Returns true if the identifier looks like a DID (starts with "did:").
pub fn is_did(id: &str) -> bool {
    id.starts_with("did:")
}

/// Validate a VID string. Currently accepts DIDs and any non-empty string.
pub fn validate_vid(id: &str) -> Result<(), TspError> {
    if id.is_empty() {
        return Err(TspError::Vid("VID cannot be empty".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_private_vid() {
        let vid = PrivateVid::generate("did:example:alice");
        assert_eq!(vid.id, "did:example:alice");
        assert_ne!(vid.signing_key, [0u8; 32]);
        assert_ne!(vid.decryption_key, [0u8; 32]);
    }

    #[test]
    fn private_vid_to_resolved() {
        let vid = PrivateVid::generate("did:example:bob");
        let resolved = vid.to_resolved();
        assert_eq!(resolved.id, vid.id);
        assert_eq!(resolved.signing_key, vid.verifying_key);
        assert_eq!(resolved.encryption_key, vid.encryption_key);
    }

    #[test]
    fn is_did_detection() {
        assert!(is_did("did:example:123"));
        assert!(is_did("did:key:z6Mk..."));
        assert!(is_did("did:web:example.com"));
        assert!(!is_did("keri:EDP..."));
        assert!(!is_did("https://example.com"));
        assert!(!is_did(""));
    }

    #[test]
    fn validate_vid_rejects_empty() {
        assert!(validate_vid("").is_err());
        assert!(validate_vid("did:example:123").is_ok());
        assert!(validate_vid("some-other-vid").is_ok());
    }

    #[test]
    fn from_keys_derives_public_correctly() {
        use ed25519_dalek::SigningKey;

        let sk = SigningKey::generate(&mut rand_10::rng());
        let expected_pk = sk.verifying_key().to_bytes();

        let vid = PrivateVid::from_keys("test", sk.to_bytes(), [0u8; 32]);
        assert_eq!(vid.verifying_key, expected_pk);
    }

    #[test]
    fn debug_redacts_keys() {
        let vid = PrivateVid::generate("test");
        let debug = format!("{vid:?}");
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains(&format!("{:?}", vid.signing_key)));
    }
}
