//! Structured error type for data-integrity operations.
//!
//! Variants carry enough structure for programmatic matching — callers can
//! distinguish between "key is the wrong type" and "signature does not
//! verify", which lead to different remediation paths.

use affinidi_secrets_resolver::secrets::KeyType;
use thiserror::Error;

use crate::crypto_suites::CryptoSuite;

/// Why a signature failed to verify.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignatureFailure {
    /// The signature bytes are the wrong length or shape for the algorithm.
    Malformed,
    /// The signature parsed correctly but did not verify against the data.
    Invalid,
}

impl std::fmt::Display for SignatureFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed => f.write_str("malformed"),
            Self::Invalid => f.write_str("invalid"),
        }
    }
}

/// Errors raised by data-integrity signing and verification.
///
/// This type is `#[non_exhaustive]`: callers must include a wildcard arm
/// when matching, so future additions do not constitute breaking changes.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum DataIntegrityError {
    /// The cryptosuite identifier is not recognised by this build, either
    /// because the name is unknown or because the matching Cargo feature is
    /// disabled.
    #[error("unsupported cryptosuite: {name}")]
    UnsupportedCryptoSuite { name: String },

    /// The signer's key type is not compatible with the requested cryptosuite.
    #[error(
        "key type {actual:?} is not compatible with cryptosuite {suite:?} (expected {expected:?})"
    )]
    KeyTypeMismatch {
        expected: KeyType,
        actual: KeyType,
        suite: CryptoSuite,
    },

    /// The signature could not be verified.
    #[error("signature {reason} for cryptosuite {suite:?}")]
    InvalidSignature {
        suite: CryptoSuite,
        reason: SignatureFailure,
    },

    /// A public key has an unexpected multicodec, length, or encoding.
    #[error("invalid public key (codec={codec:?}, len={len}): {reason}")]
    InvalidPublicKey {
        codec: Option<u64>,
        len: usize,
        reason: String,
    },

    /// Canonicalization (JCS / RDFC / other) of the document or proof config
    /// failed.
    #[error("canonicalization failed: {0}")]
    Canonicalization(String),

    /// The proof document is structurally invalid (missing required fields,
    /// wrong type, malformed `created` timestamp, mismatched `@context`,
    /// etc.).
    #[error("malformed proof: {0}")]
    MalformedProof(String),

    /// A conformance check against the Data Integrity spec failed for a
    /// reason other than the signature itself (e.g. missing `proofPurpose`,
    /// wrong `type`, `created` in the future).
    #[error("spec conformance check failed: {0}")]
    Conformance(String),

    /// A signer (local or remote) returned an error while producing a
    /// signature.
    #[error("signing failed")]
    Signing(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// A verification-method resolver (did:key, did:web, etc.) failed to
    /// locate or decode the requested key.
    #[error("resolver error: {0}")]
    Resolver(String),
}

impl DataIntegrityError {
    /// Wraps any signer error (local keys, HSM, KMS) in the `Signing`
    /// variant. Preserves the source chain for debuggers.
    pub fn signing<E>(e: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Signing(Box::new(e))
    }
}
