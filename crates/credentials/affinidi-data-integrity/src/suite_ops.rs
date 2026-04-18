//! Per-cryptosuite operations.
//!
//! Each cryptosuite gets its own ZST impl of [`CryptoSuiteOps`]. The
//! [`CryptoSuite`] enum in [`crate::crypto_suites`] delegates to these
//! impls via a single `match` in its method bodies — so adding a new
//! suite is:
//!
//! 1. Add an enum variant in `crypto_suites.rs`.
//! 2. Add a new impl of `CryptoSuiteOps` here.
//! 3. Add one arm to [`CryptoSuite::ops`] that routes to the new impl.
//!
//! No registry and no dynamic dispatch in the hot path — the enum
//! delegates to a static `&'static dyn CryptoSuiteOps` and the compiler
//! can devirtualise where profitable.

use affinidi_secrets_resolver::secrets::KeyType;

use crate::DataIntegrityError;
use crate::crypto_suites::CryptoSuite;

/// Canonicalization algorithm used by a cryptosuite.
///
/// `Custom` is a marker variant: cryptosuites that do canonicalization
/// out-of-band (BBS-2023's selective-disclosure pipeline is the only
/// current example) use it to signal "don't route through the standard
/// JCS/RDFC hash-then-sign path." The per-suite [`CryptoSuiteOps`]
/// implementation is expected to handle verification itself.
///
/// Future non-JCS/non-RDFC suites (COSE, CBOR-based schemes) may
/// warrant a callback-based variant; at that point this enum will gain
/// a `Callback(...)` arm. The `#[non_exhaustive]` attribute makes that
/// additive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Canonicalization {
    /// RFC 8785 JSON Canonicalization Scheme.
    Jcs,
    /// W3C RDF Dataset Canonicalization 1.0 (URDNA2015).
    Rdfc,
    /// Cryptosuite-specific canonicalization handled out-of-band
    /// (e.g. BBS-2023's selective-disclosure pipeline).
    Custom,
}

/// Behaviour shared by every Data Integrity cryptosuite.
///
/// Implementors are typically ZSTs (`struct Foo;`) registered in the
/// match at [`CryptoSuite::ops`]. The trait is intentionally small —
/// signing is always driven by [`crate::signer::Signer`], so only the
/// verify + metadata surface lives here.
pub trait CryptoSuiteOps: Send + Sync + 'static {
    /// The canonical string identifier used on the wire
    /// (e.g. `"eddsa-jcs-2022"`, `"mldsa44-jcs-2024"`).
    fn name(&self) -> &'static str;

    /// Which canonicalization algorithm this suite uses.
    fn canonicalization(&self) -> Canonicalization;

    /// Key types accepted by this suite. Always non-empty except for
    /// BBS-2023 (which uses BLS12-381 keys not modelled by [`KeyType`]).
    fn compatible_key_types(&self) -> &'static [KeyType];

    /// Verifies a signature.
    fn verify(&self, key: &[u8], data: &[u8], sig: &[u8]) -> Result<(), DataIntegrityError>;
}

// ---------------------------------------------------------------------
// Ed25519 / EdDSA-2022
// ---------------------------------------------------------------------

/// `eddsa-jcs-2022` — EdDSA signatures over JCS-canonicalized documents.
pub struct EddsaJcs2022;
/// `eddsa-rdfc-2022` — EdDSA signatures over RDFC-canonicalized documents.
pub struct EddsaRdfc2022;

fn eddsa_verify(key: &[u8], data: &[u8], sig: &[u8]) -> Result<(), DataIntegrityError> {
    use crate::SignatureFailure;
    use ed25519_dalek::{Signature, VerifyingKey};

    let verifying_key =
        VerifyingKey::try_from(key).map_err(|_| DataIntegrityError::InvalidPublicKey {
            codec: None,
            len: key.len(),
            reason: "invalid Ed25519 public key bytes".to_string(),
        })?;
    let signature =
        Signature::from_slice(sig).map_err(|_| DataIntegrityError::InvalidSignature {
            suite: CryptoSuite::EddsaJcs2022,
            reason: SignatureFailure::Malformed,
        })?;
    verifying_key.verify_strict(data, &signature).map_err(|_| {
        DataIntegrityError::InvalidSignature {
            suite: CryptoSuite::EddsaJcs2022,
            reason: SignatureFailure::Invalid,
        }
    })
}

impl CryptoSuiteOps for EddsaJcs2022 {
    fn name(&self) -> &'static str {
        "eddsa-jcs-2022"
    }
    fn canonicalization(&self) -> Canonicalization {
        Canonicalization::Jcs
    }
    fn compatible_key_types(&self) -> &'static [KeyType] {
        &[KeyType::Ed25519]
    }
    fn verify(&self, key: &[u8], data: &[u8], sig: &[u8]) -> Result<(), DataIntegrityError> {
        eddsa_verify(key, data, sig)
    }
}

impl CryptoSuiteOps for EddsaRdfc2022 {
    fn name(&self) -> &'static str {
        "eddsa-rdfc-2022"
    }
    fn canonicalization(&self) -> Canonicalization {
        Canonicalization::Rdfc
    }
    fn compatible_key_types(&self) -> &'static [KeyType] {
        &[KeyType::Ed25519]
    }
    fn verify(&self, key: &[u8], data: &[u8], sig: &[u8]) -> Result<(), DataIntegrityError> {
        eddsa_verify(key, data, sig)
    }
}

// ---------------------------------------------------------------------
// BBS-2023 (selective disclosure)
// ---------------------------------------------------------------------

#[cfg(feature = "bbs-2023")]
/// `bbs-2023` — BBS+ signatures with selective disclosure.
pub struct Bbs2023;

#[cfg(feature = "bbs-2023")]
impl CryptoSuiteOps for Bbs2023 {
    fn name(&self) -> &'static str {
        "bbs-2023"
    }
    fn canonicalization(&self) -> Canonicalization {
        Canonicalization::Custom
    }
    fn compatible_key_types(&self) -> &'static [KeyType] {
        &[]
    }
    fn verify(&self, _key: &[u8], _data: &[u8], _sig: &[u8]) -> Result<(), DataIntegrityError> {
        Err(DataIntegrityError::UnsupportedCryptoSuite {
            name: "bbs-2023 verification uses bbs_2023::verify_proof, not CryptoSuiteOps::verify"
                .to_string(),
        })
    }
}

// ---------------------------------------------------------------------
// ML-DSA-44 (FIPS 204)
// ---------------------------------------------------------------------

#[cfg(feature = "ml-dsa")]
/// `mldsa44-jcs-2024` — ML-DSA-44 signatures over JCS-canonicalized documents.
pub struct MlDsa44Jcs2024;
#[cfg(feature = "ml-dsa")]
/// `mldsa44-rdfc-2024` — ML-DSA-44 signatures over RDFC-canonicalized documents.
pub struct MlDsa44Rdfc2024;

#[cfg(feature = "ml-dsa")]
fn ml_dsa_44_verify(
    suite: CryptoSuite,
    key: &[u8],
    data: &[u8],
    sig: &[u8],
) -> Result<(), DataIntegrityError> {
    use crate::SignatureFailure;
    affinidi_crypto::ml_dsa::verify_ml_dsa_44(key, data, sig).map_err(|_| {
        DataIntegrityError::InvalidSignature {
            suite,
            reason: SignatureFailure::Invalid,
        }
    })
}

#[cfg(feature = "ml-dsa")]
impl CryptoSuiteOps for MlDsa44Jcs2024 {
    fn name(&self) -> &'static str {
        "mldsa44-jcs-2024"
    }
    fn canonicalization(&self) -> Canonicalization {
        Canonicalization::Jcs
    }
    fn compatible_key_types(&self) -> &'static [KeyType] {
        &[KeyType::MlDsa44]
    }
    fn verify(&self, key: &[u8], data: &[u8], sig: &[u8]) -> Result<(), DataIntegrityError> {
        ml_dsa_44_verify(CryptoSuite::MlDsa44Jcs2024, key, data, sig)
    }
}

#[cfg(feature = "ml-dsa")]
impl CryptoSuiteOps for MlDsa44Rdfc2024 {
    fn name(&self) -> &'static str {
        "mldsa44-rdfc-2024"
    }
    fn canonicalization(&self) -> Canonicalization {
        Canonicalization::Rdfc
    }
    fn compatible_key_types(&self) -> &'static [KeyType] {
        &[KeyType::MlDsa44]
    }
    fn verify(&self, key: &[u8], data: &[u8], sig: &[u8]) -> Result<(), DataIntegrityError> {
        ml_dsa_44_verify(CryptoSuite::MlDsa44Rdfc2024, key, data, sig)
    }
}

// ---------------------------------------------------------------------
// SLH-DSA-SHA2-128s (FIPS 205)
// ---------------------------------------------------------------------

#[cfg(feature = "slh-dsa")]
/// `slhdsa128-jcs-2024` — SLH-DSA-SHA2-128s over JCS-canonicalized documents.
pub struct SlhDsa128Jcs2024;
#[cfg(feature = "slh-dsa")]
/// `slhdsa128-rdfc-2024` — SLH-DSA-SHA2-128s over RDFC-canonicalized documents.
pub struct SlhDsa128Rdfc2024;

#[cfg(feature = "slh-dsa")]
fn slh_dsa_verify(
    suite: CryptoSuite,
    key: &[u8],
    data: &[u8],
    sig: &[u8],
) -> Result<(), DataIntegrityError> {
    use crate::SignatureFailure;
    affinidi_crypto::slh_dsa::verify_slh_dsa_sha2_128s(key, data, sig).map_err(|_| {
        DataIntegrityError::InvalidSignature {
            suite,
            reason: SignatureFailure::Invalid,
        }
    })
}

#[cfg(feature = "slh-dsa")]
impl CryptoSuiteOps for SlhDsa128Jcs2024 {
    fn name(&self) -> &'static str {
        "slhdsa128-jcs-2024"
    }
    fn canonicalization(&self) -> Canonicalization {
        Canonicalization::Jcs
    }
    fn compatible_key_types(&self) -> &'static [KeyType] {
        &[KeyType::SlhDsaSha2_128s]
    }
    fn verify(&self, key: &[u8], data: &[u8], sig: &[u8]) -> Result<(), DataIntegrityError> {
        slh_dsa_verify(CryptoSuite::SlhDsa128Jcs2024, key, data, sig)
    }
}

#[cfg(feature = "slh-dsa")]
impl CryptoSuiteOps for SlhDsa128Rdfc2024 {
    fn name(&self) -> &'static str {
        "slhdsa128-rdfc-2024"
    }
    fn canonicalization(&self) -> Canonicalization {
        Canonicalization::Rdfc
    }
    fn compatible_key_types(&self) -> &'static [KeyType] {
        &[KeyType::SlhDsaSha2_128s]
    }
    fn verify(&self, key: &[u8], data: &[u8], sig: &[u8]) -> Result<(), DataIntegrityError> {
        slh_dsa_verify(CryptoSuite::SlhDsa128Rdfc2024, key, data, sig)
    }
}
