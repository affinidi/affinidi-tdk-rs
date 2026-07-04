//! Key type enumeration

use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::CryptoError;

/// Known cryptographic key types.
///
/// This enum is `#[non_exhaustive]`: new algorithms (hybrid schemes, future
/// NIST standards, vendor-specific key types) will be added in minor
/// releases without breaking match-all arms.
///
/// No `Default` impl is provided on purpose: a key without a known
/// algorithm is a programming error in this crate, not a sensible
/// default state. `KeyType::Unknown` exists for parsing paths that
/// receive an unrecognised curve or codec identifier.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Zeroize)]
#[non_exhaustive]
pub enum KeyType {
    Ed25519,
    X25519,
    P256,
    P384,
    P521,
    Secp256k1,
    /// BLS12-381 G2 public key — the verification key of a BBS+ issuer
    /// (`bbs-2023` Data-Integrity cryptosuite). A 96-byte compressed G2 point,
    /// multicodec `0xeb`.
    Bls12381G2,
    /// ML-DSA-44 (FIPS 204) — post-quantum signature scheme.
    #[cfg(feature = "ml-dsa")]
    MlDsa44,
    /// ML-DSA-65 (FIPS 204) — post-quantum signature scheme.
    #[cfg(feature = "ml-dsa")]
    MlDsa65,
    /// ML-DSA-87 (FIPS 204) — post-quantum signature scheme.
    #[cfg(feature = "ml-dsa")]
    MlDsa87,
    /// SLH-DSA-SHA2-128s (FIPS 205) — stateless hash-based post-quantum signature.
    #[cfg(feature = "slh-dsa")]
    SlhDsaSha2_128s,
    /// Unrecognised or unsupported key type. Produced by parsing paths
    /// on unknown curve identifiers; should never be constructed directly.
    Unknown,
}

impl TryFrom<&str> for KeyType {
    type Error = CryptoError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "Ed25519" => Ok(KeyType::Ed25519),
            "X25519" => Ok(KeyType::X25519),
            "P-256" => Ok(KeyType::P256),
            "P-384" => Ok(KeyType::P384),
            "P-521" => Ok(KeyType::P521),
            "secp256k1" => Ok(KeyType::Secp256k1),
            "Bls12381G2" => Ok(KeyType::Bls12381G2),
            #[cfg(feature = "ml-dsa")]
            "ML-DSA-44" => Ok(KeyType::MlDsa44),
            #[cfg(feature = "ml-dsa")]
            "ML-DSA-65" => Ok(KeyType::MlDsa65),
            #[cfg(feature = "ml-dsa")]
            "ML-DSA-87" => Ok(KeyType::MlDsa87),
            #[cfg(feature = "slh-dsa")]
            "SLH-DSA-SHA2-128s" => Ok(KeyType::SlhDsaSha2_128s),
            _ => Err(CryptoError::UnsupportedKeyType(value.to_string())),
        }
    }
}

impl fmt::Display for KeyType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            KeyType::Ed25519 => write!(f, "Ed25519"),
            KeyType::X25519 => write!(f, "X25519"),
            KeyType::P256 => write!(f, "P-256"),
            KeyType::P384 => write!(f, "P-384"),
            KeyType::P521 => write!(f, "P-521"),
            KeyType::Secp256k1 => write!(f, "secp256k1"),
            KeyType::Bls12381G2 => write!(f, "Bls12381G2"),
            #[cfg(feature = "ml-dsa")]
            KeyType::MlDsa44 => write!(f, "ML-DSA-44"),
            #[cfg(feature = "ml-dsa")]
            KeyType::MlDsa65 => write!(f, "ML-DSA-65"),
            #[cfg(feature = "ml-dsa")]
            KeyType::MlDsa87 => write!(f, "ML-DSA-87"),
            #[cfg(feature = "slh-dsa")]
            KeyType::SlhDsaSha2_128s => write!(f, "SLH-DSA-SHA2-128s"),
            KeyType::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Key-agreement (ECDH) curve mapping.
///
/// Gated on the `jose` feature because [`Curve`](crate::jose::key_agreement::Curve)
/// — the JOSE key-agreement curve set — only exists when the JOSE primitives
/// are compiled in.
#[cfg(feature = "jose")]
impl KeyType {
    /// The elliptic curve this key type uses for ECDH key agreement, or
    /// `None` when the key type cannot perform key agreement.
    ///
    /// This is the **single source of truth** for the `KeyType` →
    /// [`Curve`](crate::jose::key_agreement::Curve) mapping. Every DIDComm
    /// pack/unpack path — authcrypt/anoncrypt sender-key selection and JWE
    /// recipient decryption — routes through here instead of re-implementing
    /// the match, so the paths can never disagree on which curve a key uses.
    /// Signature-only or non-key-agreement suites (Ed25519, BLS12-381 G2,
    /// ML-DSA, SLH-DSA) and [`KeyType::Unknown`] return `None`; callers
    /// translate that into their own contextual error.
    ///
    /// The match is deliberately **exhaustive with no wildcard arm**: adding a
    /// new [`KeyType`] variant is a compile error here until it is explicitly
    /// classified, so a future key-agreement curve can never be silently
    /// dropped from negotiation.
    pub fn key_agreement_curve(&self) -> Option<crate::jose::key_agreement::Curve> {
        use crate::jose::key_agreement::Curve;
        match self {
            KeyType::X25519 => Some(Curve::X25519),
            KeyType::P256 => Some(Curve::P256),
            KeyType::Secp256k1 => Some(Curve::K256),
            KeyType::P384 => Some(Curve::P384),
            KeyType::P521 => Some(Curve::P521),
            KeyType::Ed25519 | KeyType::Bls12381G2 | KeyType::Unknown => None,
            #[cfg(feature = "ml-dsa")]
            KeyType::MlDsa44 | KeyType::MlDsa65 | KeyType::MlDsa87 => None,
            #[cfg(feature = "slh-dsa")]
            KeyType::SlhDsaSha2_128s => None,
        }
    }
}

#[cfg(all(test, feature = "jose"))]
mod key_agreement_curve_tests {
    use super::KeyType;
    use crate::jose::key_agreement::Curve;

    #[test]
    fn maps_every_key_agreement_curve() {
        assert_eq!(KeyType::X25519.key_agreement_curve(), Some(Curve::X25519));
        assert_eq!(KeyType::P256.key_agreement_curve(), Some(Curve::P256));
        assert_eq!(KeyType::Secp256k1.key_agreement_curve(), Some(Curve::K256));
        assert_eq!(KeyType::P384.key_agreement_curve(), Some(Curve::P384));
        assert_eq!(KeyType::P521.key_agreement_curve(), Some(Curve::P521));
    }

    #[test]
    fn signature_and_unknown_types_have_no_curve() {
        assert_eq!(KeyType::Ed25519.key_agreement_curve(), None);
        assert_eq!(KeyType::Bls12381G2.key_agreement_curve(), None);
        assert_eq!(KeyType::Unknown.key_agreement_curve(), None);
    }

    #[cfg(feature = "ml-dsa")]
    #[test]
    fn ml_dsa_types_have_no_curve() {
        assert_eq!(KeyType::MlDsa44.key_agreement_curve(), None);
        assert_eq!(KeyType::MlDsa65.key_agreement_curve(), None);
        assert_eq!(KeyType::MlDsa87.key_agreement_curve(), None);
    }

    #[cfg(feature = "slh-dsa")]
    #[test]
    fn slh_dsa_type_has_no_curve() {
        assert_eq!(KeyType::SlhDsaSha2_128s.key_agreement_curve(), None);
    }
}
