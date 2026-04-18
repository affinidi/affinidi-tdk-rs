//! Key type enumeration

use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::CryptoError;

/// Known cryptographic key types
#[derive(Debug, Default, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Zeroize)]
pub enum KeyType {
    Ed25519,
    X25519,
    P256,
    P384,
    P521,
    Secp256k1,
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
    #[default]
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
