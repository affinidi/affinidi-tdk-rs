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
            KeyType::Unknown => write!(f, "Unknown"),
        }
    }
}
