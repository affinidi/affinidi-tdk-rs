//! Cryptographic primitives and JWK types for Affinidi TDK
//!
//! This crate provides:
//! - JWK (JSON Web Key) types per RFC 7517
//! - Key generation for various curves (Ed25519, X25519, P-256, P-384, secp256k1)
//! - Key conversion utilities (e.g., Ed25519 → X25519)

mod error;
mod jwk;
mod key_type;

#[cfg(feature = "ed25519")]
pub mod ed25519;

#[cfg(feature = "p256")]
pub mod p256;

#[cfg(feature = "k256")]
pub mod secp256k1;

#[cfg(feature = "p384")]
pub mod p384;

pub use error::CryptoError;
pub use jwk::{ECParams, JWK, OctectParams, Params};
pub use key_type::KeyType;
