//! Crypto-related Secret generation methods
//!
//! These modules implement `Secret::generate_*` methods that use
//! `affinidi-crypto` for the underlying key operations.

#[cfg(feature = "ed25519")]
pub mod ed25519;

#[cfg(feature = "p256")]
pub mod p256;

#[cfg(feature = "k256")]
pub mod secp256k1;

#[cfg(feature = "p384")]
pub mod p384;
