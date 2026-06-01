//! Cryptographic primitives for DIDComm v2.1.
//!
//! - Key agreement: X25519, P-256, K-256 via trait dispatch
//! - Content encryption: A256CBC-HS512
//! - Key wrapping: AES-256 Key Wrap (RFC 3394)
//! - Key derivation: JOSE Concat KDF for ECDH-ES and ECDH-1PU
//! - Signing: Ed25519 (EdDSA)

pub mod aes_kw;
pub mod content_encryption;
pub mod ecdh_1pu;
pub mod ecdh_es;
pub mod key_agreement;
pub mod signing;

/// Known-answer / golden-master tests that pin the byte-level output of
/// every JOSE primitive. The #327 migration to `affinidi-crypto` must
/// keep these passing unchanged.
#[cfg(test)]
mod kat;
