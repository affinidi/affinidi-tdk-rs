//! JOSE cryptographic primitives (`jose` feature).
//!
//! Centralizes the JOSE crypto previously hand-rolled in
//! `affinidi-messaging-didcomm` (#327): the Concat KDF, AES-256 Key Wrap,
//! A256CBC-HS512 content encryption, EdDSA, ECDH key agreement (X25519 /
//! P-256 / K-256), and the ECDH-ES / ECDH-1PU derivations that combine
//! them — plus the algorithm traits that make them extensible.
//!
//! Two ways to call:
//!
//! - **Free functions** ([`aes_kw`], [`content_encryption`],
//!   [`concat_kdf`], [`signing`], [`key_agreement`], [`ecdh`]) — the
//!   workhorses, ported verbatim from didcomm. Their byte-level output is
//!   pinned by [`kat`].
//! - **Traits** ([`traits`]) — `KeyWrap`, `ContentEncryption`,
//!   `KeyDerivation`, `JwsSigner`/`JwsVerifier` with concrete impls
//!   (`A256Kw`, `A256CbcHs512`, `ConcatKdf`, `Ed25519`). The
//!   open-for-extension seam for adding new algorithms. Curves are
//!   runtime-dispatched via [`key_agreement::Curve`]; adding one is a
//!   localized change (see that module).

pub mod aes_kw;
pub mod concat_kdf;
pub mod content_encryption;
pub mod ecdh;
pub mod key_agreement;
pub mod signing;
pub mod traits;

pub use key_agreement::{Curve, EphemeralKeyPair, PrivateKeyAgreement, PublicKeyAgreement};
pub use traits::{
    A256CbcHs512, A256Kw, ConcatKdf, ContentEncryption, Ed25519, JwsSigner, JwsVerifier,
    KeyDerivation, KeyWrap,
};

/// Known-answer / golden-master tests. These assert the **same** expected
/// bytes as the harness in `affinidi-messaging-didcomm` (PR #336): because
/// the implementations here are a verbatim port, matching those vectors
/// proves the move is byte-identical. PR 5d removes the didcomm copies and
/// rewires it onto this module; these vectors are the contract.
#[cfg(test)]
mod kat;
