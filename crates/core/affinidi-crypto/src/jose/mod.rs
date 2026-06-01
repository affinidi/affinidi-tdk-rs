//! JOSE cryptographic primitives (`jose` feature).
//!
//! Centralizes the JOSE crypto previously hand-rolled in
//! `affinidi-messaging-didcomm` (#327). This PR (5b) lands the **stateless
//! primitives** — the Concat KDF, AES-256 Key Wrap, A256CBC-HS512 content
//! encryption, and EdDSA — plus the algorithm traits that make them
//! extensible (see [`traits`]). ECDH key agreement / curve types land in a
//! later PR; until then `concat_kdf*` take the raw shared secret `z`
//! directly.
//!
//! Two ways to call:
//!
//! - **Free functions** ([`aes_kw`], [`content_encryption`],
//!   [`concat_kdf`], [`signing`]) — the workhorses, ported verbatim from
//!   didcomm. Their byte-level output is pinned by [`kat`].
//! - **Traits** ([`traits`]) — `KeyWrap`, `ContentEncryption`,
//!   `KeyDerivation`, `JwsSigner`/`JwsVerifier` with concrete impls
//!   (`A256Kw`, `A256CbcHs512`, `ConcatKdf`, `Ed25519`). The
//!   open-for-extension seam for adding new algorithms.

pub mod aes_kw;
pub mod concat_kdf;
pub mod content_encryption;
pub mod signing;
pub mod traits;

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
