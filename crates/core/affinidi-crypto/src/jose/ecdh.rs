//! ECDH key derivation: ECDH-ES (anoncrypt) and ECDH-1PU (authcrypt).
//!
//! Combines the [key agreement](super::key_agreement) step with the
//! [Concat KDF](super::concat_kdf) to produce a key-wrapping key (KEK).
//! Ported from `affinidi-messaging-didcomm` for #327; byte-level output is
//! locked by [`super::kat`] (the ECDH-1PU KEK golden matches PR #336).

use crate::error::CryptoError;

use super::concat_kdf::{concat_kdf, concat_kdf_1pu, concat_kdf_1pu_legacy};
use super::key_agreement::{EphemeralKeyPair, PrivateKeyAgreement, PublicKeyAgreement};

// ─── ECDH-ES (anonymous encryption) ─────────────────────────────────────────

/// Derive a KEK with ECDH-ES + Concat KDF (sender side).
pub fn derive_key_es(
    ephemeral: &PrivateKeyAgreement,
    recipient_public: &PublicKeyAgreement,
    alg: &[u8],
    apu: &[u8],
    apv: &[u8],
    key_len: u32,
) -> Result<Vec<u8>, CryptoError> {
    let z = ephemeral.diffie_hellman(recipient_public)?;
    concat_kdf(&z, alg, apu, apv, key_len)
}

/// Derive a KEK with ECDH-ES + Concat KDF (recipient side).
pub fn derive_key_es_recipient(
    recipient_private: &PrivateKeyAgreement,
    ephemeral_public: &PublicKeyAgreement,
    alg: &[u8],
    apu: &[u8],
    apv: &[u8],
    key_len: u32,
) -> Result<Vec<u8>, CryptoError> {
    let z = recipient_private.diffie_hellman(ephemeral_public)?;
    concat_kdf(&z, alg, apu, apv, key_len)
}

/// Sender-side `ECDH-ES+A256KW` wrapping key (256-bit) for one recipient.
pub fn derive_sender_key(
    ephemeral: &EphemeralKeyPair,
    recipient_public: &PublicKeyAgreement,
    apu: &[u8],
    apv: &[u8],
) -> Result<[u8; 32], CryptoError> {
    let kek = derive_key_es(
        &ephemeral.private,
        recipient_public,
        b"ECDH-ES+A256KW",
        apu,
        apv,
        256,
    )?;
    kek.try_into()
        .map_err(|_| CryptoError::KeyAgreement("derived key wrong size".into()))
}

// ─── ECDH-1PU (authenticated encryption) ────────────────────────────────────

/// Derive a KEK with ECDH-1PU + Concat KDF (sender side).
///
/// `Z = Ze || Zs` where `Ze = ECDH(ephemeral, recipient)` and
/// `Zs = ECDH(sender, recipient)`. The content-encryption tag `cc_tag` is
/// fed length-prefixed into the KDF (the #322-correct encoding).
#[allow(clippy::too_many_arguments)]
pub fn derive_key_1pu(
    ephemeral: &PrivateKeyAgreement,
    sender_private: &PrivateKeyAgreement,
    recipient_public: &PublicKeyAgreement,
    alg: &[u8],
    apu: &[u8],
    apv: &[u8],
    cc_tag: &[u8],
    key_len: u32,
) -> Result<Vec<u8>, CryptoError> {
    let ze = ephemeral.diffie_hellman(recipient_public)?;
    let zs = sender_private.diffie_hellman(recipient_public)?;
    let mut z = Vec::with_capacity(ze.len() + zs.len());
    z.extend_from_slice(&ze);
    z.extend_from_slice(&zs);
    concat_kdf_1pu(&z, alg, apu, apv, key_len, cc_tag)
}

/// Derive a KEK with ECDH-1PU + Concat KDF (recipient side).
#[allow(clippy::too_many_arguments)]
pub fn derive_key_1pu_recipient(
    recipient_private: &PrivateKeyAgreement,
    sender_public: &PublicKeyAgreement,
    ephemeral_public: &PublicKeyAgreement,
    alg: &[u8],
    apu: &[u8],
    apv: &[u8],
    cc_tag: &[u8],
    key_len: u32,
) -> Result<Vec<u8>, CryptoError> {
    let ze = recipient_private.diffie_hellman(ephemeral_public)?;
    let zs = recipient_private.diffie_hellman(sender_public)?;
    let mut z = Vec::with_capacity(ze.len() + zs.len());
    z.extend_from_slice(&ze);
    z.extend_from_slice(&zs);
    concat_kdf_1pu(&z, alg, apu, apv, key_len, cc_tag)
}

/// Recipient-side ECDH-1PU derivation using the **legacy** (pre-#322)
/// Concat KDF that fed `cc_tag` without a length prefix. Transitional —
/// used only by the decrypt fallback so a fixed node can still receive
/// authcrypt from an unpatched peer during rollout.
#[allow(clippy::too_many_arguments)]
pub fn derive_key_1pu_recipient_legacy(
    recipient_private: &PrivateKeyAgreement,
    sender_public: &PublicKeyAgreement,
    ephemeral_public: &PublicKeyAgreement,
    alg: &[u8],
    apu: &[u8],
    apv: &[u8],
    cc_tag: &[u8],
    key_len: u32,
) -> Result<Vec<u8>, CryptoError> {
    let ze = recipient_private.diffie_hellman(ephemeral_public)?;
    let zs = recipient_private.diffie_hellman(sender_public)?;
    let mut z = Vec::with_capacity(ze.len() + zs.len());
    z.extend_from_slice(&ze);
    z.extend_from_slice(&zs);
    concat_kdf_1pu_legacy(&z, alg, apu, apv, key_len, cc_tag)
}

/// Sender-side `ECDH-1PU+A256KW` wrapping key (256-bit) for one recipient.
pub fn derive_sender_key_1pu(
    ephemeral: &EphemeralKeyPair,
    sender_private: &PrivateKeyAgreement,
    recipient_public: &PublicKeyAgreement,
    apu: &[u8],
    apv: &[u8],
    cc_tag: &[u8],
) -> Result<[u8; 32], CryptoError> {
    let kek = derive_key_1pu(
        &ephemeral.private,
        sender_private,
        recipient_public,
        b"ECDH-1PU+A256KW",
        apu,
        apv,
        cc_tag,
        256,
    )?;
    kek.try_into()
        .map_err(|_| CryptoError::KeyAgreement("derived key wrong size".into()))
}
