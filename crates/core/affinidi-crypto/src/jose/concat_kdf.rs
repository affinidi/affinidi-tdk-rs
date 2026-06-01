//! JOSE Concat KDF (NIST SP 800-56A single-pass, SHA-256).
//!
//! Two flavours, both stateless over the raw shared secret `z` (the
//! ECDH key-agreement step that produces `z` lands in a later #327 PR):
//!
//! - [`concat_kdf`] — ECDH-ES (RFC 7518 §4.6).
//! - [`concat_kdf_1pu`] — ECDH-1PU (draft-madden-jose-ecdh-1pu-04 §2.3),
//!   which appends the content-encryption authentication tag (`cc_tag`)
//!   as the final, **length-prefixed** OtherInfo field. The missing
//!   length prefix was bug #322; [`concat_kdf_1pu_legacy`] preserves the
//!   pre-fix behaviour for the decrypt-fallback migration path only.
//!
//! Ported verbatim from `affinidi-messaging-didcomm`; byte-level output is
//! locked by [`super::kat`].

use sha2::{Digest, Sha256};

use crate::error::CryptoError;

/// JOSE Concat KDF for ECDH-ES (RFC 7518 §4.6).
///
/// `otherinfo = round(1) || Z || len‖AlgorithmID || len‖PartyUInfo ||
/// len‖PartyVInfo || keydatalen`, hashed once with SHA-256 and truncated
/// to `key_len_bits`.
pub fn concat_kdf(
    z: &[u8],
    alg: &[u8],
    apu: &[u8],
    apv: &[u8],
    key_len_bits: u32,
) -> Result<Vec<u8>, CryptoError> {
    let key_len_bytes = (key_len_bits / 8) as usize;

    // For 256-bit keys, one round of SHA-256 is sufficient.
    let mut hasher = Sha256::new();

    // round = 1 (big-endian u32)
    hasher.update(1u32.to_be_bytes());

    // Z (shared secret)
    hasher.update(z);

    // AlgorithmID: len(4) || value
    hasher.update((alg.len() as u32).to_be_bytes());
    hasher.update(alg);

    // PartyUInfo: len(4) || value
    hasher.update((apu.len() as u32).to_be_bytes());
    hasher.update(apu);

    // PartyVInfo: len(4) || value
    hasher.update((apv.len() as u32).to_be_bytes());
    hasher.update(apv);

    // SuppPubInfo: key length in bits (big-endian u32)
    hasher.update(key_len_bits.to_be_bytes());

    let hash = hasher.finalize();
    Ok(hash[..key_len_bytes].to_vec())
}

/// JOSE Concat KDF for ECDH-1PU. The content-encryption authentication
/// tag is fed as the final OtherInfo entry, **length-prefixed** with a
/// 32-bit big-endian length exactly like every other variable-length
/// field (draft-madden-jose-ecdh-1pu-04 §2.3 / Appendix B.9; matches
/// askar / didcomm-python). An empty `cc_tag` is identical to
/// [`concat_kdf`].
pub fn concat_kdf_1pu(
    z: &[u8],
    alg: &[u8],
    apu: &[u8],
    apv: &[u8],
    key_len_bits: u32,
    cc_tag: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    concat_kdf_1pu_inner(z, alg, apu, apv, key_len_bits, cc_tag, false)
}

/// Pre-fix ECDH-1PU Concat KDF that fed `cc_tag` **without** a length
/// prefix — non-conformant, see #322. Retained only for the decrypt
/// fallback during migration; never use it for packing.
pub fn concat_kdf_1pu_legacy(
    z: &[u8],
    alg: &[u8],
    apu: &[u8],
    apv: &[u8],
    key_len_bits: u32,
    cc_tag: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    concat_kdf_1pu_inner(z, alg, apu, apv, key_len_bits, cc_tag, true)
}

fn concat_kdf_1pu_inner(
    z: &[u8],
    alg: &[u8],
    apu: &[u8],
    apv: &[u8],
    key_len_bits: u32,
    cc_tag: &[u8],
    legacy_tag_encoding: bool,
) -> Result<Vec<u8>, CryptoError> {
    if cc_tag.is_empty() {
        // No tag — identical to standard Concat KDF (matches ECDH-ES). The
        // legacy/spec distinction only concerns the tag encoding, so an
        // empty tag is identical either way.
        return concat_kdf(z, alg, apu, apv, key_len_bits);
    }

    let key_len_bytes = (key_len_bits / 8) as usize;

    let mut hasher = Sha256::new();

    // round = 1
    hasher.update(1u32.to_be_bytes());

    // Z
    hasher.update(z);

    // AlgorithmID
    hasher.update((alg.len() as u32).to_be_bytes());
    hasher.update(alg);

    // PartyUInfo
    hasher.update((apu.len() as u32).to_be_bytes());
    hasher.update(apu);

    // PartyVInfo
    hasher.update((apv.len() as u32).to_be_bytes());
    hasher.update(apv);

    // SuppPubInfo: key length in bits
    hasher.update(key_len_bits.to_be_bytes());

    // SuppPrivInfo: cc_tag, length-prefixed per the ECDH-1PU draft. The
    // legacy path omits the prefix (#322) and exists only for the decrypt
    // fallback.
    if !legacy_tag_encoding {
        hasher.update((cc_tag.len() as u32).to_be_bytes());
    }
    hasher.update(cc_tag);

    let hash = hasher.finalize();
    Ok(hash[..key_len_bytes].to_vec())
}
