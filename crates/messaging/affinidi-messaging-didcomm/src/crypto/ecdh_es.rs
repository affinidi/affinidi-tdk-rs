//! ECDH-ES key derivation using JOSE Concat KDF (RFC 7518 Section 4.6).
//!
//! Used for anonymous encryption (anoncrypt) in DIDComm v2.1.

use sha2::{Digest, Sha256};

use crate::crypto::key_agreement::{EphemeralKeyPair, PrivateKeyAgreement, PublicKeyAgreement};
use crate::error::DIDCommError;

/// Derive a key wrapping key using ECDH-ES + Concat KDF.
///
/// # Arguments
/// * `ephemeral` - Ephemeral private key (generated per-message)
/// * `recipient_public` - Recipient's public key
/// * `alg` - Algorithm identifier (e.g., "ECDH-ES+A256KW")
/// * `apu` - PartyUInfo (raw bytes, typically empty for anoncrypt)
/// * `apv` - PartyVInfo (raw bytes, SHA-256 of sorted recipient kids)
/// * `key_len` - Output key length in bits (256 for A256KW)
pub fn derive_key_es(
    ephemeral: &PrivateKeyAgreement,
    recipient_public: &PublicKeyAgreement,
    alg: &[u8],
    apu: &[u8],
    apv: &[u8],
    key_len: u32,
) -> Result<Vec<u8>, DIDCommError> {
    // Z = ECDH(ephemeral, recipient)
    let z = ephemeral.diffie_hellman(recipient_public)?;

    // Concat KDF (single pass SHA-256)
    concat_kdf(&z, alg, apu, apv, key_len)
}

/// Derive a key wrapping key for the recipient side (decryption).
pub fn derive_key_es_recipient(
    recipient_private: &PrivateKeyAgreement,
    ephemeral_public: &PublicKeyAgreement,
    alg: &[u8],
    apu: &[u8],
    apv: &[u8],
    key_len: u32,
) -> Result<Vec<u8>, DIDCommError> {
    let z = recipient_private.diffie_hellman(ephemeral_public)?;
    concat_kdf(&z, alg, apu, apv, key_len)
}

/// JOSE Concat KDF (NIST SP 800-56A, single-pass SHA-256).
///
/// otherinfo = AlgorithmID || PartyUInfo || PartyVInfo || SuppPubInfo
/// where each field is length-prefixed with a 4-byte big-endian length.
pub(crate) fn concat_kdf(
    z: &[u8],
    alg: &[u8],
    apu: &[u8],
    apv: &[u8],
    key_len_bits: u32,
) -> Result<Vec<u8>, DIDCommError> {
    let key_len_bytes = (key_len_bits / 8) as usize;

    // For 256-bit keys, one round of SHA-256 is sufficient
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

/// Generate an ephemeral key pair and derive a wrapping key for one recipient.
pub fn derive_sender_key(
    ephemeral: &EphemeralKeyPair,
    recipient_public: &PublicKeyAgreement,
    apu: &[u8],
    apv: &[u8],
) -> Result<[u8; 32], DIDCommError> {
    let kek = derive_key_es(
        &ephemeral.private,
        recipient_public,
        b"ECDH-ES+A256KW",
        apu,
        apv,
        256,
    )?;
    let arr: [u8; 32] = kek
        .try_into()
        .map_err(|_| DIDCommError::KeyAgreement("derived key wrong size".into()))?;
    Ok(arr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::key_agreement::{Curve, PrivateKeyAgreement};

    #[test]
    fn ecdh_es_x25519_roundtrip() {
        let ephemeral = PrivateKeyAgreement::generate(Curve::X25519);
        let recipient = PrivateKeyAgreement::generate(Curve::X25519);

        let sender_kek = derive_key_es(
            &ephemeral,
            &recipient.public_key(),
            b"ECDH-ES+A256KW",
            b"",
            b"apv",
            256,
        )
        .unwrap();

        let recipient_kek = derive_key_es_recipient(
            &recipient,
            &ephemeral.public_key(),
            b"ECDH-ES+A256KW",
            b"",
            b"apv",
            256,
        )
        .unwrap();

        assert_eq!(sender_kek, recipient_kek);
        assert_eq!(sender_kek.len(), 32);
    }

    #[test]
    fn ecdh_es_k256_roundtrip() {
        let ephemeral = PrivateKeyAgreement::generate(Curve::K256);
        let recipient = PrivateKeyAgreement::generate(Curve::K256);

        let sender_kek = derive_key_es(
            &ephemeral,
            &recipient.public_key(),
            b"ECDH-ES+A256KW",
            b"",
            b"apv",
            256,
        )
        .unwrap();

        let recipient_kek = derive_key_es_recipient(
            &recipient,
            &ephemeral.public_key(),
            b"ECDH-ES+A256KW",
            b"",
            b"apv",
            256,
        )
        .unwrap();

        assert_eq!(sender_kek, recipient_kek);
        assert_eq!(sender_kek.len(), 32);
    }

    #[test]
    fn ecdh_es_p256_roundtrip() {
        let ephemeral = PrivateKeyAgreement::generate(Curve::P256);
        let recipient = PrivateKeyAgreement::generate(Curve::P256);

        let sender_kek = derive_key_es(
            &ephemeral,
            &recipient.public_key(),
            b"ECDH-ES+A256KW",
            b"",
            b"apv",
            256,
        )
        .unwrap();

        let recipient_kek = derive_key_es_recipient(
            &recipient,
            &ephemeral.public_key(),
            b"ECDH-ES+A256KW",
            b"",
            b"apv",
            256,
        )
        .unwrap();

        assert_eq!(sender_kek, recipient_kek);
    }
}
