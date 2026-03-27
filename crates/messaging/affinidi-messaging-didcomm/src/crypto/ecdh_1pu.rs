//! ECDH-1PU key derivation (RFC 9481).
//!
//! Used for authenticated encryption (authcrypt) in DIDComm v2.1.
//! Combines ephemeral-to-recipient and sender-to-recipient DH shared secrets.

use crate::crypto::ecdh_es::concat_kdf;
use crate::crypto::key_agreement::{EphemeralKeyPair, PrivateKeyAgreement, PublicKeyAgreement};
use crate::error::DIDCommError;

/// Derive a key wrapping key using ECDH-1PU + Concat KDF.
///
/// ECDH-1PU concatenates two shared secrets:
/// - Ze = ECDH(ephemeral, recipient)   — ephemeral-static
/// - Zs = ECDH(sender, recipient)      — static-static
/// - Z = Ze || Zs
///
/// For A256CBC-HS512, the authentication tag from content encryption is
/// included as SuppPrivInfo in the KDF (cc_tag parameter).
///
/// # Arguments
/// * `ephemeral` - Ephemeral key pair (generated per-message)
/// * `sender_private` - Sender's static private key
/// * `recipient_public` - Recipient's public key
/// * `alg` - Algorithm identifier (e.g., "ECDH-1PU+A256KW")
/// * `apu` - PartyUInfo (raw bytes of sender kid)
/// * `apv` - PartyVInfo (raw bytes, SHA-256 of sorted recipient kids)
/// * `cc_tag` - Content encryption authentication tag (for tag-in-KDF)
/// * `key_len` - Output key length in bits (256 for A256KW)
pub fn derive_key_1pu(
    ephemeral: &PrivateKeyAgreement,
    sender_private: &PrivateKeyAgreement,
    recipient_public: &PublicKeyAgreement,
    alg: &[u8],
    apu: &[u8],
    apv: &[u8],
    cc_tag: &[u8],
    key_len: u32,
) -> Result<Vec<u8>, DIDCommError> {
    // Ze = ECDH(ephemeral, recipient)
    let ze = ephemeral.diffie_hellman(recipient_public)?;

    // Zs = ECDH(sender, recipient)
    let zs = sender_private.diffie_hellman(recipient_public)?;

    // Z = Ze || Zs
    let mut z = Vec::with_capacity(ze.len() + zs.len());
    z.extend_from_slice(&ze);
    z.extend_from_slice(&zs);

    // Use Concat KDF with SuppPrivInfo = cc_tag
    concat_kdf_1pu(&z, alg, apu, apv, key_len, cc_tag)
}

/// Derive key wrapping key on the recipient side.
pub fn derive_key_1pu_recipient(
    recipient_private: &PrivateKeyAgreement,
    sender_public: &PublicKeyAgreement,
    ephemeral_public: &PublicKeyAgreement,
    alg: &[u8],
    apu: &[u8],
    apv: &[u8],
    cc_tag: &[u8],
    key_len: u32,
) -> Result<Vec<u8>, DIDCommError> {
    // Ze = ECDH(recipient, ephemeral)
    let ze = recipient_private.diffie_hellman(ephemeral_public)?;

    // Zs = ECDH(recipient, sender)
    let zs = recipient_private.diffie_hellman(sender_public)?;

    // Z = Ze || Zs
    let mut z = Vec::with_capacity(ze.len() + zs.len());
    z.extend_from_slice(&ze);
    z.extend_from_slice(&zs);

    concat_kdf_1pu(&z, alg, apu, apv, key_len, cc_tag)
}

/// Concat KDF with SuppPrivInfo for ECDH-1PU (includes cc_tag).
fn concat_kdf_1pu(
    z: &[u8],
    alg: &[u8],
    apu: &[u8],
    apv: &[u8],
    key_len_bits: u32,
    cc_tag: &[u8],
) -> Result<Vec<u8>, DIDCommError> {
    if cc_tag.is_empty() {
        // No tag — same as standard Concat KDF
        return concat_kdf(z, alg, apu, apv, key_len_bits);
    }

    use sha2::{Digest, Sha256};
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

    // SuppPrivInfo: cc_tag (the auth tag from content encryption)
    hasher.update(cc_tag);

    let hash = hasher.finalize();
    Ok(hash[..key_len_bytes].to_vec())
}

/// Derive sender-side wrapping key for one recipient using ECDH-1PU.
pub fn derive_sender_key_1pu(
    ephemeral: &EphemeralKeyPair,
    sender_private: &PrivateKeyAgreement,
    recipient_public: &PublicKeyAgreement,
    apu: &[u8],
    apv: &[u8],
    cc_tag: &[u8],
) -> Result<[u8; 32], DIDCommError> {
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
    fn ecdh_1pu_x25519_roundtrip() {
        let sender = PrivateKeyAgreement::generate(Curve::X25519);
        let recipient = PrivateKeyAgreement::generate(Curve::X25519);
        let ephemeral = PrivateKeyAgreement::generate(Curve::X25519);

        let cc_tag = [0xAA; 32]; // simulated auth tag

        let sender_kek = derive_key_1pu(
            &ephemeral,
            &sender,
            &recipient.public_key(),
            b"ECDH-1PU+A256KW",
            b"sender-kid",
            b"apv",
            &cc_tag,
            256,
        )
        .unwrap();

        let recipient_kek = derive_key_1pu_recipient(
            &recipient,
            &sender.public_key(),
            &ephemeral.public_key(),
            b"ECDH-1PU+A256KW",
            b"sender-kid",
            b"apv",
            &cc_tag,
            256,
        )
        .unwrap();

        assert_eq!(sender_kek, recipient_kek);
        assert_eq!(sender_kek.len(), 32);
    }

    #[test]
    fn ecdh_1pu_p256_roundtrip() {
        let sender = PrivateKeyAgreement::generate(Curve::P256);
        let recipient = PrivateKeyAgreement::generate(Curve::P256);
        let ephemeral = PrivateKeyAgreement::generate(Curve::P256);

        let sender_kek = derive_key_1pu(
            &ephemeral,
            &sender,
            &recipient.public_key(),
            b"ECDH-1PU+A256KW",
            b"",
            b"apv",
            b"", // no tag
            256,
        )
        .unwrap();

        let recipient_kek = derive_key_1pu_recipient(
            &recipient,
            &sender.public_key(),
            &ephemeral.public_key(),
            b"ECDH-1PU+A256KW",
            b"",
            b"apv",
            b"",
            256,
        )
        .unwrap();

        assert_eq!(sender_kek, recipient_kek);
    }

    #[test]
    fn ecdh_1pu_k256_roundtrip() {
        let sender = PrivateKeyAgreement::generate(Curve::K256);
        let recipient = PrivateKeyAgreement::generate(Curve::K256);
        let ephemeral = PrivateKeyAgreement::generate(Curve::K256);

        let cc_tag = [0xBB; 32];

        let sender_kek = derive_key_1pu(
            &ephemeral,
            &sender,
            &recipient.public_key(),
            b"ECDH-1PU+A256KW",
            b"sender-kid",
            b"apv",
            &cc_tag,
            256,
        )
        .unwrap();

        let recipient_kek = derive_key_1pu_recipient(
            &recipient,
            &sender.public_key(),
            &ephemeral.public_key(),
            b"ECDH-1PU+A256KW",
            b"sender-kid",
            b"apv",
            &cc_tag,
            256,
        )
        .unwrap();

        assert_eq!(sender_kek, recipient_kek);
        assert_eq!(sender_kek.len(), 32);
    }

    #[test]
    fn different_tag_produces_different_key() {
        let sender = PrivateKeyAgreement::generate(Curve::X25519);
        let recipient = PrivateKeyAgreement::generate(Curve::X25519);
        let ephemeral = PrivateKeyAgreement::generate(Curve::X25519);

        let kek1 = derive_key_1pu(
            &ephemeral,
            &sender,
            &recipient.public_key(),
            b"ECDH-1PU+A256KW",
            b"",
            b"apv",
            &[0x01; 32],
            256,
        )
        .unwrap();

        let kek2 = derive_key_1pu(
            &ephemeral,
            &sender,
            &recipient.public_key(),
            b"ECDH-1PU+A256KW",
            b"",
            b"apv",
            &[0x02; 32],
            256,
        )
        .unwrap();

        assert_ne!(kek1, kek2);
    }
}
