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

/// Recipient-side ECDH-1PU derivation using the **legacy** (pre-0.14)
/// Concat KDF that fed `cc_tag` without a length prefix.
///
/// Transitional: used only by the decrypt fallback so a fixed node can
/// still receive authcrypt messages packed by an unpatched peer during
/// rollout. Delete once the ecosystem has upgraded. See
/// [`concat_kdf_1pu_legacy`] and issue #322.
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
) -> Result<Vec<u8>, DIDCommError> {
    let ze = recipient_private.diffie_hellman(ephemeral_public)?;
    let zs = recipient_private.diffie_hellman(sender_public)?;
    let mut z = Vec::with_capacity(ze.len() + zs.len());
    z.extend_from_slice(&ze);
    z.extend_from_slice(&zs);

    concat_kdf_1pu_legacy(&z, alg, apu, apv, key_len, cc_tag)
}

/// Concat KDF for ECDH-1PU. The content-encryption authentication tag is
/// fed as the final OtherInfo entry, **length-prefixed** with a 32-bit
/// big-endian length exactly like every other variable-length field.
///
/// This matches the ECDH-1PU draft (draft-madden-jose-ecdh-1pu-04 §2.3 /
/// Appendix B.9 test vector) and the askar / didcomm-python
/// implementations. The draft concatenates the length-prefixed tag onto
/// SuppPubInfo after `keydatalen`; because Concat KDF hashes
/// `… ‖ SuppPubInfo ‖ SuppPrivInfo`, feeding `keydatalen ‖ len ‖ tag`
/// (here) produces an identical byte stream and KEK.
fn concat_kdf_1pu(
    z: &[u8],
    alg: &[u8],
    apu: &[u8],
    apv: &[u8],
    key_len_bits: u32,
    cc_tag: &[u8],
) -> Result<Vec<u8>, DIDCommError> {
    concat_kdf_1pu_inner(z, alg, apu, apv, key_len_bits, cc_tag, false)
}

/// Pre-0.14 ECDH-1PU Concat KDF that fed `cc_tag` **without** a length
/// prefix — non-conformant, see issue #322. Retained only for the
/// decrypt fallback during migration; do not use for packing.
fn concat_kdf_1pu_legacy(
    z: &[u8],
    alg: &[u8],
    apu: &[u8],
    apv: &[u8],
    key_len_bits: u32,
    cc_tag: &[u8],
) -> Result<Vec<u8>, DIDCommError> {
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
) -> Result<Vec<u8>, DIDCommError> {
    if cc_tag.is_empty() {
        // No tag — same as standard Concat KDF (matches ECDH-ES). The
        // legacy/spec distinction only concerns the tag encoding, so an
        // empty tag is identical either way.
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

    // SuppPrivInfo: cc_tag (the auth tag from content encryption),
    // length-prefixed per the ECDH-1PU draft. The legacy path omits the
    // prefix (issue #322) and exists only for the decrypt fallback.
    if !legacy_tag_encoding {
        hasher.update((cc_tag.len() as u32).to_be_bytes());
    }
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

/// Test-only sender-side KEK using the **legacy** (pre-0.14, unprefixed
/// tag) Concat KDF. Lets tests synthesise a JWE exactly as an unpatched
/// peer would, so the recipient-side decrypt fallback can be exercised.
/// Deliberately `cfg(test)` — no legacy *sender* derivation ships in
/// production; only [`derive_key_1pu_recipient_legacy`] does.
#[cfg(test)]
pub(crate) fn derive_sender_key_1pu_legacy(
    ephemeral: &EphemeralKeyPair,
    sender_private: &PrivateKeyAgreement,
    recipient_public: &PublicKeyAgreement,
    apu: &[u8],
    apv: &[u8],
    cc_tag: &[u8],
) -> Result<[u8; 32], DIDCommError> {
    let ze = ephemeral.private.diffie_hellman(recipient_public)?;
    let zs = sender_private.diffie_hellman(recipient_public)?;
    let mut z = Vec::with_capacity(ze.len() + zs.len());
    z.extend_from_slice(&ze);
    z.extend_from_slice(&zs);
    let kek = concat_kdf_1pu_legacy(&z, b"ECDH-1PU+A256KW", apu, apv, 256, cc_tag)?;
    kek.try_into()
        .map_err(|_| DIDCommError::KeyAgreement("derived key wrong size".into()))
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

    /// Regression for #322: the spec-correct Concat KDF must
    /// length-prefix `cc_tag` (32-bit big-endian) exactly like the other
    /// OtherInfo fields, and must differ from the legacy (unprefixed)
    /// derivation. Pins the byte-level encoding against a hand-built
    /// hash so it can't silently regress.
    #[test]
    fn concat_kdf_1pu_length_prefixes_tag() {
        use sha2::{Digest, Sha256};

        let z = b"0123456789abcdef0123456789abcdef"; // 32 bytes
        let alg = b"ECDH-1PU+A256KW".as_slice();
        let apu = b"did:example:alice#key-1".as_slice();
        let apv = b"apv-bytes".as_slice();
        let tag = [0xABu8; 32];
        let key_len_bits = 256u32;

        // Independently build the spec-correct OtherInfo, with the tag
        // length-prefixed (the bytes under test: `00 00 00 20`).
        let mut h = Sha256::new();
        h.update(1u32.to_be_bytes());
        h.update(z);
        h.update((alg.len() as u32).to_be_bytes());
        h.update(alg);
        h.update((apu.len() as u32).to_be_bytes());
        h.update(apu);
        h.update((apv.len() as u32).to_be_bytes());
        h.update(apv);
        h.update(key_len_bits.to_be_bytes());
        h.update((tag.len() as u32).to_be_bytes());
        h.update(tag);
        let expected = h.finalize()[..32].to_vec();

        let got = concat_kdf_1pu(z, alg, apu, apv, key_len_bits, &tag).unwrap();
        assert_eq!(got, expected, "KDF must length-prefix the cc_tag");

        let legacy = concat_kdf_1pu_legacy(z, alg, apu, apv, key_len_bits, &tag).unwrap();
        assert_ne!(
            got, legacy,
            "the 4-byte length prefix must change the derived key"
        );
    }

    /// Models the issue #322 interop break directly: a spec-correct
    /// (length-prefixed) KEK — what credo-ts / didcomm-python and our own
    /// fixed packer produce — must NOT equal the legacy (pre-0.14) KEK an
    /// unpatched recipient would derive. I.e. an unpatched peer cannot
    /// reconstruct the spec-correct KEK, which is exactly why authcrypt
    /// failed bidirectionally before this fix.
    #[test]
    fn spec_correct_kek_differs_from_legacy_for_recipient() {
        let sender = PrivateKeyAgreement::generate(Curve::X25519);
        let recipient = PrivateKeyAgreement::generate(Curve::X25519);
        let ephemeral = EphemeralKeyPair::generate(Curve::X25519);
        let cc_tag = [0x5Au8; 32];

        let correct = derive_key_1pu_recipient(
            &recipient,
            &sender.public_key(),
            &ephemeral.public,
            b"ECDH-1PU+A256KW",
            b"did:example:alice#key-1",
            b"apv",
            &cc_tag,
            256,
        )
        .unwrap();
        let legacy = derive_key_1pu_recipient_legacy(
            &recipient,
            &sender.public_key(),
            &ephemeral.public,
            b"ECDH-1PU+A256KW",
            b"did:example:alice#key-1",
            b"apv",
            &cc_tag,
            256,
        )
        .unwrap();
        assert_ne!(
            correct, legacy,
            "spec-correct and legacy KEKs must differ (the #322 interop break)"
        );
    }
}
