//! `did:key` helpers for Ed25519 / X25519 with raw-bytes ergonomics.
//!
//! This module sits on top of [`crate::ed25519`] and gives callers doing
//! HPKE, sealed transfer, or other non-DIDComm key agreement a clean
//! `&[u8; 32]` API for going between a `did:key:z6Mk…` identifier and
//! the Ed25519 / X25519 keys they need for ECDH.
//!
//! The existing multikey-string helpers in [`crate::ed25519`] stay for
//! multikey-native callers (e.g. `affinidi-secrets-resolver`); these
//! helpers are purely additive for crypto-native callers that already
//! have raw bytes.
//!
//! Only `did:key` encodings for Ed25519 public keys (multicodec `0xed`)
//! are handled here. Other key types (P-256, secp256k1, X25519, ML-DSA)
//! can be added when needed — their multicodec values already live in
//! [`crate::KeyType`] / `affinidi_encoding`.

use affinidi_encoding::{ED25519_PUB, MultiEncoded, MultiEncodedBuf};
use base58::{FromBase58, ToBase58};
use ed25519_dalek::VerifyingKey;

use crate::{CryptoError, error::Result};

const DID_KEY_PREFIX: &str = "did:key:";

/// Encode a 32-byte Ed25519 public key as a `did:key:z6Mk…` identifier.
pub fn ed25519_pub_to_did_key(pubkey: &[u8; 32]) -> String {
    let multikey = MultiEncodedBuf::encode_bytes(ED25519_PUB, pubkey)
        .into_bytes()
        .to_base58();
    format!("{DID_KEY_PREFIX}z{multikey}")
}

/// Decode a `did:key:z6Mk…` string to its raw 32-byte Ed25519 public key.
///
/// Errors on a missing `did:key:` prefix, missing multibase `z` prefix,
/// a multicodec other than Ed25519-pub (`0xed`), or payload bytes not 32
/// long. The returned bytes are not validated as a well-formed Ed25519
/// point; use [`ed25519_pub_to_x25519_bytes`] or `VerifyingKey::from_bytes`
/// to perform that check when it matters.
pub fn did_key_to_ed25519_pub(did: &str) -> Result<[u8; 32]> {
    let multibase = did
        .strip_prefix(DID_KEY_PREFIX)
        .ok_or_else(|| CryptoError::Decoding(format!("Expected '{DID_KEY_PREFIX}' prefix")))?;
    let base58 = multibase.strip_prefix('z').ok_or_else(|| {
        CryptoError::Decoding("Expected multibase 'z' prefix after 'did:key:'".into())
    })?;
    let decoded = base58
        .from_base58()
        .map_err(|_| CryptoError::Decoding("Couldn't decode base58".into()))?;

    let multicodec = MultiEncoded::new(decoded.as_slice())?;
    if multicodec.codec() != ED25519_PUB {
        return Err(CryptoError::KeyError(format!(
            "Expected Ed25519 public key, instead received codec 0x{:x}",
            multicodec.codec()
        )));
    }
    let data = multicodec.data();
    if data.len() != 32 {
        return Err(CryptoError::KeyError(format!(
            "Invalid public key byte length: expected 32, got {}",
            data.len()
        )));
    }

    let mut out = [0u8; 32];
    out.copy_from_slice(data);
    Ok(out)
}

/// Derive the X25519 public key for an Ed25519 public key, returning raw
/// bytes. Convenience wrapper around
/// [`crate::ed25519::ed25519_public_to_x25519`] for callers that have
/// raw bytes (HPKE, ECDH) rather than a multikey string.
pub fn ed25519_pub_to_x25519_bytes(pubkey: &[u8; 32]) -> Result<[u8; 32]> {
    let vk = VerifyingKey::from_bytes(pubkey)
        .map_err(|e| CryptoError::KeyError(format!("Couldn't create Ed25519 VerifyingKey: {e}")))?;
    Ok(vk.to_montgomery().to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ed25519::{ed25519_private_to_x25519, generate};
    use affinidi_encoding::X25519_PUB;
    use ed25519_dalek::SigningKey;
    use x25519_dalek::{PublicKey, StaticSecret};

    // Ed25519 secret key from the lifted `check_x25519` vector
    // (affinidi-secrets-resolver/src/secrets.rs).
    const ED25519_SK: [u8; 32] = [
        202, 104, 239, 81, 53, 110, 80, 252, 198, 23, 155, 162, 215, 98, 223, 173, 227, 188, 110,
        54, 127, 45, 185, 206, 174, 29, 44, 147, 76, 66, 196, 195,
    ];
    const CURVE25519_SK: [u8; 32] = [
        200, 255, 64, 61, 17, 52, 112, 33, 205, 71, 186, 13, 131, 12, 241, 136, 223, 5, 152, 40,
        95, 187, 83, 168, 142, 10, 234, 215, 70, 210, 148, 104,
    ];

    #[test]
    fn ed25519_pub_to_did_key_roundtrip() {
        let kp = generate(None);
        let pubkey: [u8; 32] = kp.public_bytes.as_slice().try_into().unwrap();

        let did = ed25519_pub_to_did_key(&pubkey);
        // Ed25519 multicodec 0xed01 always renders with the `z6Mk` prefix
        // under base58btc.
        assert!(
            did.starts_with("did:key:z6Mk"),
            "expected did:key:z6Mk prefix, got {did}"
        );

        let back = did_key_to_ed25519_pub(&did).unwrap();
        assert_eq!(back, pubkey);
    }

    #[test]
    fn ed25519_pub_to_did_key_deterministic_for_seed() {
        // Two encodings of the same pubkey must match exactly.
        let signing = SigningKey::from_bytes(&ED25519_SK);
        let pub_bytes: [u8; 32] = signing.verifying_key().to_bytes();

        let a = ed25519_pub_to_did_key(&pub_bytes);
        let b = ed25519_pub_to_did_key(&pub_bytes);
        assert_eq!(a, b);
        assert!(a.starts_with("did:key:z6Mk"));
    }

    #[test]
    fn did_key_to_ed25519_pub_missing_did_key_prefix() {
        let no_prefix = "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
        let err = did_key_to_ed25519_pub(no_prefix).unwrap_err();
        assert!(
            matches!(err, CryptoError::Decoding(ref m) if m.contains("did:key:")),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn did_key_to_ed25519_pub_missing_multibase_prefix() {
        let bad = "did:key:6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
        let err = did_key_to_ed25519_pub(bad).unwrap_err();
        assert!(
            matches!(err, CryptoError::Decoding(ref m) if m.contains('z')),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn did_key_to_ed25519_pub_wrong_multicodec() {
        // Build a did:key-shaped string carrying an X25519 public key
        // multicodec (0xec) — valid multibase, wrong algorithm.
        let payload = MultiEncodedBuf::encode_bytes(X25519_PUB, &[0u8; 32])
            .into_bytes()
            .to_base58();
        let did = format!("did:key:z{payload}");

        let err = did_key_to_ed25519_pub(&did).unwrap_err();
        assert!(
            matches!(err, CryptoError::KeyError(ref m) if m.contains("codec")),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn did_key_to_ed25519_pub_wrong_length() {
        // Ed25519 multicodec but a 16-byte payload instead of 32.
        let payload = MultiEncodedBuf::encode_bytes(ED25519_PUB, &[0u8; 16])
            .into_bytes()
            .to_base58();
        let did = format!("did:key:z{payload}");

        let err = did_key_to_ed25519_pub(&did).unwrap_err();
        assert!(
            matches!(err, CryptoError::KeyError(ref m) if m.contains("length") || m.contains("32")),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn ed25519_pub_to_x25519_bytes_matches_private_derivation() {
        // Lifted from affinidi-secrets-resolver check_x25519: the Ed25519
        // secret maps to CURVE25519_SK. Deriving the X25519 public key two
        // ways (from the converted secret, and directly from the Ed25519
        // public via Montgomery) must agree.
        let signing = SigningKey::from_bytes(&ED25519_SK);
        let ed_pub: [u8; 32] = signing.verifying_key().to_bytes();

        let x_sk = ed25519_private_to_x25519(&ED25519_SK);
        assert_eq!(x_sk, CURVE25519_SK);

        let expected = PublicKey::from(&StaticSecret::from(x_sk)).to_bytes();
        let actual = ed25519_pub_to_x25519_bytes(&ed_pub).unwrap();
        assert_eq!(actual, expected);
    }
}
