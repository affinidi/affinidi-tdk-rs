//! `did:key` framing for BLS12-381 G2 public keys (BBS+ issuer verification
//! keys).
//!
//! A BBS+ issuer (`bbs-2023` Data-Integrity cryptosuite) signs with a
//! BLS12-381 key pair whose **public** key is a point in G2 — 96 bytes
//! compressed, multicodec `0xeb`. These helpers go between that raw 96-byte key
//! and a `did:key:zUC7…` identifier so a BBS issuer DID (or a `#bbs-key-0`
//! verification method) can be expressed with the same `did:key` machinery the
//! rest of the workspace uses for Ed25519.
//!
//! ## Framing only — no curve arithmetic
//!
//! Like [`crate::did_key`] for Ed25519, these helpers are **byte framing**: they
//! validate the multicodec and length but do **not** parse or validate the bytes
//! as a well-formed G2 point. That keeps the BLS12-381 curve dependency out of
//! this base crate entirely — point validation lives in `affinidi-bbs`, which
//! interprets the bytes when the key is actually used to verify a signature.

use affinidi_encoding::{BLS12381_G2_PUB, MultiEncoded, MultiEncodedBuf};
use base58::{FromBase58, ToBase58};

use crate::{CryptoError, error::Result};

const DID_KEY_PREFIX: &str = "did:key:";

/// The compressed byte length of a BLS12-381 G2 public key.
pub const BLS12381_G2_PUB_LEN: usize = 96;

/// Encode a 96-byte BLS12-381 G2 public key as a `did:key:zUC7…` identifier.
pub fn g2_pub_to_did_key(pubkey: &[u8; BLS12381_G2_PUB_LEN]) -> String {
    let multikey = MultiEncodedBuf::encode_bytes(BLS12381_G2_PUB, pubkey)
        .into_bytes()
        .to_base58();
    format!("{DID_KEY_PREFIX}z{multikey}")
}

/// Decode a `did:key:zUC7…` string to its raw 96-byte BLS12-381 G2 public key.
///
/// Errors on a missing `did:key:` prefix, missing multibase `z` prefix, a
/// multicodec other than BLS12-381-G2-pub (`0xeb`), or a payload that isn't 96
/// bytes. The returned bytes are **not** validated as a well-formed G2 point —
/// `affinidi-bbs` performs that check when it parses the key for verification.
pub fn did_key_to_g2_pub(did: &str) -> Result<[u8; BLS12381_G2_PUB_LEN]> {
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
    if multicodec.codec() != BLS12381_G2_PUB {
        return Err(CryptoError::KeyError(format!(
            "Expected BLS12-381 G2 public key, instead received codec 0x{:x}",
            multicodec.codec()
        )));
    }
    let data = multicodec.data();
    if data.len() != BLS12381_G2_PUB_LEN {
        return Err(CryptoError::KeyError(format!(
            "Invalid public key byte length: expected {BLS12381_G2_PUB_LEN}, got {}",
            data.len()
        )));
    }

    let mut out = [0u8; BLS12381_G2_PUB_LEN];
    out.copy_from_slice(data);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_encoding::ED25519_PUB;

    /// A fixed 96-byte stand-in for a compressed G2 point. The helpers do byte
    /// framing only, so any 96 bytes round-trips (curve validity is checked in
    /// `affinidi-bbs`, not here).
    fn sample_g2() -> [u8; BLS12381_G2_PUB_LEN] {
        let mut k = [0u8; BLS12381_G2_PUB_LEN];
        for (i, b) in k.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(1);
        }
        k
    }

    #[test]
    fn g2_pub_to_did_key_roundtrip() {
        let key = sample_g2();
        let did = g2_pub_to_did_key(&key);
        // multibase `z` (base58btc). (Real G2 points, whose leading byte carries
        // the compression bits, canonically render `zUC7…`; a synthetic key
        // need not, so we assert the framing + the round-trip, not the prefix.)
        assert!(
            did.starts_with("did:key:z"),
            "expected did:key:z prefix, got {did}"
        );
        let back = did_key_to_g2_pub(&did).unwrap();
        assert_eq!(back, key);
    }

    #[test]
    fn g2_pub_to_did_key_is_deterministic() {
        let key = sample_g2();
        assert_eq!(g2_pub_to_did_key(&key), g2_pub_to_did_key(&key));
    }

    #[test]
    fn did_key_to_g2_pub_missing_did_key_prefix() {
        let err = did_key_to_g2_pub("zUC7abc").unwrap_err();
        assert!(
            matches!(err, CryptoError::Decoding(ref m) if m.contains("did:key:")),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn did_key_to_g2_pub_missing_multibase_prefix() {
        let err = did_key_to_g2_pub("did:key:UC7abc").unwrap_err();
        assert!(
            matches!(err, CryptoError::Decoding(ref m) if m.contains('z')),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn did_key_to_g2_pub_wrong_multicodec() {
        // A valid did:key carrying an Ed25519 key (codec 0xed) — wrong algorithm.
        let payload = MultiEncodedBuf::encode_bytes(ED25519_PUB, &[0u8; 32])
            .into_bytes()
            .to_base58();
        let did = format!("did:key:z{payload}");
        let err = did_key_to_g2_pub(&did).unwrap_err();
        assert!(
            matches!(err, CryptoError::KeyError(ref m) if m.contains("codec")),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn did_key_to_g2_pub_wrong_length() {
        // Correct G2 multicodec but a 48-byte payload (a G1-sized key).
        let payload = MultiEncodedBuf::encode_bytes(BLS12381_G2_PUB, &[0u8; 48])
            .into_bytes()
            .to_base58();
        let did = format!("did:key:z{payload}");
        let err = did_key_to_g2_pub(&did).unwrap_err();
        assert!(
            matches!(err, CryptoError::KeyError(ref m) if m.contains("length") || m.contains("96")),
            "unexpected error: {err:?}"
        );
    }
}
