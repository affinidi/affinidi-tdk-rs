/*!
 * Hash operations for BBS signatures.
 *
 * Implements:
 * - `hash_to_scalar`: Hash arbitrary data to a BLS12-381 scalar
 * - `messages_to_scalars`: Convert message byte arrays to scalars
 *
 * Uses `elliptic_curve::hash2curve::ExpandMsgXmd<Sha256>` for exact
 * compatibility with the `bls12_381_plus` hash-to-curve implementation.
 */

use bls12_381_plus::Scalar;
use elliptic_curve::hash2curve::{ExpandMsg, ExpandMsgXmd, Expander};
use sha2::Sha256;

use crate::ciphersuite::Ciphersuite;
use crate::error::Result;

/// Hash arbitrary bytes to a BLS12-381 scalar.
///
/// Per IETF draft §4.3.3:
/// 1. `uniform_bytes = expand_message(msg_octets, dst, expand_len)`
/// 2. Return `OS2IP(uniform_bytes) mod r`
///
/// Uses the `elliptic_curve` crate's `ExpandMsgXmd<Sha256>` to ensure
/// byte-exact compatibility with `bls12_381_plus` hash-to-curve.
pub fn hash_to_scalar(data: &[u8], dst: &[u8], _cs: Ciphersuite) -> Result<Scalar> {
    let expand_len = 48; // ceil((255 + 128) / 8)
    let mut uniform_bytes = vec![0u8; expand_len];
    <ExpandMsgXmd<Sha256> as ExpandMsg<'_>>::expand_message(&[data], &[dst], expand_len)
        .expect("expand_message should not fail")
        .fill_bytes(&mut uniform_bytes);
    Ok(scalar_from_wide_bytes(&uniform_bytes))
}

/// Convert message byte arrays to scalars.
///
/// Per IETF draft §4.3.1:
/// For each message: `hash_to_scalar(message, api_id || "MAP_MSG_TO_SCALAR_AS_HASH_")`
pub fn messages_to_scalars(messages: &[&[u8]], cs: Ciphersuite) -> Result<Vec<Scalar>> {
    let mut dst = cs.api_id();
    dst.extend_from_slice(b"MAP_MSG_TO_SCALAR_AS_HASH_");

    messages
        .iter()
        .map(|msg| hash_to_scalar(msg, &dst, cs))
        .collect()
}

/// Expand message using ExpandMsgXmd<SHA-256> from the elliptic_curve crate.
///
/// This is the canonical expand_message implementation used throughout BBS
/// for both generator creation and hash_to_scalar.
pub fn expand_message_xmd_sha256(msg: &[u8], dst: &[u8], len_in_bytes: usize) -> Vec<u8> {
    let mut output = vec![0u8; len_in_bytes];
    <ExpandMsgXmd<Sha256> as ExpandMsg<'_>>::expand_message(&[msg], &[dst], len_in_bytes)
        .expect("expand_message should not fail")
        .fill_bytes(&mut output);
    output
}

/// Convert a wide byte array to a scalar via OS2IP mod r.
///
/// Uses `Scalar::from_okm` which expects exactly 48 bytes and performs
/// a wide reduction modulo the BLS12-381 group order.
fn scalar_from_wide_bytes(bytes: &[u8]) -> Scalar {
    let mut wide = [0u8; 48];
    let len = bytes.len().min(48);
    let start = 48 - len;
    wide[start..].copy_from_slice(&bytes[..len]);
    Scalar::from_okm(&wide)
}

/// Serialize a scalar to big-endian bytes (32 bytes).
pub fn scalar_to_bytes(s: &Scalar) -> [u8; 32] {
    s.to_be_bytes()
}

/// Deserialize a scalar from big-endian bytes.
pub fn scalar_from_bytes(bytes: &[u8; 32]) -> Option<Scalar> {
    let s = Scalar::from_be_bytes(bytes);
    if s.is_some().into() {
        Some(s.unwrap())
    } else {
        None
    }
}

/// I2OSP (Integer to Octet String Primitive) per RFC 8017.
pub fn i2osp(value: u64, length: usize) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    if length >= 8 {
        let mut result = vec![0u8; length - 8];
        result.extend_from_slice(&bytes);
        result
    } else {
        bytes[8 - length..].to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_to_scalar_produces_nonzero() {
        let s = hash_to_scalar(b"test message", b"test-dst", Ciphersuite::Bls12381Sha256).unwrap();
        assert_ne!(s, Scalar::ZERO);
    }

    #[test]
    fn hash_to_scalar_deterministic() {
        let s1 = hash_to_scalar(b"same input", b"same-dst", Ciphersuite::Bls12381Sha256).unwrap();
        let s2 = hash_to_scalar(b"same input", b"same-dst", Ciphersuite::Bls12381Sha256).unwrap();
        assert_eq!(s1, s2);
    }

    #[test]
    fn hash_to_scalar_different_inputs() {
        let s1 = hash_to_scalar(b"input1", b"dst", Ciphersuite::Bls12381Sha256).unwrap();
        let s2 = hash_to_scalar(b"input2", b"dst", Ciphersuite::Bls12381Sha256).unwrap();
        assert_ne!(s1, s2);
    }

    #[test]
    fn messages_to_scalars_correct_count() {
        let msgs: Vec<&[u8]> = vec![b"msg1", b"msg2", b"msg3"];
        let scalars = messages_to_scalars(&msgs, Ciphersuite::Bls12381Sha256).unwrap();
        assert_eq!(scalars.len(), 3);
    }

    #[test]
    fn expand_message_output_length() {
        let result = expand_message_xmd_sha256(b"test", b"dst-at-least-16-bytes!", 48);
        assert_eq!(result.len(), 48);

        let result = expand_message_xmd_sha256(b"test", b"dst-at-least-16-bytes!", 64);
        assert_eq!(result.len(), 64);
    }

    #[test]
    fn i2osp_values() {
        assert_eq!(i2osp(0, 1), vec![0]);
        assert_eq!(i2osp(1, 1), vec![1]);
        assert_eq!(i2osp(256, 2), vec![1, 0]);
        assert_eq!(i2osp(1, 4), vec![0, 0, 0, 1]);
    }

    #[test]
    fn scalar_roundtrip() {
        let s = hash_to_scalar(
            b"roundtrip",
            b"dst-for-roundtrip-test!",
            Ciphersuite::Bls12381Sha256,
        )
        .unwrap();
        let bytes = scalar_to_bytes(&s);
        let recovered = scalar_from_bytes(&bytes).unwrap();
        assert_eq!(s, recovered);
    }

    #[test]
    fn hash_to_scalar_matches_ietf_fixture() {
        // From DIF fixture: bls12-381-sha-256/h2s.json
        let msg = hex::decode("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02")
            .unwrap();
        let dst = hex::decode("4242535f424c53313233383147315f584d443a5348412d3235365f535357555f524f5f4832475f484d32535f4832535f").unwrap();
        let expected = "0f90cbee27beb214e6545becb8404640d3612da5d6758dffeccd77ed7169807c";

        let scalar = hash_to_scalar(&msg, &dst, Ciphersuite::Bls12381Sha256).unwrap();
        assert_eq!(hex::encode(scalar_to_bytes(&scalar)), expected);
    }

    #[test]
    fn messages_to_scalars_match_ietf_fixture() {
        // From DIF fixture: bls12-381-sha-256/MapMessageToScalarAsHash.json
        let msg0 = hex::decode("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02")
            .unwrap();
        let expected_scalar0 = "1cb5bb86114b34dc438a911617655a1db595abafac92f47c5001799cf624b430";

        let messages: Vec<&[u8]> = vec![&msg0];
        let scalars = messages_to_scalars(&messages, Ciphersuite::Bls12381Sha256).unwrap();
        assert_eq!(hex::encode(scalar_to_bytes(&scalars[0])), expected_scalar0);
    }
}
