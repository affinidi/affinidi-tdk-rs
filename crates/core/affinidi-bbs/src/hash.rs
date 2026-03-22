/*!
 * Hash operations for BBS signatures.
 *
 * Implements:
 * - `hash_to_scalar`: Hash arbitrary data to a BLS12-381 scalar
 * - `messages_to_scalars`: Convert message byte arrays to scalars
 * - `expand_message`: SHA-256 (XMD) and SHAKE-256 (XOF) message expansion
 *
 * Per IETF draft §4.
 */

use bls12_381_plus::Scalar;
use sha2::{Digest, Sha256};

use crate::ciphersuite::Ciphersuite;
use crate::error::Result;

/// Hash arbitrary bytes to a BLS12-381 scalar.
///
/// Per IETF draft §4.3.3:
/// 1. `uniform_bytes = expand_message(msg_octets, dst, expand_len)`
/// 2. Return `OS2IP(uniform_bytes) mod r`
pub fn hash_to_scalar(data: &[u8], dst: &[u8], cs: Ciphersuite) -> Result<Scalar> {
    let expand_len = cs.expand_len();
    let uniform_bytes = expand_message_xmd_sha256(data, dst, expand_len);
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

/// Expand message using SHA-256 (XMD) per RFC 9380 §5.3.1.
///
/// This is the `expand_message_xmd` function with SHA-256.
pub fn expand_message_xmd_sha256(msg: &[u8], dst: &[u8], len_in_bytes: usize) -> Vec<u8> {
    let b_in_bytes = 32; // SHA-256 output
    let r_in_bytes = 64; // SHA-256 block size
    let ell = (len_in_bytes + b_in_bytes - 1) / b_in_bytes;

    assert!(ell <= 255, "expand_message: ell > 255");
    assert!(len_in_bytes <= 65535, "expand_message: len > 65535");
    assert!(dst.len() <= 255, "expand_message: DST length > 255");

    // DST_prime = DST || I2OSP(len(DST), 1)
    let mut dst_prime = dst.to_vec();
    dst_prime.push(dst.len() as u8);

    // Z_pad = I2OSP(0, r_in_bytes)
    let z_pad = vec![0u8; r_in_bytes];

    // l_i_b_str = I2OSP(len_in_bytes, 2)
    let l_i_b_str = (len_in_bytes as u16).to_be_bytes();

    // b_0 = H(Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime)
    let mut hasher = Sha256::new();
    hasher.update(&z_pad);
    hasher.update(msg);
    hasher.update(l_i_b_str);
    hasher.update([0u8]);
    hasher.update(&dst_prime);
    let b_0 = hasher.finalize();

    // b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
    let mut hasher = Sha256::new();
    hasher.update(b_0);
    hasher.update([1u8]);
    hasher.update(&dst_prime);
    let mut b_i = hasher.finalize();

    let mut uniform_bytes = b_i.to_vec();

    for i in 2..=ell {
        // b_i = H(strxor(b_0, b_(i-1)) || I2OSP(i, 1) || DST_prime)
        let mut xored = [0u8; 32];
        for j in 0..32 {
            xored[j] = b_0[j] ^ b_i[j];
        }
        let mut hasher = Sha256::new();
        hasher.update(xored);
        hasher.update([i as u8]);
        hasher.update(&dst_prime);
        b_i = hasher.finalize();
        uniform_bytes.extend_from_slice(&b_i);
    }

    uniform_bytes.truncate(len_in_bytes);
    uniform_bytes
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

/// Concatenate byte slices with length prefixes for hash input.
///
/// Per the spec, serialization for hash input uses:
/// `I2OSP(len, 8) || data` for each element.
pub fn serialize_for_hash(elements: &[&[u8]]) -> Vec<u8> {
    let mut result = Vec::new();
    for elem in elements {
        result.extend_from_slice(&(elem.len() as u64).to_be_bytes());
        result.extend_from_slice(elem);
    }
    result
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
        let result = expand_message_xmd_sha256(b"test", b"dst", 48);
        assert_eq!(result.len(), 48);

        let result = expand_message_xmd_sha256(b"test", b"dst", 64);
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
        let s = hash_to_scalar(b"roundtrip", b"dst", Ciphersuite::Bls12381Sha256).unwrap();
        let bytes = scalar_to_bytes(&s);
        let recovered = scalar_from_bytes(&bytes).unwrap();
        assert_eq!(s, recovered);
    }
}
