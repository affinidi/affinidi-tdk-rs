//! AES-256 Key Wrap (RFC 3394).
//!
//! Wraps and unwraps a content encryption key (CEK) using a key wrapping key (KEK).

use aes::Aes256;
use aes::cipher::{BlockEncrypt, BlockDecrypt, KeyInit};

use crate::error::DIDCommError;

const IV: u64 = 0xA6A6A6A6A6A6A6A6;

/// Wrap a key using AES-256 Key Wrap (RFC 3394).
///
/// Input key must be a multiple of 8 bytes. Output is input_len + 8 bytes.
pub fn wrap(kek: &[u8; 32], plaintext_key: &[u8]) -> Result<Vec<u8>, DIDCommError> {
    let n = plaintext_key.len();
    if n % 8 != 0 || n < 16 {
        return Err(DIDCommError::KeyWrap(
            "key to wrap must be >= 16 bytes and multiple of 8".into(),
        ));
    }

    let cipher = Aes256::new(kek.into());
    let n_blocks = n / 8;

    // Initialize: A = IV, R[1..n] = plaintext blocks
    let mut a = IV;
    let mut r: Vec<u64> = plaintext_key
        .chunks_exact(8)
        .map(|chunk| u64::from_be_bytes(chunk.try_into().unwrap()))
        .collect();

    // 6 * n rounds
    for j in 0..6u64 {
        for i in 0..n_blocks {
            // B = AES(K, A || R[i])
            let mut block = [0u8; 16];
            block[..8].copy_from_slice(&a.to_be_bytes());
            block[8..].copy_from_slice(&r[i].to_be_bytes());

            let b = aes::Block::from_mut_slice(&mut block);
            cipher.encrypt_block(b);

            // A = MSB(64, B) XOR t where t = (n*j)+i+1
            let t = (n_blocks as u64) * j + (i as u64) + 1;
            a = u64::from_be_bytes(block[..8].try_into().unwrap()) ^ t;
            r[i] = u64::from_be_bytes(block[8..].try_into().unwrap());
        }
    }

    // Output: A || R[1] || ... || R[n]
    let mut output = Vec::with_capacity(8 + n);
    output.extend_from_slice(&a.to_be_bytes());
    for block in &r {
        output.extend_from_slice(&block.to_be_bytes());
    }

    Ok(output)
}

/// Unwrap a key using AES-256 Key Wrap (RFC 3394).
///
/// Input must be wrapped_len bytes (plaintext_len + 8). Returns the unwrapped key.
pub fn unwrap(kek: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>, DIDCommError> {
    let total = ciphertext.len();
    if total % 8 != 0 || total < 24 {
        return Err(DIDCommError::KeyWrap(
            "wrapped key must be >= 24 bytes and multiple of 8".into(),
        ));
    }

    let cipher = Aes256::new(kek.into());
    let n_blocks = (total / 8) - 1;

    // Initialize: A = C[0], R[i] = C[i]
    let mut a = u64::from_be_bytes(ciphertext[..8].try_into().unwrap());
    let mut r: Vec<u64> = ciphertext[8..]
        .chunks_exact(8)
        .map(|chunk| u64::from_be_bytes(chunk.try_into().unwrap()))
        .collect();

    // Unwrap: 6 * n rounds in reverse
    for j in (0..6u64).rev() {
        for i in (0..n_blocks).rev() {
            let t = (n_blocks as u64) * j + (i as u64) + 1;

            let mut block = [0u8; 16];
            block[..8].copy_from_slice(&(a ^ t).to_be_bytes());
            block[8..].copy_from_slice(&r[i].to_be_bytes());

            let b = aes::Block::from_mut_slice(&mut block);
            cipher.decrypt_block(b);

            a = u64::from_be_bytes(block[..8].try_into().unwrap());
            r[i] = u64::from_be_bytes(block[8..].try_into().unwrap());
        }
    }

    // Verify IV
    if a != IV {
        return Err(DIDCommError::KeyWrap(
            "key unwrap integrity check failed".into(),
        ));
    }

    let mut output = Vec::with_capacity(n_blocks * 8);
    for block in &r {
        output.extend_from_slice(&block.to_be_bytes());
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_unwrap_roundtrip() {
        let kek = [0x42u8; 32];
        let key = [0xAB_u8; 32]; // 32-byte key to wrap

        let wrapped = wrap(&kek, &key).unwrap();
        assert_eq!(wrapped.len(), 40); // 32 + 8

        let unwrapped = unwrap(&kek, &wrapped).unwrap();
        assert_eq!(unwrapped, key);
    }

    #[test]
    fn wrap_unwrap_64_byte_cek() {
        let kek = [0x01u8; 32];
        let cek = [0xFFu8; 64]; // A256CBC-HS512 CEK size

        let wrapped = wrap(&kek, &cek).unwrap();
        assert_eq!(wrapped.len(), 72);

        let unwrapped = unwrap(&kek, &wrapped).unwrap();
        assert_eq!(unwrapped, cek);
    }

    #[test]
    fn wrong_kek_fails() {
        let kek1 = [0x01u8; 32];
        let kek2 = [0x02u8; 32];
        let key = [0xABu8; 32];

        let wrapped = wrap(&kek1, &key).unwrap();
        assert!(unwrap(&kek2, &wrapped).is_err());
    }

    #[test]
    fn tampered_wrapped_fails() {
        let kek = [0x42u8; 32];
        let key = [0xABu8; 32];

        let mut wrapped = wrap(&kek, &key).unwrap();
        wrapped[4] ^= 0xFF;
        assert!(unwrap(&kek, &wrapped).is_err());
    }

    #[test]
    fn too_small_key_fails() {
        let kek = [0x42u8; 32];
        assert!(wrap(&kek, &[0u8; 8]).is_err()); // must be >= 16
    }
}
