//! AES-256 Key Wrap (RFC 3394).
//!
//! Wraps and unwraps a content encryption key (CEK) using a key wrapping
//! key (KEK). Ported verbatim from `affinidi-messaging-didcomm` as part of
//! the #327 JOSE crypto centralization — the byte-level behaviour is locked
//! by the known-answer tests in [`super::kat`].

use aes::Aes256;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};

use crate::error::CryptoError;

const IV: u64 = 0xA6A6A6A6A6A6A6A6;

/// Wrap a key using AES-256 Key Wrap (RFC 3394).
///
/// Input key must be a multiple of 8 bytes and at least 16 bytes. Output
/// is `input_len + 8` bytes.
pub fn wrap(kek: &[u8; 32], plaintext_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let n = plaintext_key.len();
    if !n.is_multiple_of(8) || n < 16 {
        return Err(CryptoError::KeyWrap(
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
        for (i, ri) in r.iter_mut().enumerate().take(n_blocks) {
            // B = AES(K, A || R[i])
            let mut block = [0u8; 16];
            block[..8].copy_from_slice(&a.to_be_bytes());
            block[8..].copy_from_slice(&ri.to_be_bytes());

            let b = aes::Block::from_mut_slice(&mut block);
            cipher.encrypt_block(b);

            // A = MSB(64, B) XOR t where t = (n*j)+i+1
            let t = (n_blocks as u64) * j + (i as u64) + 1;
            a = u64::from_be_bytes(block[..8].try_into().unwrap()) ^ t;
            *ri = u64::from_be_bytes(block[8..].try_into().unwrap());
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
/// Input must be `plaintext_len + 8` bytes. Returns the unwrapped key, or
/// an error if the integrity check fails.
pub fn unwrap(kek: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let total = ciphertext.len();
    if !total.is_multiple_of(8) || total < 24 {
        return Err(CryptoError::KeyWrap(
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
        return Err(CryptoError::KeyWrap(
            "key unwrap integrity check failed".into(),
        ));
    }

    let mut output = Vec::with_capacity(n_blocks * 8);
    for block in &r {
        output.extend_from_slice(&block.to_be_bytes());
    }

    Ok(output)
}
