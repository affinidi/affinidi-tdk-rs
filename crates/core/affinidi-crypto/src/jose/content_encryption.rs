//! A256CBC-HS512 content encryption (RFC 7516 / 7518).
//!
//! Composite AEAD: AES-256-CBC + HMAC-SHA-512 (truncated to 256 bits).
//! The 64-byte CEK is split: first 32 bytes = HMAC key, last 32 bytes =
//! AES key. Ported verbatim from `affinidi-messaging-didcomm` for the #327
//! centralization; byte-level behaviour is locked by [`super::kat`].

use aes::Aes256;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use rand_core::RngCore;
use sha2::Sha512;
use subtle::ConstantTimeEq;

use crate::error::CryptoError;

type Aes256CbcEnc = cbc::Encryptor<Aes256>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;

/// CEK size for A256CBC-HS512 (32 bytes MAC key + 32 bytes AES key).
pub const CEK_SIZE: usize = 64;

/// IV size for AES-CBC.
pub const IV_SIZE: usize = 16;

/// Authentication tag size (HMAC-SHA-512 truncated to 256 bits).
pub const TAG_SIZE: usize = 32;

/// Generate a random 64-byte CEK.
pub fn generate_cek() -> [u8; CEK_SIZE] {
    let mut cek = [0u8; CEK_SIZE];
    rand_core::OsRng.fill_bytes(&mut cek);
    cek
}

/// Generate a random 16-byte IV.
pub fn generate_iv() -> [u8; IV_SIZE] {
    let mut iv = [0u8; IV_SIZE];
    rand_core::OsRng.fill_bytes(&mut iv);
    iv
}

/// Encrypt with A256CBC-HS512. Returns `(ciphertext, tag)`.
pub fn encrypt(
    plaintext: &[u8],
    cek: &[u8; CEK_SIZE],
    iv: &[u8; IV_SIZE],
    aad: &[u8],
) -> Result<(Vec<u8>, [u8; TAG_SIZE]), CryptoError> {
    let mac_key = &cek[..32];
    let enc_key = &cek[32..];

    // PKCS7 padding: pad to AES block size (16 bytes)
    let pad_len = 16 - (plaintext.len() % 16);
    let mut padded = Vec::with_capacity(plaintext.len() + pad_len);
    padded.extend_from_slice(plaintext);
    padded.resize(plaintext.len() + pad_len, pad_len as u8);

    // AES-256-CBC encrypt
    let enc_key_arr: [u8; 32] = enc_key.try_into().unwrap();
    let encryptor = Aes256CbcEnc::new(&enc_key_arr.into(), iv.into());
    let ciphertext =
        encryptor.encrypt_padded_vec_mut::<cbc::cipher::block_padding::NoPadding>(&padded);

    // HMAC-SHA-512 over: AAD || IV || ciphertext || AAD_len_bits (big-endian u64)
    let aad_len_bits = (aad.len() as u64) * 8;
    let mut hmac = <Hmac<Sha512>>::new_from_slice(mac_key)
        .map_err(|e| CryptoError::ContentEncryption(format!("HMAC init failed: {e}")))?;
    hmac.update(aad);
    hmac.update(iv);
    hmac.update(&ciphertext);
    hmac.update(&aad_len_bits.to_be_bytes());
    let full_tag = hmac.finalize().into_bytes();

    // Truncate to first 32 bytes
    let mut tag = [0u8; TAG_SIZE];
    tag.copy_from_slice(&full_tag[..TAG_SIZE]);

    Ok((ciphertext, tag))
}

/// Decrypt with A256CBC-HS512. Verifies the tag in constant time before
/// decrypting.
pub fn decrypt(
    ciphertext: &[u8],
    cek: &[u8; CEK_SIZE],
    iv: &[u8; IV_SIZE],
    aad: &[u8],
    tag: &[u8; TAG_SIZE],
) -> Result<Vec<u8>, CryptoError> {
    let mac_key = &cek[..32];
    let enc_key = &cek[32..];

    // Verify HMAC first
    let aad_len_bits = (aad.len() as u64) * 8;
    let mut hmac = <Hmac<Sha512>>::new_from_slice(mac_key)
        .map_err(|e| CryptoError::ContentEncryption(format!("HMAC init failed: {e}")))?;
    hmac.update(aad);
    hmac.update(iv);
    hmac.update(ciphertext);
    hmac.update(&aad_len_bits.to_be_bytes());
    let full_tag = hmac.finalize().into_bytes();

    // Constant-time tag comparison to prevent timing attacks
    if full_tag[..TAG_SIZE].ct_eq(tag).unwrap_u8() != 1 {
        return Err(CryptoError::ContentEncryption(
            "authentication tag mismatch".into(),
        ));
    }

    // AES-256-CBC decrypt
    let enc_key_arr: [u8; 32] = enc_key.try_into().unwrap();
    let decryptor = Aes256CbcDec::new(&enc_key_arr.into(), iv.into());
    let buf = ciphertext.to_vec();
    let decrypted = decryptor
        .decrypt_padded_vec_mut::<cbc::cipher::block_padding::NoPadding>(&buf)
        .map_err(|e| CryptoError::ContentEncryption(format!("AES-CBC decrypt failed: {e}")))?;

    // Remove PKCS7 padding
    if decrypted.is_empty() {
        return Err(CryptoError::ContentEncryption(
            "decrypted data is empty".into(),
        ));
    }
    let pad_len = *decrypted.last().unwrap() as usize;
    if pad_len == 0 || pad_len > 16 || pad_len > decrypted.len() {
        return Err(CryptoError::ContentEncryption(
            "invalid PKCS7 padding".into(),
        ));
    }
    // Verify all padding bytes
    for &b in &decrypted[decrypted.len() - pad_len..] {
        if b as usize != pad_len {
            return Err(CryptoError::ContentEncryption(
                "invalid PKCS7 padding".into(),
            ));
        }
    }
    let plaintext = &decrypted[..decrypted.len() - pad_len];

    Ok(plaintext.to_vec())
}
