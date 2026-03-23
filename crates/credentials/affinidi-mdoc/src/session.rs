/*!
 * Session encryption for mdoc proximity presentation.
 *
 * Per ISO 18013-5, proximity (NFC/BLE) data exchange uses AES-256-GCM
 * with session keys derived via HKDF-SHA-256 from a shared secret
 * established through ECDH key agreement.
 *
 * # Key Derivation
 *
 * ```text
 * shared_secret = ECDH(device_key, reader_key)
 * sk_device = HKDF-SHA-256(shared_secret, salt=session_transcript, info="SKDevice")
 * sk_reader = HKDF-SHA-256(shared_secret, salt=session_transcript, info="SKReader")
 * ```
 *
 * # Encryption
 *
 * AES-256-GCM with 12-byte nonces (counter-based).
 */

use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce, aead::Aead};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::{MdocError, Result};

/// Derive a session key using HKDF-SHA-256.
///
/// # Arguments
///
/// * `shared_secret` - The ECDH shared secret bytes
/// * `salt` - The session transcript bytes (context binding)
/// * `info` - The key purpose label ("SKDevice" or "SKReader")
///
/// # Returns
///
/// 32-byte AES-256 key.
pub fn derive_session_key(shared_secret: &[u8], salt: &[u8], info: &str) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(salt), shared_secret);
    let mut key = [0u8; 32];
    hk.expand(info.as_bytes(), &mut key)
        .map_err(|e| MdocError::Cose(format!("HKDF expand failed: {e}")))?;
    Ok(key)
}

/// Encrypt data using AES-256-GCM.
///
/// # Arguments
///
/// * `key` - 32-byte AES-256 key
/// * `nonce` - 12-byte nonce (typically counter-based)
/// * `plaintext` - Data to encrypt
///
/// # Returns
///
/// Ciphertext with appended 16-byte authentication tag.
pub fn encrypt_aes256gcm(
    key: &[u8; 32],
    nonce_bytes: &[u8; 12],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| MdocError::Cose(format!("AES-256-GCM encryption failed: {e}")))
}

/// Decrypt data using AES-256-GCM.
///
/// # Arguments
///
/// * `key` - 32-byte AES-256 key
/// * `nonce` - 12-byte nonce (same as used for encryption)
/// * `ciphertext` - Ciphertext with appended authentication tag
///
/// # Returns
///
/// Decrypted plaintext.
pub fn decrypt_aes256gcm(
    key: &[u8; 32],
    nonce_bytes: &[u8; 12],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| MdocError::Cose(format!("AES-256-GCM decryption failed: {e}")))
}

/// Session key pair for mdoc proximity communication.
///
/// Contains both device and reader keys derived from the same shared secret.
pub struct SessionKeys {
    /// Key for device → reader communication.
    pub sk_device: [u8; 32],
    /// Key for reader → device communication.
    pub sk_reader: [u8; 32],
}

impl SessionKeys {
    /// Derive session keys from a shared secret and session transcript.
    ///
    /// Per ISO 18013-5 §9.1.1.5:
    /// - `sk_device = HKDF(shared_secret, transcript, "SKDevice")`
    /// - `sk_reader = HKDF(shared_secret, transcript, "SKReader")`
    pub fn derive(shared_secret: &[u8], session_transcript: &[u8]) -> Result<Self> {
        let sk_device = derive_session_key(shared_secret, session_transcript, "SKDevice")?;
        let sk_reader = derive_session_key(shared_secret, session_transcript, "SKReader")?;

        Ok(SessionKeys {
            sk_device,
            sk_reader,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_session_keys() {
        let shared_secret = b"shared-secret-from-ecdh-key-agreement";
        let transcript = b"session-transcript-cbor-bytes";

        let keys = SessionKeys::derive(shared_secret, transcript).unwrap();

        // Keys should be 32 bytes
        assert_eq!(keys.sk_device.len(), 32);
        assert_eq!(keys.sk_reader.len(), 32);

        // Device and reader keys must be different
        assert_ne!(keys.sk_device, keys.sk_reader);
    }

    #[test]
    fn derive_keys_deterministic() {
        let k1 = SessionKeys::derive(b"secret", b"transcript").unwrap();
        let k2 = SessionKeys::derive(b"secret", b"transcript").unwrap();

        assert_eq!(k1.sk_device, k2.sk_device);
        assert_eq!(k1.sk_reader, k2.sk_reader);
    }

    #[test]
    fn derive_different_secrets_different_keys() {
        let k1 = SessionKeys::derive(b"secret1", b"transcript").unwrap();
        let k2 = SessionKeys::derive(b"secret2", b"transcript").unwrap();

        assert_ne!(k1.sk_device, k2.sk_device);
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 32];
        let nonce = [0u8; 12];
        let plaintext = b"Hello, eIDAS 2.0 mdoc proximity!";

        let ciphertext = encrypt_aes256gcm(&key, &nonce, plaintext).unwrap();
        assert_ne!(ciphertext, plaintext.as_slice());
        // Ciphertext = plaintext + 16-byte auth tag
        assert_eq!(ciphertext.len(), plaintext.len() + 16);

        let decrypted = decrypt_aes256gcm(&key, &nonce, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_wrong_key_fails() {
        let key1 = [0x42u8; 32];
        let key2 = [0x43u8; 32];
        let nonce = [0u8; 12];

        let ciphertext = encrypt_aes256gcm(&key1, &nonce, b"secret").unwrap();
        assert!(decrypt_aes256gcm(&key2, &nonce, &ciphertext).is_err());
    }

    #[test]
    fn decrypt_wrong_nonce_fails() {
        let key = [0x42u8; 32];
        let nonce1 = [0u8; 12];
        let nonce2 = [1u8; 12];

        let ciphertext = encrypt_aes256gcm(&key, &nonce1, b"secret").unwrap();
        assert!(decrypt_aes256gcm(&key, &nonce2, &ciphertext).is_err());
    }

    #[test]
    fn decrypt_tampered_ciphertext_fails() {
        let key = [0x42u8; 32];
        let nonce = [0u8; 12];

        let mut ciphertext = encrypt_aes256gcm(&key, &nonce, b"secret").unwrap();
        // Tamper with one byte
        ciphertext[0] ^= 0xFF;

        assert!(decrypt_aes256gcm(&key, &nonce, &ciphertext).is_err());
    }

    #[test]
    fn full_session_encryption_flow() {
        // Simulate device and reader deriving session keys
        let shared_secret = b"ecdh-shared-secret-32-bytes!!!!";
        let transcript = b"session-transcript";

        let keys = SessionKeys::derive(shared_secret, transcript).unwrap();

        // Device encrypts a message for the reader
        let device_nonce = [0u8; 12];
        let message = b"DeviceResponse CBOR bytes";
        let encrypted = encrypt_aes256gcm(&keys.sk_device, &device_nonce, message).unwrap();

        // Reader decrypts using the same device key
        let decrypted = decrypt_aes256gcm(&keys.sk_device, &device_nonce, &encrypted).unwrap();
        assert_eq!(decrypted, message);
    }
}
