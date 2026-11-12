/*!
 * Session encryption for mdoc proximity presentation.
 *
 * Per ISO/IEC 18013-5 §9.1.1.5, proximity (NFC/BLE) data exchange uses
 * AES-256-GCM with session keys derived via HKDF-SHA-256 from the ECDH
 * shared secret of the device and reader ephemeral keys.
 *
 * # Key Derivation
 *
 * ```text
 * Zab       = ECDH(EDeviceKey, EReaderKey)
 * salt      = SHA-256(SessionTranscriptBytes)   ; #6.24(bstr .cbor SessionTranscript)
 * SKDevice  = HKDF-SHA-256(IKM = Zab, salt, info = "SKDevice", L = 32)
 * SKReader  = HKDF-SHA-256(IKM = Zab, salt, info = "SKReader", L = 32)
 * ```
 *
 * # Encryption
 *
 * The reader encrypts with `SKReader`, the mdoc with `SKDevice`. The 12-byte
 * IV is an 8-byte sender identifier (`0` for the reader, `1` for the mdoc)
 * followed by a 4-byte big-endian message counter that starts at 1 for the
 * first message under each key. [`SessionEncryption`] keeps both counters.
 */

use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::{MdocError, Result};
use crate::session_transcript::SessionTranscript;

/// Derive one session key (`"SKDevice"` or `"SKReader"`) per ISO/IEC 18013-5
/// §9.1.1.5: HKDF-SHA-256 over the ECDH shared secret, with salt
/// SHA-256(SessionTranscriptBytes) and `info` as the label.
pub fn derive_session_key(
    shared_secret: &[u8],
    session_transcript: &SessionTranscript,
    info: &str,
) -> Result<[u8; 32]> {
    let salt = session_transcript.hkdf_salt()?;
    hkdf_sha256(shared_secret, &salt, info.as_bytes())
}

pub(crate) fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8]) -> Result<[u8; 32]> {
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(info, &mut key)
        .map_err(|e| MdocError::Cose(format!("HKDF expand failed: {e}")))?;
    Ok(key)
}

/// Encrypt data using AES-256-GCM.
///
/// Low-level primitive: the caller is responsible for never reusing a nonce
/// under the same key. Prefer [`SessionEncryption`], which builds the
/// ISO/IEC 18013-5 IV and keeps the message counters.
///
/// Returns the ciphertext with the 16-byte authentication tag appended.
pub fn encrypt_aes256gcm(
    key: &[u8; 32],
    nonce_bytes: &[u8; 12],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| MdocError::Cose(format!("AES-256-GCM invalid key: {e}")))?;
    let nonce = Nonce::from(*nonce_bytes);

    cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| MdocError::Cose(format!("AES-256-GCM encryption failed: {e}")))
}

/// Decrypt data using AES-256-GCM.
///
/// Low-level primitive; prefer [`SessionEncryption`].
///
/// `ciphertext` carries the appended authentication tag.
pub fn decrypt_aes256gcm(
    key: &[u8; 32],
    nonce_bytes: &[u8; 12],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| MdocError::Cose(format!("AES-256-GCM invalid key: {e}")))?;
    let nonce = Nonce::from(*nonce_bytes);

    cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|e| MdocError::Cose(format!("AES-256-GCM decryption failed: {e}")))
}

/// Session key pair for mdoc proximity communication.
///
/// Both keys are overwritten with zeros when the value is dropped.
pub struct SessionKeys {
    /// `SKDevice`: the mdoc encrypts with it, the reader decrypts.
    pub sk_device: [u8; 32],
    /// `SKReader`: the reader encrypts with it, the mdoc decrypts.
    pub sk_reader: [u8; 32],
}

impl SessionKeys {
    /// Derive `SKDevice` and `SKReader` from the ECDH shared secret and the
    /// session transcript, per ISO/IEC 18013-5 §9.1.1.5 (salt is
    /// SHA-256(SessionTranscriptBytes)).
    pub fn derive(shared_secret: &[u8], session_transcript: &SessionTranscript) -> Result<Self> {
        let salt = session_transcript.hkdf_salt()?;
        Ok(SessionKeys {
            sk_device: hkdf_sha256(shared_secret, &salt, b"SKDevice")?,
            sk_reader: hkdf_sha256(shared_secret, &salt, b"SKReader")?,
        })
    }
}

impl Drop for SessionKeys {
    fn drop(&mut self) {
        wipe(&mut self.sk_device);
        wipe(&mut self.sk_reader);
    }
}

fn wipe(bytes: &mut [u8; 32]) {
    for byte in bytes.iter_mut() {
        // SAFETY: `byte` is a valid, aligned, exclusive reference to a u8.
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

/// Which side of a proximity session this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRole {
    /// The mdoc reader: encrypts with `SKReader`, IV identifier 0.
    Reader,
    /// The mdoc (holder device): encrypts with `SKDevice`, IV identifier 1.
    Device,
}

impl SessionRole {
    fn peer(self) -> Self {
        match self {
            SessionRole::Reader => SessionRole::Device,
            SessionRole::Device => SessionRole::Reader,
        }
    }

    fn identifier(self) -> u64 {
        match self {
            SessionRole::Reader => 0,
            SessionRole::Device => 1,
        }
    }
}

/// The ISO/IEC 18013-5 §9.1.1.5 IV for a message from `sender`: the 8-byte
/// sender identifier followed by the 4-byte big-endian message counter.
pub fn session_nonce(sender: SessionRole, counter: u32) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..8].copy_from_slice(&sender.identifier().to_be_bytes());
    nonce[8..].copy_from_slice(&counter.to_be_bytes());
    nonce
}

/// One side of an encrypted proximity session.
///
/// Encrypts outgoing messages with this side's key and decrypts incoming
/// ones with the peer's, building each IV from the sender identifier and a
/// message counter that starts at 1. Each counter only moves forward, so a
/// nonce is never reused for encryption, and a repeated or out-of-order
/// incoming message fails to decrypt. A failed decryption does not advance
/// the counter.
pub struct SessionEncryption {
    keys: SessionKeys,
    role: SessionRole,
    sent: u32,
    received: u32,
}

impl SessionEncryption {
    /// Start a session as `role` with keys from [`SessionKeys::derive`].
    pub fn new(keys: SessionKeys, role: SessionRole) -> Self {
        Self {
            keys,
            role,
            sent: 0,
            received: 0,
        }
    }

    /// This side's role.
    pub fn role(&self) -> SessionRole {
        self.role
    }

    fn key_of(&self, sender: SessionRole) -> &[u8; 32] {
        match sender {
            SessionRole::Reader => &self.keys.sk_reader,
            SessionRole::Device => &self.keys.sk_device,
        }
    }

    /// Encrypt the next outgoing message.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let counter = self
            .sent
            .checked_add(1)
            .ok_or_else(|| MdocError::Session("outgoing message counter exhausted".into()))?;
        let ciphertext = encrypt_aes256gcm(
            self.key_of(self.role),
            &session_nonce(self.role, counter),
            plaintext,
        )?;
        self.sent = counter;
        Ok(ciphertext)
    }

    /// Decrypt the next incoming message from the peer.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let peer = self.role.peer();
        let counter = self
            .received
            .checked_add(1)
            .ok_or_else(|| MdocError::Session("incoming message counter exhausted".into()))?;
        let plaintext =
            decrypt_aes256gcm(self.key_of(peer), &session_nonce(peer, counter), ciphertext)?;
        self.received = counter;
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device_engagement::DeviceEngagement;
    use sha2::Digest;

    fn cose_key(fill: u8) -> ciborium::Value {
        ciborium::Value::Map(vec![
            (
                ciborium::Value::Integer(1.into()),
                ciborium::Value::Integer(2.into()),
            ),
            (
                ciborium::Value::Integer((-1).into()),
                ciborium::Value::Integer(1.into()),
            ),
            (
                ciborium::Value::Integer((-2).into()),
                ciborium::Value::Bytes(vec![fill; 32]),
            ),
            (
                ciborium::Value::Integer((-3).into()),
                ciborium::Value::Bytes(vec![fill.wrapping_add(1); 32]),
            ),
        ])
    }

    fn transcript(reader_fill: u8) -> SessionTranscript {
        let de = DeviceEngagement::new(cose_key(0xaa)).unwrap();
        SessionTranscript::new_qr(&de, cose_key(reader_fill)).unwrap()
    }

    /// `#6.24(bstr)` header for a byte string of `len` bytes, written out by
    /// hand so the test does not reuse the code under test.
    fn tag24_header(len: usize) -> Vec<u8> {
        let mut header = vec![0xd8, 0x18];
        match len {
            0..=23 => header.push(0x40 | len as u8),
            24..=0xff => header.extend_from_slice(&[0x58, len as u8]),
            _ => {
                header.push(0x59);
                header.extend_from_slice(&(len as u16).to_be_bytes());
            }
        }
        header
    }

    #[test]
    fn salt_is_sha256_of_tagged_session_transcript() {
        let transcript = transcript(0xbb);
        let cbor = transcript.to_cbor_bytes().unwrap();
        let mut tagged = tag24_header(cbor.len());
        tagged.extend_from_slice(&cbor);

        assert_eq!(transcript.to_tagged_bytes().unwrap(), tagged);
        assert_eq!(
            transcript.hkdf_salt().unwrap().as_slice(),
            &Sha256::digest(&tagged)[..]
        );
    }

    #[test]
    fn session_keys_follow_iso_derivation() {
        let shared_secret = [0x11u8; 32];
        let transcript = transcript(0xbb);
        let cbor = transcript.to_cbor_bytes().unwrap();
        let mut tagged = tag24_header(cbor.len());
        tagged.extend_from_slice(&cbor);
        let salt = Sha256::digest(&tagged);

        let expected = |info: &[u8]| {
            let mut key = [0u8; 32];
            Hkdf::<Sha256>::new(Some(&salt[..]), &shared_secret)
                .expand(info, &mut key)
                .unwrap();
            key
        };

        let keys = SessionKeys::derive(&shared_secret, &transcript).unwrap();
        assert_eq!(keys.sk_device, expected(b"SKDevice"));
        assert_eq!(keys.sk_reader, expected(b"SKReader"));
        assert_eq!(
            derive_session_key(&shared_secret, &transcript, "SKReader").unwrap(),
            keys.sk_reader
        );
    }

    #[test]
    fn session_keys_do_not_use_the_untagged_transcript_as_salt() {
        let shared_secret = [0x11u8; 32];
        let transcript = transcript(0xbb);
        let untagged_salt = transcript.to_cbor_bytes().unwrap();

        let keys = SessionKeys::derive(&shared_secret, &transcript).unwrap();
        let mut previous = [0u8; 32];
        Hkdf::<Sha256>::new(Some(&untagged_salt), &shared_secret)
            .expand(b"SKDevice", &mut previous)
            .unwrap();
        assert_ne!(keys.sk_device, previous);
    }

    #[test]
    fn session_keys_depend_on_secret_and_transcript() {
        let base = SessionKeys::derive(b"secret-1", &transcript(0xbb)).unwrap();
        let other_secret = SessionKeys::derive(b"secret-2", &transcript(0xbb)).unwrap();
        let other_transcript = SessionKeys::derive(b"secret-1", &transcript(0xcc)).unwrap();
        let again = SessionKeys::derive(b"secret-1", &transcript(0xbb)).unwrap();

        assert_ne!(base.sk_device, base.sk_reader);
        assert_ne!(base.sk_device, other_secret.sk_device);
        assert_ne!(base.sk_device, other_transcript.sk_device);
        assert_eq!(base.sk_device, again.sk_device);
        assert_eq!(base.sk_reader, again.sk_reader);
    }

    #[test]
    fn session_nonce_layout() {
        assert_eq!(
            session_nonce(SessionRole::Reader, 1),
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        );
        assert_eq!(
            session_nonce(SessionRole::Device, 0x0102_0304),
            [0, 0, 0, 0, 0, 0, 0, 1, 1, 2, 3, 4]
        );
    }

    fn session_pair() -> (SessionEncryption, SessionEncryption) {
        let secret = [0x22u8; 32];
        let transcript = transcript(0xbb);
        (
            SessionEncryption::new(
                SessionKeys::derive(&secret, &transcript).unwrap(),
                SessionRole::Reader,
            ),
            SessionEncryption::new(
                SessionKeys::derive(&secret, &transcript).unwrap(),
                SessionRole::Device,
            ),
        )
    }

    #[test]
    fn session_encryption_round_trip_both_directions() {
        let (mut reader, mut device) = session_pair();

        let request = reader.encrypt(b"DeviceRequest").unwrap();
        assert_eq!(device.decrypt(&request).unwrap(), b"DeviceRequest");

        let response = device.encrypt(b"DeviceResponse").unwrap();
        assert_eq!(reader.decrypt(&response).unwrap(), b"DeviceResponse");

        let second = reader.encrypt(b"second request").unwrap();
        assert_eq!(device.decrypt(&second).unwrap(), b"second request");
    }

    #[test]
    fn session_encryption_uses_sender_key_and_counter_from_one() {
        let secret = [0x22u8; 32];
        let transcript = transcript(0xbb);
        let keys = SessionKeys::derive(&secret, &transcript).unwrap();
        let (mut reader, mut device) = session_pair();

        let from_reader = reader.encrypt(b"first").unwrap();
        assert_eq!(
            decrypt_aes256gcm(
                &keys.sk_reader,
                &session_nonce(SessionRole::Reader, 1),
                &from_reader
            )
            .unwrap(),
            b"first"
        );

        let from_device = device.encrypt(b"reply").unwrap();
        assert_eq!(
            decrypt_aes256gcm(
                &keys.sk_device,
                &session_nonce(SessionRole::Device, 1),
                &from_device
            )
            .unwrap(),
            b"reply"
        );
    }

    #[test]
    fn same_plaintext_twice_gives_different_ciphertexts() {
        let (mut reader, _) = session_pair();
        let first = reader.encrypt(b"same").unwrap();
        let second = reader.encrypt(b"same").unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn repeated_incoming_message_is_rejected() {
        let (mut reader, mut device) = session_pair();
        let request = reader.encrypt(b"once").unwrap();
        assert!(device.decrypt(&request).is_ok());
        assert!(device.decrypt(&request).is_err());
    }

    #[test]
    fn out_of_order_message_is_rejected_and_counter_kept() {
        let (mut reader, mut device) = session_pair();
        let first = reader.encrypt(b"first").unwrap();
        let second = reader.encrypt(b"second").unwrap();

        assert!(device.decrypt(&second).is_err());
        assert_eq!(device.decrypt(&first).unwrap(), b"first");
        assert_eq!(device.decrypt(&second).unwrap(), b"second");
    }

    #[test]
    fn own_messages_do_not_decrypt_as_peer_messages() {
        let (mut reader, _) = session_pair();
        let (mut other_reader, _) = session_pair();
        let request = reader.encrypt(b"to device").unwrap();
        assert!(other_reader.decrypt(&request).is_err());
    }

    #[test]
    fn exhausted_counter_is_an_error() {
        let (mut reader, _) = session_pair();
        reader.sent = u32::MAX;
        assert!(matches!(
            reader.encrypt(b"one too many"),
            Err(MdocError::Session(_))
        ));
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 32];
        let nonce = [0u8; 12];
        let plaintext = b"Hello, eIDAS 2.0 mdoc proximity!";

        let ciphertext = encrypt_aes256gcm(&key, &nonce, plaintext).unwrap();
        assert_ne!(ciphertext, plaintext.as_slice());
        assert_eq!(ciphertext.len(), plaintext.len() + 16);

        let decrypted = decrypt_aes256gcm(&key, &nonce, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_wrong_key_fails() {
        let nonce = [0u8; 12];
        let ciphertext = encrypt_aes256gcm(&[0x42u8; 32], &nonce, b"secret").unwrap();
        assert!(decrypt_aes256gcm(&[0x43u8; 32], &nonce, &ciphertext).is_err());
    }

    #[test]
    fn decrypt_wrong_nonce_fails() {
        let key = [0x42u8; 32];
        let ciphertext = encrypt_aes256gcm(&key, &[0u8; 12], b"secret").unwrap();
        assert!(decrypt_aes256gcm(&key, &[1u8; 12], &ciphertext).is_err());
    }

    #[test]
    fn decrypt_tampered_ciphertext_fails() {
        let key = [0x42u8; 32];
        let nonce = [0u8; 12];
        let mut ciphertext = encrypt_aes256gcm(&key, &nonce, b"secret").unwrap();
        ciphertext[0] ^= 0xFF;
        assert!(decrypt_aes256gcm(&key, &nonce, &ciphertext).is_err());
    }
}
