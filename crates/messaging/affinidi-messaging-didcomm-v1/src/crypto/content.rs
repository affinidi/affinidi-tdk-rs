//! Content encryption for the RFC 0019 envelope body.
//!
//! # The `enc` header lies, and it matters
//!
//! An RFC 0019 protected header always reads:
//!
//! ```json
//! { "enc": "xchacha20poly1305_ietf", ... }
//! ```
//!
//! but the algorithm every deployed v1 agent actually uses is
//! **ChaCha20-Poly1305 IETF**, with a **12-byte** nonce — not XChaCha20 with a
//! 24-byte one. RFC 0019's own prose gives it away (it names
//! `crypto_aead_chacha20poly1305_ietf_encrypt_detached` two paragraphs below
//! the header that says `x…`), and Credo confirms it: its envelope service
//! writes the `xchacha20poly1305_ietf` string into the header and then calls
//! its KMS with `algorithm: 'C20P'`, which is 12-byte-nonce ChaCha20-Poly1305.
//!
//! Implementing what the header says produces envelopes with a 24-byte `iv`
//! that no Aries-lineage agent can open, and rejects every envelope they send.
//! So this module implements ChaCha20-Poly1305 IETF, and
//! [`ENC_ALGORITHM`] carries the misnomer verbatim because interop requires
//! emitting it and accepting it.
//!
//! This is a v1-only hazard: DIDComm v2.1 uses `A256CBC-HS512`, whose header
//! value and algorithm agree.

use chacha20poly1305::ChaCha20Poly1305;
use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use rand_10::Rng;
use zeroize::Zeroizing;

use crate::error::DIDCommV1Error;

/// The `enc` value RFC 0019 mandates in the protected header.
///
/// A misnomer — see the [module docs](self). The bytes on the wire are
/// ChaCha20-Poly1305 IETF regardless of what this string says.
pub const ENC_ALGORITHM: &str = "xchacha20poly1305_ietf";

/// Content encryption key length, in bytes.
pub const KEY_LEN: usize = 32;
/// Content encryption nonce length, in bytes. **12**, not 24 — see the
/// [module docs](self).
pub const NONCE_LEN: usize = 12;
/// Poly1305 tag length, in bytes.
pub const TAG_LEN: usize = 16;

/// A freshly generated content encryption key, zeroized on drop.
pub fn generate_cek() -> Zeroizing<[u8; KEY_LEN]> {
    let mut cek = Zeroizing::new([0u8; KEY_LEN]);
    rand_10::rng().fill_bytes(cek.as_mut());
    cek
}

/// A random content-encryption nonce.
pub fn random_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    rand_10::rng().fill_bytes(&mut nonce);
    nonce
}

/// Encrypt `plaintext` under `cek`, returning the detached `(ciphertext, tag)`.
///
/// `aad` is the base64url-encoded protected header **as ASCII bytes** — not the
/// decoded JSON. Binding the header this way is what stops an intermediary
/// rewriting a recipient entry or the `alg` without detection.
pub fn encrypt(
    cek: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; TAG_LEN]), DIDCommV1Error> {
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(cek));
    let mut buffer = plaintext.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(GenericArray::from_slice(nonce), aad, &mut buffer)
        .map_err(|_| {
            DIDCommV1Error::ContentEncryption("ChaCha20-Poly1305 encryption failed".into())
        })?;
    Ok((buffer, tag.into()))
}

/// Inverse of [`encrypt`]. Fails if `aad`, `tag`, or `cek` do not match.
pub fn decrypt(
    cek: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; TAG_LEN],
) -> Result<Vec<u8>, DIDCommV1Error> {
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(cek));
    let mut buffer = ciphertext.to_vec();
    cipher
        .decrypt_in_place_detached(
            GenericArray::from_slice(nonce),
            aad,
            &mut buffer,
            GenericArray::from_slice(tag),
        )
        .map_err(|_| {
            DIDCommV1Error::ContentEncryption("ChaCha20-Poly1305 authentication failed".into())
        })?;
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let cek = [4u8; KEY_LEN];
        let nonce = [5u8; NONCE_LEN];
        let aad = b"eyJhbGciOiJBdXRoY3J5cHQifQ";

        let (ciphertext, tag) = encrypt(&cek, &nonce, aad, b"the message").unwrap();
        let plaintext = decrypt(&cek, &nonce, aad, &ciphertext, &tag).unwrap();
        assert_eq!(plaintext, b"the message");
    }

    /// The AAD binds the protected header. Tampering with it — which is exactly
    /// what a mediator rewriting a recipient entry would do — must fail.
    #[test]
    fn rejects_modified_aad() {
        let cek = [4u8; KEY_LEN];
        let nonce = [5u8; NONCE_LEN];

        let (ciphertext, tag) = encrypt(&cek, &nonce, b"header-a", b"the message").unwrap();
        assert!(decrypt(&cek, &nonce, b"header-b", &ciphertext, &tag).is_err());
    }

    #[test]
    fn rejects_modified_tag() {
        let cek = [4u8; KEY_LEN];
        let nonce = [5u8; NONCE_LEN];

        let (ciphertext, mut tag) = encrypt(&cek, &nonce, b"aad", b"the message").unwrap();
        tag[0] ^= 0xff;
        assert!(decrypt(&cek, &nonce, b"aad", &ciphertext, &tag).is_err());
    }

    /// Guards the trap this module exists to document: the nonce is 12 bytes,
    /// despite the `enc` header naming XChaCha20 (which would be 24).
    #[test]
    fn nonce_is_twelve_bytes_despite_the_enc_header() {
        assert_eq!(NONCE_LEN, 12);
        assert_eq!(ENC_ALGORITHM, "xchacha20poly1305_ietf");
    }
}
