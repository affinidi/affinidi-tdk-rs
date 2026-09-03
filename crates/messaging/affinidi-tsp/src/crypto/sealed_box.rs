//! Libsodium sealed box, the second PKAE scheme TSP defines (Rev 3 §8.3).
//!
//! # Deprecated on arrival
//!
//! §8 keeps this scheme for implementations that already had it and tells new
//! ones otherwise: "implementors SHOULD consider migrating to the HPKE option
//! specified in this document. We MAY remove this option in the future." It is
//! here to *read* messages from peers that still send them, not as a choice
//! worth making. [`crate::crypto::hpke`] is the scheme to use.
//!
//! # Why it needs separate handling at all
//!
//! A sealed box is anonymous — the construction generates a throwaway keypair
//! and never involves the sender's own key, so nothing in the ciphertext says
//! who produced it. HPKE-Base is anonymous too, but TSP binds the sender into
//! its AAD; a sealed box has no AAD to bind. §8 therefore requires the sender
//! VID to travel *inside* the encrypted payload, and §3.7 step 7 has the
//! receiver check it against the envelope. Two payload rules follow, both
//! enforced by the packing code rather than here: `VID_sndr` must carry the
//! sender rather than the NULL VID, and the digest is Blake2b-256 under CESR
//! code `F` rather than SHA-256 under `I`.
//!
//! # The construction
//!
//! libsodium's `crypto_box_seal`, exactly:
//!
//! ```text
//! ephemeral_pk, ephemeral_sk = X25519 keypair, fresh per message
//! nonce  = Blake2b-192(ephemeral_pk ‖ recipient_pk)
//! key    = HSalsa20(X25519(ephemeral_sk, recipient_pk), 0^16)
//! sealed = ephemeral_pk ‖ Poly1305_MAC ‖ XSalsa20(plaintext)
//! ```
//!
//! Three details that a self-consistent implementation gets wrong silently,
//! because it agrees with itself and with nobody else:
//!
//! - **The HSalsa20 step is not optional.** The raw X25519 output is not the
//!   secretbox key. Skipping it round-trips perfectly and interoperates with
//!   nothing.
//! - **The MAC comes first.** libsodium's `crypto_box_easy` emits
//!   `MAC ‖ ciphertext`, where most AEAD APIs append the tag.
//! - **The nonce is derived, not random.** It is bound to both public keys,
//!   which is what makes a fixed nonce safe here: the ephemeral key is fresh
//!   per message, so the nonce cannot repeat under a given shared key.

use blake2::Blake2b;
use blake2::digest::Digest;
use blake2::digest::consts::{U10, U16, U24};
use crypto_secretbox::{AeadInPlace, KeyInit, XSalsa20Poly1305, aead::generic_array::GenericArray};
use rand_core::RngCore;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::error::TspError;

/// The XSalsa20-Poly1305 nonce length.
const NONCE_LEN: usize = 24;
/// Poly1305 tag length.
const MAC_LEN: usize = 16;
/// Bytes a sealed box adds to its plaintext: the ephemeral public key and the
/// MAC.
pub const SEAL_OVERHEAD: usize = 32 + MAC_LEN;

/// libsodium `crypto_box_beforenm`: `HSalsa20(X25519(sk, pk), 0^16)`.
///
/// An all-zero X25519 output means the peer supplied a small-order point, and
/// the "shared" secret is then a constant it knew in advance. libsodium rejects
/// that and so does this — otherwise an attacker-chosen public key forces a
/// known key.
fn shared_key(secret: &StaticSecret, public: &PublicKey) -> Result<Zeroizing<[u8; 32]>, TspError> {
    let shared = secret.diffie_hellman(public);
    if !shared.was_contributory() {
        return Err(TspError::SealedBox(
            "X25519 produced an all-zero shared secret (peer supplied a small-order point)".into(),
        ));
    }
    let derived = salsa20::hsalsa::<U10>(
        GenericArray::from_slice(shared.as_bytes()),
        &GenericArray::<u8, U16>::default(),
    );
    Ok(Zeroizing::new(derived.into()))
}

/// The sealed-box nonce: `Blake2b-192(ephemeral_pk ‖ recipient_pk)`.
fn seal_nonce(ephemeral_public: &[u8; 32], recipient_public: &[u8; 32]) -> [u8; NONCE_LEN] {
    let mut hasher = Blake2b::<U24>::new();
    hasher.update(ephemeral_public);
    hasher.update(recipient_public);
    hasher.finalize().into()
}

/// libsodium `crypto_box_seal`.
///
/// The ephemeral key is generated here and discarded. Reusing one across
/// messages would link them to a single sender, which is the property the
/// scheme exists to remove.
pub fn seal(plaintext: &[u8], recipient_public: &[u8; 32]) -> Result<Vec<u8>, TspError> {
    let mut ephemeral_secret = Zeroizing::new([0u8; 32]);
    rand_core::OsRng.fill_bytes(ephemeral_secret.as_mut());
    seal_with_ephemeral(plaintext, recipient_public, &ephemeral_secret)
}

/// [`seal`] with a caller-supplied ephemeral secret.
///
/// A sealed box is non-deterministic, so this is the only way to reproduce one
/// byte for byte — which the specification's own test vectors require, since
/// they publish `skEm` precisely so a vector can be regenerated rather than
/// only decrypted. Production callers want [`seal`].
pub fn seal_with_ephemeral(
    plaintext: &[u8],
    recipient_public: &[u8; 32],
    ephemeral_secret: &[u8; 32],
) -> Result<Vec<u8>, TspError> {
    let secret = StaticSecret::from(*ephemeral_secret);
    let ephemeral_public = PublicKey::from(&secret);
    let nonce = seal_nonce(ephemeral_public.as_bytes(), recipient_public);
    let key = shared_key(&secret, &PublicKey::from(*recipient_public))?;

    // libsodium emits MAC ‖ ciphertext, so the tag is written in front of the
    // encrypted bytes rather than appended.
    let cipher = XSalsa20Poly1305::new(GenericArray::from_slice(key.as_ref()));
    let mut buffer = plaintext.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(GenericArray::from_slice(&nonce), &[], &mut buffer)
        .map_err(|_| TspError::SealedBox("sealed box encryption failed".into()))?;

    let mut out = Vec::with_capacity(32 + MAC_LEN + buffer.len());
    out.extend_from_slice(ephemeral_public.as_bytes());
    out.extend_from_slice(&tag);
    out.extend_from_slice(&buffer);
    Ok(out)
}

/// libsodium `crypto_box_seal_open`.
pub fn open(
    sealed: &[u8],
    recipient_public: &[u8; 32],
    recipient_secret: &[u8; 32],
) -> Result<Vec<u8>, TspError> {
    if sealed.len() < SEAL_OVERHEAD {
        return Err(TspError::SealedBox(format!(
            "sealed box is {} bytes, shorter than its {SEAL_OVERHEAD}-byte overhead",
            sealed.len()
        )));
    }
    let (ephemeral_public, rest) = sealed.split_at(32);
    let ephemeral_public: [u8; 32] = ephemeral_public
        .try_into()
        .expect("split_at(32) yields exactly 32 bytes");
    let (mac, ciphertext) = rest.split_at(MAC_LEN);

    let nonce = seal_nonce(&ephemeral_public, recipient_public);
    let secret = StaticSecret::from(*recipient_secret);
    let key = shared_key(&secret, &PublicKey::from(ephemeral_public))?;

    let cipher = XSalsa20Poly1305::new(GenericArray::from_slice(key.as_ref()));
    let mut buffer = ciphertext.to_vec();
    cipher
        .decrypt_in_place_detached(
            GenericArray::from_slice(&nonce),
            &[],
            &mut buffer,
            GenericArray::from_slice(mac),
        )
        .map_err(|_| TspError::SealedBox("sealed box authentication failed".into()))?;
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair() -> ([u8; 32], [u8; 32]) {
        let mut sk = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut sk);
        let secret = StaticSecret::from(sk);
        (sk, PublicKey::from(&secret).to_bytes())
    }

    #[test]
    fn round_trips() {
        let (sk, pk) = keypair();
        let sealed = seal(b"hello world", &pk).unwrap();
        assert_eq!(sealed.len(), 11 + SEAL_OVERHEAD);
        assert_eq!(open(&sealed, &pk, &sk).unwrap(), b"hello world");
    }

    /// The ephemeral key is fresh per message, so two seals of the same
    /// plaintext to the same recipient share no bytes. That is the whole point
    /// of the scheme — a fixed ephemeral key would link every message to one
    /// sender.
    #[test]
    fn two_seals_of_the_same_plaintext_differ() {
        let (_, pk) = keypair();
        assert_ne!(seal(b"same", &pk).unwrap(), seal(b"same", &pk).unwrap());
    }

    /// A sealed box is anonymous: opening it needs only the recipient's own
    /// keys, and nothing in it identifies the sender. This is why §8 requires
    /// the sender VID inside the payload — there is nowhere else for it to
    /// live.
    #[test]
    fn opening_needs_no_sender_key() {
        let (sk, pk) = keypair();
        let sealed = seal(b"anonymous", &pk).unwrap();
        assert_eq!(open(&sealed, &pk, &sk).unwrap(), b"anonymous");
    }

    #[test]
    fn a_tampered_box_fails_to_open() {
        let (sk, pk) = keypair();
        let mut sealed = seal(b"hello", &pk).unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert!(open(&sealed, &pk, &sk).is_err());
    }

    /// A box sealed to one recipient does not open for another.
    #[test]
    fn a_box_for_someone_else_does_not_open() {
        let (_, pk_a) = keypair();
        let (sk_b, pk_b) = keypair();
        let sealed = seal(b"for a", &pk_a).unwrap();
        assert!(open(&sealed, &pk_b, &sk_b).is_err());
    }

    #[test]
    fn a_truncated_box_is_refused_by_length() {
        let (sk, pk) = keypair();
        assert!(open(&[0u8; SEAL_OVERHEAD - 1], &pk, &sk).is_err());
    }

    /// The nonce is a function of both public keys, so it is reproducible and
    /// binds the box to its recipient.
    #[test]
    fn the_nonce_binds_both_keys() {
        let (_, a) = keypair();
        let (_, b) = keypair();
        assert_eq!(seal_nonce(&a, &b), seal_nonce(&a, &b));
        assert_ne!(seal_nonce(&a, &b), seal_nonce(&b, &a));
    }
}
