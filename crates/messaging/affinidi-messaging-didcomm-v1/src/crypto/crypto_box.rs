//! libsodium `crypto_box` and `crypto_box_seal`, over X25519 + XSalsa20-Poly1305.
//!
//! RFC 0019 wraps the content encryption key with these two primitives:
//! authcrypt uses `crypto_box` (the sender's key authenticates the wrap),
//! anoncrypt uses `crypto_box_seal` (an ephemeral sender, so nothing is
//! authenticated). Both are re-implemented here rather than pulled from the
//! RustCrypto `crypto_box` crate — see the [module docs](super) for why.
//!
//! # Wire layouts
//!
//! These match libsodium exactly, and both differ from the RustCrypto AEAD
//! default of a *trailing* tag:
//!
//! ```text
//! crypto_box_easy(m, n, pk, sk)  ->  MAC(16) || ciphertext
//! crypto_box_seal(m, pk)         ->  ephemeral_pk(32) || MAC(16) || ciphertext
//! ```
//!
//! Getting the MAC to the wrong end produces a value the same length as a
//! correct one that no other implementation can open, so [`kat`](self#tests)
//! pins both layouts against libsodium-generated vectors.

use blake2::Blake2b;
use blake2::Digest;
use crypto_secretbox::XSalsa20Poly1305;
use crypto_secretbox::aead::generic_array::GenericArray;
use crypto_secretbox::aead::generic_array::typenum::{U10, U16, U24};
use crypto_secretbox::aead::{AeadInPlace, KeyInit};
use rand_10::Rng;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::error::DIDCommV1Error;

/// Length of a `crypto_box` nonce, in bytes.
pub const NONCE_LEN: usize = 24;
/// Length of the Poly1305 authentication tag, in bytes.
pub const MAC_LEN: usize = 16;
/// Bytes a sealed box adds to its plaintext: an ephemeral public key plus a MAC.
pub const SEAL_OVERHEAD: usize = 32 + MAC_LEN;

/// Derive the `crypto_box` shared key: `HSalsa20(X25519(sk, pk), 0^16)`.
///
/// This is libsodium's `crypto_box_beforenm`. The HSalsa20 step is not
/// optional decoration — the raw X25519 output is *not* the secretbox key, and
/// skipping it yields a self-consistent implementation that cannot talk to any
/// other agent.
///
/// # Security
///
/// An all-zero X25519 output means the peer supplied a small-order point, and
/// the "shared" secret is then a constant the peer knows in advance. libsodium
/// rejects that (`crypto_scalarmult` returns -1) and so does this: the
/// `was_contributory` check below is what stops an attacker-chosen public key
/// from forcing a known CEK-wrapping key.
fn shared_key(
    secret: &StaticSecret,
    public: &PublicKey,
) -> Result<Zeroizing<[u8; 32]>, DIDCommV1Error> {
    let shared = secret.diffie_hellman(public);
    if !shared.was_contributory() {
        return Err(DIDCommV1Error::KeyAgreement(
            "X25519 produced an all-zero shared secret (peer supplied a small-order point)".into(),
        ));
    }
    let derived = salsa20::hsalsa::<U10>(
        GenericArray::from_slice(shared.as_bytes()),
        &GenericArray::<u8, U16>::default(),
    );
    Ok(Zeroizing::new(derived.into()))
}

/// XSalsa20-Poly1305 under a raw key, emitting libsodium's `MAC || ciphertext`.
fn secretbox_easy(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>, DIDCommV1Error> {
    let cipher = XSalsa20Poly1305::new(GenericArray::from_slice(key));
    let mut buffer = plaintext.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(GenericArray::from_slice(nonce), &[], &mut buffer)
        .map_err(|_| DIDCommV1Error::KeyWrap("XSalsa20-Poly1305 encryption failed".into()))?;

    // libsodium prepends the MAC; the RustCrypto `Aead::encrypt` convenience
    // method would append it. Assemble the libsodium order explicitly.
    let mut out = Vec::with_capacity(MAC_LEN + buffer.len());
    out.extend_from_slice(&tag);
    out.extend_from_slice(&buffer);
    Ok(out)
}

/// Inverse of [`secretbox_easy`].
fn secretbox_open_easy(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    boxed: &[u8],
) -> Result<Vec<u8>, DIDCommV1Error> {
    if boxed.len() < MAC_LEN {
        return Err(DIDCommV1Error::KeyWrap(format!(
            "boxed value is {} bytes, shorter than the {MAC_LEN}-byte MAC",
            boxed.len()
        )));
    }
    let (tag, ciphertext) = boxed.split_at(MAC_LEN);
    let cipher = XSalsa20Poly1305::new(GenericArray::from_slice(key));
    let mut buffer = ciphertext.to_vec();
    cipher
        .decrypt_in_place_detached(
            GenericArray::from_slice(nonce),
            &[],
            &mut buffer,
            GenericArray::from_slice(tag),
        )
        .map_err(|_| DIDCommV1Error::KeyWrap("XSalsa20-Poly1305 authentication failed".into()))?;
    Ok(buffer)
}

/// libsodium `crypto_box_easy`: authenticated encryption from `sender_secret`
/// to `recipient_public`. Returns `MAC || ciphertext`.
pub fn seal_authenticated(
    plaintext: &[u8],
    nonce: &[u8; NONCE_LEN],
    recipient_public: &[u8; 32],
    sender_secret: &[u8; 32],
) -> Result<Vec<u8>, DIDCommV1Error> {
    let secret = StaticSecret::from(*sender_secret);
    let key = shared_key(&secret, &PublicKey::from(*recipient_public))?;
    secretbox_easy(&key, nonce, plaintext)
}

/// libsodium `crypto_box_open_easy`: the inverse of [`seal_authenticated`].
///
/// Success is what authenticates the sender: only a holder of the secret key
/// matching `sender_public` could have produced a value that opens under this
/// shared key. That is the whole basis of v1 authcrypt.
pub fn open_authenticated(
    boxed: &[u8],
    nonce: &[u8; NONCE_LEN],
    sender_public: &[u8; 32],
    recipient_secret: &[u8; 32],
) -> Result<Vec<u8>, DIDCommV1Error> {
    let secret = StaticSecret::from(*recipient_secret);
    let key = shared_key(&secret, &PublicKey::from(*sender_public))?;
    secretbox_open_easy(&key, nonce, boxed)
}

/// libsodium `crypto_box_seal`: anonymous encryption to `recipient_public`.
///
/// Generates a single-use keypair, derives the nonce as
/// `Blake2b-192(ephemeral_pk || recipient_pk)`, and returns
/// `ephemeral_pk || MAC || ciphertext`. The recipient can decrypt but learns
/// nothing about who sent it — which is exactly why an anoncrypt v1 message
/// has no authenticated sender to route a reply or an error to.
pub fn seal_anonymous(
    plaintext: &[u8],
    recipient_public: &[u8; 32],
) -> Result<Vec<u8>, DIDCommV1Error> {
    let mut ephemeral_secret = Zeroizing::new([0u8; 32]);
    rand_10::rng().fill_bytes(ephemeral_secret.as_mut());
    seal_anonymous_with_ephemeral(plaintext, recipient_public, &ephemeral_secret)
}

/// [`seal_anonymous`] with a caller-supplied ephemeral secret.
///
/// Exposed so a test can produce a byte-exact envelope to compare against a
/// vector from another implementation; a sealed box is otherwise
/// non-deterministic and can only be checked by round-tripping. Production
/// callers want [`seal_anonymous`], which generates the ephemeral key itself —
/// reusing one across messages links them to a single sender and defeats the
/// point of anoncrypt.
pub fn seal_anonymous_with_ephemeral(
    plaintext: &[u8],
    recipient_public: &[u8; 32],
    ephemeral_secret: &[u8; 32],
) -> Result<Vec<u8>, DIDCommV1Error> {
    let secret = StaticSecret::from(*ephemeral_secret);
    let ephemeral_public = PublicKey::from(&secret);
    let nonce = seal_nonce(ephemeral_public.as_bytes(), recipient_public);

    let key = shared_key(&secret, &PublicKey::from(*recipient_public))?;
    let body = secretbox_easy(&key, &nonce, plaintext)?;

    let mut out = Vec::with_capacity(32 + body.len());
    out.extend_from_slice(ephemeral_public.as_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

/// libsodium `crypto_box_seal_open`: the inverse of [`seal_anonymous`].
pub fn open_anonymous(
    sealed: &[u8],
    recipient_public: &[u8; 32],
    recipient_secret: &[u8; 32],
) -> Result<Vec<u8>, DIDCommV1Error> {
    if sealed.len() < SEAL_OVERHEAD {
        return Err(DIDCommV1Error::KeyWrap(format!(
            "sealed box is {} bytes, shorter than its {SEAL_OVERHEAD}-byte overhead",
            sealed.len()
        )));
    }
    let (ephemeral_public, body) = sealed.split_at(32);
    let ephemeral_public: [u8; 32] = ephemeral_public
        .try_into()
        .expect("split_at(32) yields exactly 32 bytes");

    let nonce = seal_nonce(&ephemeral_public, recipient_public);
    let secret = StaticSecret::from(*recipient_secret);
    let key = shared_key(&secret, &PublicKey::from(ephemeral_public))?;
    secretbox_open_easy(&key, &nonce, body)
}

/// The sealed-box nonce: `Blake2b-192(ephemeral_pk || recipient_pk)`.
///
/// Binding the nonce to both keys is what makes a sealed box safe without a
/// random nonce — the ephemeral key is fresh per message, so the nonce cannot
/// repeat under a given shared key.
fn seal_nonce(ephemeral_public: &[u8; 32], recipient_public: &[u8; 32]) -> [u8; NONCE_LEN] {
    let mut hasher = Blake2b::<U24>::new();
    hasher.update(ephemeral_public);
    hasher.update(recipient_public);
    hasher.finalize().into()
}

/// A random `crypto_box` nonce.
pub fn random_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    rand_10::rng().fill_bytes(&mut nonce);
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Vectors produced by libsodium (`libsodium-wrappers` 0.7) for the fixed
    /// inputs below. These pin the two things a self-consistent-but-wrong
    /// implementation gets away with: the HSalsa20 key-derivation step, and
    /// the MAC-first byte order.
    mod kat {
        pub const SENDER_SECRET: [u8; 32] = [1u8; 32];
        pub const RECIPIENT_SECRET: [u8; 32] = [2u8; 32];
        pub const NONCE: [u8; 24] = [3u8; 24];
        pub const MESSAGE: [u8; 32] = [9u8; 32];

        /// `crypto_box_beforenm(recipient_pk, sender_sk)`.
        pub const SHARED_KEY_HEX: &str =
            "18a99320f3488fa18a04239715d8ee738065e65c3d4b2898522d6c3d4ead588c";
        /// `crypto_box_easy(MESSAGE, NONCE, recipient_pk, SENDER_SECRET)`.
        pub const BOXED_HEX: &str = "5aa024f58876fef951f473cb57604f30ea227606221f33a72d092f7e73a3c9f2c353a9bc611d03ed5f52ba4f7b6c733a";
        /// The Poly1305 tag alone, from `crypto_secretbox_detached`.
        pub const MAC_HEX: &str = "5aa024f58876fef951f473cb57604f30";
    }

    fn public_of(secret: &[u8; 32]) -> [u8; 32] {
        PublicKey::from(&StaticSecret::from(*secret)).to_bytes()
    }

    #[test]
    fn shared_key_matches_libsodium_beforenm() {
        let recipient_public = public_of(&kat::RECIPIENT_SECRET);
        let key = shared_key(
            &StaticSecret::from(kat::SENDER_SECRET),
            &PublicKey::from(recipient_public),
        )
        .unwrap();
        assert_eq!(
            hex::encode(key.as_ref()),
            kat::SHARED_KEY_HEX,
            "HSalsa20(X25519(sk, pk), 0^16) must equal libsodium's crypto_box_beforenm"
        );
    }

    #[test]
    fn crypto_box_matches_libsodium_and_is_mac_first() {
        let recipient_public = public_of(&kat::RECIPIENT_SECRET);
        let boxed = seal_authenticated(
            &kat::MESSAGE,
            &kat::NONCE,
            &recipient_public,
            &kat::SENDER_SECRET,
        )
        .unwrap();

        assert_eq!(hex::encode(&boxed), kat::BOXED_HEX);
        assert!(
            hex::encode(&boxed).starts_with(kat::MAC_HEX),
            "libsodium puts the MAC first; a trailing tag is silently incompatible"
        );
    }

    #[test]
    fn crypto_box_roundtrip() {
        let sender_public = public_of(&kat::SENDER_SECRET);
        let recipient_public = public_of(&kat::RECIPIENT_SECRET);

        let boxed = seal_authenticated(
            b"hello v1",
            &kat::NONCE,
            &recipient_public,
            &kat::SENDER_SECRET,
        )
        .unwrap();
        let opened =
            open_authenticated(&boxed, &kat::NONCE, &sender_public, &kat::RECIPIENT_SECRET)
                .unwrap();
        assert_eq!(opened, b"hello v1");
    }

    #[test]
    fn crypto_box_open_rejects_a_different_sender() {
        let recipient_public = public_of(&kat::RECIPIENT_SECRET);
        let wrong_sender = public_of(&[7u8; 32]);

        let boxed = seal_authenticated(
            b"hello",
            &kat::NONCE,
            &recipient_public,
            &kat::SENDER_SECRET,
        )
        .unwrap();
        assert!(
            open_authenticated(&boxed, &kat::NONCE, &wrong_sender, &kat::RECIPIENT_SECRET).is_err(),
            "opening under the wrong sender key must fail — this is what authenticates authcrypt"
        );
    }

    #[test]
    fn sealed_box_roundtrip_and_layout() {
        let recipient_public = public_of(&kat::RECIPIENT_SECRET);
        let sealed = seal_anonymous(b"anonymous", &recipient_public).unwrap();

        assert_eq!(sealed.len(), b"anonymous".len() + SEAL_OVERHEAD);
        let opened = open_anonymous(&sealed, &recipient_public, &kat::RECIPIENT_SECRET).unwrap();
        assert_eq!(opened, b"anonymous");
    }

    /// libsodium: `crypto_box_seal` body is `crypto_box_easy` under a nonce of
    /// `Blake2b-192(epk || rpk)`. Verified here by opening the body with the
    /// authenticated path, using the derived nonce and the embedded ephemeral
    /// key — if the nonce derivation were wrong this would fail.
    #[test]
    fn sealed_box_body_is_crypto_box_under_blake2b_nonce() {
        let recipient_public = public_of(&kat::RECIPIENT_SECRET);
        let sealed = seal_anonymous(b"anonymous", &recipient_public).unwrap();

        let ephemeral_public: [u8; 32] = sealed[..32].try_into().unwrap();
        let nonce = seal_nonce(&ephemeral_public, &recipient_public);
        let opened = open_authenticated(
            &sealed[32..],
            &nonce,
            &ephemeral_public,
            &kat::RECIPIENT_SECRET,
        )
        .unwrap();
        assert_eq!(opened, b"anonymous");
    }

    #[test]
    fn sealed_box_is_non_deterministic() {
        let recipient_public = public_of(&kat::RECIPIENT_SECRET);
        let a = seal_anonymous(b"same", &recipient_public).unwrap();
        let b = seal_anonymous(b"same", &recipient_public).unwrap();
        assert_ne!(a, b, "each sealed box must use a fresh ephemeral key");
    }

    #[test]
    fn rejects_small_order_public_key() {
        // The canonical all-zero small-order point: X25519 against it yields an
        // all-zero "shared" secret that the peer knows in advance.
        let small_order = [0u8; 32];
        let err =
            seal_authenticated(b"x", &kat::NONCE, &small_order, &kat::SENDER_SECRET).unwrap_err();
        assert!(matches!(err, DIDCommV1Error::KeyAgreement(_)));
    }

    #[test]
    fn open_rejects_truncated_input() {
        let recipient_public = public_of(&kat::RECIPIENT_SECRET);
        assert!(open_anonymous(&[0u8; 10], &recipient_public, &kat::RECIPIENT_SECRET).is_err());
        assert!(
            open_authenticated(
                &[0u8; 4],
                &kat::NONCE,
                &recipient_public,
                &kat::RECIPIENT_SECRET
            )
            .is_err()
        );
    }
}
