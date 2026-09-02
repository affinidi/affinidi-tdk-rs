//! HPKE-Base implementation using primitives.
//!
//! Suite: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305, **Base**
//! mode — the only PKAE configuration TSP spec Rev 3 §8 mandates.
//!
//! Rev 2 required HPKE-Auth, and this module implemented it. Rev 3 removes that
//! mode outright, and with it the receiver's ability to check at the HPKE layer
//! that the sender held a given KEM private key. That check is not lost, it
//! moves: sender authenticity now rests on the TSP signature over the envelope
//! and payload, and the ESSR binding of the ciphertext to the sender's identity
//! is carried by the associated data, which names `VID_sndr`. A ciphertext that
//! does not open under the receiver-computed `aad` MUST be rejected — which is
//! what makes passing the AAD correctly a security-relevant detail here rather
//! than a formality.
//!
//! Two inputs therefore changed meaning as well as value. `aad` was empty and is
//! now `CONCAT(TSP_Version, VID_sndr, VID_rcvr)`; `info` was the envelope frame
//! and is now the fixed protocol code `YTSP-`.
//!
//! This implements only the specific HPKE suite required by TSP, built from
//! standard cryptographic primitives rather than a generic HPKE library.

use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, KeyInit, aead::generic_array::GenericArray};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::error::TspError;

// HPKE constants for our suite
const MODE_BASE: u8 = 0x00;

const N_SECRET: usize = 32; // KEM shared secret size
const N_K: usize = 32; // ChaCha20Poly1305 key size
const N_N: usize = 12; // ChaCha20Poly1305 nonce size
const N_H: usize = 32; // HKDF-SHA256 hash output size

/// Result of HPKE-Base sealing.
pub struct SealResult {
    /// The encapsulated key (32 bytes, X25519 ephemeral public key).
    pub enc: [u8; 32],
    /// The ciphertext (plaintext + 16-byte Poly1305 tag).
    pub ciphertext: Vec<u8>,
}

/// Seal (encrypt) a plaintext for a recipient — `SealBase` in RFC 9180 terms.
///
/// Base mode does not authenticate the sender at the HPKE layer. In TSP that
/// role is filled by the signature over the message plus the `aad`, which binds
/// the ciphertext to `VID_sndr`; see the module docs.
///
/// # Nonce safety
///
/// Each call to `seal()` generates a fresh ephemeral X25519 keypair inside
/// [`encap`]. Because the ephemeral secret key is unique per call, the ECDH
/// shared secret is unique, and therefore [`key_schedule`] derives a unique
/// `(key, base_nonce)` pair for every message. The `base_nonce` is used exactly
/// once (sequence number 0) and then discarded, so there is no nonce reuse even
/// though we do not maintain an explicit counter.
///
/// # Arguments
/// * `plaintext` - The data to encrypt
/// * `aad` - Associated data; for TSP, `TSP_Version ‖ VID_sndr ‖ VID_rcvr`
/// * `recipient_pk` - Recipient's X25519 public key (32 bytes)
/// * `info` - Context info; for TSP, the protocol code `YTSP-`
pub fn seal(
    plaintext: &[u8],
    aad: &[u8],
    recipient_pk: &[u8; 32],
    info: &[u8],
) -> Result<SealResult, TspError> {
    let pk_r = PublicKey::from(*recipient_pk);

    let (shared_secret, enc) = encap(&pk_r)?;
    let (key, base_nonce) = key_schedule(&shared_secret, info)?;

    let mut ciphertext = plaintext.to_vec();
    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| TspError::Hpke(format!("ChaCha20Poly1305 invalid key: {e}")))?;
    let nonce = GenericArray::from(base_nonce);
    cipher
        .encrypt_in_place(&nonce, aad, &mut ciphertext)
        .map_err(|e| TspError::Hpke(format!("ChaCha20Poly1305 seal failed: {e}")))?;

    Ok(SealResult { enc, ciphertext })
}

/// Open (decrypt) a ciphertext — `OpenBase` in RFC 9180 terms.
///
/// The caller must compute `aad` from the receiver's own view of the envelope,
/// per Rev 3 §8: `VID_rcvr` is taken from local state (or checked for equality
/// against the message), and a ciphertext that does not open under that `aad`
/// is rejected. That check is what carries the ESSR sender binding in Base mode.
///
/// # Nonce safety
///
/// The `enc` field carries the sender's ephemeral public key, which is unique
/// per message. [`decap`] uses it to recover the same unique shared secret that
/// was produced by `seal`, so the derived `(key, base_nonce)` pair is equally
/// unique and used only once.
///
/// # Arguments
/// * `ciphertext` - The encrypted data (including 16-byte Poly1305 tag)
/// * `aad` - Associated data; must match what the sender used
/// * `enc` - The encapsulated key from the sender
/// * `recipient_sk` - Recipient's X25519 private key (32 bytes)
/// * `info` - Context info; must match what the sender used
pub fn open(
    ciphertext: &[u8],
    aad: &[u8],
    enc: &[u8; 32],
    recipient_sk: &[u8; 32],
    info: &[u8],
) -> Result<Vec<u8>, TspError> {
    let sk_r = StaticSecret::from(*recipient_sk);

    let shared_secret = decap(enc, &sk_r)?;
    let (key, base_nonce) = key_schedule(&shared_secret, info)?;

    let mut plaintext = ciphertext.to_vec();
    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| TspError::Hpke(format!("ChaCha20Poly1305 invalid key: {e}")))?;
    let nonce = GenericArray::from(base_nonce);
    cipher
        .decrypt_in_place(&nonce, aad, &mut plaintext)
        .map_err(|_| {
            TspError::Hpke("ChaCha20Poly1305 open failed: authentication tag mismatch".into())
        })?;

    Ok(plaintext)
}

/// Encap: generate a shared secret for the recipient (RFC 9180 §4.1, Base).
///
/// 1. Generate an ephemeral X25519 keypair
/// 2. One DH, ephemeral→recipient
/// 3. Derive the shared secret over `enc ‖ pkRm`
///
/// Base mode differs from Auth in both halves: one DH instead of two, and a
/// KEM context of `enc ‖ pkRm` rather than `enc ‖ pkRm ‖ pkSm`. The sender's
/// static key does not participate at all.
fn encap(pk_r: &PublicKey) -> Result<([u8; N_SECRET], [u8; 32]), TspError> {
    let sk_e = StaticSecret::random_from_rng(&mut rand_10::rng());
    let pk_e = PublicKey::from(&sk_e);

    let mut dh = *sk_e.diffie_hellman(pk_r).as_bytes();

    let enc = pk_e.to_bytes();
    let mut kem_context = [0u8; 64]; // enc || pkRm
    kem_context[..32].copy_from_slice(&enc);
    kem_context[32..].copy_from_slice(pk_r.as_bytes());

    let shared_secret = extract_and_expand(&dh, &kem_context)?;
    dh.zeroize();

    Ok((shared_secret, enc))
}

/// Decap: recover the shared secret using the recipient's private key.
fn decap(enc: &[u8; 32], sk_r: &StaticSecret) -> Result<[u8; N_SECRET], TspError> {
    let pk_e = PublicKey::from(*enc);
    let pk_r = PublicKey::from(sk_r);

    let mut dh = *sk_r.diffie_hellman(&pk_e).as_bytes();

    let mut kem_context = [0u8; 64]; // enc || pkRm
    kem_context[..32].copy_from_slice(enc);
    kem_context[32..].copy_from_slice(pk_r.as_bytes());

    let shared_secret = extract_and_expand(&dh, &kem_context)?;
    dh.zeroize();

    Ok(shared_secret)
}

/// KEM ExtractAndExpand (RFC 9180 §4.1)
fn extract_and_expand(dh: &[u8], kem_context: &[u8]) -> Result<[u8; N_SECRET], TspError> {
    let kem_suite_id = KEM_SUITE_ID;

    // eae_prk = LabeledExtract("", "eae_prk", dh)  (RFC 9180 §4.1)
    let prk = labeled_extract(kem_suite_id, &[], b"eae_prk", dh)?;

    // shared_secret = LabeledExpand(eae_prk, "shared_secret", kem_context, Nsecret)
    let mut shared_secret = [0u8; N_SECRET];
    labeled_expand(
        kem_suite_id,
        &prk,
        b"shared_secret",
        kem_context,
        &mut shared_secret,
    )?;

    Ok(shared_secret)
}

/// HPKE KeySchedule (RFC 9180 §5.1) — derives encryption key and nonce.
fn key_schedule(
    shared_secret: &[u8; N_SECRET],
    info: &[u8],
) -> Result<([u8; N_K], [u8; N_N]), TspError> {
    let suite_id = HPKE_SUITE_ID;

    // For Base mode without PSK: psk = "" and psk_id = ""
    let psk = b"";
    let psk_id = b"";

    // psk_id_hash = LabeledExtract("", "psk_id_hash", psk_id)
    let psk_id_hash = labeled_extract(suite_id, &[], b"psk_id_hash", psk_id)?;

    // info_hash = LabeledExtract("", "info_hash", info)
    let info_hash = labeled_extract(suite_id, &[], b"info_hash", info)?;

    // ks_context = mode || psk_id_hash || info_hash (1 + 32 + 32 = 65 bytes, fixed size)
    let mut ks_context = [0u8; 1 + N_H + N_H];
    ks_context[0] = MODE_BASE;
    ks_context[1..1 + N_H].copy_from_slice(&psk_id_hash);
    ks_context[1 + N_H..].copy_from_slice(&info_hash);

    // secret = LabeledExtract(shared_secret, "secret", psk)
    let secret = labeled_extract(suite_id, shared_secret, b"secret", psk)?;

    // key = LabeledExpand(secret, "key", ks_context, Nk)
    let mut key = [0u8; N_K];
    labeled_expand(suite_id, &secret, b"key", &ks_context, &mut key)?;

    // base_nonce = LabeledExpand(secret, "base_nonce", ks_context, Nn)
    let mut base_nonce = [0u8; N_N];
    labeled_expand(
        suite_id,
        &secret,
        b"base_nonce",
        &ks_context,
        &mut base_nonce,
    )?;

    Ok((key, base_nonce))
}

/// LabeledExtract (RFC 9180 §4)
/// labeled_ikm = "HPKE-v1" || suite_id || label || ikm
/// return Extract(salt, labeled_ikm)
fn labeled_extract(
    suite_id: &[u8],
    salt: &[u8],
    label: &[u8],
    ikm: &[u8],
) -> Result<[u8; N_H], TspError> {
    let mut labeled_ikm = Vec::with_capacity(7 + suite_id.len() + label.len() + ikm.len());
    labeled_ikm.extend_from_slice(b"HPKE-v1");
    labeled_ikm.extend_from_slice(suite_id);
    labeled_ikm.extend_from_slice(label);
    labeled_ikm.extend_from_slice(ikm);

    // HKDF-Extract: RFC 9180 LabeledExtract returns the PRK = Extract(salt, labeled_ikm)
    // directly (NOT Expand(PRK, "")). Use Hkdf::extract to get the raw PRK.
    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), &labeled_ikm);
    let mut out = [0u8; N_H];
    out.copy_from_slice(&prk);

    Ok(out)
}

/// LabeledExpand (RFC 9180 §4)
/// labeled_info = I2OSP(L, 2) || "HPKE-v1" || suite_id || label || info
/// return Expand(prk, labeled_info, L)
fn labeled_expand(
    suite_id: &[u8],
    prk: &[u8],
    label: &[u8],
    info: &[u8],
    out: &mut [u8],
) -> Result<(), TspError> {
    let length = out.len() as u16;

    let mut labeled_info = Vec::with_capacity(2 + 7 + suite_id.len() + label.len() + info.len());
    labeled_info.extend_from_slice(&length.to_be_bytes());
    labeled_info.extend_from_slice(b"HPKE-v1");
    labeled_info.extend_from_slice(suite_id);
    labeled_info.extend_from_slice(label);
    labeled_info.extend_from_slice(info);

    // HKDF-Expand using prk as the PRK directly
    let hkdf = Hkdf::<Sha256>::from_prk(prk)
        .map_err(|e| TspError::Hpke(format!("HKDF from_prk failed: {e}")))?;
    hkdf.expand(&labeled_info, out)
        .map_err(|e| TspError::Hpke(format!("HKDF expand failed: {e}")))?;

    Ok(())
}

/// KEM suite ID: "KEM" || I2OSP(kem_id, 2)
const KEM_SUITE_ID: &[u8] = b"KEM\x00\x20";

/// HPKE suite ID: "HPKE" || I2OSP(kem_id, 2) || I2OSP(kdf_id, 2) || I2OSP(aead_id, 2)
/// = HPKE || 0x0020 (DHKEM X25519) || 0x0001 (HKDF-SHA256) || 0x0003 (ChaCha20Poly1305).
const HPKE_SUITE_ID: &[u8] = b"HPKE\x00\x20\x00\x01\x00\x03";

#[cfg(test)]
mod tests {
    use super::*;

    fn hex32(s: &str) -> [u8; 32] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    /// RFC 9180 Appendix A.2 — mode_base, DHKEM(X25519, HKDF-SHA256),
    /// HKDF-SHA256, ChaCha20Poly1305. This is exactly the suite TSP Rev 3 §8
    /// mandates, so the official vector pins our whole Base-mode path: decap,
    /// the key schedule, and the AEAD.
    ///
    /// A round-trip test cannot do this job. `seal` and `open` share every
    /// derivation, so they agree with each other under a wrong mode byte, a
    /// wrong KEM context, or a wrong label just as readily as under a right
    /// one — which is precisely how a Rev 2 implementation could look healthy
    /// while speaking a protocol no one else speaks.
    #[test]
    fn rfc9180_a2_base_mode_known_answer() {
        let sk_rm = hex32("8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb");
        let enc = hex32("1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a");
        let info = hex::decode("4f6465206f6e2061204772656369616e2055726e").unwrap();
        let aad = hex::decode("436f756e742d30").unwrap();
        let ct = hex::decode(
            "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28",
        )
        .unwrap();
        let expected_pt =
            hex::decode("4265617574792069732074727574682c20747275746820626561757479").unwrap();

        let pt = open(&ct, &aad, &enc, &sk_rm, &info).unwrap();
        assert_eq!(pt, expected_pt);
    }

    /// The same vector's intermediate values, checked individually so a failure
    /// says *which* stage drifted rather than only that decryption failed.
    #[test]
    fn rfc9180_a2_shared_secret_and_key_schedule() {
        let sk_rm = hex32("8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb");
        let enc = hex32("1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a");
        let info = hex::decode("4f6465206f6e2061204772656369616e2055726e").unwrap();

        let shared_secret = decap(&enc, &StaticSecret::from(sk_rm)).unwrap();
        assert_eq!(
            hex::encode(shared_secret),
            "0bbe78490412b4bbea4812666f7916932b828bba79942424abb65244930d69a7",
        );

        let (key, base_nonce) = key_schedule(&shared_secret, &info).unwrap();
        assert_eq!(
            hex::encode(key),
            "ad2744de8e17f4ebba575b3f5f5a8fa1f69c2a07f6e7500bc60ca6e3e3ec1c91",
        );
        assert_eq!(hex::encode(base_nonce), "5c4d98150661b848853b547f");
    }

    #[test]
    fn seal_open_roundtrip() {
        let recipient_sk = StaticSecret::random_from_rng(&mut rand_10::rng());
        let recipient_pk = PublicKey::from(&recipient_sk);

        let plaintext = b"Hello, TSP!";
        let aad = b"version|sender|receiver";
        let info = crate::message::wire::TSP_INFO;

        let sealed = seal(plaintext, aad, recipient_pk.as_bytes(), info).unwrap();
        assert_eq!(sealed.ciphertext.len(), plaintext.len() + 16);

        let opened = open(
            &sealed.ciphertext,
            aad,
            &sealed.enc,
            &recipient_sk.to_bytes(),
            info,
        )
        .unwrap();
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn wrong_recipient_key_fails() {
        let recipient_sk = StaticSecret::random_from_rng(&mut rand_10::rng());
        let recipient_pk = PublicKey::from(&recipient_sk);
        let wrong_sk = StaticSecret::random_from_rng(&mut rand_10::rng());

        let sealed = seal(b"secret", b"aad", recipient_pk.as_bytes(), b"").unwrap();

        assert!(
            open(
                &sealed.ciphertext,
                b"aad",
                &sealed.enc,
                &wrong_sk.to_bytes(),
                b"",
            )
            .is_err()
        );
    }

    /// The AAD is where the ESSR sender binding lives in Base mode: it names
    /// `VID_sndr`, so a receiver that computes it from its own view of the
    /// envelope cannot open a ciphertext sealed for a different sender.
    #[test]
    fn tampered_aad_fails() {
        let recipient_sk = StaticSecret::random_from_rng(&mut rand_10::rng());
        let recipient_pk = PublicKey::from(&recipient_sk);

        let sealed = seal(b"secret", b"original-aad", recipient_pk.as_bytes(), b"").unwrap();

        assert!(
            open(
                &sealed.ciphertext,
                b"tampered-aad",
                &sealed.enc,
                &recipient_sk.to_bytes(),
                b"",
            )
            .is_err()
        );
    }

    #[test]
    fn mismatched_info_fails() {
        let recipient_sk = StaticSecret::random_from_rng(&mut rand_10::rng());
        let recipient_pk = PublicKey::from(&recipient_sk);

        let sealed = seal(b"secret", b"aad", recipient_pk.as_bytes(), b"YTSP-").unwrap();

        assert!(
            open(
                &sealed.ciphertext,
                b"aad",
                &sealed.enc,
                &recipient_sk.to_bytes(),
                b"OTHER",
            )
            .is_err()
        );
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let recipient_sk = StaticSecret::random_from_rng(&mut rand_10::rng());
        let recipient_pk = PublicKey::from(&recipient_sk);

        let sealed = seal(b"secret", b"aad", recipient_pk.as_bytes(), b"").unwrap();

        let mut tampered = sealed.ciphertext.clone();
        tampered[0] ^= 0xFF;

        assert!(
            open(
                &tampered,
                b"aad",
                &sealed.enc,
                &recipient_sk.to_bytes(),
                b"",
            )
            .is_err()
        );
    }

    #[test]
    fn empty_plaintext() {
        let recipient_sk = StaticSecret::random_from_rng(&mut rand_10::rng());
        let recipient_pk = PublicKey::from(&recipient_sk);

        let sealed = seal(b"", b"aad", recipient_pk.as_bytes(), b"info").unwrap();
        assert_eq!(sealed.ciphertext.len(), 16); // just the tag

        let opened = open(
            &sealed.ciphertext,
            b"aad",
            &sealed.enc,
            &recipient_sk.to_bytes(),
            b"info",
        )
        .unwrap();
        assert!(opened.is_empty());
    }

    #[test]
    fn large_plaintext() {
        let recipient_sk = StaticSecret::random_from_rng(&mut rand_10::rng());
        let recipient_pk = PublicKey::from(&recipient_sk);

        let plaintext = vec![0x42u8; 65536];
        let sealed = seal(&plaintext, b"", recipient_pk.as_bytes(), b"").unwrap();
        let opened = open(
            &sealed.ciphertext,
            b"",
            &sealed.enc,
            &recipient_sk.to_bytes(),
            b"",
        )
        .unwrap();
        assert_eq!(opened, plaintext);
    }

    /// Every message gets a fresh ephemeral keypair, so two seals of the same
    /// plaintext to the same recipient share neither `enc` nor ciphertext.
    #[test]
    fn each_seal_uses_a_fresh_ephemeral() {
        let recipient_sk = StaticSecret::random_from_rng(&mut rand_10::rng());
        let recipient_pk = PublicKey::from(&recipient_sk);

        let a = seal(b"same", b"aad", recipient_pk.as_bytes(), b"").unwrap();
        let b = seal(b"same", b"aad", recipient_pk.as_bytes(), b"").unwrap();

        assert_ne!(a.enc, b.enc);
        assert_ne!(a.ciphertext, b.ciphertext);
    }
}
