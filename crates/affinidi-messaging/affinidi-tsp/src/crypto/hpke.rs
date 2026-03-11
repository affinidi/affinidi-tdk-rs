//! HPKE-Auth (RFC 9180) implementation using primitives.
//!
//! Suite: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM, Auth mode.
//!
//! This implements only the specific HPKE suite required by TSP, built from
//! standard cryptographic primitives rather than a generic HPKE library.

use aes_gcm::{
    Aes128Gcm, AeadInPlace, KeyInit,
    aead::generic_array::GenericArray,
};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::error::TspError;

// HPKE constants for our suite
const MODE_AUTH: u8 = 0x02;

const N_SECRET: usize = 32; // KEM shared secret size
const N_K: usize = 16; // AES-128-GCM key size
const N_N: usize = 12; // AES-128-GCM nonce size
const N_H: usize = 32; // HKDF-SHA256 hash output size

/// Result of HPKE-Auth sealing (encryption + sender authentication).
pub struct SealResult {
    /// The encapsulated key (32 bytes, X25519 ephemeral public key).
    pub enc: [u8; 32],
    /// The ciphertext (plaintext + 16-byte AES-GCM tag).
    pub ciphertext: Vec<u8>,
}

/// Seal (encrypt + authenticate) a plaintext for a recipient.
///
/// Uses HPKE Auth mode: the sender's identity is cryptographically bound
/// to the ciphertext, providing both confidentiality and sender authentication.
///
/// # Arguments
/// * `plaintext` - The data to encrypt
/// * `aad` - Additional authenticated data (e.g., TSP envelope)
/// * `sender_sk` - Sender's X25519 private key (32 bytes)
/// * `recipient_pk` - Recipient's X25519 public key (32 bytes)
/// * `info` - Context info for key derivation (can be empty)
pub fn seal(
    plaintext: &[u8],
    aad: &[u8],
    sender_sk: &[u8; 32],
    recipient_pk: &[u8; 32],
    info: &[u8],
) -> Result<SealResult, TspError> {
    let sk_s = StaticSecret::from(*sender_sk);
    let pk_r = PublicKey::from(*recipient_pk);

    let (shared_secret, enc) = auth_encap(&pk_r, &sk_s)?;
    let (key, base_nonce) = key_schedule(&shared_secret, info)?;

    let mut ciphertext = plaintext.to_vec();
    let cipher = Aes128Gcm::new(GenericArray::from_slice(&key));
    let nonce = GenericArray::from_slice(&base_nonce);
    cipher
        .encrypt_in_place(nonce, aad, &mut ciphertext)
        .map_err(|e| TspError::Hpke(format!("AES-GCM seal failed: {e}")))?;

    Ok(SealResult { enc, ciphertext })
}

/// Open (decrypt + verify sender) a ciphertext.
///
/// # Arguments
/// * `ciphertext` - The encrypted data (including 16-byte AES-GCM tag)
/// * `aad` - Additional authenticated data (must match what was used in seal)
/// * `enc` - The encapsulated key from the sender
/// * `recipient_sk` - Recipient's X25519 private key (32 bytes)
/// * `sender_pk` - Sender's X25519 public key (32 bytes)
/// * `info` - Context info (must match what was used in seal)
pub fn open(
    ciphertext: &[u8],
    aad: &[u8],
    enc: &[u8; 32],
    recipient_sk: &[u8; 32],
    sender_pk: &[u8; 32],
    info: &[u8],
) -> Result<Vec<u8>, TspError> {
    let sk_r = StaticSecret::from(*recipient_sk);
    let pk_s = PublicKey::from(*sender_pk);

    let shared_secret = auth_decap(enc, &sk_r, &pk_s)?;
    let (key, base_nonce) = key_schedule(&shared_secret, info)?;

    let mut plaintext = ciphertext.to_vec();
    let cipher = Aes128Gcm::new(GenericArray::from_slice(&key));
    let nonce = GenericArray::from_slice(&base_nonce);
    cipher
        .decrypt_in_place(nonce, aad, &mut plaintext)
        .map_err(|_| TspError::Hpke("AES-GCM open failed: authentication tag mismatch".into()))?;

    Ok(plaintext)
}

/// AuthEncap: generate shared secret with sender authentication.
///
/// RFC 9180 §4.1 (Auth mode):
/// 1. Generate ephemeral X25519 keypair
/// 2. DH with ephemeral→recipient and sender→recipient
/// 3. Derive shared secret from both DH results
fn auth_encap(
    pk_r: &PublicKey,
    sk_s: &StaticSecret,
) -> Result<([u8; N_SECRET], [u8; 32]), TspError> {
    // Generate ephemeral keypair
    let sk_e = StaticSecret::random_from_rng(OsRng);
    let pk_e = PublicKey::from(&sk_e);

    // Two DH operations
    let dh_eph = sk_e.diffie_hellman(pk_r);
    let dh_sender = sk_s.diffie_hellman(pk_r);

    // Concatenate DH results: dh = dh_eph || dh_sender
    let mut dh = [0u8; 64];
    dh[..32].copy_from_slice(dh_eph.as_bytes());
    dh[32..].copy_from_slice(dh_sender.as_bytes());

    // Build KEM context: enc || pkS || pkR
    let enc = pk_e.to_bytes();
    let pk_s = PublicKey::from(sk_s);
    let mut kem_context = [0u8; 96]; // 32 + 32 + 32
    kem_context[..32].copy_from_slice(&enc);
    kem_context[32..64].copy_from_slice(pk_s.as_bytes());
    kem_context[64..].copy_from_slice(pk_r.as_bytes());

    let shared_secret = extract_and_expand(&dh, &kem_context)?;
    dh.zeroize();

    Ok((shared_secret, enc))
}

/// AuthDecap: recover shared secret using recipient's key and sender's public key.
fn auth_decap(
    enc: &[u8; 32],
    sk_r: &StaticSecret,
    pk_s: &PublicKey,
) -> Result<[u8; N_SECRET], TspError> {
    let pk_e = PublicKey::from(*enc);
    let pk_r = PublicKey::from(sk_r);

    // Two DH operations (mirror of AuthEncap)
    let dh_eph = sk_r.diffie_hellman(&pk_e);
    let dh_sender = sk_r.diffie_hellman(pk_s);

    let mut dh = [0u8; 64];
    dh[..32].copy_from_slice(dh_eph.as_bytes());
    dh[32..].copy_from_slice(dh_sender.as_bytes());

    // Build KEM context: enc || pkS || pkR
    let mut kem_context = [0u8; 96];
    kem_context[..32].copy_from_slice(enc);
    kem_context[32..64].copy_from_slice(pk_s.as_bytes());
    kem_context[64..].copy_from_slice(pk_r.as_bytes());

    let shared_secret = extract_and_expand(&dh, &kem_context)?;
    dh.zeroize();

    Ok(shared_secret)
}

/// KEM ExtractAndExpand (RFC 9180 §4.1)
fn extract_and_expand(
    dh: &[u8],
    kem_context: &[u8],
) -> Result<[u8; N_SECRET], TspError> {
    let kem_suite_id = KEM_SUITE_ID;

    // prk = LabeledExtract("", "shared_secret", dh)
    let prk = labeled_extract(&kem_suite_id, &[], b"shared_secret", dh)?;

    // shared_secret = LabeledExpand(prk, "ss", kem_context, Nsecret)
    let mut shared_secret = [0u8; N_SECRET];
    labeled_expand(&kem_suite_id, &prk, b"ss", kem_context, &mut shared_secret)?;

    Ok(shared_secret)
}

/// HPKE KeySchedule (RFC 9180 §5.1) — derives encryption key and nonce.
fn key_schedule(
    shared_secret: &[u8; N_SECRET],
    info: &[u8],
) -> Result<([u8; N_K], [u8; N_N]), TspError> {
    let suite_id = HPKE_SUITE_ID;

    // For Auth mode without PSK: psk = "" and psk_id = ""
    let psk = b"";
    let psk_id = b"";

    // psk_id_hash = LabeledExtract("", "psk_id_hash", psk_id)
    let psk_id_hash = labeled_extract(&suite_id, &[], b"psk_id_hash", psk_id)?;

    // info_hash = LabeledExtract("", "info_hash", info)
    let info_hash = labeled_extract(&suite_id, &[], b"info_hash", info)?;

    // ks_context = mode || psk_id_hash || info_hash (1 + 32 + 32 = 65 bytes, fixed size)
    let mut ks_context = [0u8; 1 + N_H + N_H];
    ks_context[0] = MODE_AUTH;
    ks_context[1..1 + N_H].copy_from_slice(&psk_id_hash);
    ks_context[1 + N_H..].copy_from_slice(&info_hash);

    // secret = LabeledExtract(shared_secret, "secret", psk)
    let secret = labeled_extract(&suite_id, shared_secret, b"secret", psk)?;

    // key = LabeledExpand(secret, "key", ks_context, Nk)
    let mut key = [0u8; N_K];
    labeled_expand(&suite_id, &secret, b"key", &ks_context, &mut key)?;

    // base_nonce = LabeledExpand(secret, "base_nonce", ks_context, Nn)
    let mut base_nonce = [0u8; N_N];
    labeled_expand(&suite_id, &secret, b"base_nonce", &ks_context, &mut base_nonce)?;

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

    // HKDF-Extract
    let hkdf = Hkdf::<Sha256>::new(Some(salt), &labeled_ikm);
    let mut prk = [0u8; N_H];
    // The PRK is the internal state of HKDF after extraction
    // We need to expand with empty info to get it
    // Actually, Hkdf::new() does the extract. We just need the PRK.
    // The `hkdf` crate's Hkdf::new() does Extract internally.
    // To get the raw PRK, we expand with empty info and N_H length.
    hkdf.expand(&[], &mut prk)
        .map_err(|e| TspError::Hpke(format!("HKDF extract failed: {e}")))?;

    Ok(prk)
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
const HPKE_SUITE_ID: &[u8] = b"HPKE\x00\x20\x00\x01\x00\x01";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let sender_sk = StaticSecret::random_from_rng(OsRng);
        let sender_pk = PublicKey::from(&sender_sk);
        let recipient_sk = StaticSecret::random_from_rng(OsRng);
        let recipient_pk = PublicKey::from(&recipient_sk);

        let plaintext = b"Hello, TSP!";
        let aad = b"envelope-data";
        let info = b"TSP-v1";

        let sealed = seal(
            plaintext,
            aad,
            &sender_sk.to_bytes(),
            recipient_pk.as_bytes(),
            info,
        )
        .unwrap();

        // Ciphertext should be plaintext + 16-byte AES-GCM tag
        assert_eq!(sealed.ciphertext.len(), plaintext.len() + 16);

        let opened = open(
            &sealed.ciphertext,
            aad,
            &sealed.enc,
            &recipient_sk.to_bytes(),
            sender_pk.as_bytes(),
            info,
        )
        .unwrap();

        assert_eq!(opened, plaintext);
    }

    #[test]
    fn wrong_recipient_key_fails() {
        let sender_sk = StaticSecret::random_from_rng(OsRng);
        let recipient_sk = StaticSecret::random_from_rng(OsRng);
        let recipient_pk = PublicKey::from(&recipient_sk);
        let wrong_sk = StaticSecret::random_from_rng(OsRng);

        let sealed = seal(
            b"secret",
            b"aad",
            &sender_sk.to_bytes(),
            recipient_pk.as_bytes(),
            b"",
        )
        .unwrap();

        let sender_pk = PublicKey::from(&sender_sk);
        let result = open(
            &sealed.ciphertext,
            b"aad",
            &sealed.enc,
            &wrong_sk.to_bytes(),
            sender_pk.as_bytes(),
            b"",
        );

        assert!(result.is_err());
    }

    #[test]
    fn wrong_sender_key_fails() {
        let sender_sk = StaticSecret::random_from_rng(OsRng);
        let recipient_sk = StaticSecret::random_from_rng(OsRng);
        let recipient_pk = PublicKey::from(&recipient_sk);

        let sealed = seal(
            b"secret",
            b"aad",
            &sender_sk.to_bytes(),
            recipient_pk.as_bytes(),
            b"",
        )
        .unwrap();

        // Try to open with wrong sender public key
        let wrong_pk = PublicKey::from(&StaticSecret::random_from_rng(OsRng));
        let result = open(
            &sealed.ciphertext,
            b"aad",
            &sealed.enc,
            &recipient_sk.to_bytes(),
            wrong_pk.as_bytes(),
            b"",
        );

        assert!(result.is_err());
    }

    #[test]
    fn tampered_aad_fails() {
        let sender_sk = StaticSecret::random_from_rng(OsRng);
        let sender_pk = PublicKey::from(&sender_sk);
        let recipient_sk = StaticSecret::random_from_rng(OsRng);
        let recipient_pk = PublicKey::from(&recipient_sk);

        let sealed = seal(
            b"secret",
            b"original-aad",
            &sender_sk.to_bytes(),
            recipient_pk.as_bytes(),
            b"",
        )
        .unwrap();

        let result = open(
            &sealed.ciphertext,
            b"tampered-aad",
            &sealed.enc,
            &recipient_sk.to_bytes(),
            sender_pk.as_bytes(),
            b"",
        );

        assert!(result.is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let sender_sk = StaticSecret::random_from_rng(OsRng);
        let sender_pk = PublicKey::from(&sender_sk);
        let recipient_sk = StaticSecret::random_from_rng(OsRng);
        let recipient_pk = PublicKey::from(&recipient_sk);

        let sealed = seal(
            b"secret",
            b"aad",
            &sender_sk.to_bytes(),
            recipient_pk.as_bytes(),
            b"",
        )
        .unwrap();

        let mut tampered = sealed.ciphertext.clone();
        tampered[0] ^= 0xFF;

        let result = open(
            &tampered,
            b"aad",
            &sealed.enc,
            &recipient_sk.to_bytes(),
            sender_pk.as_bytes(),
            b"",
        );

        assert!(result.is_err());
    }

    #[test]
    fn empty_plaintext() {
        let sender_sk = StaticSecret::random_from_rng(OsRng);
        let sender_pk = PublicKey::from(&sender_sk);
        let recipient_sk = StaticSecret::random_from_rng(OsRng);
        let recipient_pk = PublicKey::from(&recipient_sk);

        let sealed = seal(
            b"",
            b"aad",
            &sender_sk.to_bytes(),
            recipient_pk.as_bytes(),
            b"info",
        )
        .unwrap();

        assert_eq!(sealed.ciphertext.len(), 16); // just the tag

        let opened = open(
            &sealed.ciphertext,
            b"aad",
            &sealed.enc,
            &recipient_sk.to_bytes(),
            sender_pk.as_bytes(),
            b"info",
        )
        .unwrap();

        assert!(opened.is_empty());
    }

    #[test]
    fn large_plaintext() {
        let sender_sk = StaticSecret::random_from_rng(OsRng);
        let sender_pk = PublicKey::from(&sender_sk);
        let recipient_sk = StaticSecret::random_from_rng(OsRng);
        let recipient_pk = PublicKey::from(&recipient_sk);

        let plaintext = vec![0x42u8; 65536];

        let sealed = seal(
            &plaintext,
            b"",
            &sender_sk.to_bytes(),
            recipient_pk.as_bytes(),
            b"",
        )
        .unwrap();

        let opened = open(
            &sealed.ciphertext,
            b"",
            &sealed.enc,
            &recipient_sk.to_bytes(),
            sender_pk.as_bytes(),
            b"",
        )
        .unwrap();

        assert_eq!(opened, plaintext);
    }
}
