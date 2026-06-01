//! Known-answer tests (KATs) for the DIDComm JOSE crypto primitives.
//!
//! # Why this module exists
//!
//! Issue #327 centralises this crate's hand-rolled JOSE crypto (ECDH-1PU,
//! ECDH-ES, the Concat KDF, A256KW, A256CBC-HS512, EdDSA) into
//! `affinidi-crypto`. That migration rewrites now-*fixed* crypto (the
//! #322 ECDH-1PU KDF bug), so the entire risk is a silent change in the
//! bytes on the wire. These tests are the safety net: they pin the
//! exact output of each primitive **before** the migration so the moved
//! implementation can be proven byte-identical **after**.
//!
//! Two kinds of vector live here:
//!
//! 1. **Spec known-answer vectors** — fixed inputs and outputs taken
//!    verbatim from a published standard. These prove spec-correctness,
//!    not just stability. Currently: AES-256 Key Wrap (RFC 3394 §4.6).
//!
//! 2. **Golden-master vectors** — deterministic inputs with outputs
//!    captured from the current (post-#326, spec-correct) implementation.
//!    They don't independently prove spec-correctness, but they lock the
//!    byte-level behaviour so the #327 rewrite can't drift. Each is
//!    annotated with how it was produced. When the primitive moves to
//!    `affinidi-crypto`, port the *same* vector there and assert the same
//!    expected bytes.
//!
//! If a change to any primitive is intended to alter output, that is a
//! wire-breaking change and the vector (and a migration note) must be
//! updated deliberately — never "to make the test pass".

#![cfg(test)]

use crate::crypto::ecdh_1pu::{derive_key_1pu, derive_key_1pu_recipient};
use crate::crypto::ecdh_es::concat_kdf;
use crate::crypto::key_agreement::{Curve, PrivateKeyAgreement};
use crate::crypto::{aes_kw, content_encryption, signing};

/// Lower-case hex of a byte slice, for comparison against vector literals.
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Decode an even-length lower/upper-case hex string to bytes.
fn unhex(s: &str) -> Vec<u8> {
    assert!(
        s.len().is_multiple_of(2),
        "hex string must have even length"
    );
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

// Deterministic key seeds for the golden vectors. Arbitrary fixed bytes —
// the point is reproducibility, not key quality.
const SENDER_SEED: [u8; 32] = [0x11; 32];
const RECIP_SEED: [u8; 32] = [0x22; 32];
const EPH_SEED: [u8; 32] = [0x33; 32];
const ED_SEED: [u8; 32] = [0x44; 32];

// ─── Spec KAT: AES-256 Key Wrap (RFC 3394 §4.6) ─────────────────────────────

/// RFC 3394 §4.6 — "Wrap 128 bits of Key Data with a 256-bit KEK".
/// This is a published known-answer vector, so it proves the A256KW
/// implementation is spec-correct (not merely self-consistent).
#[test]
fn aes256_kw_rfc3394_section_4_6() {
    let kek: [u8; 32] = core::array::from_fn(|i| i as u8); // 00 01 .. 1f
    let key_data = unhex("00112233445566778899aabbccddeeff"); // 128-bit CEK
    const EXPECTED_WRAPPED: &str = "64e8c3f9ce0f5ba263e9777905818a2a93c8191e7d6e8ae7";

    let wrapped = aes_kw::wrap(&kek, &key_data).expect("wrap");
    assert_eq!(
        hex(&wrapped),
        EXPECTED_WRAPPED,
        "A256KW must match RFC 3394 §4.6"
    );

    let unwrapped = aes_kw::unwrap(&kek, &wrapped).expect("unwrap");
    assert_eq!(unwrapped, key_data, "unwrap must invert wrap");
}

// ─── Golden: Concat KDF for ECDH-ES (RFC 7518 §4.6) ─────────────────────────

/// Golden master for the SHA-256 Concat KDF used by ECDH-ES.
/// Captured from the current implementation with `Z = 00..1f`,
/// `alg = "ECDH-ES+A256KW"`, `apu = "Alice"`, `apv = "Bob"`, 256-bit
/// output. Locks the OtherInfo encoding (round || Z || len-prefixed
/// alg/apu/apv || keydatalen).
#[test]
fn concat_kdf_es_golden() {
    let z: [u8; 32] = core::array::from_fn(|i| i as u8);
    const EXPECTED: &str = "5655555b3d044d53f6b50fd49674ff388654cb284a4f6d4e2112de7b876a59d6";

    let dk = concat_kdf(&z, b"ECDH-ES+A256KW", b"Alice", b"Bob", 256).expect("concat_kdf");
    assert_eq!(hex(&dk), EXPECTED, "ECDH-ES Concat KDF output changed");
}

// ─── Golden: ECDH-1PU KEK derivation (incl. the #322 length-prefixed tag) ───

/// Golden master for the full ECDH-1PU + Concat-KDF-1PU KEK derivation
/// over X25519, including the spec-correct length-prefixed `cc_tag` that
/// #322 fixed. Captured from the current implementation with the fixed
/// seeds below, `apu = "did:example:alice#key-1"`, `apv = "apv-bytes"`,
/// `cc_tag = 0xAB×32`, 256-bit output. Also asserts the recipient side
/// derives the identical KEK.
#[test]
fn ecdh_1pu_x25519_kek_golden() {
    const EXPECTED_KEK: &str = "f3cc56f46a09991543b654ce36e0913bb8c9656ad53fa159f732c0edcf1a4f9c";

    let sender = PrivateKeyAgreement::from_raw_bytes(Curve::X25519, &SENDER_SEED).unwrap();
    let recip = PrivateKeyAgreement::from_raw_bytes(Curve::X25519, &RECIP_SEED).unwrap();
    let eph = PrivateKeyAgreement::from_raw_bytes(Curve::X25519, &EPH_SEED).unwrap();
    let cc_tag = [0xABu8; 32];

    let kek = derive_key_1pu(
        &eph,
        &sender,
        &recip.public_key(),
        b"ECDH-1PU+A256KW",
        b"did:example:alice#key-1",
        b"apv-bytes",
        &cc_tag,
        256,
    )
    .expect("derive_key_1pu");
    assert_eq!(hex(&kek), EXPECTED_KEK, "ECDH-1PU KEK changed");

    let kek_recipient = derive_key_1pu_recipient(
        &recip,
        &sender.public_key(),
        &eph.public_key(),
        b"ECDH-1PU+A256KW",
        b"did:example:alice#key-1",
        b"apv-bytes",
        &cc_tag,
        256,
    )
    .expect("derive_key_1pu_recipient");
    assert_eq!(
        kek_recipient, kek,
        "sender and recipient must derive the same KEK"
    );
}

// ─── Golden: A256CBC-HS512 content encryption (RFC 7518 §5.2.6) ──────────────

/// Golden master for A256CBC-HS512. Captured from the current
/// implementation with `CEK = 00..3f` (64 bytes), `IV = f0..ff`,
/// `AAD = "aad"`, plaintext `"DIDComm KAT plaintext"`. Locks the
/// ciphertext and the 32-byte truncated HMAC-SHA-512 tag, then verifies
/// decrypt round-trips and that a flipped tag is rejected.
#[test]
fn a256cbc_hs512_golden() {
    const EXPECTED_CT: &str = "f74554842ded8fa32ff9b5185f9a7df88d3fd7539a5d8012abf5b82aeacd9ebd";
    const EXPECTED_TAG: &str = "83dbed2db1a941c503ce5a28b0fdf14180a9869426366fae9dc2d8a81cfc4223";

    let cek: [u8; 64] = core::array::from_fn(|i| i as u8);
    let iv: [u8; 16] = core::array::from_fn(|i| (0xF0 + i) as u8);
    let plaintext = b"DIDComm KAT plaintext";

    let (ct, tag) = content_encryption::encrypt(plaintext, &cek, &iv, b"aad").expect("encrypt");
    assert_eq!(hex(&ct), EXPECTED_CT, "A256CBC-HS512 ciphertext changed");
    assert_eq!(hex(&tag), EXPECTED_TAG, "A256CBC-HS512 tag changed");

    let recovered = content_encryption::decrypt(&ct, &cek, &iv, b"aad", &tag).expect("decrypt");
    assert_eq!(recovered, plaintext, "decrypt must round-trip");

    // A single-bit tag corruption must fail authentication.
    let mut bad_tag = tag;
    bad_tag[0] ^= 0x01;
    assert!(
        content_encryption::decrypt(&ct, &cek, &iv, b"aad", &bad_tag).is_err(),
        "corrupted tag must be rejected"
    );
}

// ─── Golden: Ed25519 (EdDSA) signing ────────────────────────────────────────

/// Golden master for EdDSA. Captured from the current implementation
/// with the 32-byte seed below over message `"DIDComm KAT message"`.
/// Locks the derived public key and signature, verifies the signature,
/// and checks that a tampered message is rejected.
#[test]
fn ed25519_eddsa_golden() {
    const EXPECTED_PK: &str = "d759793bbc13a2819a827c76adb6fba8a49aee007f49f2d0992d99b825ad2c48";
    const EXPECTED_SIG: &str = "86209dd05dd745917219c1cf7fded1726cc4b9a8063edb88554a6d5bb8f86adfa17de70c841ef7c0a727c819177ccbcac44611f23e5d646aa922373f3291e000";

    let msg = b"DIDComm KAT message";
    let pk = signing::public_key_from_private(&ED_SEED);
    assert_eq!(
        hex(&pk),
        EXPECTED_PK,
        "Ed25519 public key derivation changed"
    );

    let sig = signing::sign(msg, &ED_SEED).expect("sign");
    assert_eq!(hex(&sig), EXPECTED_SIG, "Ed25519 signature changed");

    assert!(
        signing::verify(msg, &sig, &pk).is_ok(),
        "signature must verify"
    );
    assert!(
        signing::verify(b"tampered", &sig, &pk).is_err(),
        "signature must not verify a different message"
    );
}
