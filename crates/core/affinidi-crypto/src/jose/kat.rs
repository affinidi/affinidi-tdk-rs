//! Known-answer tests for `affinidi-crypto::jose`.
//!
//! These mirror the harness in `affinidi-messaging-didcomm`
//! (`src/crypto/kat.rs`, PR #336). The expected bytes are **identical**:
//! since this module is a verbatim port, matching the same vectors proves
//! the #327 move changed nothing on the wire. When PR 5d deletes the
//! didcomm copies and rewires onto this module, these vectors are the
//! contract that nothing drifted.
//!
//! - `aes256_kw_rfc3394_section_4_6` — real spec vector (RFC 3394 §4.6).
//! - `concat_kdf_es_golden`, `a256cbc_hs512_golden`, `ed25519_eddsa_golden`
//!   — same golden masters as #336; portable because the code is identical.
//! - `concat_kdf_1pu_*` — structural lock of the #322 length-prefixed tag.
//! - `ecdh_1pu_x25519_kek_golden` — the full ECDH-1PU + Concat-KDF KEK,
//!   asserting the **same** `f3cc56…` golden as didcomm #336 (closes the
//!   vector 5b deferred until key agreement landed).

#![cfg(test)]

use super::ecdh::{
    derive_key_1pu, derive_key_1pu_recipient, derive_key_es, derive_key_es_recipient,
};
use super::key_agreement::{Curve, PrivateKeyAgreement, PublicKeyAgreement};
use super::{A256CbcHs512, A256Kw, ContentEncryption, Ed25519, JwsSigner, JwsVerifier, KeyWrap};
use super::{aes_kw, concat_kdf, content_encryption, signing};

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "hex must be even length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

// ─── AES-256-KW: RFC 3394 §4.6 (spec vector) ────────────────────────────────

#[test]
fn aes256_kw_rfc3394_section_4_6() {
    let kek: [u8; 32] = core::array::from_fn(|i| i as u8);
    let key_data = unhex("00112233445566778899aabbccddeeff");
    const EXPECTED_WRAPPED: &str = "64e8c3f9ce0f5ba263e9777905818a2a93c8191e7d6e8ae7";

    let wrapped = aes_kw::wrap(&kek, &key_data).expect("wrap");
    assert_eq!(
        hex(&wrapped),
        EXPECTED_WRAPPED,
        "A256KW must match RFC 3394 §4.6"
    );
    assert_eq!(aes_kw::unwrap(&kek, &wrapped).expect("unwrap"), key_data);

    // Same vector through the trait surface.
    let via_trait = A256Kw.wrap(&kek, &key_data).expect("trait wrap");
    assert_eq!(hex(&via_trait), EXPECTED_WRAPPED);
    assert_eq!(A256Kw.algorithm(), "A256KW");
}

// ─── Concat KDF (ECDH-ES) — same golden as didcomm #336 ─────────────────────

#[test]
fn concat_kdf_es_golden() {
    let z: [u8; 32] = core::array::from_fn(|i| i as u8);
    // Identical expected bytes to didcomm src/crypto/kat.rs (#336).
    const EXPECTED: &str = "5655555b3d044d53f6b50fd49674ff388654cb284a4f6d4e2112de7b876a59d6";

    let dk = concat_kdf::concat_kdf(&z, b"ECDH-ES+A256KW", b"Alice", b"Bob", 256).unwrap();
    assert_eq!(
        hex(&dk),
        EXPECTED,
        "ECDH-ES Concat KDF output drifted from didcomm"
    );
}

// ─── Concat KDF (ECDH-1PU) — #322 length-prefixed tag, structural lock ──────

#[test]
fn concat_kdf_1pu_length_prefixes_tag() {
    use sha2::{Digest, Sha256};

    let z = b"0123456789abcdef0123456789abcdef";
    let alg = b"ECDH-1PU+A256KW".as_slice();
    let apu = b"did:example:alice#key-1".as_slice();
    let apv = b"apv-bytes".as_slice();
    let tag = [0xABu8; 32];

    // Independently rebuild the spec-correct OtherInfo with the tag
    // length-prefixed (the bytes under test: 00 00 00 20).
    let mut h = Sha256::new();
    h.update(1u32.to_be_bytes());
    h.update(z);
    h.update((alg.len() as u32).to_be_bytes());
    h.update(alg);
    h.update((apu.len() as u32).to_be_bytes());
    h.update(apu);
    h.update((apv.len() as u32).to_be_bytes());
    h.update(apv);
    h.update(256u32.to_be_bytes());
    h.update((tag.len() as u32).to_be_bytes());
    h.update(tag);
    let expected = h.finalize()[..32].to_vec();

    let got = concat_kdf::concat_kdf_1pu(z, alg, apu, apv, 256, &tag).unwrap();
    assert_eq!(got, expected, "1PU KDF must length-prefix the cc_tag");

    let legacy = concat_kdf::concat_kdf_1pu_legacy(z, alg, apu, apv, 256, &tag).unwrap();
    assert_ne!(
        got, legacy,
        "the 4-byte length prefix must change the key (#322)"
    );

    // Empty tag must equal the plain ECDH-ES Concat KDF.
    let no_tag = concat_kdf::concat_kdf_1pu(z, alg, apu, apv, 256, b"").unwrap();
    let es = concat_kdf::concat_kdf(z, alg, apu, apv, 256).unwrap();
    assert_eq!(no_tag, es, "empty cc_tag must match ECDH-ES Concat KDF");
}

// ─── ECDH-1PU KEK over X25519 — same golden as didcomm #336 ─────────────────

#[test]
fn ecdh_1pu_x25519_kek_golden() {
    // Identical fixed seeds, params, and expected KEK to didcomm
    // src/crypto/kat.rs (#336) — proves key agreement + Concat-KDF-1PU
    // port byte-identically end to end.
    const EXPECTED_KEK: &str = "f3cc56f46a09991543b654ce36e0913bb8c9656ad53fa159f732c0edcf1a4f9c";

    let sender = PrivateKeyAgreement::from_raw_bytes(Curve::X25519, &[0x11; 32]).unwrap();
    let recip = PrivateKeyAgreement::from_raw_bytes(Curve::X25519, &[0x22; 32]).unwrap();
    let eph = PrivateKeyAgreement::from_raw_bytes(Curve::X25519, &[0x33; 32]).unwrap();
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
    .unwrap();
    assert_eq!(hex(&kek), EXPECTED_KEK, "ECDH-1PU KEK drifted from didcomm");

    let kek_r = derive_key_1pu_recipient(
        &recip,
        &sender.public_key(),
        &eph.public_key(),
        b"ECDH-1PU+A256KW",
        b"did:example:alice#key-1",
        b"apv-bytes",
        &cc_tag,
        256,
    )
    .unwrap();
    assert_eq!(kek_r, kek, "sender and recipient must derive the same KEK");
}

#[test]
fn ecdh_es_roundtrip_all_curves() {
    for curve in [Curve::X25519, Curve::P256, Curve::K256] {
        let recip = PrivateKeyAgreement::generate(curve);
        let eph = PrivateKeyAgreement::generate(curve);
        let s = derive_key_es(
            &eph,
            &recip.public_key(),
            b"ECDH-ES+A256KW",
            b"",
            b"apv",
            256,
        )
        .unwrap();
        let r = derive_key_es_recipient(
            &recip,
            &eph.public_key(),
            b"ECDH-ES+A256KW",
            b"",
            b"apv",
            256,
        )
        .unwrap();
        assert_eq!(s, r, "ECDH-ES KEK must agree for {curve:?}");
        assert_eq!(s.len(), 32);
    }
}

#[test]
fn public_key_jwk_roundtrip_all_curves() {
    for curve in [Curve::X25519, Curve::P256, Curve::K256] {
        let pk = PrivateKeyAgreement::generate(curve).public_key();
        let jwk = pk.to_jwk();
        let parsed = PublicKeyAgreement::from_jwk(&jwk).unwrap();
        // Re-encoding the parsed key must reproduce the same JWK.
        assert_eq!(
            parsed.to_jwk(),
            jwk,
            "JWK round-trip mismatch for {curve:?}"
        );
        assert_eq!(parsed.curve(), curve);
    }
}

// ─── A256CBC-HS512 — same golden as didcomm #336 ────────────────────────────

#[test]
fn a256cbc_hs512_golden() {
    const EXPECTED_CT: &str = "f74554842ded8fa32ff9b5185f9a7df88d3fd7539a5d8012abf5b82aeacd9ebd";
    const EXPECTED_TAG: &str = "83dbed2db1a941c503ce5a28b0fdf14180a9869426366fae9dc2d8a81cfc4223";

    let cek: [u8; 64] = core::array::from_fn(|i| i as u8);
    let iv: [u8; 16] = core::array::from_fn(|i| (0xF0 + i) as u8);
    let plaintext = b"DIDComm KAT plaintext";

    let (ct, tag) = content_encryption::encrypt(plaintext, &cek, &iv, b"aad").unwrap();
    assert_eq!(
        hex(&ct),
        EXPECTED_CT,
        "A256CBC-HS512 ciphertext drifted from didcomm"
    );
    assert_eq!(
        hex(&tag),
        EXPECTED_TAG,
        "A256CBC-HS512 tag drifted from didcomm"
    );

    let recovered = content_encryption::decrypt(&ct, &cek, &iv, b"aad", &tag).unwrap();
    assert_eq!(recovered, plaintext);

    // Same vector through the trait surface, incl. tag-tamper rejection.
    let (ct2, tag2) = A256CbcHs512.encrypt(plaintext, &cek, &iv, b"aad").unwrap();
    assert_eq!(hex(&ct2), EXPECTED_CT);
    assert_eq!(hex(&tag2), EXPECTED_TAG);
    let mut bad = tag2.clone();
    bad[0] ^= 0x01;
    assert!(
        A256CbcHs512.decrypt(&ct2, &cek, &iv, b"aad", &bad).is_err(),
        "corrupted tag must be rejected"
    );
}

// ─── EdDSA — same golden as didcomm #336 ────────────────────────────────────

#[test]
fn ed25519_eddsa_golden() {
    const EXPECTED_PK: &str = "d759793bbc13a2819a827c76adb6fba8a49aee007f49f2d0992d99b825ad2c48";
    const EXPECTED_SIG: &str = "86209dd05dd745917219c1cf7fded1726cc4b9a8063edb88554a6d5bb8f86adfa17de70c841ef7c0a727c819177ccbcac44611f23e5d646aa922373f3291e000";

    let seed = [0x44u8; 32];
    let msg = b"DIDComm KAT message";

    let pk = signing::public_key_from_private(&seed);
    assert_eq!(
        hex(&pk),
        EXPECTED_PK,
        "Ed25519 public key drifted from didcomm"
    );

    let sig = signing::sign(msg, &seed).unwrap();
    assert_eq!(
        hex(&sig),
        EXPECTED_SIG,
        "Ed25519 signature drifted from didcomm"
    );

    assert!(signing::verify(msg, &sig, &pk).is_ok());
    assert!(signing::verify(b"tampered", &sig, &pk).is_err());

    // Same vector through the trait surface.
    let sig_t = Ed25519.sign(msg, &seed).unwrap();
    assert_eq!(hex(&sig_t), EXPECTED_SIG);
    assert!(Ed25519.verify(msg, &sig_t, &pk).is_ok());
}
