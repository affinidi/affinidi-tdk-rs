//! Shared fixtures for the `affinidi-messaging-didcomm` fuzz targets (issue #477).
//!
//! Fixed, deterministic key material so every target opens the *same* recipient
//! and a committed seed corpus stays valid across runs. The keys are
//! intentionally hard-coded constants — this is a fuzz harness, never a
//! production path.
//!
//! External harnesses that want richer, seed-parameterised helpers can use
//! `affinidi-tdk-test-support`'s `didcomm_fuzz` module instead; this crate keeps
//! its dependency graph minimal so the sanitizer build stays fast.

use std::sync::OnceLock;

use affinidi_crypto::jose::key_agreement::{Curve, PrivateKeyAgreement, PublicKeyAgreement};
use affinidi_messaging_didcomm::jwe::encrypt;
use affinidi_messaging_didcomm::jws::sign;
use affinidi_messaging_didcomm::Message;

/// Key ids the targets address the fixed fuzz identities by.
pub const RECIPIENT_KID: &str = "did:fuzz:recipient#key-1";
pub const SENDER_KID: &str = "did:fuzz:sender#key-1";
pub const SIGNER_KID: &str = "did:fuzz:signer#key-1";

/// Fixed X25519 recipient private key, derived once and cached so the hot fuzz
/// loop never re-derives. Any 32 bytes are a valid X25519 scalar (the curve
/// clamps), so construction is total.
pub fn recipient() -> &'static PrivateKeyAgreement {
    static K: OnceLock<PrivateKeyAgreement> = OnceLock::new();
    K.get_or_init(|| {
        PrivateKeyAgreement::from_raw_bytes(Curve::X25519, &[0x11; 32])
            .expect("valid X25519 scalar")
    })
}

/// Fixed X25519 sender (authcrypt) private key, cached.
pub fn sender() -> &'static PrivateKeyAgreement {
    static K: OnceLock<PrivateKeyAgreement> = OnceLock::new();
    K.get_or_init(|| {
        PrivateKeyAgreement::from_raw_bytes(Curve::X25519, &[0x22; 32])
            .expect("valid X25519 scalar")
    })
}

/// Fixed sender public key for the authcrypt ECDH-1PU path, cached.
pub fn sender_public() -> &'static PublicKeyAgreement {
    static K: OnceLock<PublicKeyAgreement> = OnceLock::new();
    K.get_or_init(|| sender().public_key())
}

/// Fixed Ed25519 signer keypair as `(secret, public)` 32-byte arrays.
pub fn signer() -> ([u8; 32], [u8; 32]) {
    let secret = [0x33u8; 32];
    let sk = ed25519_dalek::SigningKey::from_bytes(&secret);
    (secret, sk.verifying_key().to_bytes())
}

/// A few structurally varied messages the seed corpus is built from.
fn sample_messages() -> Vec<Message> {
    vec![
        Message::new(
            "https://didcomm.org/basicmessage/2.0/message",
            serde_json::json!({ "content": "hello" }),
        ),
        Message::new(
            "https://didcomm.org/trust-ping/2.0/ping",
            serde_json::json!({ "response_requested": true, "nested": { "a": [1, 2, 3] } }),
        )
        .from("did:example:alice"),
    ]
}

/// Build the committed seed corpus: `(relative_path, bytes)` of valid envelopes
/// addressed to the fixed fuzz keys, one of each protected shape per sample.
/// Used by the `gen_corpus` binary; the same shapes the targets decrypt/verify.
pub fn seed_corpus() -> Vec<(String, Vec<u8>)> {
    let recipient_pk = recipient().public_key();
    let sender_key = sender();
    let (signer_secret, _) = signer();

    let mut out = Vec::new();
    for (i, msg) in sample_messages().into_iter().enumerate() {
        let plaintext = msg.to_json().expect("sample serializes");

        let anon = encrypt::anoncrypt(&plaintext, &[(RECIPIENT_KID, &recipient_pk)])
            .expect("anoncrypt sample");
        out.push((format!("unpack/anoncrypt-{i}.json"), anon.into_bytes()));

        let auth = encrypt::authcrypt(
            &plaintext,
            SENDER_KID,
            sender_key,
            &[(RECIPIENT_KID, &recipient_pk)],
        )
        .expect("authcrypt sample");
        out.push((format!("unpack/authcrypt-{i}.json"), auth.into_bytes()));

        let signed =
            sign::sign_ed25519(&plaintext, SIGNER_KID, &signer_secret).expect("signed sample");
        out.push((format!("unpack/signed-{i}.json"), signed.into_bytes()));

        out.push((format!("unpack/plaintext-{i}.json"), plaintext));
    }
    out
}
