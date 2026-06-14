/*!
 * Deterministic DIDComm envelope fixtures for coverage-guided fuzzing (issue #477).
 *
 * Coverage-guided fuzzers (cargo-fuzz / libFuzzer) targeting
 * [`affinidi_messaging_didcomm::message::unpack::unpack`] and
 * [`affinidi_messaging_didcomm::jwe::decrypt::decrypt`] hit a wall: those
 * entry points are already pure and synchronous (no resolver, no network — the
 * recipient key is a *parameter*, not a lookup), but a mutated envelope only
 * reaches the post-decrypt code (`Message::from_json` on the recovered
 * plaintext) when it decrypts under a key the harness actually holds. With
 * random keys every input dies at the AEAD tag check and that coverage is never
 * explored.
 *
 * This module closes that gap with **deterministic** key material plus packing
 * helpers, so a harness can mint valid-ish envelopes from a seed and fuzz from
 * there. Each [`PackedEnvelope`] carries the envelope string *and* the exact key
 * parameters `unpack()` needs to open it, so the harness never has to track keys
 * separately. [`seed_corpus`] returns a representative set to seed the corpus.
 *
 * **TEST-ONLY.** These keys are predictable by construction; never use them on a
 * production key path. That is why this lives in the dev-dependency-only
 * `affinidi-tdk-test-support` crate rather than behind a feature on the
 * production `affinidi-messaging-didcomm` crate — a known private key must never
 * reach a production dependency tree. See the sibling [`crate::determinism`]
 * module, which derives seeded `did:peer` identities on the same principle.
 *
 * ```
 * use affinidi_tdk_test_support::didcomm_fuzz::seed_corpus;
 * use affinidi_messaging_didcomm::message::unpack::unpack;
 *
 * // Every seed envelope opens cleanly under the keys it ships with — exactly
 * // what a fuzz harness needs as a starting corpus before it mutates.
 * for env in seed_corpus() {
 *     unpack(
 *         &env.envelope,
 *         env.recipient_kid.as_deref(),
 *         env.recipient_private.as_ref(),
 *         env.sender_public.as_ref(),
 *         env.signer_public.as_ref(),
 *     )
 *     .expect("seed corpus envelope should unpack");
 * }
 * ```
 */

use affinidi_crypto::CryptoError;
use affinidi_messaging_didcomm::Message;
use affinidi_messaging_didcomm::message::pack::{
    pack_encrypted_anoncrypt, pack_encrypted_authcrypt, pack_signed,
};

// Re-exported so callers can name the curve / key types without depending on
// affinidi-crypto directly.
pub use affinidi_crypto::jose::key_agreement::{Curve, PrivateKeyAgreement, PublicKeyAgreement};

/// Errors from building a deterministic envelope fixture.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DidcommFuzzError {
    /// A seeded key could not be constructed on the requested curve. For the
    /// NIST curves a small fraction of seeds map to a scalar outside the field;
    /// bump the seed and retry. X25519 (the default DIDComm shape) accepts any
    /// 32-byte seed.
    #[error("seeded key: {0}")]
    Key(#[from] CryptoError),

    /// Packing the message into an envelope failed.
    #[error("pack: {0}")]
    Pack(String),
}

/// A deterministic key-agreement keypair with its key id, ready to pass to the
/// DIDComm pack/unpack APIs.
pub struct FixtureKey {
    /// The key id (DID URL fragment) this key is addressed by in an envelope.
    pub kid: String,
    /// The private key. Deterministic for a given `(curve, seed)`.
    pub private: PrivateKeyAgreement,
}

impl FixtureKey {
    /// The matching public key.
    pub fn public(&self) -> PublicKeyAgreement {
        self.private.public_key()
    }
}

/// A packed DIDComm envelope plus the exact parameters
/// [`affinidi_messaging_didcomm::message::unpack::unpack`] needs to open it.
///
/// The field shape mirrors `unpack`'s argument list one-to-one so a harness can
/// forward them directly. Which fields are populated depends on the envelope:
/// authcrypt fills recipient + `sender_public`; anoncrypt fills recipient only;
/// a signed envelope fills `signer_public` only; plaintext fills none.
pub struct PackedEnvelope {
    /// The serialized JWE / JWS / plaintext envelope — the fuzzer's seed input.
    pub envelope: String,
    /// Recipient key id, for encrypted envelopes.
    pub recipient_kid: Option<String>,
    /// Recipient private key, for encrypted envelopes.
    pub recipient_private: Option<PrivateKeyAgreement>,
    /// Sender public key, for authcrypt (ECDH-1PU) envelopes.
    pub sender_public: Option<PublicKeyAgreement>,
    /// Signer Ed25519 public key, for signed (JWS) envelopes.
    pub signer_public: Option<[u8; 32]>,
}

/// Derive a deterministic key-agreement keypair from `seed` on `curve`.
///
/// **Same `(curve, seed)` → same key**, every run. X25519 accepts any seed
/// (the scalar is clamped); the NIST curves reject the rare seed that lands
/// outside the field — see [`DidcommFuzzError::Key`].
pub fn key_agreement_from_seed(
    curve: Curve,
    seed: u64,
    kid: impl Into<String>,
) -> Result<FixtureKey, DidcommFuzzError> {
    let bytes = expand_seed(seed, KEY_DOMAIN_KA);
    let private = PrivateKeyAgreement::from_raw_bytes(curve, &bytes)?;
    Ok(FixtureKey {
        kid: kid.into(),
        private,
    })
}

/// Derive a deterministic Ed25519 signing keypair from `seed`, returning
/// `(secret_bytes, public_bytes)` in the `[u8; 32]` form the DIDComm signing
/// APIs use.
pub fn signing_keypair_from_seed(seed: u64) -> ([u8; 32], [u8; 32]) {
    let secret = expand_seed(seed, KEY_DOMAIN_SIGN);
    let signing = ed25519_dalek::SigningKey::from_bytes(&secret);
    (secret, signing.verifying_key().to_bytes())
}

/// Pack `msg` as an authcrypt (ECDH-1PU, sender-authenticated) JWE addressed to
/// a deterministic recipient/sender derived from `seed`.
pub fn authcrypt_envelope(seed: u64, msg: &Message) -> Result<PackedEnvelope, DidcommFuzzError> {
    let sender = key_agreement_from_seed(Curve::X25519, seed ^ SENDER_SALT, sender_kid(seed))?;
    let recipient = key_agreement_from_seed(Curve::X25519, seed, recipient_kid(seed))?;

    let envelope = pack_encrypted_authcrypt(
        msg,
        &sender.kid,
        &sender.private,
        &[(recipient.kid.as_str(), &recipient.public())],
    )
    .map_err(|e| DidcommFuzzError::Pack(e.to_string()))?;

    Ok(PackedEnvelope {
        envelope,
        recipient_kid: Some(recipient.kid),
        recipient_private: Some(recipient.private),
        sender_public: Some(sender.public()),
        signer_public: None,
    })
}

/// Pack `msg` as an anoncrypt (ECDH-ES, anonymous) JWE addressed to a
/// deterministic recipient derived from `seed`.
pub fn anoncrypt_envelope(seed: u64, msg: &Message) -> Result<PackedEnvelope, DidcommFuzzError> {
    let recipient = key_agreement_from_seed(Curve::X25519, seed, recipient_kid(seed))?;

    let envelope = pack_encrypted_anoncrypt(msg, &[(recipient.kid.as_str(), &recipient.public())])
        .map_err(|e| DidcommFuzzError::Pack(e.to_string()))?;

    Ok(PackedEnvelope {
        envelope,
        recipient_kid: Some(recipient.kid),
        recipient_private: Some(recipient.private),
        sender_public: None,
        signer_public: None,
    })
}

/// Pack `msg` as a signed (JWS, EdDSA) envelope under a deterministic Ed25519
/// key derived from `seed`.
pub fn signed_envelope(seed: u64, msg: &Message) -> Result<PackedEnvelope, DidcommFuzzError> {
    let (secret, public) = signing_keypair_from_seed(seed);

    let envelope = pack_signed(msg, &signer_kid(seed), &secret)
        .map_err(|e| DidcommFuzzError::Pack(e.to_string()))?;

    Ok(PackedEnvelope {
        envelope,
        recipient_kid: None,
        recipient_private: None,
        sender_public: None,
        signer_public: Some(public),
    })
}

/// A small, representative set of valid envelopes to seed a fuzz corpus: one of
/// each protected shape (authcrypt, anoncrypt, signed, plaintext) over a couple
/// of message bodies. Every entry opens cleanly under the keys it ships with.
///
/// The *keys* are deterministic (seeded), but the envelope bytes are not stable
/// across runs: encryption draws a fresh ephemeral key + IV and `Message::new`
/// mints a random UUID — exactly as production does. That is fine for seeding;
/// the harness wants valid-and-openable inputs, not byte-identical ones. Dump
/// `.envelope` to files if a committed on-disk corpus is wanted.
pub fn seed_corpus() -> Vec<PackedEnvelope> {
    let mut out = Vec::new();
    for (seed, msg) in sample_messages().into_iter().enumerate() {
        let seed = seed as u64;
        // `expect` is fine here: X25519 + Ed25519 derivation is total, and the
        // sample messages are valid by construction. A panic means a genuine
        // regression in the pack path, which is exactly what we want surfaced.
        out.push(authcrypt_envelope(seed, &msg).expect("authcrypt seed"));
        out.push(anoncrypt_envelope(seed, &msg).expect("anoncrypt seed"));
        out.push(signed_envelope(seed, &msg).expect("signed seed"));
        out.push(plaintext_envelope(&msg));
    }
    out
}

/// Pack `msg` as a bare plaintext DIDComm message (no crypto protection).
fn plaintext_envelope(msg: &Message) -> PackedEnvelope {
    // Plaintext serialization is infallible for a well-formed Message.
    let envelope = serde_json::to_string(msg).expect("plaintext serialize");
    PackedEnvelope {
        envelope,
        recipient_kid: None,
        recipient_private: None,
        sender_public: None,
        signer_public: None,
    }
}

/// A couple of structurally varied sample messages for the seed corpus.
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

// ── deterministic key derivation ──────────────────────────────────────────

/// Domain tag separating key-agreement keys from signing keys derived off the
/// same seed.
const KEY_DOMAIN_KA: u8 = 0x01;
const KEY_DOMAIN_SIGN: u8 = 0x02;

/// Salt mixed into a seed to derive the authcrypt *sender* key, so sender and
/// recipient never collide.
const SENDER_SALT: u64 = 0xA5A5_A5A5_A5A5_A5A5;

/// Fill 32 deterministic bytes from `(seed, domain)` via SplitMix64. Not
/// cryptographic — these are throwaway test keys — but stable across runs and
/// platforms, which is all the corpus needs.
fn expand_seed(seed: u64, domain: u8) -> [u8; 32] {
    let mut state = seed ^ ((domain as u64) << 56) ^ 0x9E37_79B9_7F4A_7C15;
    let mut out = [0u8; 32];
    for chunk in out.chunks_mut(8) {
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        chunk.copy_from_slice(&z.to_le_bytes()[..chunk.len()]);
    }
    out
}

fn recipient_kid(seed: u64) -> String {
    format!("did:example:recipient-{seed}#key-1")
}

fn sender_kid(seed: u64) -> String {
    format!("did:example:sender-{seed}#key-1")
}

fn signer_kid(seed: u64) -> String {
    format!("did:example:signer-{seed}#key-1")
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_messaging_didcomm::UnpackResult;
    use affinidi_messaging_didcomm::message::unpack::unpack;

    fn unpack_envelope(env: &PackedEnvelope) -> UnpackResult {
        unpack(
            &env.envelope,
            env.recipient_kid.as_deref(),
            env.recipient_private.as_ref(),
            env.sender_public.as_ref(),
            env.signer_public.as_ref(),
        )
        .expect("envelope should unpack")
    }

    #[test]
    fn key_agreement_is_deterministic() {
        let a = key_agreement_from_seed(Curve::X25519, 7, "kid").unwrap();
        let b = key_agreement_from_seed(Curve::X25519, 7, "kid").unwrap();
        assert_eq!(a.public().to_public_bytes(), b.public().to_public_bytes());

        let c = key_agreement_from_seed(Curve::X25519, 8, "kid").unwrap();
        assert_ne!(a.public().to_public_bytes(), c.public().to_public_bytes());
    }

    #[test]
    fn signing_keypair_is_deterministic() {
        assert_eq!(signing_keypair_from_seed(3), signing_keypair_from_seed(3));
        assert_ne!(signing_keypair_from_seed(3), signing_keypair_from_seed(4));
    }

    #[test]
    fn authcrypt_round_trips_and_authenticates() {
        let msg = Message::new("t", serde_json::json!({ "x": 1 }));
        let env = authcrypt_envelope(42, &msg).unwrap();
        match unpack_envelope(&env) {
            UnpackResult::Encrypted {
                message,
                authenticated,
                ..
            } => {
                assert_eq!(message.body["x"], 1);
                assert!(authenticated, "authcrypt must bind the sender");
            }
            _ => panic!("expected Encrypted"),
        }
    }

    #[test]
    fn anoncrypt_round_trips_without_auth() {
        let msg = Message::new("t", serde_json::json!({ "x": 2 }));
        let env = anoncrypt_envelope(42, &msg).unwrap();
        match unpack_envelope(&env) {
            UnpackResult::Encrypted {
                message,
                authenticated,
                ..
            } => {
                assert_eq!(message.body["x"], 2);
                assert!(!authenticated, "anoncrypt is anonymous");
            }
            _ => panic!("expected Encrypted"),
        }
    }

    #[test]
    fn signed_round_trips() {
        let msg = Message::new("t", serde_json::json!({ "x": 3 }));
        let env = signed_envelope(42, &msg).unwrap();
        match unpack_envelope(&env) {
            UnpackResult::Signed { message, .. } => assert_eq!(message.body["x"], 3),
            _ => panic!("expected Signed"),
        }
    }

    #[test]
    fn seed_corpus_all_unpack() {
        let corpus = seed_corpus();
        assert!(!corpus.is_empty());
        // Every seed envelope must open cleanly under the keys it ships with —
        // that is the whole contract a fuzz harness relies on.
        for env in &corpus {
            unpack_envelope(env);
        }
    }
}
