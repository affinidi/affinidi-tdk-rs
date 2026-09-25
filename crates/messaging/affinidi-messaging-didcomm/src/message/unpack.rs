//! Message unpacking — detect format and dispatch to appropriate handler.

use crate::error::DIDCommError;
use crate::jwe::decrypt::SenderKey;
use crate::jws::verify::{SignerKey, VerifiedJws, verify_bound};
use crate::message::Message;
use affinidi_crypto::jose::key_agreement::{PrivateKeyAgreement, PublicKeyAgreement};

/// The result of unpacking a DIDComm message.
///
/// `#[non_exhaustive]` so future envelope shapes can be added without a
/// breaking change — match with a `_ =>` arm.
#[non_exhaustive]
pub enum UnpackResult {
    /// An encrypted message was decrypted.
    Encrypted {
        message: Message,
        /// Sender was cryptographically bound via authcrypt (ECDH-1PU).
        authenticated: bool,
        /// Authcrypt sender KID: the JWE `skid`, which the supplied sender key
        /// was checked against. `None` for anoncrypt.
        sender_kid: Option<String>,
        recipient_kid: String,
        /// Always `false`: the pre-0.14 (issue #322) ECDH-1PU KEK is no
        /// longer accepted.
        #[deprecated(
            since = "0.15.9",
            note = "always false: the pre-0.14 ECDH-1PU KEK is no longer accepted"
        )]
        legacy_kek_used: bool,
        /// `true` if the encrypted payload was itself a signed JWS
        /// (DIDComm v2.1 sign-then-encrypt) that was verified — i.e. the
        /// message carries non-repudiation, not just authentication.
        non_repudiation: bool,
        /// Inner JWS signer KID, when `non_repudiation` is `true`.
        signer_kid: Option<String>,
    },
    /// A signed message was verified.
    Signed {
        message: Message,
        signer_kid: Option<String>,
    },
    /// A plaintext message (no crypto protection).
    Plaintext(Message),
}

/// [`unpack_bound`] for callers that hold keys without their key ids.
///
/// An authcrypt JWE cannot be opened this way: with no key id there is no way
/// to tell whose key `sender_public` is, so passing one for an ECDH-1PU JWE is
/// refused with [`DIDCommError::SenderKeyBinding`]. Anoncrypt and plaintext
/// unpack as before. `signer_public` is taken to be the Ed25519 key of the
/// signature's `kid`, which is reported as `signer_kid`.
#[deprecated(
    since = "0.15.9",
    note = "use `unpack_bound` with a `SenderKey` / `SignerKey`. An authcrypt JWE is refused \
            here when a sender key is passed, since nothing ties the key to the JWE's `skid`; \
            `signer_public` must be the key resolved for the JWS `kid`"
)]
pub fn unpack(
    input: &str,
    recipient_kid: Option<&str>,
    recipient_private: Option<&PrivateKeyAgreement>,
    sender_public: Option<&PublicKeyAgreement>,
    signer_public: Option<&[u8; 32]>,
) -> Result<UnpackResult, DIDCommError> {
    if sender_public.is_some()
        && let Ok(Some(_)) = crate::jwe::decrypt::authcrypt_sender_kid(input)
    {
        return Err(unbound_sender_key());
    }
    unpack_with(
        input,
        recipient_kid,
        recipient_private,
        None,
        signer_public.map(Signer::HeaderKid),
    )
}

pub(crate) fn unbound_sender_key() -> DIDCommError {
    DIDCommError::SenderKeyBinding(
        "an authcrypt JWE needs the sender key bound to its `skid`; \
         use `decrypt_bound` / `unpack_bound` with a `SenderKey`"
            .into(),
    )
}

/// Detect the message format from JSON and unpack accordingly.
///
/// Detection heuristic:
/// - Has "protected" + "recipients" + "ciphertext" → JWE (encrypted)
/// - Has "payload" + "signatures" → JWS (signed)
/// - Has "type" → plaintext DIDComm message
///
/// For encrypted messages, both `recipient_kid`/`recipient_private` are required.
/// For authcrypt, `sender` is also required and must be the key named by the
/// JWE `skid` (see [`crate::jwe::decrypt::authcrypt_sender_kid`]).
/// For signed messages, `signer` is required: the message is refused unless
/// it carries a signature by `signer.kid()` that verifies under its key, and
/// `signer_kid` is that key id.
///
/// If a decrypted JWE turns out to wrap a JWS (DIDComm v2.1
/// sign-then-encrypt for non-repudiation), the inner signature is
/// verified too — `signer` is then also required, and the result
/// is [`UnpackResult::Encrypted`] with `non_repudiation = true`.
pub fn unpack_bound(
    input: &str,
    recipient_kid: Option<&str>,
    recipient_private: Option<&PrivateKeyAgreement>,
    sender: Option<SenderKey<'_>>,
    signer: Option<SignerKey<'_>>,
) -> Result<UnpackResult, DIDCommError> {
    unpack_with(
        input,
        recipient_kid,
        recipient_private,
        sender,
        signer.map(Signer::Bound),
    )
}

/// How a JWS signature is checked: against a key bound to its key id, or —
/// for the deprecated key-only entry point — against an Ed25519 key taken to
/// be that of whatever `kid` the signature names.
enum Signer<'a> {
    Bound(SignerKey<'a>),
    HeaderKid(&'a [u8; 32]),
}

fn verify_signed(jws: &str, signer: Option<&Signer<'_>>) -> Result<VerifiedJws, DIDCommError> {
    match signer {
        Some(Signer::Bound(signer)) => verify_bound(jws, *signer),
        #[allow(deprecated)]
        Some(Signer::HeaderKid(public)) => crate::jws::verify::verify_ed25519(jws, public),
        None => Err(DIDCommError::InvalidMessage(
            "a signer key is required to verify a signed (JWS) message".into(),
        )),
    }
}

#[allow(deprecated)]
fn unpack_with(
    input: &str,
    recipient_kid: Option<&str>,
    recipient_private: Option<&PrivateKeyAgreement>,
    sender: Option<SenderKey<'_>>,
    signer: Option<Signer<'_>>,
) -> Result<UnpackResult, DIDCommError> {
    let value: serde_json::Value = serde_json::from_str(input)
        .map_err(|e| DIDCommError::InvalidMessage(format!("invalid JSON: {e}")))?;

    if value.get("ciphertext").is_some() && value.get("recipients").is_some() {
        let kid = recipient_kid
            .ok_or_else(|| DIDCommError::InvalidMessage("recipient_kid required for JWE".into()))?;
        let private = recipient_private.ok_or_else(|| {
            DIDCommError::InvalidMessage("recipient_private required for JWE".into())
        })?;

        let decrypted = crate::jwe::decrypt::decrypt_bound(input, kid, private, sender)?;

        // DIDComm v2.1 sign-then-encrypt (non-repudiation): the decrypted
        // payload is itself a JWS, not a bare Message. Detect that and
        // verify the inner signature rather than trying to parse the JWS
        // envelope as a Message (issue #324). Detection is unambiguous —
        // a plaintext DIDComm message has `id`/`type`, never
        // `payload`+`signatures`.
        let inner_is_jws = serde_json::from_slice::<serde_json::Value>(&decrypted.plaintext)
            .ok()
            .is_some_and(|v| v.get("payload").is_some() && v.get("signatures").is_some());

        if inner_is_jws {
            let inner = std::str::from_utf8(&decrypted.plaintext).map_err(|e| {
                DIDCommError::InvalidMessage(format!("inner JWS is not valid UTF-8: {e}"))
            })?;
            let verified = verify_signed(inner, signer.as_ref())?;
            let message = Message::from_json(&verified.payload)?;

            return Ok(UnpackResult::Encrypted {
                message,
                authenticated: decrypted.authenticated,
                sender_kid: decrypted.sender_kid,
                recipient_kid: decrypted.recipient_kid,
                legacy_kek_used: false,
                non_repudiation: true,
                signer_kid: verified.signer_kid,
            });
        }

        let message = Message::from_json(&decrypted.plaintext)?;

        Ok(UnpackResult::Encrypted {
            message,
            authenticated: decrypted.authenticated,
            sender_kid: decrypted.sender_kid,
            recipient_kid: decrypted.recipient_kid,
            legacy_kek_used: false,
            non_repudiation: false,
            signer_kid: None,
        })
    } else if value.get("payload").is_some() && value.get("signatures").is_some() {
        let verified = verify_signed(input, signer.as_ref())?;
        let message = Message::from_json(&verified.payload)?;

        Ok(UnpackResult::Signed {
            message,
            signer_kid: verified.signer_kid,
        })
    } else if value.get("type").is_some() {
        let message = Message::from_json(input.as_bytes())?;
        Ok(UnpackResult::Plaintext(message))
    } else {
        Err(DIDCommError::InvalidMessage(
            "cannot detect message format: expected JWE, JWS, or plaintext".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jws::verify::VerifyKey;
    use crate::message::pack;
    use affinidi_crypto::jose::key_agreement::Curve;

    #[test]
    fn unpack_encrypted_authcrypt() {
        let sender = PrivateKeyAgreement::generate(Curve::X25519);
        let recipient = PrivateKeyAgreement::generate(Curve::X25519);

        let msg = Message::new("test", serde_json::json!({"data": 1})).from("did:example:alice");

        let packed = pack::pack_encrypted_authcrypt(
            &msg,
            "did:example:alice#key-1",
            &sender,
            &[("did:example:bob#key-1", &recipient.public_key())],
        )
        .unwrap();

        let result = unpack_bound(
            &packed,
            Some("did:example:bob#key-1"),
            Some(&recipient),
            Some(SenderKey::new(
                "did:example:alice#key-1",
                &sender.public_key(),
            )),
            None,
        )
        .unwrap();

        match result {
            UnpackResult::Encrypted {
                message,
                authenticated,
                ..
            } => {
                assert!(authenticated);
                assert_eq!(message.body["data"], 1);
            }
            _ => panic!("expected Encrypted"),
        }
    }

    #[test]
    fn unpack_signed() {
        let sk = ed25519_dalek::SigningKey::generate(&mut rand_10::rng());
        let key = VerifyKey::Ed25519(sk.verifying_key().to_bytes());

        let msg = Message::new("test", serde_json::json!({}));
        let packed = pack::pack_signed(&msg, "did:example:alice#key-1", &sk.to_bytes()).unwrap();

        let result = unpack_bound(
            &packed,
            None,
            None,
            None,
            Some(SignerKey::new("did:example:alice#key-1", &key)),
        )
        .unwrap();
        match result {
            UnpackResult::Signed { signer_kid, .. } => {
                assert_eq!(signer_kid.as_deref(), Some("did:example:alice#key-1"));
            }
            _ => panic!("expected Signed"),
        }
    }

    #[test]
    fn unpack_plaintext() {
        let msg = Message::new("test", serde_json::json!({"x": true}));
        let packed = pack::pack_plaintext(&msg).unwrap();

        let result = unpack_bound(&packed, None, None, None, None).unwrap();
        match result {
            UnpackResult::Plaintext(m) => {
                assert_eq!(m.body["x"], true);
            }
            _ => panic!("expected Plaintext"),
        }
    }

    /// #324: DIDComm v2.1 sign-then-encrypt — a JWS wrapped in an
    /// authcrypt JWE (credo-ts `packSignedAndEncrypted`). unpack_bound() must
    /// decrypt, verify the inner signature, and report non-repudiation +
    /// the inner signer kid.
    #[test]
    fn unpack_sign_then_encrypt() {
        let sk = ed25519_dalek::SigningKey::generate(&mut rand_10::rng());
        let signer_key = VerifyKey::Ed25519(sk.verifying_key().to_bytes());
        let sender = PrivateKeyAgreement::generate(Curve::X25519);
        let recipient = PrivateKeyAgreement::generate(Curve::X25519);

        let msg = Message::new("test", serde_json::json!({"data": 42})).from("did:example:alice");

        // Sign first, then encrypt the JWS bytes (sign-then-encrypt).
        let jws = pack::pack_signed(&msg, "did:example:alice#sign-1", &sk.to_bytes()).unwrap();
        let jwe = crate::jwe::encrypt::authcrypt(
            jws.as_bytes(),
            "did:example:alice#key-1",
            &sender,
            &[("did:example:bob#key-1", &recipient.public_key())],
        )
        .unwrap();

        let result = unpack_bound(
            &jwe,
            Some("did:example:bob#key-1"),
            Some(&recipient),
            Some(SenderKey::new(
                "did:example:alice#key-1",
                &sender.public_key(),
            )),
            Some(SignerKey::new("did:example:alice#sign-1", &signer_key)),
        )
        .unwrap();

        match result {
            UnpackResult::Encrypted {
                message,
                authenticated,
                non_repudiation,
                signer_kid,
                ..
            } => {
                assert!(authenticated);
                assert!(
                    non_repudiation,
                    "sign-then-encrypt must set non_repudiation"
                );
                assert_eq!(signer_kid.as_deref(), Some("did:example:alice#sign-1"));
                assert_eq!(message.body["data"], 42);
            }
            _ => panic!("expected Encrypted"),
        }
    }

    /// A sign-then-encrypt message decrypts but cannot be verified
    /// without the signer's public key — unpack_bound() must surface that
    /// rather than returning an unverified message.
    #[test]
    fn unpack_sign_then_encrypt_requires_signer_public() {
        let sk = ed25519_dalek::SigningKey::generate(&mut rand_10::rng());
        let sender = PrivateKeyAgreement::generate(Curve::X25519);
        let recipient = PrivateKeyAgreement::generate(Curve::X25519);

        let msg = Message::new("test", serde_json::json!({}));
        let jws = pack::pack_signed(&msg, "did:example:alice#sign-1", &sk.to_bytes()).unwrap();
        let jwe = crate::jwe::encrypt::authcrypt(
            jws.as_bytes(),
            "did:example:alice#key-1",
            &sender,
            &[("did:example:bob#key-1", &recipient.public_key())],
        )
        .unwrap();

        // signer_public = None → must error, not return an unverified message.
        let result = unpack_bound(
            &jwe,
            Some("did:example:bob#key-1"),
            Some(&recipient),
            Some(SenderKey::new(
                "did:example:alice#key-1",
                &sender.public_key(),
            )),
            None,
        );
        assert!(result.is_err());
    }
}
