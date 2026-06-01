//! Message unpacking — detect format and dispatch to appropriate handler.

use crate::error::DIDCommError;
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
        /// Authcrypt sender KID (from the JWE `apu`/`skid`).
        sender_kid: Option<String>,
        recipient_kid: String,
        /// `true` if decryption only succeeded under the legacy
        /// (pre-0.14, issue #322) ECDH-1PU KEK — i.e. an unpatched
        /// sender. A migration signal; see [`crate::jwe`].
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

/// Detect the message format from JSON and unpack accordingly.
///
/// Detection heuristic:
/// - Has "protected" + "recipients" + "ciphertext" → JWE (encrypted)
/// - Has "payload" + "signatures" → JWS (signed)
/// - Has "type" → plaintext DIDComm message
///
/// For encrypted messages, both `recipient_kid`/`recipient_private` are required.
/// For authcrypt, `sender_public` is also required.
/// For signed messages, `signer_public` is required.
///
/// If a decrypted JWE turns out to wrap a JWS (DIDComm v2.1
/// sign-then-encrypt for non-repudiation), the inner signature is
/// verified too — `signer_public` is then also required, and the result
/// is [`UnpackResult::Encrypted`] with `non_repudiation = true`.
pub fn unpack(
    input: &str,
    recipient_kid: Option<&str>,
    recipient_private: Option<&PrivateKeyAgreement>,
    sender_public: Option<&PublicKeyAgreement>,
    signer_public: Option<&[u8; 32]>,
) -> Result<UnpackResult, DIDCommError> {
    let value: serde_json::Value = serde_json::from_str(input)
        .map_err(|e| DIDCommError::InvalidMessage(format!("invalid JSON: {e}")))?;

    if value.get("ciphertext").is_some() && value.get("recipients").is_some() {
        // JWE — encrypted message
        let kid = recipient_kid
            .ok_or_else(|| DIDCommError::InvalidMessage("recipient_kid required for JWE".into()))?;
        let private = recipient_private.ok_or_else(|| {
            DIDCommError::InvalidMessage("recipient_private required for JWE".into())
        })?;

        let decrypted = crate::jwe::decrypt::decrypt(input, kid, private, sender_public)?;

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
            let pk = signer_public.ok_or_else(|| {
                DIDCommError::InvalidMessage(
                    "decrypted payload is a signed JWS (sign-then-encrypt); \
                     signer_public is required to verify it"
                        .into(),
                )
            })?;
            let inner = std::str::from_utf8(&decrypted.plaintext).map_err(|e| {
                DIDCommError::InvalidMessage(format!("inner JWS is not valid UTF-8: {e}"))
            })?;
            let verified = crate::jws::verify::verify_ed25519(inner, pk)?;
            let message = Message::from_json(&verified.payload)?;

            return Ok(UnpackResult::Encrypted {
                message,
                authenticated: decrypted.authenticated,
                sender_kid: decrypted.sender_kid,
                recipient_kid: decrypted.recipient_kid,
                legacy_kek_used: decrypted.legacy_kek_used,
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
            legacy_kek_used: decrypted.legacy_kek_used,
            non_repudiation: false,
            signer_kid: None,
        })
    } else if value.get("payload").is_some() && value.get("signatures").is_some() {
        // JWS — signed message
        let pk = signer_public
            .ok_or_else(|| DIDCommError::InvalidMessage("signer_public required for JWS".into()))?;

        let verified = crate::jws::verify::verify_ed25519(input, pk)?;
        let message = Message::from_json(&verified.payload)?;

        Ok(UnpackResult::Signed {
            message,
            signer_kid: verified.signer_kid,
        })
    } else if value.get("type").is_some() {
        // Plaintext DIDComm message
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

        let result = unpack(
            &packed,
            Some("did:example:bob#key-1"),
            Some(&recipient),
            Some(&sender.public_key()),
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
        let sk = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let pk = sk.verifying_key().to_bytes();

        let msg = Message::new("test", serde_json::json!({}));
        let packed = pack::pack_signed(&msg, "did:example:alice#key-1", &sk.to_bytes()).unwrap();

        let result = unpack(&packed, None, None, None, Some(&pk)).unwrap();
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

        let result = unpack(&packed, None, None, None, None).unwrap();
        match result {
            UnpackResult::Plaintext(m) => {
                assert_eq!(m.body["x"], true);
            }
            _ => panic!("expected Plaintext"),
        }
    }

    /// #324: DIDComm v2.1 sign-then-encrypt — a JWS wrapped in an
    /// authcrypt JWE (credo-ts `packSignedAndEncrypted`). unpack() must
    /// decrypt, verify the inner signature, and report non-repudiation +
    /// the inner signer kid.
    #[test]
    fn unpack_sign_then_encrypt() {
        let sk = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let signer_pk = sk.verifying_key().to_bytes();
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

        let result = unpack(
            &jwe,
            Some("did:example:bob#key-1"),
            Some(&recipient),
            Some(&sender.public_key()),
            Some(&signer_pk),
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
    /// without the signer's public key — unpack() must surface that
    /// rather than returning an unverified message.
    #[test]
    fn unpack_sign_then_encrypt_requires_signer_public() {
        let sk = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
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
        let result = unpack(
            &jwe,
            Some("did:example:bob#key-1"),
            Some(&recipient),
            Some(&sender.public_key()),
            None,
        );
        assert!(result.is_err());
    }
}
