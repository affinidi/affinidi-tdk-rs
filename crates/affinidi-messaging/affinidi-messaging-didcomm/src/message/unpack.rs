//! Message unpacking — detect format and dispatch to appropriate handler.

use crate::crypto::key_agreement::{PrivateKeyAgreement, PublicKeyAgreement};
use crate::error::DIDCommError;
use crate::message::Message;

/// The result of unpacking a DIDComm message.
pub enum UnpackResult {
    /// An encrypted message was decrypted.
    Encrypted {
        message: Message,
        authenticated: bool,
        sender_kid: Option<String>,
        recipient_kid: String,
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

        let decrypted =
            crate::jwe::decrypt::decrypt(input, kid, private, sender_public)?;

        let message = Message::from_json(&decrypted.plaintext)?;

        Ok(UnpackResult::Encrypted {
            message,
            authenticated: decrypted.authenticated,
            sender_kid: decrypted.sender_kid,
            recipient_kid: decrypted.recipient_kid,
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
    use crate::crypto::key_agreement::Curve;
    use crate::message::pack;

    #[test]
    fn unpack_encrypted_authcrypt() {
        let sender = PrivateKeyAgreement::generate(Curve::X25519);
        let recipient = PrivateKeyAgreement::generate(Curve::X25519);

        let msg = Message::new("test", serde_json::json!({"data": 1}))
            .from("did:example:alice");

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
        let sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
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
}
