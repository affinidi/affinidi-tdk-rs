//! Message packing — encrypt, sign, or send plaintext DIDComm messages.

use crate::crypto::key_agreement::{PrivateKeyAgreement, PublicKeyAgreement};
use crate::error::DIDCommError;
use crate::jwe::{decrypt, encrypt};
use crate::jws::sign;
use crate::message::Message;

/// Pack a message as encrypted (authcrypt — sender authenticated).
///
/// # Arguments
/// * `msg` - The DIDComm message to encrypt
/// * `sender_kid` - The sender's key agreement key ID
/// * `sender_private` - The sender's key agreement private key
/// * `recipients` - Slice of (kid, public_key) pairs for each recipient
pub fn pack_encrypted_authcrypt(
    msg: &Message,
    sender_kid: &str,
    sender_private: &PrivateKeyAgreement,
    recipients: &[(&str, &PublicKeyAgreement)],
) -> Result<String, DIDCommError> {
    let plaintext = msg.to_json()?;
    encrypt::authcrypt(&plaintext, sender_kid, sender_private, recipients)
}

/// Pack a message as encrypted (anoncrypt — anonymous).
///
/// # Arguments
/// * `msg` - The DIDComm message to encrypt
/// * `recipients` - Slice of (kid, public_key) pairs for each recipient
pub fn pack_encrypted_anoncrypt(
    msg: &Message,
    recipients: &[(&str, &PublicKeyAgreement)],
) -> Result<String, DIDCommError> {
    let plaintext = msg.to_json()?;
    encrypt::anoncrypt(&plaintext, recipients)
}

/// Pack a message as signed (JWS with EdDSA).
///
/// # Arguments
/// * `msg` - The DIDComm message to sign
/// * `signer_kid` - The signer's key ID (DID URL)
/// * `private_key` - The signer's Ed25519 private key
pub fn pack_signed(
    msg: &Message,
    signer_kid: &str,
    private_key: &[u8; 32],
) -> Result<String, DIDCommError> {
    let payload = msg.to_json()?;
    sign::sign_ed25519(&payload, signer_kid, private_key)
}

/// Pack a message as plaintext JSON.
pub fn pack_plaintext(msg: &Message) -> Result<String, DIDCommError> {
    serde_json::to_string(msg).map_err(|e| DIDCommError::Serialization(format!("plaintext: {e}")))
}

/// Unpack an encrypted message (convenience re-export of decrypt).
pub use decrypt::decrypt as unpack_encrypted;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::key_agreement::Curve;

    #[test]
    fn pack_unpack_authcrypt() {
        let msg = Message::new(
            "https://didcomm.org/basicmessage/2.0/message",
            serde_json::json!({"content": "Hello!"}),
        )
        .from("did:example:alice")
        .to(vec!["did:example:bob".into()]);

        let sender = PrivateKeyAgreement::generate(Curve::X25519);
        let recipient = PrivateKeyAgreement::generate(Curve::X25519);

        let packed = pack_encrypted_authcrypt(
            &msg,
            "did:example:alice#key-1",
            &sender,
            &[("did:example:bob#key-1", &recipient.public_key())],
        )
        .unwrap();

        let decrypted = unpack_encrypted(
            &packed,
            "did:example:bob#key-1",
            &recipient,
            Some(&sender.public_key()),
        )
        .unwrap();

        let unpacked = Message::from_json(&decrypted.plaintext).unwrap();
        assert_eq!(unpacked.body["content"], "Hello!");
        assert!(decrypted.authenticated);
    }

    #[test]
    fn pack_unpack_anoncrypt() {
        let msg = Message::new(
            "https://didcomm.org/basicmessage/2.0/message",
            serde_json::json!({"content": "Anonymous!"}),
        );

        let recipient = PrivateKeyAgreement::generate(Curve::X25519);

        let packed =
            pack_encrypted_anoncrypt(&msg, &[("did:example:bob#key-1", &recipient.public_key())])
                .unwrap();

        let decrypted =
            unpack_encrypted(&packed, "did:example:bob#key-1", &recipient, None).unwrap();

        let unpacked = Message::from_json(&decrypted.plaintext).unwrap();
        assert_eq!(unpacked.body["content"], "Anonymous!");
        assert!(!decrypted.authenticated);
    }

    #[test]
    fn pack_signed_roundtrip() {
        let sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);

        let msg =
            Message::new("test-type", serde_json::json!({"data": 42})).from("did:example:alice");

        let packed = pack_signed(&msg, "did:example:alice#key-1", &sk.to_bytes()).unwrap();

        let verified =
            crate::jws::verify::verify_ed25519(&packed, &sk.verifying_key().to_bytes()).unwrap();
        let unpacked = Message::from_json(&verified.payload).unwrap();
        assert_eq!(unpacked.body["data"], 42);
    }

    #[test]
    fn pack_plaintext_roundtrip() {
        let msg = Message::new("test-type", serde_json::json!({"hello": "world"}));

        let packed = pack_plaintext(&msg).unwrap();
        let unpacked: Message = serde_json::from_str(&packed).unwrap();
        assert_eq!(unpacked.body["hello"], "world");
    }
}
