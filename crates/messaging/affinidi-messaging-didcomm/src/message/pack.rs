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
    fn pack_unpack_authcrypt_p256() {
        let msg = Message::new(
            "https://didcomm.org/basicmessage/2.0/message",
            serde_json::json!({"content": "P-256 Hello!"}),
        )
        .from("did:example:alice")
        .to(vec!["did:example:bob".into()]);

        let sender = PrivateKeyAgreement::generate(Curve::P256);
        let recipient = PrivateKeyAgreement::generate(Curve::P256);

        let packed = pack_encrypted_authcrypt(
            &msg,
            "did:example:alice#p256",
            &sender,
            &[("did:example:bob#p256", &recipient.public_key())],
        )
        .unwrap();

        let decrypted = unpack_encrypted(
            &packed,
            "did:example:bob#p256",
            &recipient,
            Some(&sender.public_key()),
        )
        .unwrap();

        let unpacked = Message::from_json(&decrypted.plaintext).unwrap();
        assert_eq!(unpacked.body["content"], "P-256 Hello!");
        assert!(decrypted.authenticated);
    }

    #[test]
    fn pack_unpack_authcrypt_k256() {
        let msg = Message::new(
            "https://didcomm.org/basicmessage/2.0/message",
            serde_json::json!({"content": "K-256 Hello!"}),
        )
        .from("did:example:alice")
        .to(vec!["did:example:bob".into()]);

        let sender = PrivateKeyAgreement::generate(Curve::K256);
        let recipient = PrivateKeyAgreement::generate(Curve::K256);

        let packed = pack_encrypted_authcrypt(
            &msg,
            "did:example:alice#k256",
            &sender,
            &[("did:example:bob#k256", &recipient.public_key())],
        )
        .unwrap();

        let decrypted = unpack_encrypted(
            &packed,
            "did:example:bob#k256",
            &recipient,
            Some(&sender.public_key()),
        )
        .unwrap();

        let unpacked = Message::from_json(&decrypted.plaintext).unwrap();
        assert_eq!(unpacked.body["content"], "K-256 Hello!");
        assert!(decrypted.authenticated);
    }

    #[test]
    fn pack_unpack_anoncrypt_p256() {
        let msg = Message::new(
            "https://didcomm.org/basicmessage/2.0/message",
            serde_json::json!({"content": "P-256 anon"}),
        );

        let recipient = PrivateKeyAgreement::generate(Curve::P256);

        let packed =
            pack_encrypted_anoncrypt(&msg, &[("did:example:bob#p256", &recipient.public_key())])
                .unwrap();

        let decrypted =
            unpack_encrypted(&packed, "did:example:bob#p256", &recipient, None).unwrap();

        let unpacked = Message::from_json(&decrypted.plaintext).unwrap();
        assert_eq!(unpacked.body["content"], "P-256 anon");
        assert!(!decrypted.authenticated);
    }

    #[test]
    fn pack_unpack_anoncrypt_k256() {
        let msg = Message::new(
            "https://didcomm.org/basicmessage/2.0/message",
            serde_json::json!({"content": "K-256 anon"}),
        );

        let recipient = PrivateKeyAgreement::generate(Curve::K256);

        let packed =
            pack_encrypted_anoncrypt(&msg, &[("did:example:bob#k256", &recipient.public_key())])
                .unwrap();

        let decrypted =
            unpack_encrypted(&packed, "did:example:bob#k256", &recipient, None).unwrap();

        let unpacked = Message::from_json(&decrypted.plaintext).unwrap();
        assert_eq!(unpacked.body["content"], "K-256 anon");
        assert!(!decrypted.authenticated);
    }

    /// Test signed-then-encrypted: sign a message first, then encrypt the JWS
    /// as an attachment in a wrapper message.
    #[test]
    fn pack_signed_then_authcrypt() {
        let sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let sender_ka = PrivateKeyAgreement::generate(Curve::X25519);
        let recipient_ka = PrivateKeyAgreement::generate(Curve::X25519);

        let msg = Message::new("test-type", serde_json::json!({"signed_encrypted": true}))
            .from("did:example:alice");

        // Step 1: Sign
        let signed = pack_signed(&msg, "did:example:alice#sign-1", &sk.to_bytes()).unwrap();

        // Step 2: Wrap signed JWS in a message and encrypt
        let wrapper = Message::new(
            "signed-encrypted-wrapper",
            serde_json::json!({"jws": signed}),
        );

        let packed = pack_encrypted_authcrypt(
            &wrapper,
            "did:example:alice#ka-1",
            &sender_ka,
            &[("did:example:bob#ka-1", &recipient_ka.public_key())],
        )
        .unwrap();

        // Step 3: Decrypt
        let decrypted = unpack_encrypted(
            &packed,
            "did:example:bob#ka-1",
            &recipient_ka,
            Some(&sender_ka.public_key()),
        )
        .unwrap();
        assert!(decrypted.authenticated);

        // Step 4: Extract and verify the signed inner payload
        let inner = Message::from_json(&decrypted.plaintext).unwrap();
        let jws_str = inner.body["jws"].as_str().unwrap();
        let verified =
            crate::jws::verify::verify_ed25519(jws_str, &sk.verifying_key().to_bytes()).unwrap();
        let original = Message::from_json(&verified.payload).unwrap();
        assert_eq!(original.body["signed_encrypted"], true);
    }

    #[test]
    fn pack_plaintext_roundtrip() {
        let msg = Message::new("test-type", serde_json::json!({"hello": "world"}));

        let packed = pack_plaintext(&msg).unwrap();
        let unpacked: Message = serde_json::from_str(&packed).unwrap();
        assert_eq!(unpacked.body["hello"], "world");
    }
}
