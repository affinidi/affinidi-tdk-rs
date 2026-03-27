//! JWE encryption — build DIDComm encrypted messages.

use base64ct::{Base64UrlUnpadded, Encoding};
use sha2::{Digest, Sha256};

use crate::crypto::{aes_kw, content_encryption, ecdh_1pu, ecdh_es, key_agreement::*};
use crate::error::DIDCommError;
use crate::jwe::envelope::*;

/// Encrypt a plaintext payload for one or more recipients using authcrypt (ECDH-1PU).
///
/// The sender is cryptographically bound to the ciphertext.
pub fn authcrypt(
    plaintext: &[u8],
    sender_kid: &str,
    sender_private: &PrivateKeyAgreement,
    recipients: &[(&str, &PublicKeyAgreement)], // (kid, public_key)
) -> Result<String, DIDCommError> {
    if recipients.is_empty() {
        return Err(DIDCommError::InvalidMessage("no recipients".into()));
    }
    if sender_kid.is_empty() {
        return Err(DIDCommError::InvalidMessage(
            "sender KID must not be empty".into(),
        ));
    }

    let curve = recipients[0].1.curve();
    // Validate all recipients use the same curve
    for (kid, pk) in recipients {
        if kid.is_empty() {
            return Err(DIDCommError::InvalidMessage(
                "recipient KID must not be empty".into(),
            ));
        }
        if pk.curve() != curve {
            return Err(DIDCommError::KeyAgreement(format!(
                "all recipients must use the same curve; expected {curve:?} but '{}' uses {:?}",
                kid,
                pk.curve()
            )));
        }
    }
    let ephemeral = EphemeralKeyPair::generate(curve);

    // Compute APU and APV
    let apu_raw = sender_kid.as_bytes();
    let apv_raw = compute_apv(recipients.iter().map(|(kid, _)| *kid));

    // Generate CEK and IV, encrypt content
    let cek = content_encryption::generate_cek();
    let iv = content_encryption::generate_iv();

    // Build protected header (needed as AAD before encryption)
    let protected_header = ProtectedHeader {
        typ: Some("application/didcomm-encrypted+json".into()),
        alg: "ECDH-1PU+A256KW".into(),
        enc: "A256CBC-HS512".into(),
        skid: Some(sender_kid.to_string()),
        apu: Some(Base64UrlUnpadded::encode_string(apu_raw)),
        apv: Base64UrlUnpadded::encode_string(&apv_raw),
        epk: ephemeral.public.to_jwk(),
    };
    let protected_str = serde_json::to_string(&protected_header)
        .map_err(|e| DIDCommError::Serialization(format!("protected header: {e}")))?;
    let protected_b64 = Base64UrlUnpadded::encode_string(protected_str.as_bytes());

    // Encrypt plaintext with CEK
    let (ciphertext, tag) =
        content_encryption::encrypt(plaintext, &cek, &iv, protected_b64.as_bytes())?;

    // Wrap CEK for each recipient using ECDH-1PU (with tag-in-KDF)
    let mut jwe_recipients = Vec::with_capacity(recipients.len());
    for (kid, recipient_pub) in recipients {
        let kek = ecdh_1pu::derive_sender_key_1pu(
            &ephemeral,
            sender_private,
            recipient_pub,
            apu_raw,
            &apv_raw,
            &tag,
        )?;
        let wrapped = aes_kw::wrap(&kek, &cek)?;
        jwe_recipients.push(Recipient {
            header: PerRecipientHeader {
                kid: kid.to_string(),
            },
            encrypted_key: Base64UrlUnpadded::encode_string(&wrapped),
        });
    }

    let jwe = Jwe {
        protected: protected_b64,
        recipients: jwe_recipients,
        iv: Base64UrlUnpadded::encode_string(&iv),
        ciphertext: Base64UrlUnpadded::encode_string(&ciphertext),
        tag: Base64UrlUnpadded::encode_string(&tag),
    };

    serde_json::to_string(&jwe).map_err(|e| DIDCommError::Serialization(format!("JWE: {e}")))
}

/// Encrypt a plaintext payload for one or more recipients using anoncrypt (ECDH-ES).
///
/// Anonymous encryption — no sender identity is bound.
pub fn anoncrypt(
    plaintext: &[u8],
    recipients: &[(&str, &PublicKeyAgreement)],
) -> Result<String, DIDCommError> {
    if recipients.is_empty() {
        return Err(DIDCommError::InvalidMessage("no recipients".into()));
    }

    let curve = recipients[0].1.curve();
    // Validate all recipients use the same curve and have non-empty KIDs
    for (kid, pk) in recipients {
        if kid.is_empty() {
            return Err(DIDCommError::InvalidMessage(
                "recipient KID must not be empty".into(),
            ));
        }
        if pk.curve() != curve {
            return Err(DIDCommError::KeyAgreement(format!(
                "all recipients must use the same curve; expected {curve:?} but '{}' uses {:?}",
                kid,
                pk.curve()
            )));
        }
    }
    let ephemeral = EphemeralKeyPair::generate(curve);

    let apv_raw = compute_apv(recipients.iter().map(|(kid, _)| *kid));

    let cek = content_encryption::generate_cek();
    let iv = content_encryption::generate_iv();

    let protected_header = ProtectedHeader {
        typ: Some("application/didcomm-encrypted+json".into()),
        alg: "ECDH-ES+A256KW".into(),
        enc: "A256CBC-HS512".into(),
        skid: None,
        apu: None,
        apv: Base64UrlUnpadded::encode_string(&apv_raw),
        epk: ephemeral.public.to_jwk(),
    };
    let protected_str = serde_json::to_string(&protected_header)
        .map_err(|e| DIDCommError::Serialization(format!("protected header: {e}")))?;
    let protected_b64 = Base64UrlUnpadded::encode_string(protected_str.as_bytes());

    let (ciphertext, tag) =
        content_encryption::encrypt(plaintext, &cek, &iv, protected_b64.as_bytes())?;

    let mut jwe_recipients = Vec::with_capacity(recipients.len());
    for (kid, recipient_pub) in recipients {
        let kek = ecdh_es::derive_sender_key(&ephemeral, recipient_pub, &[], &apv_raw)?;
        let wrapped = aes_kw::wrap(&kek, &cek)?;
        jwe_recipients.push(Recipient {
            header: PerRecipientHeader {
                kid: kid.to_string(),
            },
            encrypted_key: Base64UrlUnpadded::encode_string(&wrapped),
        });
    }

    let jwe = Jwe {
        protected: protected_b64,
        recipients: jwe_recipients,
        iv: Base64UrlUnpadded::encode_string(&iv),
        ciphertext: Base64UrlUnpadded::encode_string(&ciphertext),
        tag: Base64UrlUnpadded::encode_string(&tag),
    };

    serde_json::to_string(&jwe).map_err(|e| DIDCommError::Serialization(format!("JWE: {e}")))
}

/// Compute APV: SHA-256 of sorted, dot-joined recipient KIDs.
fn compute_apv<'a>(kids: impl Iterator<Item = &'a str>) -> Vec<u8> {
    let mut sorted: Vec<&str> = kids.collect();
    sorted.sort();
    Sha256::digest(sorted.join(".").as_bytes()).to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authcrypt_produces_valid_jwe() {
        let sender = PrivateKeyAgreement::generate(Curve::X25519);
        let recipient = PrivateKeyAgreement::generate(Curve::X25519);
        let recipient_pub = recipient.public_key();

        let jwe_str = authcrypt(
            b"Hello, DIDComm!",
            "did:example:alice#key-1",
            &sender,
            &[("did:example:bob#key-1", &recipient_pub)],
        )
        .unwrap();

        let jwe: Jwe = serde_json::from_str(&jwe_str).unwrap();
        assert_eq!(jwe.recipients.len(), 1);
        assert_eq!(jwe.recipients[0].header.kid, "did:example:bob#key-1");

        // Verify protected header
        let header_json = Base64UrlUnpadded::decode_vec(&jwe.protected).unwrap();
        let header: ProtectedHeader = serde_json::from_slice(&header_json).unwrap();
        assert_eq!(header.alg, "ECDH-1PU+A256KW");
        assert_eq!(header.enc, "A256CBC-HS512");
        assert!(header.skid.is_some());
    }

    #[test]
    fn anoncrypt_produces_valid_jwe() {
        let recipient = PrivateKeyAgreement::generate(Curve::X25519);
        let recipient_pub = recipient.public_key();

        let jwe_str = anoncrypt(
            b"Anonymous message",
            &[("did:example:bob#key-1", &recipient_pub)],
        )
        .unwrap();

        let jwe: Jwe = serde_json::from_str(&jwe_str).unwrap();
        assert_eq!(jwe.recipients.len(), 1);

        let header_json = Base64UrlUnpadded::decode_vec(&jwe.protected).unwrap();
        let header: ProtectedHeader = serde_json::from_slice(&header_json).unwrap();
        assert_eq!(header.alg, "ECDH-ES+A256KW");
        assert!(header.skid.is_none());
    }

    #[test]
    fn authcrypt_produces_valid_jwe_p256() {
        let sender = PrivateKeyAgreement::generate(Curve::P256);
        let recipient = PrivateKeyAgreement::generate(Curve::P256);
        let recipient_pub = recipient.public_key();

        let jwe_str = authcrypt(
            b"P-256 message",
            "did:example:alice#p256",
            &sender,
            &[("did:example:bob#p256", &recipient_pub)],
        )
        .unwrap();

        let jwe: Jwe = serde_json::from_str(&jwe_str).unwrap();
        assert_eq!(jwe.recipients.len(), 1);

        let header_json = Base64UrlUnpadded::decode_vec(&jwe.protected).unwrap();
        let header: ProtectedHeader = serde_json::from_slice(&header_json).unwrap();
        assert_eq!(header.alg, "ECDH-1PU+A256KW");
        assert_eq!(header.enc, "A256CBC-HS512");
        assert_eq!(header.epk["crv"], "P-256");
    }

    #[test]
    fn authcrypt_produces_valid_jwe_k256() {
        let sender = PrivateKeyAgreement::generate(Curve::K256);
        let recipient = PrivateKeyAgreement::generate(Curve::K256);
        let recipient_pub = recipient.public_key();

        let jwe_str = authcrypt(
            b"K-256 message",
            "did:example:alice#k256",
            &sender,
            &[("did:example:bob#k256", &recipient_pub)],
        )
        .unwrap();

        let jwe: Jwe = serde_json::from_str(&jwe_str).unwrap();
        assert_eq!(jwe.recipients.len(), 1);

        let header_json = Base64UrlUnpadded::decode_vec(&jwe.protected).unwrap();
        let header: ProtectedHeader = serde_json::from_slice(&header_json).unwrap();
        assert_eq!(header.alg, "ECDH-1PU+A256KW");
        assert_eq!(header.epk["crv"], "secp256k1");
    }

    #[test]
    fn anoncrypt_produces_valid_jwe_p256() {
        let recipient = PrivateKeyAgreement::generate(Curve::P256);
        let recipient_pub = recipient.public_key();

        let jwe_str =
            anoncrypt(b"P-256 anon", &[("did:example:bob#p256", &recipient_pub)]).unwrap();

        let jwe: Jwe = serde_json::from_str(&jwe_str).unwrap();
        let header_json = Base64UrlUnpadded::decode_vec(&jwe.protected).unwrap();
        let header: ProtectedHeader = serde_json::from_slice(&header_json).unwrap();
        assert_eq!(header.alg, "ECDH-ES+A256KW");
        assert_eq!(header.epk["crv"], "P-256");
    }

    #[test]
    fn anoncrypt_produces_valid_jwe_k256() {
        let recipient = PrivateKeyAgreement::generate(Curve::K256);
        let recipient_pub = recipient.public_key();

        let jwe_str =
            anoncrypt(b"K-256 anon", &[("did:example:bob#k256", &recipient_pub)]).unwrap();

        let jwe: Jwe = serde_json::from_str(&jwe_str).unwrap();
        let header_json = Base64UrlUnpadded::decode_vec(&jwe.protected).unwrap();
        let header: ProtectedHeader = serde_json::from_slice(&header_json).unwrap();
        assert_eq!(header.alg, "ECDH-ES+A256KW");
        assert_eq!(header.epk["crv"], "secp256k1");
    }

    #[test]
    fn multi_recipient_anoncrypt() {
        let r1 = PrivateKeyAgreement::generate(Curve::X25519);
        let r2 = PrivateKeyAgreement::generate(Curve::X25519);
        let r3 = PrivateKeyAgreement::generate(Curve::X25519);

        let jwe_str = anoncrypt(
            b"Multi anon",
            &[
                ("did:example:a#key-1", &r1.public_key()),
                ("did:example:b#key-1", &r2.public_key()),
                ("did:example:c#key-1", &r3.public_key()),
            ],
        )
        .unwrap();

        let jwe: Jwe = serde_json::from_str(&jwe_str).unwrap();
        assert_eq!(jwe.recipients.len(), 3);
        assert!(
            jwe.recipients
                .iter()
                .any(|r| r.header.kid == "did:example:a#key-1")
        );
        assert!(
            jwe.recipients
                .iter()
                .any(|r| r.header.kid == "did:example:b#key-1")
        );
        assert!(
            jwe.recipients
                .iter()
                .any(|r| r.header.kid == "did:example:c#key-1")
        );
    }

    #[test]
    fn authcrypt_empty_recipients_fails() {
        let sender = PrivateKeyAgreement::generate(Curve::X25519);
        let result = authcrypt(b"msg", "did:example:alice#key-1", &sender, &[]);
        assert!(result.is_err());
    }

    #[test]
    fn anoncrypt_empty_recipients_fails() {
        let result = anoncrypt(b"msg", &[]);
        assert!(result.is_err());
    }

    #[test]
    fn authcrypt_mixed_curves_fails() {
        let sender = PrivateKeyAgreement::generate(Curve::X25519);
        let r1 = PrivateKeyAgreement::generate(Curve::X25519);
        let r2 = PrivateKeyAgreement::generate(Curve::P256);

        let result = authcrypt(
            b"mixed",
            "did:example:alice#key-1",
            &sender,
            &[
                ("did:example:bob#x25519", &r1.public_key()),
                ("did:example:carol#p256", &r2.public_key()),
            ],
        );
        assert!(result.is_err());
    }

    #[test]
    fn multi_recipient_authcrypt() {
        let sender = PrivateKeyAgreement::generate(Curve::X25519);
        let r1 = PrivateKeyAgreement::generate(Curve::X25519);
        let r2 = PrivateKeyAgreement::generate(Curve::X25519);

        let jwe_str = authcrypt(
            b"Multi-recipient",
            "did:example:alice#key-1",
            &sender,
            &[
                ("did:example:bob#key-1", &r1.public_key()),
                ("did:example:carol#key-1", &r2.public_key()),
            ],
        )
        .unwrap();

        let jwe: Jwe = serde_json::from_str(&jwe_str).unwrap();
        assert_eq!(jwe.recipients.len(), 2);
    }
}
