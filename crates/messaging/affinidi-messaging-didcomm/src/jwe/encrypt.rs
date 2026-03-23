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

    let curve = recipients[0].1.curve();
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
    let (ciphertext, tag) = content_encryption::encrypt(plaintext, &cek, &iv, protected_b64.as_bytes())?;

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

    serde_json::to_string(&jwe)
        .map_err(|e| DIDCommError::Serialization(format!("JWE: {e}")))
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

    let (ciphertext, tag) = content_encryption::encrypt(plaintext, &cek, &iv, protected_b64.as_bytes())?;

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

    serde_json::to_string(&jwe)
        .map_err(|e| DIDCommError::Serialization(format!("JWE: {e}")))
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
