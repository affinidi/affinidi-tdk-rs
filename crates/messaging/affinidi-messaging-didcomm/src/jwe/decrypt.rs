//! JWE decryption — parse and decrypt DIDComm encrypted messages.

use base64ct::{Base64UrlUnpadded, Encoding};

use crate::error::DIDCommError;
use crate::jwe::envelope::*;
use affinidi_crypto::jose::{aes_kw, content_encryption, ecdh, key_agreement::*};

/// Result of decrypting a JWE.
pub struct DecryptedJwe {
    /// The decrypted plaintext.
    pub plaintext: Vec<u8>,
    /// The parsed protected header.
    pub header: ProtectedHeader,
    /// Whether authcrypt was used (sender authenticated).
    pub authenticated: bool,
    /// The sender KID (if authcrypt).
    pub sender_kid: Option<String>,
    /// The recipient KID that was used to decrypt.
    pub recipient_kid: String,
    /// `true` if the message only decrypted under the legacy (pre-0.14,
    /// issue #322) ECDH-1PU KEK — i.e. the sender is an unpatched peer.
    /// Always `false` for anoncrypt and for spec-correct authcrypt.
    /// Surfaced as a migration signal: once this stops occurring across
    /// the deployment, the legacy fallback can be removed.
    pub legacy_kek_used: bool,
}

/// Decrypt a JWE string.
///
/// Tries each recipient in order until one matches the provided private key.
///
/// # Arguments
/// * `jwe_str` - The JWE JSON string
/// * `recipient_kid` - The recipient's key ID to look for
/// * `recipient_private` - The recipient's private key agreement key
/// * `sender_public` - The sender's public key (required for authcrypt, None for anoncrypt)
pub fn decrypt(
    jwe_str: &str,
    recipient_kid: &str,
    recipient_private: &PrivateKeyAgreement,
    sender_public: Option<&PublicKeyAgreement>,
) -> Result<DecryptedJwe, DIDCommError> {
    // Parse JWE
    let jwe: Jwe = serde_json::from_str(jwe_str)
        .map_err(|e| DIDCommError::InvalidMessage(format!("invalid JWE JSON: {e}")))?;

    // Decode protected header
    let header_bytes = Base64UrlUnpadded::decode_vec(&jwe.protected).map_err(|e| {
        DIDCommError::InvalidMessage(format!("invalid protected header base64: {e}"))
    })?;
    let header: ProtectedHeader = serde_json::from_slice(&header_bytes)
        .map_err(|e| DIDCommError::InvalidMessage(format!("invalid protected header JSON: {e}")))?;

    // Decode IV, ciphertext, tag
    let iv_bytes = Base64UrlUnpadded::decode_vec(&jwe.iv)
        .map_err(|e| DIDCommError::InvalidMessage(format!("invalid IV: {e}")))?;
    let iv: [u8; 16] = iv_bytes
        .try_into()
        .map_err(|_| DIDCommError::InvalidMessage("IV must be 16 bytes".into()))?;

    let ciphertext = Base64UrlUnpadded::decode_vec(&jwe.ciphertext)
        .map_err(|e| DIDCommError::InvalidMessage(format!("invalid ciphertext: {e}")))?;

    let tag_bytes = Base64UrlUnpadded::decode_vec(&jwe.tag)
        .map_err(|e| DIDCommError::InvalidMessage(format!("invalid tag: {e}")))?;
    let tag: [u8; 32] = tag_bytes
        .try_into()
        .map_err(|_| DIDCommError::InvalidMessage("tag must be 32 bytes".into()))?;

    // Find matching recipient
    let recipient = jwe
        .recipients
        .iter()
        .find(|r| r.header.kid == recipient_kid)
        .ok_or_else(|| {
            DIDCommError::InvalidMessage(format!("recipient {recipient_kid} not found in JWE"))
        })?;

    // Decode wrapped key
    let wrapped_key = Base64UrlUnpadded::decode_vec(&recipient.encrypted_key)
        .map_err(|e| DIDCommError::InvalidMessage(format!("invalid encrypted_key: {e}")))?;

    // Parse ephemeral public key from header
    let epk = PublicKeyAgreement::from_jwk(&header.epk)?;

    // Decode APU and APV
    let apu_raw = header
        .apu
        .as_ref()
        .map(|s| Base64UrlUnpadded::decode_vec(s))
        .transpose()
        .map_err(|e| DIDCommError::InvalidMessage(format!("invalid apu: {e}")))?
        .unwrap_or_default();

    let apv_raw = Base64UrlUnpadded::decode_vec(&header.apv)
        .map_err(|e| DIDCommError::InvalidMessage(format!("invalid apv: {e}")))?;

    // Determine algorithm, derive the KEK, and unwrap the CEK.
    let (cek_bytes, authenticated, sender_kid_str, legacy_kek_used) = match header.alg.as_str() {
        "ECDH-1PU+A256KW" => {
            let sender_pub = sender_public.ok_or_else(|| {
                DIDCommError::InvalidMessage(
                    "authcrypt requires sender public key for decryption".into(),
                )
            })?;

            let sender_kid_str = String::from_utf8(apu_raw.clone()).ok();

            // Derive the spec-correct KEK (length-prefixed cc_tag).
            let kek: [u8; 32] = ecdh::derive_key_1pu_recipient(
                recipient_private,
                sender_pub,
                &epk,
                b"ECDH-1PU+A256KW",
                &apu_raw,
                &apv_raw,
                &tag,
                256,
            )?
            .try_into()
            .map_err(|_| DIDCommError::KeyAgreement("KEK wrong size".into()))?;

            // Try the spec-correct KEK first. If AES-Key-Wrap integrity
            // fails, the sender may be an unpatched peer that derived the
            // legacy (pre-0.14, unprefixed-tag) KEK — retry with that so
            // we stay interoperable during migration (issue #322). A
            // genuinely bad message fails both and returns the second
            // error.
            match aes_kw::unwrap(&kek, &wrapped_key) {
                Ok(cek) => (cek, true, sender_kid_str, false),
                Err(_) => {
                    let legacy_kek: [u8; 32] = ecdh::derive_key_1pu_recipient_legacy(
                        recipient_private,
                        sender_pub,
                        &epk,
                        b"ECDH-1PU+A256KW",
                        &apu_raw,
                        &apv_raw,
                        &tag,
                        256,
                    )?
                    .try_into()
                    .map_err(|_| DIDCommError::KeyAgreement("KEK wrong size".into()))?;
                    let cek = aes_kw::unwrap(&legacy_kek, &wrapped_key)?;
                    (cek, true, sender_kid_str, true)
                }
            }
        }
        "ECDH-ES+A256KW" => {
            let kek: [u8; 32] = ecdh::derive_key_es_recipient(
                recipient_private,
                &epk,
                b"ECDH-ES+A256KW",
                &apu_raw,
                &apv_raw,
                256,
            )?
            .try_into()
            .map_err(|_| DIDCommError::KeyAgreement("KEK wrong size".into()))?;
            let cek = aes_kw::unwrap(&kek, &wrapped_key)?;
            (cek, false, None, false)
        }
        alg => {
            return Err(DIDCommError::UnsupportedAlgorithm(format!(
                "unsupported alg: {alg}"
            )));
        }
    };

    let cek: [u8; 64] = cek_bytes
        .try_into()
        .map_err(|_| DIDCommError::KeyWrap("unwrapped CEK wrong size".into()))?;

    let plaintext =
        content_encryption::decrypt(&ciphertext, &cek, &iv, jwe.protected.as_bytes(), &tag)?;

    Ok(DecryptedJwe {
        plaintext,
        header,
        authenticated,
        sender_kid: sender_kid_str,
        recipient_kid: recipient_kid.to_string(),
        legacy_kek_used,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwe::encrypt;

    #[test]
    fn authcrypt_roundtrip_x25519() {
        let sender = PrivateKeyAgreement::generate(Curve::X25519);
        let recipient = PrivateKeyAgreement::generate(Curve::X25519);

        let jwe_str = encrypt::authcrypt(
            b"Hello authcrypt!",
            "did:example:alice#key-1",
            &sender,
            &[("did:example:bob#key-1", &recipient.public_key())],
        )
        .unwrap();

        let result = decrypt(
            &jwe_str,
            "did:example:bob#key-1",
            &recipient,
            Some(&sender.public_key()),
        )
        .unwrap();

        assert_eq!(result.plaintext, b"Hello authcrypt!");
        assert!(result.authenticated);
        assert!(result.sender_kid.is_some());
    }

    #[test]
    fn anoncrypt_roundtrip_x25519() {
        let recipient = PrivateKeyAgreement::generate(Curve::X25519);

        let jwe_str = encrypt::anoncrypt(
            b"Hello anoncrypt!",
            &[("did:example:bob#key-1", &recipient.public_key())],
        )
        .unwrap();

        let result = decrypt(&jwe_str, "did:example:bob#key-1", &recipient, None).unwrap();

        assert_eq!(result.plaintext, b"Hello anoncrypt!");
        assert!(!result.authenticated);
    }

    #[test]
    fn authcrypt_roundtrip_p384_p521() {
        // Full ECDH-1PU JWE roundtrip on the larger NIST curves: the wire
        // layer is curve-agnostic (ephemeral is generated on the recipient's
        // curve), so these must pack and unpack like the others.
        for curve in [Curve::P384, Curve::P521] {
            let sender = PrivateKeyAgreement::generate(curve);
            let recipient = PrivateKeyAgreement::generate(curve);

            let jwe_str = encrypt::authcrypt(
                b"big-curve authcrypt",
                "did:example:alice#ec",
                &sender,
                &[("did:example:bob#ec", &recipient.public_key())],
            )
            .unwrap();

            let result = decrypt(
                &jwe_str,
                "did:example:bob#ec",
                &recipient,
                Some(&sender.public_key()),
            )
            .unwrap();

            assert_eq!(result.plaintext, b"big-curve authcrypt", "curve {curve:?}");
            assert!(result.authenticated, "curve {curve:?}");
        }
    }

    #[test]
    fn anoncrypt_roundtrip_p384_p521() {
        for curve in [Curve::P384, Curve::P521] {
            let recipient = PrivateKeyAgreement::generate(curve);

            let jwe_str = encrypt::anoncrypt(
                b"big-curve anoncrypt",
                &[("did:example:bob#ec", &recipient.public_key())],
            )
            .unwrap();

            let result = decrypt(&jwe_str, "did:example:bob#ec", &recipient, None).unwrap();

            assert_eq!(result.plaintext, b"big-curve anoncrypt", "curve {curve:?}");
            assert!(!result.authenticated, "curve {curve:?}");
        }
    }

    #[test]
    fn authcrypt_roundtrip_p256() {
        let sender = PrivateKeyAgreement::generate(Curve::P256);
        let recipient = PrivateKeyAgreement::generate(Curve::P256);

        let jwe_str = encrypt::authcrypt(
            b"P-256 authcrypt",
            "did:example:alice#p256-key",
            &sender,
            &[("did:example:bob#p256-key", &recipient.public_key())],
        )
        .unwrap();

        let result = decrypt(
            &jwe_str,
            "did:example:bob#p256-key",
            &recipient,
            Some(&sender.public_key()),
        )
        .unwrap();

        assert_eq!(result.plaintext, b"P-256 authcrypt");
    }

    #[test]
    fn anoncrypt_roundtrip_k256() {
        let recipient = PrivateKeyAgreement::generate(Curve::K256);

        let jwe_str = encrypt::anoncrypt(
            b"K-256 anoncrypt",
            &[("did:example:bob#k256-key", &recipient.public_key())],
        )
        .unwrap();

        let result = decrypt(&jwe_str, "did:example:bob#k256-key", &recipient, None).unwrap();

        assert_eq!(result.plaintext, b"K-256 anoncrypt");
    }

    #[test]
    fn authcrypt_roundtrip_k256() {
        let sender = PrivateKeyAgreement::generate(Curve::K256);
        let recipient = PrivateKeyAgreement::generate(Curve::K256);

        let jwe_str = encrypt::authcrypt(
            b"K-256 authcrypt",
            "did:example:alice#k256-key",
            &sender,
            &[("did:example:bob#k256-key", &recipient.public_key())],
        )
        .unwrap();

        let result = decrypt(
            &jwe_str,
            "did:example:bob#k256-key",
            &recipient,
            Some(&sender.public_key()),
        )
        .unwrap();

        assert_eq!(result.plaintext, b"K-256 authcrypt");
        assert!(result.authenticated);
    }

    #[test]
    fn anoncrypt_roundtrip_p256() {
        let recipient = PrivateKeyAgreement::generate(Curve::P256);

        let jwe_str = encrypt::anoncrypt(
            b"P-256 anoncrypt",
            &[("did:example:bob#p256-key", &recipient.public_key())],
        )
        .unwrap();

        let result = decrypt(&jwe_str, "did:example:bob#p256-key", &recipient, None).unwrap();

        assert_eq!(result.plaintext, b"P-256 anoncrypt");
        assert!(!result.authenticated);
    }

    #[test]
    fn multi_recipient_anoncrypt_x25519() {
        let r1 = PrivateKeyAgreement::generate(Curve::X25519);
        let r2 = PrivateKeyAgreement::generate(Curve::X25519);

        let jwe_str = encrypt::anoncrypt(
            b"multi-recipient anoncrypt",
            &[
                ("did:example:bob#key-1", &r1.public_key()),
                ("did:example:carol#key-1", &r2.public_key()),
            ],
        )
        .unwrap();

        // Both recipients should be able to decrypt
        let result1 = decrypt(&jwe_str, "did:example:bob#key-1", &r1, None).unwrap();
        assert_eq!(result1.plaintext, b"multi-recipient anoncrypt");
        assert!(!result1.authenticated);

        let result2 = decrypt(&jwe_str, "did:example:carol#key-1", &r2, None).unwrap();
        assert_eq!(result2.plaintext, b"multi-recipient anoncrypt");
    }

    #[test]
    fn multi_recipient_authcrypt_p256() {
        let sender = PrivateKeyAgreement::generate(Curve::P256);
        let r1 = PrivateKeyAgreement::generate(Curve::P256);
        let r2 = PrivateKeyAgreement::generate(Curve::P256);

        let jwe_str = encrypt::authcrypt(
            b"multi P-256 authcrypt",
            "did:example:alice#p256",
            &sender,
            &[
                ("did:example:bob#p256", &r1.public_key()),
                ("did:example:carol#p256", &r2.public_key()),
            ],
        )
        .unwrap();

        let result1 = decrypt(
            &jwe_str,
            "did:example:bob#p256",
            &r1,
            Some(&sender.public_key()),
        )
        .unwrap();
        assert_eq!(result1.plaintext, b"multi P-256 authcrypt");
        assert!(result1.authenticated);

        let result2 = decrypt(
            &jwe_str,
            "did:example:carol#p256",
            &r2,
            Some(&sender.public_key()),
        )
        .unwrap();
        assert_eq!(result2.plaintext, b"multi P-256 authcrypt");
        assert!(result2.authenticated);
    }

    #[test]
    fn multi_recipient_authcrypt_k256() {
        let sender = PrivateKeyAgreement::generate(Curve::K256);
        let r1 = PrivateKeyAgreement::generate(Curve::K256);
        let r2 = PrivateKeyAgreement::generate(Curve::K256);

        let jwe_str = encrypt::authcrypt(
            b"multi K-256 authcrypt",
            "did:example:alice#k256",
            &sender,
            &[
                ("did:example:bob#k256", &r1.public_key()),
                ("did:example:carol#k256", &r2.public_key()),
            ],
        )
        .unwrap();

        let result1 = decrypt(
            &jwe_str,
            "did:example:bob#k256",
            &r1,
            Some(&sender.public_key()),
        )
        .unwrap();
        assert_eq!(result1.plaintext, b"multi K-256 authcrypt");

        let result2 = decrypt(
            &jwe_str,
            "did:example:carol#k256",
            &r2,
            Some(&sender.public_key()),
        )
        .unwrap();
        assert_eq!(result2.plaintext, b"multi K-256 authcrypt");
    }

    #[test]
    fn multi_recipient_anoncrypt_p256() {
        let r1 = PrivateKeyAgreement::generate(Curve::P256);
        let r2 = PrivateKeyAgreement::generate(Curve::P256);
        let r3 = PrivateKeyAgreement::generate(Curve::P256);

        let jwe_str = encrypt::anoncrypt(
            b"triple P-256 anoncrypt",
            &[
                ("did:example:a#p256", &r1.public_key()),
                ("did:example:b#p256", &r2.public_key()),
                ("did:example:c#p256", &r3.public_key()),
            ],
        )
        .unwrap();

        for (kid, key) in [
            ("did:example:a#p256", &r1),
            ("did:example:b#p256", &r2),
            ("did:example:c#p256", &r3),
        ] {
            let result = decrypt(&jwe_str, kid, key, None).unwrap();
            assert_eq!(result.plaintext, b"triple P-256 anoncrypt");
        }
    }

    #[test]
    fn multi_recipient_anoncrypt_k256() {
        let r1 = PrivateKeyAgreement::generate(Curve::K256);
        let r2 = PrivateKeyAgreement::generate(Curve::K256);

        let jwe_str = encrypt::anoncrypt(
            b"multi K-256 anoncrypt",
            &[
                ("did:example:bob#k256", &r1.public_key()),
                ("did:example:carol#k256", &r2.public_key()),
            ],
        )
        .unwrap();

        let result1 = decrypt(&jwe_str, "did:example:bob#k256", &r1, None).unwrap();
        assert_eq!(result1.plaintext, b"multi K-256 anoncrypt");

        let result2 = decrypt(&jwe_str, "did:example:carol#k256", &r2, None).unwrap();
        assert_eq!(result2.plaintext, b"multi K-256 anoncrypt");
    }

    #[test]
    fn cross_curve_authcrypt_fails() {
        let sender = PrivateKeyAgreement::generate(Curve::X25519);
        let recipient = PrivateKeyAgreement::generate(Curve::P256);

        let result = encrypt::authcrypt(
            b"cross-curve",
            "did:example:alice#x25519",
            &sender,
            &[("did:example:bob#p256", &recipient.public_key())],
        );

        // Sender (X25519) and ephemeral must match recipient curve (P256),
        // so the ECDH should fail
        assert!(result.is_err());
    }

    #[test]
    fn cross_curve_anoncrypt_recipients_fails() {
        let r1 = PrivateKeyAgreement::generate(Curve::X25519);
        let r2 = PrivateKeyAgreement::generate(Curve::P256);

        let result = encrypt::anoncrypt(
            b"mixed curves",
            &[
                ("did:example:bob#x25519", &r1.public_key()),
                ("did:example:carol#p256", &r2.public_key()),
            ],
        );

        assert!(result.is_err());
    }

    #[test]
    fn authcrypt_wrong_sender_key_fails() {
        let sender = PrivateKeyAgreement::generate(Curve::X25519);
        let wrong_sender = PrivateKeyAgreement::generate(Curve::X25519);
        let recipient = PrivateKeyAgreement::generate(Curve::X25519);

        let jwe_str = encrypt::authcrypt(
            b"secret",
            "did:example:alice#key-1",
            &sender,
            &[("did:example:bob#key-1", &recipient.public_key())],
        )
        .unwrap();

        // Decrypt with wrong sender public key should fail
        let result = decrypt(
            &jwe_str,
            "did:example:bob#key-1",
            &recipient,
            Some(&wrong_sender.public_key()),
        );
        assert!(result.is_err());
    }

    #[test]
    fn authcrypt_large_payload() {
        let sender = PrivateKeyAgreement::generate(Curve::X25519);
        let recipient = PrivateKeyAgreement::generate(Curve::X25519);
        let payload = vec![0x42u8; 100_000]; // 100KB payload

        let jwe_str = encrypt::authcrypt(
            &payload,
            "did:example:alice#key-1",
            &sender,
            &[("did:example:bob#key-1", &recipient.public_key())],
        )
        .unwrap();

        let result = decrypt(
            &jwe_str,
            "did:example:bob#key-1",
            &recipient,
            Some(&sender.public_key()),
        )
        .unwrap();

        assert_eq!(result.plaintext, payload);
    }

    #[test]
    fn wrong_recipient_key_fails() {
        let sender = PrivateKeyAgreement::generate(Curve::X25519);
        let recipient = PrivateKeyAgreement::generate(Curve::X25519);
        let wrong = PrivateKeyAgreement::generate(Curve::X25519);

        let jwe_str = encrypt::authcrypt(
            b"secret",
            "did:example:alice#key-1",
            &sender,
            &[("did:example:bob#key-1", &recipient.public_key())],
        )
        .unwrap();

        assert!(
            decrypt(
                &jwe_str,
                "did:example:bob#key-1",
                &wrong,
                Some(&sender.public_key()),
            )
            .is_err()
        );
    }

    // ── #322: dual-KEK migration fallback ────────────────────────────

    /// A JWE packed by an unpatched (legacy, unprefixed-tag) peer must
    /// still decrypt via the fallback, with `legacy_kek_used == true`.
    /// Covers all three ECDH-1PU curves.
    fn legacy_sender_decrypts_via_fallback(curve: Curve) {
        let sender = PrivateKeyAgreement::generate(curve);
        let recipient = PrivateKeyAgreement::generate(curve);

        let jwe_str = encrypt::authcrypt_legacy(
            b"from a legacy peer",
            "did:example:alice#key-1",
            &sender,
            "did:example:bob#key-1",
            &recipient.public_key(),
        )
        .unwrap();

        let result = decrypt(
            &jwe_str,
            "did:example:bob#key-1",
            &recipient,
            Some(&sender.public_key()),
        )
        .unwrap();

        assert_eq!(result.plaintext, b"from a legacy peer");
        assert!(result.authenticated);
        assert!(
            result.legacy_kek_used,
            "legacy-packed JWE should decrypt only under the legacy KEK"
        );
    }

    #[test]
    fn legacy_fallback_x25519() {
        legacy_sender_decrypts_via_fallback(Curve::X25519);
    }

    #[test]
    fn legacy_fallback_p256() {
        legacy_sender_decrypts_via_fallback(Curve::P256);
    }

    #[test]
    fn legacy_fallback_k256() {
        legacy_sender_decrypts_via_fallback(Curve::K256);
    }

    /// A spec-correct (current) authcrypt JWE must decrypt on the first
    /// (correct) KEK — the fallback must NOT be engaged.
    #[test]
    fn spec_correct_authcrypt_does_not_use_legacy_fallback() {
        let sender = PrivateKeyAgreement::generate(Curve::X25519);
        let recipient = PrivateKeyAgreement::generate(Curve::X25519);

        let jwe_str = encrypt::authcrypt(
            b"spec-correct",
            "did:example:alice#key-1",
            &sender,
            &[("did:example:bob#key-1", &recipient.public_key())],
        )
        .unwrap();

        let result = decrypt(
            &jwe_str,
            "did:example:bob#key-1",
            &recipient,
            Some(&sender.public_key()),
        )
        .unwrap();

        assert_eq!(result.plaintext, b"spec-correct");
        assert!(!result.legacy_kek_used);
    }
}
