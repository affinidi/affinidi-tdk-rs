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
    /// The authcrypt sender key id: the `skid` whose public key the caller
    /// supplied and the message decrypted under. `None` for anoncrypt.
    pub sender_kid: Option<String>,
    /// The recipient KID that was used to decrypt.
    pub recipient_kid: String,
    /// Always `false`: the pre-0.14 (issue #322) ECDH-1PU KEK is no longer
    /// accepted, so no message decrypts under it.
    #[deprecated(
        since = "0.15.9",
        note = "always false: the pre-0.14 ECDH-1PU KEK is no longer accepted"
    )]
    pub legacy_kek_used: bool,
}

/// The sender key an authcrypt JWE is decrypted against: a key id and the
/// public key that key id resolves to.
///
/// [`decrypt_bound`] refuses the message unless this `kid` is the JWE's `skid`, so a
/// key resolved for one sender cannot authenticate a message naming another.
#[derive(Clone, Copy, Debug)]
pub struct SenderKey<'a> {
    kid: &'a str,
    public: &'a PublicKeyAgreement,
}

impl<'a> SenderKey<'a> {
    pub fn new(kid: &'a str, public: &'a PublicKeyAgreement) -> Self {
        Self { kid, public }
    }

    pub fn kid(&self) -> &'a str {
        self.kid
    }

    pub fn public(&self) -> &'a PublicKeyAgreement {
        self.public
    }
}

/// The key id whose public key is needed to decrypt `jwe_str`.
///
/// `Some(skid)` for authcrypt (ECDH-1PU), after checking the header binds
/// `skid` and `apu` together (see [`ProtectedHeader::authcrypt_sender_kid`]);
/// `None` for anoncrypt. Resolve exactly this key id and pass it back to
/// [`decrypt_bound`] as a [`SenderKey`].
pub fn authcrypt_sender_kid(jwe_str: &str) -> Result<Option<String>, DIDCommError> {
    let jwe: Jwe = serde_json::from_str(jwe_str)
        .map_err(|e| DIDCommError::InvalidMessage(format!("invalid JWE JSON: {e}")))?;
    let header = ProtectedHeader::from_base64url(&jwe.protected)?;
    Ok(header.authcrypt_sender_kid()?.map(str::to_string))
}

/// Decrypt a JWE string, given the sender public key alone.
///
/// For authcrypt the key is taken to be the one named by the JWE `skid`, and
/// the same checks as [`decrypt_bound`] apply: `skid` and `apu` must both be
/// present and name the same `did#fragment` key id, or the message is refused.
/// `sender_kid` in the result is that `skid`.
#[deprecated(
    since = "0.15.9",
    note = "use `decrypt_bound` with a `SenderKey`. The key passed here must be the one \
            resolved for the JWE's `skid` (see `authcrypt_sender_kid`); nothing checks that \
            it is"
)]
pub fn decrypt(
    jwe_str: &str,
    recipient_kid: &str,
    recipient_private: &PrivateKeyAgreement,
    sender_public: Option<&PublicKeyAgreement>,
) -> Result<DecryptedJwe, DIDCommError> {
    let skid = authcrypt_sender_kid(jwe_str)?;
    let sender = skid
        .as_deref()
        .zip(sender_public)
        .map(|(kid, public)| SenderKey::new(kid, public));
    decrypt_bound(jwe_str, recipient_kid, recipient_private, sender)
}

/// Decrypt a JWE string.
///
/// # Arguments
/// * `jwe_str` - The JWE JSON string
/// * `recipient_kid` - The recipient's key ID to look for
/// * `recipient_private` - The recipient's private key agreement key
/// * `sender` - For authcrypt, the sender key named by the JWE `skid`
///   (see [`authcrypt_sender_kid`]). Ignored for anoncrypt.
///
/// # Errors
/// For authcrypt, [`DIDCommError::SenderKeyBinding`] when the header lacks
/// `skid` or `apu`, when `apu` is not `BASE64URL(skid)`, or when `sender` is
/// missing or is for a different key id than `skid`.
pub fn decrypt_bound(
    jwe_str: &str,
    recipient_kid: &str,
    recipient_private: &PrivateKeyAgreement,
    sender: Option<SenderKey<'_>>,
) -> Result<DecryptedJwe, DIDCommError> {
    let jwe: Jwe = serde_json::from_str(jwe_str)
        .map_err(|e| DIDCommError::InvalidMessage(format!("invalid JWE JSON: {e}")))?;

    let header = ProtectedHeader::from_base64url(&jwe.protected)?;

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

    let recipient = jwe
        .recipients
        .iter()
        .find(|r| r.header.kid == recipient_kid)
        .ok_or_else(|| {
            DIDCommError::InvalidMessage(format!("recipient {recipient_kid} not found in JWE"))
        })?;

    let wrapped_key = Base64UrlUnpadded::decode_vec(&recipient.encrypted_key)
        .map_err(|e| DIDCommError::InvalidMessage(format!("invalid encrypted_key: {e}")))?;

    let epk = PublicKeyAgreement::from_jwk(&header.epk)?;

    let apv_raw = Base64UrlUnpadded::decode_vec(&header.apv)
        .map_err(|e| DIDCommError::InvalidMessage(format!("invalid apv: {e}")))?;

    let (cek_bytes, authenticated, sender_kid) = match header.alg.as_str() {
        ALG_AUTHCRYPT => {
            let skid = header.authcrypt_sender_kid()?.ok_or_else(|| {
                DIDCommError::SenderKeyBinding("authcrypt header has no `skid`".into())
            })?;
            let sender = sender.ok_or_else(|| {
                DIDCommError::SenderKeyBinding(format!(
                    "authcrypt requires the public key of sender {skid}"
                ))
            })?;
            if sender.kid() != skid {
                return Err(DIDCommError::SenderKeyBinding(format!(
                    "sender key supplied for {} but the message was sent by {skid}",
                    sender.kid()
                )));
            }
            let apu_raw = skid.as_bytes();

            let kek: [u8; 32] = ecdh::derive_key_1pu_recipient(
                recipient_private,
                sender.public(),
                &epk,
                ALG_AUTHCRYPT.as_bytes(),
                apu_raw,
                &apv_raw,
                &tag,
                256,
            )?
            .try_into()
            .map_err(|_| DIDCommError::KeyAgreement("KEK wrong size".into()))?;

            let cek = aes_kw::unwrap(&kek, &wrapped_key)?;
            (cek, true, Some(skid.to_string()))
        }
        ALG_ANONCRYPT => {
            let apu_raw = header
                .apu
                .as_ref()
                .map(|s| Base64UrlUnpadded::decode_vec(s))
                .transpose()
                .map_err(|e| DIDCommError::InvalidMessage(format!("invalid apu: {e}")))?
                .unwrap_or_default();
            let kek: [u8; 32] = ecdh::derive_key_es_recipient(
                recipient_private,
                &epk,
                ALG_ANONCRYPT.as_bytes(),
                &apu_raw,
                &apv_raw,
                256,
            )?
            .try_into()
            .map_err(|_| DIDCommError::KeyAgreement("KEK wrong size".into()))?;
            let cek = aes_kw::unwrap(&kek, &wrapped_key)?;
            (cek, false, None)
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

    #[allow(deprecated)]
    Ok(DecryptedJwe {
        plaintext,
        header,
        authenticated,
        sender_kid,
        recipient_kid: recipient_kid.to_string(),
        legacy_kek_used: false,
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

        let result = decrypt_bound(
            &jwe_str,
            "did:example:bob#key-1",
            &recipient,
            Some(SenderKey::new(
                "did:example:alice#key-1",
                &sender.public_key(),
            )),
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

        let result = decrypt_bound(&jwe_str, "did:example:bob#key-1", &recipient, None).unwrap();

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

            let result = decrypt_bound(
                &jwe_str,
                "did:example:bob#ec",
                &recipient,
                Some(SenderKey::new("did:example:alice#ec", &sender.public_key())),
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

            let result = decrypt_bound(&jwe_str, "did:example:bob#ec", &recipient, None).unwrap();

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

        let result = decrypt_bound(
            &jwe_str,
            "did:example:bob#p256-key",
            &recipient,
            Some(SenderKey::new(
                "did:example:alice#p256-key",
                &sender.public_key(),
            )),
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

        let result = decrypt_bound(&jwe_str, "did:example:bob#k256-key", &recipient, None).unwrap();

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

        let result = decrypt_bound(
            &jwe_str,
            "did:example:bob#k256-key",
            &recipient,
            Some(SenderKey::new(
                "did:example:alice#k256-key",
                &sender.public_key(),
            )),
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

        let result = decrypt_bound(&jwe_str, "did:example:bob#p256-key", &recipient, None).unwrap();

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
        let result1 = decrypt_bound(&jwe_str, "did:example:bob#key-1", &r1, None).unwrap();
        assert_eq!(result1.plaintext, b"multi-recipient anoncrypt");
        assert!(!result1.authenticated);

        let result2 = decrypt_bound(&jwe_str, "did:example:carol#key-1", &r2, None).unwrap();
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

        let result1 = decrypt_bound(
            &jwe_str,
            "did:example:bob#p256",
            &r1,
            Some(SenderKey::new(
                "did:example:alice#p256",
                &sender.public_key(),
            )),
        )
        .unwrap();
        assert_eq!(result1.plaintext, b"multi P-256 authcrypt");
        assert!(result1.authenticated);

        let result2 = decrypt_bound(
            &jwe_str,
            "did:example:carol#p256",
            &r2,
            Some(SenderKey::new(
                "did:example:alice#p256",
                &sender.public_key(),
            )),
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

        let result1 = decrypt_bound(
            &jwe_str,
            "did:example:bob#k256",
            &r1,
            Some(SenderKey::new(
                "did:example:alice#k256",
                &sender.public_key(),
            )),
        )
        .unwrap();
        assert_eq!(result1.plaintext, b"multi K-256 authcrypt");

        let result2 = decrypt_bound(
            &jwe_str,
            "did:example:carol#k256",
            &r2,
            Some(SenderKey::new(
                "did:example:alice#k256",
                &sender.public_key(),
            )),
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
            let result = decrypt_bound(&jwe_str, kid, key, None).unwrap();
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

        let result1 = decrypt_bound(&jwe_str, "did:example:bob#k256", &r1, None).unwrap();
        assert_eq!(result1.plaintext, b"multi K-256 anoncrypt");

        let result2 = decrypt_bound(&jwe_str, "did:example:carol#k256", &r2, None).unwrap();
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
        let result = decrypt_bound(
            &jwe_str,
            "did:example:bob#key-1",
            &recipient,
            Some(SenderKey::new(
                "did:example:alice#key-1",
                &wrong_sender.public_key(),
            )),
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

        let result = decrypt_bound(
            &jwe_str,
            "did:example:bob#key-1",
            &recipient,
            Some(SenderKey::new(
                "did:example:alice#key-1",
                &sender.public_key(),
            )),
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
            decrypt_bound(
                &jwe_str,
                "did:example:bob#key-1",
                &wrong,
                Some(SenderKey::new(
                    "did:example:alice#key-1",
                    &sender.public_key()
                )),
            )
            .is_err()
        );
    }

    // ── #322: the pre-0.14 (unprefixed-tag) KEK is no longer accepted ──

    fn legacy_sender_is_rejected(curve: Curve) {
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

        assert!(
            decrypt_bound(
                &jwe_str,
                "did:example:bob#key-1",
                &recipient,
                Some(SenderKey::new(
                    "did:example:alice#key-1",
                    &sender.public_key()
                )),
            )
            .is_err()
        );
    }

    #[test]
    fn legacy_kek_rejected_x25519() {
        legacy_sender_is_rejected(Curve::X25519);
    }

    #[test]
    fn legacy_kek_rejected_p256() {
        legacy_sender_is_rejected(Curve::P256);
    }

    #[test]
    fn legacy_kek_rejected_k256() {
        legacy_sender_is_rejected(Curve::K256);
    }

    // ── sender key binding: `skid`, `apu` and the supplied key must agree ──

    const ALICE: &str = "did:example:alice#key-1";
    const MALLORY: &str = "did:example:mallory#key-1";
    const BOB: &str = "did:example:bob#key-1";

    fn assert_sender_binding_error(result: Result<DecryptedJwe, DIDCommError>) {
        match result {
            Err(DIDCommError::SenderKeyBinding(_)) => {}
            Err(other) => panic!("expected SenderKeyBinding, got {other:?}"),
            Ok(_) => panic!("expected SenderKeyBinding, but the JWE decrypted"),
        }
    }

    /// `skid` names the key that decrypts; `apu` names someone else. The
    /// message decrypts under the `skid` key, so only the binding check stops
    /// it from being reported as sent by the `apu` party.
    #[test]
    fn authcrypt_apu_naming_another_sender_is_rejected() {
        let mallory = PrivateKeyAgreement::generate(Curve::X25519);
        let bob = PrivateKeyAgreement::generate(Curve::X25519);

        let jwe = encrypt::authcrypt_with_party_info(
            b"hi",
            Some(MALLORY),
            Some(ALICE),
            &mallory,
            BOB,
            &bob.public_key(),
        )
        .unwrap();

        assert_sender_binding_error(decrypt_bound(
            &jwe,
            BOB,
            &bob,
            Some(SenderKey::new(MALLORY, &mallory.public_key())),
        ));
        assert_eq!(
            authcrypt_sender_kid(&jwe).unwrap_err().to_string(),
            "authcrypt sender key binding failed: authcrypt `apu` does not encode the `skid`"
        );
    }

    #[test]
    fn authcrypt_skid_naming_another_sender_is_rejected() {
        let mallory = PrivateKeyAgreement::generate(Curve::X25519);
        let alice = PrivateKeyAgreement::generate(Curve::X25519);
        let bob = PrivateKeyAgreement::generate(Curve::X25519);

        let jwe = encrypt::authcrypt_with_party_info(
            b"hi",
            Some(ALICE),
            Some(MALLORY),
            &mallory,
            BOB,
            &bob.public_key(),
        )
        .unwrap();

        for sender in [
            SenderKey::new(ALICE, &alice.public_key()),
            SenderKey::new(MALLORY, &mallory.public_key()),
        ] {
            assert_sender_binding_error(decrypt_bound(&jwe, BOB, &bob, Some(sender)));
        }
        assert!(authcrypt_sender_kid(&jwe).is_err());
    }

    #[test]
    fn authcrypt_without_skid_is_rejected() {
        let alice = PrivateKeyAgreement::generate(Curve::X25519);
        let bob = PrivateKeyAgreement::generate(Curve::X25519);

        let jwe = encrypt::authcrypt_with_party_info(
            b"hi",
            None,
            Some(ALICE),
            &alice,
            BOB,
            &bob.public_key(),
        )
        .unwrap();

        assert_sender_binding_error(decrypt_bound(
            &jwe,
            BOB,
            &bob,
            Some(SenderKey::new(ALICE, &alice.public_key())),
        ));
        assert!(authcrypt_sender_kid(&jwe).is_err());
    }

    #[test]
    fn authcrypt_without_apu_is_rejected() {
        let alice = PrivateKeyAgreement::generate(Curve::X25519);
        let bob = PrivateKeyAgreement::generate(Curve::X25519);

        let jwe = encrypt::authcrypt_with_party_info(
            b"hi",
            Some(ALICE),
            None,
            &alice,
            BOB,
            &bob.public_key(),
        )
        .unwrap();

        assert_sender_binding_error(decrypt_bound(
            &jwe,
            BOB,
            &bob,
            Some(SenderKey::new(ALICE, &alice.public_key())),
        ));
        assert!(authcrypt_sender_kid(&jwe).is_err());
    }

    #[test]
    fn authcrypt_with_empty_skid_is_rejected() {
        let alice = PrivateKeyAgreement::generate(Curve::X25519);
        let bob = PrivateKeyAgreement::generate(Curve::X25519);

        let jwe = encrypt::authcrypt_with_party_info(
            b"hi",
            Some(""),
            Some(""),
            &alice,
            BOB,
            &bob.public_key(),
        )
        .unwrap();

        assert_sender_binding_error(decrypt_bound(
            &jwe,
            BOB,
            &bob,
            Some(SenderKey::new("", &alice.public_key())),
        ));
    }

    /// The caller resolved a key for one sender, but the message names
    /// another. Refused before any key agreement, whichever key was passed.
    #[test]
    fn authcrypt_sender_key_for_a_different_kid_is_rejected() {
        let alice = PrivateKeyAgreement::generate(Curve::X25519);
        let bob = PrivateKeyAgreement::generate(Curve::X25519);

        let jwe = encrypt::authcrypt(b"hi", ALICE, &alice, &[(BOB, &bob.public_key())]).unwrap();

        assert_sender_binding_error(decrypt_bound(
            &jwe,
            BOB,
            &bob,
            Some(SenderKey::new(MALLORY, &alice.public_key())),
        ));
    }

    #[test]
    fn authcrypt_without_sender_key_is_rejected() {
        let alice = PrivateKeyAgreement::generate(Curve::X25519);
        let bob = PrivateKeyAgreement::generate(Curve::X25519);

        let jwe = encrypt::authcrypt(b"hi", ALICE, &alice, &[(BOB, &bob.public_key())]).unwrap();

        assert_sender_binding_error(decrypt_bound(&jwe, BOB, &bob, None));
    }

    #[test]
    fn authcrypt_reports_the_bound_skid() {
        let alice = PrivateKeyAgreement::generate(Curve::X25519);
        let bob = PrivateKeyAgreement::generate(Curve::X25519);

        let jwe = encrypt::authcrypt(b"hi", ALICE, &alice, &[(BOB, &bob.public_key())]).unwrap();

        assert_eq!(authcrypt_sender_kid(&jwe).unwrap().as_deref(), Some(ALICE));
        let result = decrypt_bound(
            &jwe,
            BOB,
            &bob,
            Some(SenderKey::new(ALICE, &alice.public_key())),
        )
        .unwrap();
        assert!(result.authenticated);
        assert_eq!(result.sender_kid.as_deref(), Some(ALICE));
    }

    /// Anoncrypt has no sender: no `skid` is required, a supplied sender key
    /// is ignored, and no sender is reported.
    #[test]
    fn anoncrypt_is_unaffected_by_sender_binding() {
        let alice = PrivateKeyAgreement::generate(Curve::X25519);
        let bob = PrivateKeyAgreement::generate(Curve::X25519);

        let jwe = encrypt::anoncrypt(b"anon", &[(BOB, &bob.public_key())]).unwrap();

        assert_eq!(authcrypt_sender_kid(&jwe).unwrap(), None);
        for sender in [None, Some(SenderKey::new(MALLORY, &alice.public_key()))] {
            let result = decrypt_bound(&jwe, BOB, &bob, sender).unwrap();
            assert_eq!(result.plaintext, b"anon");
            assert!(!result.authenticated);
            assert_eq!(result.sender_kid, None);
        }
    }

    /// The deprecated key-only entry point applies the same binding.
    #[test]
    #[allow(deprecated)]
    fn deprecated_decrypt_binds_the_sender_too() {
        let alice = PrivateKeyAgreement::generate(Curve::X25519);
        let mallory = PrivateKeyAgreement::generate(Curve::X25519);
        let bob = PrivateKeyAgreement::generate(Curve::X25519);

        let jwe = encrypt::authcrypt(b"hi", ALICE, &alice, &[(BOB, &bob.public_key())]).unwrap();
        let result = decrypt(&jwe, BOB, &bob, Some(&alice.public_key())).unwrap();
        assert!(result.authenticated);
        assert_eq!(result.sender_kid.as_deref(), Some(ALICE));
        assert!(!result.legacy_kek_used);

        let forged = encrypt::authcrypt_with_party_info(
            b"hi",
            Some(MALLORY),
            Some(ALICE),
            &mallory,
            BOB,
            &bob.public_key(),
        )
        .unwrap();
        assert_sender_binding_error(decrypt(&forged, BOB, &bob, Some(&mallory.public_key())));

        let anon = encrypt::anoncrypt(b"anon", &[(BOB, &bob.public_key())]).unwrap();
        assert!(!decrypt(&anon, BOB, &bob, None).unwrap().authenticated);
    }
}
