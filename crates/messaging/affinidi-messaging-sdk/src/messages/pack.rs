use affinidi_did_common::{
    Document, document::DocumentExt, verification_method::VerificationRelationship,
};
use affinidi_messaging_didcomm::{
    crypto::key_agreement::{Curve, PrivateKeyAgreement, PublicKeyAgreement},
    message::{Message, pack},
};
use affinidi_secrets_resolver::SecretsResolver;
use tracing::{Instrument, Level, span};

use crate::{ATM, SharedState, errors::ATMError};

use super::compat::PackEncryptedMetadata;

impl ATM {
    /// Pack a message for sending to a recipient
    /// from: if None, then will use anonymous encryption
    /// sign_by: currently unused (signing is not yet supported in the new crate bridge)
    /// NOTE: If the recipient DID contains a service endpoint,
    /// the message could be auto-forwarded which default to anonymous
    pub async fn pack_encrypted(
        &self,
        message: &Message,
        to: &str,
        from: Option<&str>,
        _sign_by: Option<&str>,
    ) -> Result<(String, PackEncryptedMetadata), ATMError> {
        self.inner.pack_encrypted(message, to, from).await
    }
}

impl SharedState {
    /// Pack a message for sending to a recipient
    /// from: if None, then will use anonymous encryption
    pub async fn pack_encrypted(
        &self,
        message: &Message,
        to: &str,
        from: Option<&str>,
    ) -> Result<(String, PackEncryptedMetadata), ATMError> {
        let _span = span!(Level::DEBUG, "pack_encrypted",);

        async move {
            // 1. Resolve recipient DID and get their key agreement public key
            let recipient_doc = self
                .tdk_common
                .did_resolver()
                .resolve(to)
                .await
                .map_err(|e| {
                    ATMError::DidcommError(
                        "pack_encrypted".into(),
                        format!("Failed to resolve recipient DID: {e}"),
                    )
                })?;
            let recipient_ka_kids = recipient_doc.doc.find_key_agreement(None);
            let recipient_kid = recipient_ka_kids.first().ok_or_else(|| {
                ATMError::DidcommError(
                    "pack_encrypted".into(),
                    "recipient has no key agreement key".into(),
                )
            })?;
            let recipient_pub = resolve_public_key_agreement(&recipient_doc.doc, recipient_kid)?;

            if let Some(sender_did) = from {
                // Authcrypt: resolve sender, get private key, encrypt
                let sender_doc = self
                    .tdk_common
                    .did_resolver()
                    .resolve(sender_did)
                    .await
                    .map_err(|e| {
                        ATMError::DidcommError(
                            "pack_encrypted".into(),
                            format!("Failed to resolve sender DID: {e}"),
                        )
                    })?;
                let sender_ka_kids = sender_doc.doc.find_key_agreement(None);
                let sender_kid = sender_ka_kids.first().ok_or_else(|| {
                    ATMError::DidcommError(
                        "pack_encrypted".into(),
                        "sender has no key agreement key".into(),
                    )
                })?;

                // Get sender's private key from secrets resolver
                let sender_secret = self
                    .tdk_common
                    .secrets_resolver()
                    .get_secret(sender_kid.as_ref())
                    .await
                    .ok_or_else(|| {
                        ATMError::SecretsError(format!("no secret found for {sender_kid}"))
                    })?;

                let sender_curve = key_type_to_curve(sender_secret.get_key_type())?;
                let sender_private = PrivateKeyAgreement::from_raw_bytes(
                    sender_curve,
                    sender_secret.get_private_bytes(),
                )
                .map_err(|e| {
                    ATMError::DidcommError(
                        "pack_encrypted".into(),
                        format!("invalid sender private key: {e}"),
                    )
                })?;

                let packed = pack::pack_encrypted_authcrypt(
                    message,
                    sender_kid,
                    &sender_private,
                    &[(recipient_kid, &recipient_pub)],
                )
                .map_err(|e| {
                    ATMError::DidcommError(
                        "SDK".to_string(),
                        format!("pack_encrypted() authcrypt failed. Reason: {e}"),
                    )
                })?;

                let metadata = PackEncryptedMetadata {
                    from_kid: Some(sender_kid.to_string()),
                    sign_by_kid: None,
                    to_kids: vec![recipient_kid.to_string()],
                };

                Ok((packed, metadata))
            } else {
                // Anoncrypt
                let packed =
                    pack::pack_encrypted_anoncrypt(message, &[(recipient_kid, &recipient_pub)])
                        .map_err(|e| {
                            ATMError::DidcommError(
                                "SDK".to_string(),
                                format!("pack_encrypted() anoncrypt failed. Reason: {e}"),
                            )
                        })?;

                let metadata = PackEncryptedMetadata {
                    from_kid: None,
                    sign_by_kid: None,
                    to_kids: vec![recipient_kid.to_string()],
                };

                Ok((packed, metadata))
            }
        }
        .instrument(_span)
        .await
    }

    /// creates a plaintext (unencrypted and unsigned) message
    #[allow(dead_code)]
    pub async fn pack_plaintext(&self, message: &Message) -> Result<String, ATMError> {
        let _span = span!(Level::DEBUG, "pack_plaintext",);

        async move {
            pack::pack_plaintext(message).map_err(|e| {
                ATMError::DidcommError(
                    "SDK".to_string(),
                    format!("pack_plaintext() failed. Reason: {e}"),
                )
            })
        }
        .instrument(_span)
        .await
    }
}

/// Extract a PublicKeyAgreement from a DID Document's verification method.
fn resolve_public_key_agreement(doc: &Document, kid: &str) -> Result<PublicKeyAgreement, ATMError> {
    // Find the verification method
    let vm = doc
        .key_agreement
        .iter()
        .filter_map(|ka| match ka {
            VerificationRelationship::VerificationMethod(vm) if vm.id.as_str() == kid => {
                Some(vm.as_ref())
            }
            _ => None,
        })
        .next()
        .or_else(|| doc.get_verification_method(kid))
        .ok_or_else(|| {
            ATMError::DidcommError(
                "resolve_key".into(),
                format!("verification method not found: {kid}"),
            )
        })?;

    // Try publicKeyJwk first
    if let Some(jwk_value) = vm.property_set.get("publicKeyJwk") {
        return PublicKeyAgreement::from_jwk(jwk_value).map_err(|e| {
            ATMError::DidcommError("resolve_key".into(), format!("invalid JWK: {e}"))
        });
    }

    // Try publicKeyMultibase (Multikey format)
    if let Some(multibase_value) = vm.property_set.get("publicKeyMultibase")
        && let Some(multibase_str) = multibase_value.as_str()
    {
        let (codec, key_bytes) = affinidi_encoding::decode_multikey_with_codec(multibase_str)
            .map_err(|e| {
                ATMError::DidcommError("resolve_key".into(), format!("invalid multikey: {e}"))
            })?;

        let curve = match codec {
            affinidi_encoding::X25519_PUB => Curve::X25519,
            affinidi_encoding::P256_PUB => Curve::P256,
            affinidi_encoding::SECP256K1_PUB => Curve::K256,
            _ => {
                return Err(ATMError::DidcommError(
                    "resolve_key".into(),
                    format!("unsupported multicodec for key agreement: 0x{codec:x}"),
                ));
            }
        };

        return PublicKeyAgreement::from_raw_bytes(curve, &key_bytes).map_err(|e| {
            ATMError::DidcommError("resolve_key".into(), format!("invalid key bytes: {e}"))
        });
    }

    Err(ATMError::DidcommError(
        "resolve_key".into(),
        format!("no supported key material in verification method: {kid}"),
    ))
}

/// Map from secrets resolver KeyType to DIDComm Curve.
fn key_type_to_curve(
    key_type: affinidi_secrets_resolver::secrets::KeyType,
) -> Result<Curve, ATMError> {
    match key_type {
        affinidi_secrets_resolver::secrets::KeyType::X25519 => Ok(Curve::X25519),
        affinidi_secrets_resolver::secrets::KeyType::P256 => Ok(Curve::P256),
        affinidi_secrets_resolver::secrets::KeyType::Secp256k1 => Ok(Curve::K256),
        other => Err(ATMError::DidcommError(
            "key_type_to_curve".into(),
            format!("unsupported key type for key agreement: {other:?}"),
        )),
    }
}
