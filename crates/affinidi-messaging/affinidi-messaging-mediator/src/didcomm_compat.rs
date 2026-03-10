//! Compatibility module that bridges the old `affinidi-messaging-didcomm` API
//! with the new `affinidi-messaging-didcomm` crate.
//!
//! Provides `MetaEnvelope`, `unpack`, and `pack_encrypted` functionality
//! that the mediator previously obtained from the legacy DIDComm crate.

use affinidi_did_common::{document::DocumentExt, verification_method::VerificationRelationship};
use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_messaging_didcomm::{
    crypto::key_agreement::{Curve, PrivateKeyAgreement, PublicKeyAgreement},
    jwe::decrypt::decrypt,
    message::{
        Message,
        pack::{pack_encrypted_anoncrypt, pack_encrypted_authcrypt},
    },
};
use affinidi_messaging_sdk::messages::compat::{PackEncryptedMetadata, UnpackMetadata};
use affinidi_secrets_resolver::SecretsResolver;
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};

/// Replacement for the legacy `MetaEnvelope` type.
/// Pre-parses a JWE/JWS envelope to extract routing metadata (to_did, from_did, etc.)
/// without performing full decryption.
pub struct MetaEnvelope {
    /// The raw message string
    pub raw: String,
    /// SHA-256 hash of the raw message
    pub sha256_hash: String,
    /// The `to` DID extracted from the JWE recipients (kid)
    pub to_did: Option<String>,
    /// The `from` DID extracted from the JWE protected header (skid)
    pub from_did: Option<String>,
    /// Metadata about the envelope
    pub metadata: EnvelopeMetadata,
}

/// Metadata about the envelope format
#[derive(Debug, Default)]
pub struct EnvelopeMetadata {
    pub encrypted: bool,
    pub authenticated: bool,
}

impl MetaEnvelope {
    /// Parse a raw message string to extract envelope metadata.
    /// This replaces the old `MetaEnvelope::new(&str, &DIDCacheClient)`.
    pub async fn new(
        message: &str,
        did_resolver: &DIDCacheClient,
    ) -> Result<Self, String> {
        let sha256_hash = sha256::digest(message);

        let value: serde_json::Value = serde_json::from_str(message)
            .map_err(|e| format!("Cannot parse message as JSON: {e}"))?;

        if value.get("ciphertext").is_some() && value.get("recipients").is_some() {
            // JWE envelope
            let mut to_did = None;
            let mut from_did = None;
            let mut authenticated = false;

            // Extract recipient KID to determine to_did
            if let Some(recipients) = value["recipients"].as_array() {
                for recipient in recipients {
                    if let Some(kid) = recipient["header"]["kid"].as_str() {
                        // Extract DID from kid (everything before #)
                        if let Some(hash_pos) = kid.find('#') {
                            to_did = Some(kid[..hash_pos].to_string());
                        } else {
                            to_did = Some(kid.to_string());
                        }
                        break;
                    }
                }
            }

            // Check protected header for sender info (authcrypt)
            if let Some(protected_b64) = value.get("protected").and_then(|p| p.as_str()) {
                if let Ok(protected_bytes) = BASE64_URL_SAFE_NO_PAD.decode(protected_b64) {
                    if let Ok(header) = serde_json::from_slice::<serde_json::Value>(&protected_bytes) {
                        // Check algorithm for authcrypt
                        if let Some(alg) = header.get("alg").and_then(|a| a.as_str()) {
                            if alg.contains("1PU") {
                                authenticated = true;
                                // Extract sender DID from skid
                                if let Some(skid) = header.get("skid").and_then(|s| s.as_str()) {
                                    if let Some(hash_pos) = skid.find('#') {
                                        from_did = Some(skid[..hash_pos].to_string());
                                    } else {
                                        from_did = Some(skid.to_string());
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // If we couldn't get from_did from skid, try resolving via apu header
            if from_did.is_none() && authenticated {
                // Try apu (agreement party u-info) which sometimes contains the sender kid
                if let Some(protected_b64) = value.get("protected").and_then(|p| p.as_str()) {
                    if let Ok(protected_bytes) = BASE64_URL_SAFE_NO_PAD.decode(protected_b64) {
                        if let Ok(header) = serde_json::from_slice::<serde_json::Value>(&protected_bytes) {
                            if let Some(apu) = header.get("apu").and_then(|a| a.as_str()) {
                                if let Ok(apu_bytes) = BASE64_URL_SAFE_NO_PAD.decode(apu) {
                                    if let Ok(apu_str) = String::from_utf8(apu_bytes) {
                                        if let Some(hash_pos) = apu_str.find('#') {
                                            from_did = Some(apu_str[..hash_pos].to_string());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            Ok(MetaEnvelope {
                raw: message.to_string(),
                sha256_hash,
                to_did,
                from_did,
                metadata: EnvelopeMetadata {
                    encrypted: true,
                    authenticated,
                },
            })
        } else if value.get("payload").is_some() && value.get("signatures").is_some() {
            // JWS envelope - signed but not encrypted
            Ok(MetaEnvelope {
                raw: message.to_string(),
                sha256_hash,
                to_did: None,
                from_did: None,
                metadata: EnvelopeMetadata {
                    encrypted: false,
                    authenticated: false,
                },
            })
        } else if value.get("type").is_some() {
            // Plaintext message
            let to_did = value
                .get("to")
                .and_then(|t| t.as_array())
                .and_then(|arr| arr.first())
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let from_did = value
                .get("from")
                .and_then(|f| f.as_str())
                .map(|s| s.to_string());

            Ok(MetaEnvelope {
                raw: message.to_string(),
                sha256_hash,
                to_did,
                from_did,
                metadata: EnvelopeMetadata {
                    encrypted: false,
                    authenticated: false,
                },
            })
        } else {
            Err("Cannot detect message format: expected JWE, JWS, or plaintext".to_string())
        }
    }
}

/// Unpack (decrypt) a message using the mediator's secrets resolver.
/// Replaces the old `Message::unpack(&mut envelope, &did_resolver, &secrets, &options)`.
pub async fn unpack<S: SecretsResolver>(
    message: &str,
    did_resolver: &DIDCacheClient,
    secrets_resolver: &S,
) -> Result<(Message, UnpackMetadata), String> {
    let sha256_hash = sha256::digest(message);

    let value: serde_json::Value = serde_json::from_str(message)
        .map_err(|e| format!("Cannot parse message as JSON: {e}"))?;

    if value.get("ciphertext").is_some() && value.get("recipients").is_some() {
        // JWE — encrypted message
        unpack_jwe(message, &value, &sha256_hash, did_resolver, secrets_resolver).await
    } else if value.get("payload").is_some() && value.get("signatures").is_some() {
        // JWS — signed message
        unpack_jws(message, &sha256_hash)
    } else if value.get("type").is_some() {
        // Plaintext
        let msg = Message::from_json(message.as_bytes())
            .map_err(|e| format!("Cannot parse plaintext message: {e}"))?;
        let metadata = UnpackMetadata {
            sha256_hash,
            ..Default::default()
        };
        Ok((msg, metadata))
    } else {
        Err("Cannot detect message format: expected JWE, JWS, or plaintext".to_string())
    }
}

async fn unpack_jwe<S: SecretsResolver>(
    msg_string: &str,
    value: &serde_json::Value,
    sha256_hash: &str,
    did_resolver: &DIDCacheClient,
    secrets_resolver: &S,
) -> Result<(Message, UnpackMetadata), String> {
    let recipients = value["recipients"]
        .as_array()
        .ok_or("Invalid JWE: no recipients array")?;

    let mut recipient_kid_str = String::new();
    let mut recipient_private: Option<PrivateKeyAgreement> = None;

    for recipient in recipients {
        if let Some(kid) = recipient["header"]["kid"].as_str() {
            if let Some(secret) = secrets_resolver.get_secret(kid).await {
                let curve = match secret.get_key_type() {
                    affinidi_secrets_resolver::secrets::KeyType::X25519 => Curve::X25519,
                    affinidi_secrets_resolver::secrets::KeyType::P256 => Curve::P256,
                    affinidi_secrets_resolver::secrets::KeyType::Secp256k1 => Curve::K256,
                    _ => continue,
                };
                match PrivateKeyAgreement::from_raw_bytes(curve, secret.get_private_bytes()) {
                    Ok(pk) => {
                        recipient_kid_str = kid.to_string();
                        recipient_private = Some(pk);
                        break;
                    }
                    Err(_) => continue,
                }
            }
        }
    }

    let recipient_private = recipient_private
        .ok_or("No local secret matches any JWE recipient")?;

    // Try to detect sender for authcrypt
    let sender_public = try_resolve_sender_public(msg_string, did_resolver).await;

    let decrypted = decrypt(
        msg_string,
        &recipient_kid_str,
        &recipient_private,
        sender_public.as_ref(),
    )
    .map_err(|e| format!("Couldn't decrypt message: {e}"))?;

    let msg = Message::from_json(&decrypted.plaintext)
        .map_err(|e| format!("Cannot parse decrypted message: {e}"))?;

    let metadata = UnpackMetadata {
        encrypted: true,
        authenticated: decrypted.authenticated,
        anonymous_sender: !decrypted.authenticated,
        encrypted_from_kid: decrypted.sender_kid,
        encrypted_to_kids: vec![decrypted.recipient_kid],
        sha256_hash: sha256_hash.to_string(),
        ..Default::default()
    };

    Ok((msg, metadata))
}

fn unpack_jws(
    msg_string: &str,
    sha256_hash: &str,
) -> Result<(Message, UnpackMetadata), String> {
    let value: serde_json::Value = serde_json::from_str(msg_string)
        .map_err(|e| format!("Cannot parse JWS: {e}"))?;

    let payload_b64 = value["payload"]
        .as_str()
        .ok_or("Invalid JWS: missing payload")?;

    let payload_bytes = BASE64_URL_SAFE_NO_PAD.decode(payload_b64)
        .map_err(|e| format!("Invalid JWS payload base64: {e}"))?;

    let msg = Message::from_json(&payload_bytes)
        .map_err(|e| format!("Cannot parse JWS payload: {e}"))?;

    let metadata = UnpackMetadata {
        non_repudiation: true,
        sha256_hash: sha256_hash.to_string(),
        ..Default::default()
    };

    Ok((msg, metadata))
}

async fn try_resolve_sender_public(
    jwe_str: &str,
    did_resolver: &DIDCacheClient,
) -> Option<PublicKeyAgreement> {
    let jwe: serde_json::Value = serde_json::from_str(jwe_str).ok()?;
    let protected_b64 = jwe.get("protected")?.as_str()?;
    let protected_bytes = BASE64_URL_SAFE_NO_PAD.decode(protected_b64).ok()?;
    let header: serde_json::Value = serde_json::from_slice(&protected_bytes).ok()?;

    let alg = header.get("alg")?.as_str()?;
    if !alg.contains("1PU") {
        return None;
    }

    let skid = header.get("skid")?.as_str()?;
    let sender_did = if let Some(hash_pos) = skid.find('#') {
        &skid[..hash_pos]
    } else {
        skid
    };

    let sender_doc = did_resolver.resolve(sender_did).await.ok()?;
    let sender_ka_kids = sender_doc.doc.find_key_agreement(None);
    let sender_kid = sender_ka_kids.first()?;

    let vm = sender_doc
        .doc
        .key_agreement
        .iter()
        .filter_map(|ka| match ka {
            VerificationRelationship::VerificationMethod(vm) if vm.id.as_str() == *sender_kid => {
                Some(vm.as_ref())
            }
            _ => None,
        })
        .next()
        .or_else(|| sender_doc.doc.get_verification_method(sender_kid))?;

    if let Some(jwk_value) = vm.property_set.get("publicKeyJwk") {
        return PublicKeyAgreement::from_jwk(jwk_value).ok();
    }

    if let Some(multibase_value) = vm.property_set.get("publicKeyMultibase")
        && let Some(multibase_str) = multibase_value.as_str()
    {
        let (codec, key_bytes) = affinidi_encoding::decode_multikey_with_codec(multibase_str).ok()?;
        let curve = match codec {
            affinidi_encoding::X25519_PUB => Curve::X25519,
            affinidi_encoding::P256_PUB => Curve::P256,
            affinidi_encoding::SECP256K1_PUB => Curve::K256,
            _ => return None,
        };
        return PublicKeyAgreement::from_raw_bytes(curve, &key_bytes).ok();
    }

    None
}

/// Resolve a DID's key agreement public key for encryption
fn resolve_public_key(
    doc: &affinidi_did_common::Document,
    kid: &str,
) -> Option<PublicKeyAgreement> {
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
        .or_else(|| doc.get_verification_method(kid))?;

    if let Some(jwk_value) = vm.property_set.get("publicKeyJwk") {
        return PublicKeyAgreement::from_jwk(jwk_value).ok();
    }

    if let Some(multibase_value) = vm.property_set.get("publicKeyMultibase")
        && let Some(multibase_str) = multibase_value.as_str()
    {
        let (codec, key_bytes) = affinidi_encoding::decode_multikey_with_codec(multibase_str).ok()?;
        let curve = match codec {
            affinidi_encoding::X25519_PUB => Curve::X25519,
            affinidi_encoding::P256_PUB => Curve::P256,
            affinidi_encoding::SECP256K1_PUB => Curve::K256,
            _ => return None,
        };
        return PublicKeyAgreement::from_raw_bytes(curve, &key_bytes).ok();
    }

    None
}

/// Pack (encrypt) a message for a recipient.
/// Replaces the old `Message::pack_encrypted(to, from, sign_by, did_resolver, secrets, options)`.
pub async fn pack_encrypted<S: SecretsResolver>(
    message: &Message,
    to_did: &str,
    from_did: Option<&str>,
    did_resolver: &DIDCacheClient,
    secrets_resolver: &S,
) -> Result<(String, PackEncryptedMetadata), String> {
    // Resolve recipient's key agreement public key
    let recipient_doc = did_resolver.resolve(to_did).await
        .map_err(|e| format!("Failed to resolve recipient DID: {e}"))?;
    let recipient_ka_kids = recipient_doc.doc.find_key_agreement(None);
    let recipient_kid = recipient_ka_kids.first()
        .ok_or("Recipient has no key agreement key")?;
    let recipient_public = resolve_public_key(&recipient_doc.doc, recipient_kid)
        .ok_or("Failed to resolve recipient public key")?;

    let recipients: Vec<(&str, &PublicKeyAgreement)> = vec![(recipient_kid, &recipient_public)];

    if let Some(from) = from_did {
        // Authcrypt: resolve sender's private key
        let sender_doc = did_resolver.resolve(from).await
            .map_err(|e| format!("Failed to resolve sender DID: {e}"))?;
        let sender_ka_kids = sender_doc.doc.find_key_agreement(None);
        let sender_kid = sender_ka_kids.first()
            .ok_or("Sender has no key agreement key")?;

        // Find the sender's private key from secrets
        let secret = secrets_resolver.get_secret(sender_kid).await
            .ok_or(format!("No secret found for sender kid: {sender_kid}"))?;

        let curve = match secret.get_key_type() {
            affinidi_secrets_resolver::secrets::KeyType::X25519 => Curve::X25519,
            affinidi_secrets_resolver::secrets::KeyType::P256 => Curve::P256,
            affinidi_secrets_resolver::secrets::KeyType::Secp256k1 => Curve::K256,
            _ => return Err("Unsupported key type for sender".to_string()),
        };

        let sender_private = PrivateKeyAgreement::from_raw_bytes(curve, secret.get_private_bytes())
            .map_err(|e| format!("Failed to load sender private key: {e}"))?;

        let packed = pack_encrypted_authcrypt(
            message,
            sender_kid,
            &sender_private,
            &recipients,
        )
        .map_err(|e| format!("Failed to pack authcrypt: {e}"))?;

        let metadata = PackEncryptedMetadata {
            from_kid: Some(sender_kid.to_string()),
            to_kids: vec![recipient_kid.to_string()],
            ..Default::default()
        };

        Ok((packed, metadata))
    } else {
        // Anoncrypt: no sender key needed
        let packed = pack_encrypted_anoncrypt(
            message,
            &recipients,
        )
        .map_err(|e| format!("Failed to pack anoncrypt: {e}"))?;

        let metadata = PackEncryptedMetadata {
            to_kids: vec![recipient_kid.to_string()],
            ..Default::default()
        };

        Ok((packed, metadata))
    }
}
