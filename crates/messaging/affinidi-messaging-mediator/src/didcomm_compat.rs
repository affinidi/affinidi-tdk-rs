//! Compatibility module that bridges the old `affinidi-messaging-didcomm` API
//! with the new `affinidi-messaging-didcomm` crate.
//!
//! Provides `MetaEnvelope`, `unpack`, and `pack_encrypted` functionality
//! that the mediator previously obtained from the legacy DIDComm crate.
//!
//! ## Performance optimizations
//!
//! - JSON is parsed **once** in `MetaEnvelope::new()` and the parsed value is
//!   shared with `unpack()` via `MetaEnvelope::unpack()`, eliminating redundant parsing.
//! - The protected header is decoded once during envelope creation and reused.
//! - Sender public key resolution is done lazily during decryption, not eagerly.

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

/// Pre-parsed envelope metadata extracted without decryption.
///
/// Holds the parsed JSON value so it can be passed directly to `unpack()`
/// without re-parsing. This eliminates the double-parse overhead.
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
    /// Pre-parsed JSON value (shared with unpack to avoid re-parsing)
    parsed: serde_json::Value,
    /// Pre-resolved sender DID (if authcrypt detected)
    sender_did: Option<String>,
}

/// Metadata about the envelope format
#[derive(Debug, Default)]
pub struct EnvelopeMetadata {
    pub encrypted: bool,
    pub authenticated: bool,
}

impl MetaEnvelope {
    /// Parse a raw message string to extract envelope metadata.
    ///
    /// The JSON is parsed once here. Use `self.unpack()` to decrypt using
    /// the pre-parsed value, avoiding a second parse.
    pub async fn new(message: &str, _did_resolver: &DIDCacheClient) -> Result<Self, String> {
        let sha256_hash = sha256::digest(message);

        let value: serde_json::Value = serde_json::from_str(message)
            .map_err(|e| format!("Cannot parse message as JSON: {e}"))?;

        if value.get("ciphertext").is_some() && value.get("recipients").is_some() {
            // JWE envelope
            let mut to_did = None;
            let mut from_did = None;
            let mut sender_did = None;
            let mut authenticated = false;

            // Extract recipient KID to determine to_did
            if let Some(recipients) = value["recipients"].as_array() {
                for recipient in recipients {
                    if let Some(kid) = recipient["header"]["kid"].as_str() {
                        if let Some(hash_pos) = kid.find('#') {
                            to_did = Some(kid[..hash_pos].to_string());
                        } else {
                            to_did = Some(kid.to_string());
                        }
                        break;
                    }
                }
            }

            // Decode protected header once and extract sender info
            if let Some(protected_b64) = value.get("protected").and_then(|p| p.as_str())
                && let Ok(protected_bytes) = BASE64_URL_SAFE_NO_PAD.decode(protected_b64)
                && let Ok(header) = serde_json::from_slice::<serde_json::Value>(&protected_bytes)
                && let Some(alg) = header.get("alg").and_then(|a| a.as_str())
                && alg.contains("1PU")
            {
                authenticated = true;
                // Extract sender DID from skid
                if let Some(skid) = header.get("skid").and_then(|s| s.as_str()) {
                    let did = if let Some(hash_pos) = skid.find('#') {
                        skid[..hash_pos].to_string()
                    } else {
                        skid.to_string()
                    };
                    from_did = Some(did.clone());
                    sender_did = Some(did);
                }

                // Fallback: try apu header for sender DID
                if from_did.is_none() {
                    if let Some(apu) = header.get("apu").and_then(|a| a.as_str())
                        && let Ok(apu_bytes) = BASE64_URL_SAFE_NO_PAD.decode(apu)
                        && let Ok(apu_str) = String::from_utf8(apu_bytes)
                        && let Some(hash_pos) = apu_str.find('#')
                    {
                        let did = apu_str[..hash_pos].to_string();
                        from_did = Some(did.clone());
                        sender_did = Some(did);
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
                parsed: value,
                sender_did,
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
                parsed: value,
                sender_did: None,
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
                parsed: value,
                sender_did: None,
            })
        } else {
            Err("Cannot detect message format: expected JWE, JWS, or plaintext".to_string())
        }
    }

    /// Unpack (decrypt) this envelope using the pre-parsed JSON value.
    ///
    /// This avoids re-parsing the JSON — the parsed value from `new()` is reused.
    pub async fn unpack<S: SecretsResolver>(
        &self,
        did_resolver: &DIDCacheClient,
        secrets_resolver: &S,
    ) -> Result<(Message, UnpackMetadata), String> {
        if self.parsed.get("ciphertext").is_some() && self.parsed.get("recipients").is_some() {
            self.unpack_jwe(did_resolver, secrets_resolver).await
        } else if self.parsed.get("payload").is_some() && self.parsed.get("signatures").is_some() {
            unpack_jws(&self.raw, &self.sha256_hash)
        } else if self.parsed.get("type").is_some() {
            let msg = Message::from_json(self.raw.as_bytes())
                .map_err(|e| format!("Cannot parse plaintext message: {e}"))?;
            let metadata = UnpackMetadata {
                sha256_hash: self.sha256_hash.clone(),
                ..Default::default()
            };
            Ok((msg, metadata))
        } else {
            Err("Cannot detect message format".to_string())
        }
    }

    /// Decrypt a JWE using the pre-parsed JSON and pre-extracted sender DID.
    async fn unpack_jwe<S: SecretsResolver>(
        &self,
        did_resolver: &DIDCacheClient,
        secrets_resolver: &S,
    ) -> Result<(Message, UnpackMetadata), String> {
        let recipients = self.parsed["recipients"]
            .as_array()
            .ok_or("Invalid JWE: no recipients array")?;

        let mut recipient_kid_str = String::new();
        let mut recipient_private: Option<PrivateKeyAgreement> = None;

        for recipient in recipients {
            if let Some(kid) = recipient["header"]["kid"].as_str()
                && let Some(secret) = secrets_resolver.get_secret(kid).await
            {
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

        let recipient_private =
            recipient_private.ok_or("No local secret matches any JWE recipient")?;

        // Resolve sender public key using pre-extracted sender DID (no re-parsing)
        let sender_public = if let Some(sender_did) = &self.sender_did {
            resolve_did_key_agreement(sender_did, did_resolver).await
        } else {
            None
        };

        // The decrypt() function will re-parse the JWE string internally.
        // This is unavoidable since decrypt() takes &str, not a pre-parsed struct.
        // However, we've eliminated the extra parse that was in try_resolve_sender_public().
        let decrypted = decrypt(
            &self.raw,
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
            sha256_hash: self.sha256_hash.clone(),
            ..Default::default()
        };

        Ok((msg, metadata))
    }
}

/// Standalone unpack for cases where MetaEnvelope is not used (backward compat).
pub async fn unpack<S: SecretsResolver>(
    message: &str,
    did_resolver: &DIDCacheClient,
    secrets_resolver: &S,
) -> Result<(Message, UnpackMetadata), String> {
    let envelope = MetaEnvelope::new(message, did_resolver).await?;
    envelope.unpack(did_resolver, secrets_resolver).await
}

fn unpack_jws(msg_string: &str, sha256_hash: &str) -> Result<(Message, UnpackMetadata), String> {
    let value: serde_json::Value =
        serde_json::from_str(msg_string).map_err(|e| format!("Cannot parse JWS: {e}"))?;

    let payload_b64 = value["payload"]
        .as_str()
        .ok_or("Invalid JWS: missing payload")?;

    let payload_bytes = BASE64_URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|e| format!("Invalid JWS payload base64: {e}"))?;

    let msg =
        Message::from_json(&payload_bytes).map_err(|e| format!("Cannot parse JWS payload: {e}"))?;

    let metadata = UnpackMetadata {
        non_repudiation: true,
        sha256_hash: sha256_hash.to_string(),
        ..Default::default()
    };

    Ok((msg, metadata))
}

/// Resolve a DID's first key agreement public key.
async fn resolve_did_key_agreement(
    did: &str,
    did_resolver: &DIDCacheClient,
) -> Option<PublicKeyAgreement> {
    let doc = did_resolver.resolve(did).await.ok()?;
    let ka_kids = doc.doc.find_key_agreement(None);
    let kid = ka_kids.first()?;
    resolve_public_key(&doc.doc, kid)
}

/// Resolve a public key from a DID document verification method.
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
        let (codec, key_bytes) =
            affinidi_encoding::decode_multikey_with_codec(multibase_str).ok()?;
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
pub async fn pack_encrypted<S: SecretsResolver>(
    message: &Message,
    to_did: &str,
    from_did: Option<&str>,
    did_resolver: &DIDCacheClient,
    secrets_resolver: &S,
) -> Result<(String, PackEncryptedMetadata), String> {
    // Resolve recipient's key agreement public key
    let recipient_doc = did_resolver
        .resolve(to_did)
        .await
        .map_err(|e| format!("Failed to resolve recipient DID: {e}"))?;
    let recipient_ka_kids = recipient_doc.doc.find_key_agreement(None);
    let recipient_kid = recipient_ka_kids
        .first()
        .ok_or("Recipient has no key agreement key")?;
    let recipient_public = resolve_public_key(&recipient_doc.doc, recipient_kid)
        .ok_or("Failed to resolve recipient public key")?;

    let recipients: Vec<(&str, &PublicKeyAgreement)> = vec![(recipient_kid, &recipient_public)];

    if let Some(from) = from_did {
        // Authcrypt: resolve sender's private key
        let sender_doc = did_resolver
            .resolve(from)
            .await
            .map_err(|e| format!("Failed to resolve sender DID: {e}"))?;
        let sender_ka_kids = sender_doc.doc.find_key_agreement(None);
        let sender_kid = sender_ka_kids
            .first()
            .ok_or("Sender has no key agreement key")?;

        let secret = secrets_resolver
            .get_secret(sender_kid)
            .await
            .ok_or(format!("No secret found for sender kid: {sender_kid}"))?;

        let curve = match secret.get_key_type() {
            affinidi_secrets_resolver::secrets::KeyType::X25519 => Curve::X25519,
            affinidi_secrets_resolver::secrets::KeyType::P256 => Curve::P256,
            affinidi_secrets_resolver::secrets::KeyType::Secp256k1 => Curve::K256,
            _ => return Err("Unsupported key type for sender".to_string()),
        };

        let sender_private = PrivateKeyAgreement::from_raw_bytes(curve, secret.get_private_bytes())
            .map_err(|e| format!("Failed to load sender private key: {e}"))?;

        let packed = pack_encrypted_authcrypt(message, sender_kid, &sender_private, &recipients)
            .map_err(|e| format!("Failed to pack authcrypt: {e}"))?;

        let metadata = PackEncryptedMetadata {
            from_kid: Some(sender_kid.to_string()),
            to_kids: vec![recipient_kid.to_string()],
            ..Default::default()
        };

        Ok((packed, metadata))
    } else {
        let packed = pack_encrypted_anoncrypt(message, &recipients)
            .map_err(|e| format!("Failed to pack anoncrypt: {e}"))?;

        let metadata = PackEncryptedMetadata {
            to_kids: vec![recipient_kid.to_string()],
            ..Default::default()
        };

        Ok((packed, metadata))
    }
}
