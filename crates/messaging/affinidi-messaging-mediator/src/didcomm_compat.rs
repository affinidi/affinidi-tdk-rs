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

use affinidi_crypto::jose::key_agreement::{Curve, PrivateKeyAgreement, PublicKeyAgreement};
use affinidi_did_common::{
    document::DocumentExt,
    key_negotiation::{DEFAULT_CURVE_PREFERENCE, negotiate_authcrypt, select_anoncrypt_key},
    verification_method::{VerificationMethod, VerificationRelationship},
};
use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_messaging_didcomm::{
    jwe::decrypt::decrypt,
    jws::verify::{VerifiedJws, verify_ed25519, verify_p256},
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
                if from_did.is_none()
                    && let Some(apu) = header.get("apu").and_then(|a| a.as_str())
                    && let Ok(apu_bytes) = BASE64_URL_SAFE_NO_PAD.decode(apu)
                    && let Ok(apu_str) = String::from_utf8(apu_bytes)
                    && let Some(hash_pos) = apu_str.find('#')
                {
                    let did = apu_str[..hash_pos].to_string();
                    from_did = Some(did.clone());
                    sender_did = Some(did);
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
            unpack_jws(&self.raw, &self.sha256_hash, did_resolver).await
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
                let Some(curve) = secret.get_key_type().key_agreement_curve() else {
                    continue;
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

        // Seed metadata from the OUTER JWE layer. `authenticated`/`sign_from`
        // may be promoted below if the decrypted plaintext is itself a signed
        // JWS or a nested authcrypt JWE (the regression this fixes: the old
        // shim stopped here and mis-classified those as anonymous).
        let mut metadata = UnpackMetadata {
            encrypted: true,
            authenticated: decrypted.authenticated,
            anonymous_sender: !decrypted.authenticated,
            encrypted_from_kid: decrypted.sender_kid,
            encrypted_to_kids: vec![decrypted.recipient_kid],
            sha256_hash: self.sha256_hash.clone(),
            ..Default::default()
        };

        let msg = recurse_decrypted_plaintext(
            &decrypted.plaintext,
            &recipient_kid_str,
            &recipient_private,
            did_resolver,
            &mut metadata,
            0,
        )
        .await?;

        Ok((msg, metadata))
    }
}

/// Maximum nested-envelope depth we will peel, bounding decrypt/verify work
/// against a maliciously deeply-nested message.
const MAX_NEST_DEPTH: u8 = 8;

/// Interpret a decrypted JWE plaintext and recurse into any nested envelope,
/// promoting `metadata` as authentication/signature evidence is recovered.
///
/// Three shapes can appear inside a decrypted JWE:
/// - a plaintext DIDComm `Message` (has `type`),
/// - a JWS (sign-then-encrypt — has `payload`+`signatures`), or
/// - another JWE (anoncrypt(authcrypt(..)) — has `ciphertext`+`recipients`).
///
/// `recipient_private`/`recipient_kid` are the SAME local recipient key used
/// for the outer layer, reused to peel a nested JWE addressed to us.
async fn recurse_decrypted_plaintext(
    plaintext: &[u8],
    recipient_kid: &str,
    recipient_private: &PrivateKeyAgreement,
    did_resolver: &DIDCacheClient,
    metadata: &mut UnpackMetadata,
    depth: u8,
) -> Result<Message, String> {
    if depth >= MAX_NEST_DEPTH {
        return Err(format!(
            "nested DIDComm envelope exceeds max depth {MAX_NEST_DEPTH}"
        ));
    }
    // Anything that isn't valid JSON can only be a bare Message attempt.
    let value: serde_json::Value = match serde_json::from_slice(plaintext) {
        Ok(v) => v,
        Err(_) => {
            return Message::from_json(plaintext)
                .map_err(|e| format!("Cannot parse decrypted message: {e}"));
        }
    };

    if value.get("payload").is_some() && value.get("signatures").is_some() {
        // Nested JWS: sign-then-encrypt. Verify the inner signature with the
        // signer's resolved key (Ed25519/EdDSA or P-256/ES256) and attribute
        // non-repudiation. Never trust the kid without verifying — a bad
        // signature must error.
        let jws_str = std::str::from_utf8(plaintext)
            .map_err(|e| format!("Inner JWS is not valid UTF-8: {e}"))?;

        let signer_kid = extract_jws_signer_kid(&value)
            .ok_or("Inner JWS has no signer kid to resolve a verification key")?;
        let signer_did = did_part(&signer_kid);
        let alg = extract_jws_alg(&value).unwrap_or_default();
        let verified = verify_inner_jws(jws_str, &alg, &signer_did, &signer_kid, did_resolver)
            .await
            .map_err(|e| format!("Inner JWS signature verification failed: {e}"))?;
        metadata.non_repudiation = true;
        metadata.sign_from = verified.signer_kid.or(Some(signer_kid));
        return Message::from_json(&verified.payload)
            .map_err(|e| format!("Cannot parse verified JWS payload: {e}"));
    }

    if value.get("ciphertext").is_some() && value.get("recipients").is_some() {
        // Nested JWE: anoncrypt(authcrypt(..)). Decrypt the inner layer with
        // the same local recipient key, resolving the inner sender's
        // key-agreement key (from skid/apu) so ECDH-1PU authcrypt is recovered.
        let inner_str = std::str::from_utf8(plaintext)
            .map_err(|e| format!("Inner JWE is not valid UTF-8: {e}"))?;
        let inner_sender_did = inner_jwe_sender_did(&value);
        let inner_sender_public = if let Some(did) = &inner_sender_did {
            resolve_did_key_agreement(did, did_resolver).await
        } else {
            None
        };
        let inner = decrypt(
            inner_str,
            recipient_kid,
            recipient_private,
            inner_sender_public.as_ref(),
        )
        .map_err(|e| format!("Couldn't decrypt nested JWE: {e}"))?;

        if inner.authenticated {
            metadata.authenticated = true;
            metadata.anonymous_sender = false;
            metadata.encrypted_from_kid = inner.sender_kid.clone();
        }

        // The inner plaintext may itself be a Message or a JWS — recurse.
        return Box::pin(recurse_decrypted_plaintext(
            &inner.plaintext,
            recipient_kid,
            recipient_private,
            did_resolver,
            metadata,
            depth + 1,
        ))
        .await;
    }

    // Plaintext DIDComm message (`type`), or a best-effort parse otherwise.
    Message::from_json(plaintext).map_err(|e| format!("Cannot parse decrypted message: {e}"))
}

/// Extract the signer kid from a parsed JWS (General JSON Serialization).
/// Prefers the integrity-protected header, falling back to the per-signature
/// unprotected header (where credo-ts / didcomm-python place the kid).
fn extract_jws_signer_kid(jws: &serde_json::Value) -> Option<String> {
    let sig = jws.get("signatures")?.as_array()?.first()?;

    // Protected header (base64url-encoded JSON) takes precedence.
    if let Some(protected_b64) = sig.get("protected").and_then(|p| p.as_str())
        && let Ok(bytes) = BASE64_URL_SAFE_NO_PAD.decode(protected_b64)
        && let Ok(header) = serde_json::from_slice::<serde_json::Value>(&bytes)
        && let Some(kid) = header.get("kid").and_then(|k| k.as_str())
    {
        return Some(kid.to_string());
    }

    // Fall back to the unprotected per-signature header.
    sig.get("header")
        .and_then(|h| h.get("kid"))
        .and_then(|k| k.as_str())
        .map(|s| s.to_string())
}

/// Extract the JWS signature algorithm (`alg`) from the first signature's
/// integrity-protected header. Returns `None` if absent/undecodable.
fn extract_jws_alg(jws: &serde_json::Value) -> Option<String> {
    let sig = jws.get("signatures")?.as_array()?.first()?;
    let protected_b64 = sig.get("protected").and_then(|p| p.as_str())?;
    let bytes = BASE64_URL_SAFE_NO_PAD.decode(protected_b64).ok()?;
    let header: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    header
        .get("alg")
        .and_then(|a| a.as_str())
        .map(|s| s.to_string())
}

/// Verify an inner/top-level JWS, dispatching on the JOSE `alg`:
/// `EdDSA`/`Ed25519` (Ed25519) or `ES256` (P-256). Resolves the signer's
/// verification key from their DID document and verifies the signature. Any
/// other `alg` (including a missing/undecodable one) is rejected rather than
/// assumed.
async fn verify_inner_jws(
    jws_str: &str,
    alg: &str,
    signer_did: &str,
    signer_kid: &str,
    did_resolver: &DIDCacheClient,
) -> Result<VerifiedJws, String> {
    match alg {
        // `EdDSA` is the polymorphic JOSE alg (RFC 8037); `Ed25519` is its
        // fully-specified equivalent (draft-ietf-jose-fully-specified-algorithms).
        // Both denote Ed25519 signatures here.
        "EdDSA" | "Ed25519" => {
            let pubkey =
                resolve_did_ed25519_verification(signer_did, Some(signer_kid), did_resolver)
                    .await
                    .ok_or_else(|| {
                        format!(
                            "Could not resolve Ed25519 verification key for signer {signer_kid}"
                        )
                    })?;
            verify_ed25519(jws_str, &pubkey).map_err(|e| e.to_string())
        }
        "ES256" => {
            let pubkey = resolve_did_p256_verification(signer_did, Some(signer_kid), did_resolver)
                .await
                .ok_or_else(|| {
                    format!("Could not resolve P-256 verification key for signer {signer_kid}")
                })?;
            verify_p256(jws_str, &pubkey).map_err(|e| e.to_string())
        }
        other => Err(format!(
            "Unsupported JWS signature algorithm {other:?} (expected EdDSA/Ed25519 or ES256)"
        )),
    }
}

/// Extract the inner JWE's sender DID from its protected header (`skid`, or
/// `apu` fallback), mirroring the outer-layer logic in `MetaEnvelope::new`.
fn inner_jwe_sender_did(jwe: &serde_json::Value) -> Option<String> {
    let protected_b64 = jwe.get("protected").and_then(|p| p.as_str())?;
    let bytes = BASE64_URL_SAFE_NO_PAD.decode(protected_b64).ok()?;
    let header: serde_json::Value = serde_json::from_slice(&bytes).ok()?;

    if let Some(skid) = header.get("skid").and_then(|s| s.as_str()) {
        return Some(did_part(skid));
    }
    if let Some(apu) = header.get("apu").and_then(|a| a.as_str())
        && let Ok(apu_bytes) = BASE64_URL_SAFE_NO_PAD.decode(apu)
        && let Ok(apu_str) = String::from_utf8(apu_bytes)
        && apu_str.contains('#')
    {
        return Some(did_part(&apu_str));
    }
    None
}

/// Strip the `#fragment` from a DID URL, yielding the bare DID.
fn did_part(kid: &str) -> String {
    match kid.find('#') {
        Some(pos) => kid[..pos].to_string(),
        None => kid.to_string(),
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

/// Unpack a top-level (unencrypted) JWS. Resolves the signer's Ed25519 key,
/// verifies the signature, and records `sign_from` — without this the message
/// is sender-authenticated but `sign_from` stays `None`, so the inbound
/// anonymous-envelope check wrongly rejects it.
async fn unpack_jws(
    msg_string: &str,
    sha256_hash: &str,
    did_resolver: &DIDCacheClient,
) -> Result<(Message, UnpackMetadata), String> {
    let value: serde_json::Value =
        serde_json::from_str(msg_string).map_err(|e| format!("Cannot parse JWS: {e}"))?;

    let signer_kid =
        extract_jws_signer_kid(&value).ok_or("JWS has no signer kid to resolve a key")?;
    let signer_did = did_part(&signer_kid);
    let alg = extract_jws_alg(&value).unwrap_or_default();
    let verified = verify_inner_jws(msg_string, &alg, &signer_did, &signer_kid, did_resolver)
        .await
        .map_err(|e| format!("JWS signature verification failed: {e}"))?;

    let msg = Message::from_json(&verified.payload)
        .map_err(|e| format!("Cannot parse JWS payload: {e}"))?;

    let metadata = UnpackMetadata {
        non_repudiation: true,
        sign_from: verified.signer_kid.or(Some(signer_kid)),
        sha256_hash: sha256_hash.to_string(),
        ..Default::default()
    };

    Ok((msg, metadata))
}

/// Resolve the verification method a signer authenticates with: the exact
/// `prefer_kid` when it appears in the DID's authentication relationship,
/// otherwise the DID's first authentication key.
async fn resolve_authentication_vm(
    did: &str,
    prefer_kid: Option<&str>,
    did_resolver: &DIDCacheClient,
) -> Option<VerificationMethod> {
    let doc = did_resolver.resolve(did).await.ok()?;
    let auth = doc.doc.find_authentication(None);
    let kid = prefer_kid
        .filter(|k| auth.iter().any(|a| a == k))
        .map(|k| k.to_string())
        .or_else(|| auth.first().map(|k| k.to_string()))?;
    doc.doc.get_verification_method(&kid).cloned()
}

/// Resolve a DID's Ed25519 verification (signing) public key as raw 32 bytes.
///
/// Supports `publicKeyMultibase` (multikey, `ed25519-pub` codec) and
/// `publicKeyJwk` (`OKP`/`Ed25519`).
async fn resolve_did_ed25519_verification(
    did: &str,
    prefer_kid: Option<&str>,
    did_resolver: &DIDCacheClient,
) -> Option<[u8; 32]> {
    let vm = resolve_authentication_vm(did, prefer_kid, did_resolver).await?;

    if let Some(multibase_value) = vm.property_set.get("publicKeyMultibase")
        && let Some(multibase_str) = multibase_value.as_str()
        && let Ok((codec, key_bytes)) = affinidi_encoding::decode_multikey_with_codec(multibase_str)
        && codec == affinidi_encoding::ED25519_PUB
        && key_bytes.len() == 32
    {
        return key_bytes.try_into().ok();
    }

    if let Some(jwk_value) = vm.property_set.get("publicKeyJwk")
        && jwk_value.get("kty").and_then(|v| v.as_str()) == Some("OKP")
        && jwk_value.get("crv").and_then(|v| v.as_str()) == Some("Ed25519")
        && let Some(x_b64) = jwk_value.get("x").and_then(|v| v.as_str())
        && let Ok(x_bytes) = BASE64_URL_SAFE_NO_PAD.decode(x_b64)
        && x_bytes.len() == 32
    {
        return x_bytes.try_into().ok();
    }

    None
}

/// Resolve a DID's ECDSA P-256 verification (signing) public key as SEC1 bytes.
///
/// Supports `publicKeyMultibase` (multikey, `p256-pub` codec — compressed
/// SEC1) and `publicKeyJwk` (`EC`/`P-256` — assembled into uncompressed SEC1).
async fn resolve_did_p256_verification(
    did: &str,
    prefer_kid: Option<&str>,
    did_resolver: &DIDCacheClient,
) -> Option<Vec<u8>> {
    let vm = resolve_authentication_vm(did, prefer_kid, did_resolver).await?;

    if let Some(multibase_value) = vm.property_set.get("publicKeyMultibase")
        && let Some(multibase_str) = multibase_value.as_str()
        && let Ok((codec, key_bytes)) = affinidi_encoding::decode_multikey_with_codec(multibase_str)
        && codec == affinidi_encoding::P256_PUB
    {
        // Multikey for P-256 is the compressed SEC1 point (33 bytes).
        return Some(key_bytes);
    }

    if let Some(jwk_value) = vm.property_set.get("publicKeyJwk")
        && jwk_value.get("kty").and_then(|v| v.as_str()) == Some("EC")
        && jwk_value.get("crv").and_then(|v| v.as_str()) == Some("P-256")
        && let Some(x_b64) = jwk_value.get("x").and_then(|v| v.as_str())
        && let Some(y_b64) = jwk_value.get("y").and_then(|v| v.as_str())
        && let Ok(x_bytes) = BASE64_URL_SAFE_NO_PAD.decode(x_b64)
        && let Ok(y_bytes) = BASE64_URL_SAFE_NO_PAD.decode(y_b64)
        && x_bytes.len() == 32
        && y_bytes.len() == 32
    {
        // Assemble the uncompressed SEC1 point: 0x04 || x || y.
        let mut sec1 = Vec::with_capacity(65);
        sec1.push(0x04);
        sec1.extend_from_slice(&x_bytes);
        sec1.extend_from_slice(&y_bytes);
        return Some(sec1);
    }

    None
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
            affinidi_encoding::P384_PUB => Curve::P384,
            affinidi_encoding::P521_PUB => Curve::P521,
            _ => return None,
        };
        return PublicKeyAgreement::from_raw_bytes(curve, &key_bytes).ok();
    }

    None
}

/// Pack (encrypt) a message for a recipient.
///
/// Key selection negotiates a **shared curve** between sender and recipient
/// rather than blindly taking each side's first `keyAgreement` key. A DID
/// document may advertise several key-agreement keys on different curves
/// (e.g. the mediator offers X25519 first and P-256 second, while a P-256
/// client offers only P-256); picking `first()` on both sides caused
/// `curve mismatch between private and public keys` when the curves differed.
/// The negotiation mirrors `affinidi-did-authentication`'s pack path and the
/// messaging SDK, all delegating to `affinidi_did_common::key_negotiation`.
pub async fn pack_encrypted<S: SecretsResolver>(
    message: &Message,
    to_did: &str,
    from_did: Option<&str>,
    did_resolver: &DIDCacheClient,
    secrets_resolver: &S,
) -> Result<(String, PackEncryptedMetadata), String> {
    // Resolve recipient's advertised key agreement keys.
    let recipient_doc = did_resolver
        .resolve(to_did)
        .await
        .map_err(|e| format!("Failed to resolve recipient DID: {e}"))?;
    let recipient_ka_kids = recipient_doc.doc.find_key_agreement(None);
    if recipient_ka_kids.is_empty() {
        return Err("Recipient has no key agreement key".to_string());
    }

    if let Some(from) = from_did {
        // Authcrypt: enumerate the sender's *usable* key-agreement keys (those
        // we hold a secret for, on a supported curve) so negotiation can pick a
        // curve the recipient also offers, instead of only the sender's first.
        let sender_doc = did_resolver
            .resolve(from)
            .await
            .map_err(|e| format!("Failed to resolve sender DID: {e}"))?;
        let sender_ka_kids = sender_doc.doc.find_key_agreement(None);

        let mut sender_keys: Vec<(&str, PrivateKeyAgreement, Curve)> = Vec::new();
        // Track why each advertised key was skipped, so a "no usable key" error
        // can show what the sender advertised vs. what was actually usable.
        let mut skipped: Vec<String> = Vec::new();
        for &kid in &sender_ka_kids {
            let Some(secret) = secrets_resolver.get_secret(kid).await else {
                skipped.push(format!("{kid} (no secret held)"));
                continue;
            };
            let key_type = secret.get_key_type();
            let Some(curve) = key_type.key_agreement_curve() else {
                skipped.push(format!("{kid} (unsupported key type: {key_type:?})"));
                continue;
            };
            match PrivateKeyAgreement::from_raw_bytes(curve, secret.get_private_bytes()) {
                Ok(private) => sender_keys.push((kid, private, curve)),
                Err(e) => skipped.push(format!("{kid} (invalid key material: {e})")),
            }
        }
        if sender_keys.is_empty() {
            return Err(format!(
                "Sender has no usable key-agreement key (a usable key needs a held \
                 secret on a supported curve). Advertised: [{}]; unusable: [{}]",
                sender_ka_kids.join(", "),
                skipped.join("; "),
            ));
        }
        let sender_curves: Vec<Curve> = sender_keys.iter().map(|(_, _, c)| *c).collect();

        let pairing = negotiate_authcrypt(
            &sender_curves,
            &recipient_doc.doc,
            &recipient_ka_kids,
            &DEFAULT_CURVE_PREFERENCE,
        )
        .map_err(|e| e.to_string())?;

        // The negotiated curve was drawn from `sender_curves`, so a matching
        // sender key should always be present.
        let (sender_kid, sender_private, _) = sender_keys
            .iter()
            .find(|(_, _, c)| *c == pairing.curve)
            .ok_or("internal error: negotiated curve has no matching sender key")?;

        let recipients: Vec<(&str, &PublicKeyAgreement)> =
            vec![(pairing.recipient_kid, &pairing.recipient_pub)];
        let packed = pack_encrypted_authcrypt(message, sender_kid, sender_private, &recipients)
            .map_err(|e| format!("Failed to pack authcrypt: {e}"))?;

        let metadata = PackEncryptedMetadata {
            from_kid: Some(sender_kid.to_string()),
            to_kids: vec![pairing.recipient_kid.to_string()],
            ..Default::default()
        };

        Ok((packed, metadata))
    } else {
        // Anoncrypt: pick the recipient's most-preferred usable curve.
        let (recipient_kid, recipient_public) = select_anoncrypt_key(
            &recipient_doc.doc,
            &recipient_ka_kids,
            &DEFAULT_CURVE_PREFERENCE,
        )
        .map_err(|e| e.to_string())?;

        let recipients: Vec<(&str, &PublicKeyAgreement)> = vec![(recipient_kid, &recipient_public)];
        let packed = pack_encrypted_anoncrypt(message, &recipients)
            .map_err(|e| format!("Failed to pack anoncrypt: {e}"))?;

        let metadata = PackEncryptedMetadata {
            to_kids: vec![recipient_kid.to_string()],
            ..Default::default()
        };

        Ok((packed, metadata))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// base64url-encode a JSON value as a JWS/JWE protected header.
    fn protected_b64(v: &serde_json::Value) -> String {
        BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(v).unwrap())
    }

    #[test]
    fn did_part_strips_fragment() {
        assert_eq!(did_part("did:example:alice#key-1"), "did:example:alice");
        assert_eq!(did_part("did:example:alice"), "did:example:alice");
    }

    #[test]
    fn jws_signer_kid_prefers_protected_header() {
        let protected =
            protected_b64(&json!({"alg": "ES256", "kid": "did:example:alice#protected"}));
        let jws = json!({
            "payload": "e30",
            "signatures": [{
                "protected": protected,
                "header": {"kid": "did:example:mallory#unprotected"},
                "signature": "AA"
            }]
        });
        assert_eq!(
            extract_jws_signer_kid(&jws).as_deref(),
            Some("did:example:alice#protected"),
            "integrity-protected kid must win over the unprotected one"
        );
    }

    #[test]
    fn jws_signer_kid_falls_back_to_unprotected() {
        // Protected header carries only alg (no kid) — credo-ts / didcomm-python shape.
        let protected = protected_b64(&json!({"alg": "EdDSA"}));
        let jws = json!({
            "payload": "e30",
            "signatures": [{
                "protected": protected,
                "header": {"kid": "did:example:alice#unprotected"},
                "signature": "AA"
            }]
        });
        assert_eq!(
            extract_jws_signer_kid(&jws).as_deref(),
            Some("did:example:alice#unprotected")
        );
    }

    #[test]
    fn jws_alg_extracted_from_protected_header() {
        let protected = protected_b64(&json!({"alg": "ES256", "kid": "did:example:alice#p256"}));
        let jws =
            json!({"payload": "e30", "signatures": [{"protected": protected, "signature": "AA"}]});
        assert_eq!(extract_jws_alg(&jws).as_deref(), Some("ES256"));
    }

    #[test]
    fn jws_alg_none_when_protected_undecodable() {
        let jws = json!({"payload": "e30", "signatures": [{"protected": "!!not-base64!!", "signature": "AA"}]});
        assert_eq!(extract_jws_alg(&jws), None);
    }

    #[test]
    fn inner_jwe_sender_did_from_skid() {
        let protected =
            protected_b64(&json!({"alg": "ECDH-1PU+A256KW", "skid": "did:example:bob#key-x25519"}));
        let jwe = json!({"protected": protected, "ciphertext": "x", "recipients": []});
        assert_eq!(
            inner_jwe_sender_did(&jwe).as_deref(),
            Some("did:example:bob")
        );
    }

    #[test]
    fn inner_jwe_sender_did_from_apu_fallback() {
        let apu = BASE64_URL_SAFE_NO_PAD.encode("did:example:carol#key-1");
        let protected = protected_b64(&json!({"alg": "ECDH-1PU+A256KW", "apu": apu}));
        let jwe = json!({"protected": protected});
        assert_eq!(
            inner_jwe_sender_did(&jwe).as_deref(),
            Some("did:example:carol")
        );
    }

    #[test]
    fn inner_jwe_sender_did_none_for_anoncrypt() {
        let protected = protected_b64(&json!({"alg": "ECDH-ES+A256KW"}));
        let jwe = json!({"protected": protected});
        assert_eq!(inner_jwe_sender_did(&jwe), None);
    }

    // ---------------------------------------------------------------------
    // Regression: `pack_encrypted` must negotiate a shared key-agreement
    // curve instead of blindly pairing each side's first `keyAgreement` key.
    //
    // Post-0.11.7, a P-256 client hit
    //   "Failed to pack authcrypt: key agreement failed: curve mismatch
    //    between private and public keys"
    // (ProblemReport code 47 / `e.p.message.pack`) when the mediator packed
    // its encrypted reply: the mediator advertises X25519 (`#key-1`) first
    // and P-256 (`#key-3`) second, so `.first()` paired the mediator's
    // X25519 secret with the client's only (P-256) key and ECDH failed.
    // ---------------------------------------------------------------------
    use affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder;
    use affinidi_secrets_resolver::{SimpleSecretsResolver, secrets::Secret};

    /// A `did:example` key-agreement verification method (Multikey / multibase),
    /// referenced by id from the document's `keyAgreement` set.
    fn ka_vm(kid: &str, did: &str, secret: &Secret) -> serde_json::Value {
        json!({
            "id": kid,
            "type": "Multikey",
            "controller": did,
            "publicKeyMultibase": secret.get_public_keymultibase().unwrap(),
        })
    }

    /// A local DID cache seeded with the given `did:example` documents (no network).
    async fn example_resolver(docs: &[serde_json::Value]) -> DIDCacheClient {
        let mut client = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .expect("local DID cache client");
        for doc in docs {
            client
                .add_example_did(&doc.to_string())
                .expect("register example DID");
        }
        client
    }

    /// The `epk.crv` advertised in a packed authcrypt JWE's protected header —
    /// proves which curve the ECDH actually ran on.
    fn jwe_epk_crv(packed: &str) -> Option<String> {
        let jwe: serde_json::Value = serde_json::from_str(packed).ok()?;
        let protected = jwe["protected"].as_str()?;
        let hdr: serde_json::Value =
            serde_json::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(protected).ok()?).ok()?;
        hdr["epk"]["crv"].as_str().map(str::to_string)
    }

    fn status_message(from: &str, to: &str, id: &str) -> Message {
        Message::build(
            id.to_string(),
            "https://didcomm.org/messagepickup/3.0/status".to_string(),
            json!({ "message_count": 0 }),
        )
        .from(from.to_string())
        .to(to.to_string())
        .finalize()
    }

    #[tokio::test]
    async fn pack_encrypted_negotiates_shared_curve_for_p256_client() {
        // Mediator: X25519 (`#key-1`) first, P-256 (`#key-3`) second — the
        // real mediator DID-document ordering.
        let mediator = "did:example:mediator";
        let med_x_kid = format!("{mediator}#key-1");
        let med_p_kid = format!("{mediator}#key-3");
        let med_x = Secret::generate_x25519(Some(&med_x_kid), None).unwrap();
        let med_p = Secret::generate_p256(Some(&med_p_kid), None).unwrap();

        // P-256-only client: the single shared curve is P-256.
        let client = "did:example:client";
        let cli_p_kid = format!("{client}#key-p256");
        let cli_p = Secret::generate_p256(Some(&cli_p_kid), None).unwrap();

        let mediator_doc = json!({
            "id": mediator,
            "verificationMethod": [
                ka_vm(&med_x_kid, mediator, &med_x),
                ka_vm(&med_p_kid, mediator, &med_p),
            ],
            "keyAgreement": [med_x_kid, med_p_kid],
        });
        let client_doc = json!({
            "id": client,
            "verificationMethod": [ka_vm(&cli_p_kid, client, &cli_p)],
            "keyAgreement": [cli_p_kid],
        });

        let resolver = example_resolver(&[mediator_doc, client_doc]).await;
        // The sender (mediator) holds both of its key-agreement secrets.
        let secrets = SimpleSecretsResolver::new(&[med_x, med_p]).await;

        let msg = status_message(mediator, client, "regression-curve-mismatch");
        let (packed, metadata) = pack_encrypted(&msg, client, Some(mediator), &resolver, &secrets)
            .await
            .expect("mediator must negotiate the shared P-256 curve, not fail on curve mismatch");

        // Negotiation must pick P-256 on BOTH sides — not the mediator's
        // first-listed X25519 key.
        assert_eq!(metadata.from_kid.as_deref(), Some(med_p_kid.as_str()));
        assert_eq!(metadata.to_kids, vec![cli_p_kid.clone()]);
        assert_eq!(jwe_epk_crv(&packed).as_deref(), Some("P-256"));
    }

    #[tokio::test]
    async fn pack_encrypted_reports_no_common_curve_cleanly() {
        // Mediator with ONLY X25519 key agreement + a P-256-only client: no
        // shared curve at all. The failure must be the negotiation error, not
        // the raw ECDH "curve mismatch between private and public keys".
        let mediator = "did:example:medx";
        let med_x_kid = format!("{mediator}#key-1");
        let med_x = Secret::generate_x25519(Some(&med_x_kid), None).unwrap();

        let client = "did:example:clip";
        let cli_p_kid = format!("{client}#key-p256");
        let cli_p = Secret::generate_p256(Some(&cli_p_kid), None).unwrap();

        let mediator_doc = json!({
            "id": mediator,
            "verificationMethod": [ka_vm(&med_x_kid, mediator, &med_x)],
            "keyAgreement": [med_x_kid],
        });
        let client_doc = json!({
            "id": client,
            "verificationMethod": [ka_vm(&cli_p_kid, client, &cli_p)],
            "keyAgreement": [cli_p_kid],
        });

        let resolver = example_resolver(&[mediator_doc, client_doc]).await;
        let secrets = SimpleSecretsResolver::new(&[med_x]).await;

        let msg = status_message(mediator, client, "regression-no-common-curve");
        let err = pack_encrypted(&msg, client, Some(mediator), &resolver, &secrets)
            .await
            .expect_err("no shared curve must fail");

        assert!(
            err.contains("no common key-agreement curve"),
            "expected the negotiation error, got: {err}"
        );
        assert!(
            !err.contains("curve mismatch between private and public keys"),
            "must not surface the raw ECDH mismatch string: {err}"
        );
    }

    /// A `messagepickup` status message with **no** `from` header — packed as
    /// anoncrypt when `pack_encrypted` is called with `from_did: None`.
    fn anoncrypt_message(to: &str, id: &str) -> Message {
        Message::build(
            id.to_string(),
            "https://didcomm.org/messagepickup/3.0/status".to_string(),
            json!({ "message_count": 0 }),
        )
        .to(to.to_string())
        .finalize()
    }

    #[tokio::test]
    async fn pack_encrypted_anoncrypt_uses_p256_for_p256_only_client() {
        // Anoncrypt sibling of the authcrypt regression: a mediator anoncrypt
        // reply (no `from`) to a P-256-only client must run ECDH-ES on P-256,
        // not choke selecting an absent/unusable X25519 key.
        let client = "did:example:anon-p256-client";
        let cli_p_kid = format!("{client}#key-p256");
        let cli_p = Secret::generate_p256(Some(&cli_p_kid), None).unwrap();

        let client_doc = json!({
            "id": client,
            "verificationMethod": [ka_vm(&cli_p_kid, client, &cli_p)],
            "keyAgreement": [cli_p_kid],
        });

        let resolver = example_resolver(&[client_doc]).await;
        // Anoncrypt has no sender side, so no secrets are required.
        let no_secrets: [Secret; 0] = [];
        let secrets = SimpleSecretsResolver::new(&no_secrets).await;

        let msg = anoncrypt_message(client, "regression-anoncrypt-p256");
        let (packed, metadata) = pack_encrypted(&msg, client, None, &resolver, &secrets)
            .await
            .expect("anoncrypt to a P-256-only client must pack");

        assert_eq!(metadata.to_kids, vec![cli_p_kid.clone()]);
        assert_eq!(jwe_epk_crv(&packed).as_deref(), Some("P-256"));
    }

    #[tokio::test]
    async fn pack_encrypted_anoncrypt_prefers_curve_over_document_order() {
        // Recipient lists P-256 FIRST, X25519 second. Naive `.first()`
        // selection would encrypt to P-256; the fix honours
        // DEFAULT_CURVE_PREFERENCE (X25519 > P-256), so anoncrypt must select
        // the second-listed X25519 key — proving curve-preference selection,
        // not document order.
        let client = "did:example:anon-mixed-client";
        let cli_p_kid = format!("{client}#key-p256");
        let cli_x_kid = format!("{client}#key-x25519");
        let cli_p = Secret::generate_p256(Some(&cli_p_kid), None).unwrap();
        let cli_x = Secret::generate_x25519(Some(&cli_x_kid), None).unwrap();

        let client_doc = json!({
            "id": client,
            "verificationMethod": [
                ka_vm(&cli_p_kid, client, &cli_p),
                ka_vm(&cli_x_kid, client, &cli_x),
            ],
            // P-256 listed first on purpose — the fix must ignore this order.
            "keyAgreement": [cli_p_kid, cli_x_kid],
        });

        let resolver = example_resolver(&[client_doc]).await;
        let no_secrets: [Secret; 0] = [];
        let secrets = SimpleSecretsResolver::new(&no_secrets).await;

        let msg = anoncrypt_message(client, "regression-anoncrypt-preference");
        let (packed, metadata) = pack_encrypted(&msg, client, None, &resolver, &secrets)
            .await
            .expect("anoncrypt must pack");

        assert_eq!(metadata.to_kids, vec![cli_x_kid.clone()]);
        assert_eq!(jwe_epk_crv(&packed).as_deref(), Some("X25519"));
    }

    #[tokio::test]
    async fn pack_encrypted_authcrypt_reports_unusable_sender_keys() {
        // Sender advertises an X25519 key-agreement key but we hold no secret
        // for it: the error must name what the sender advertised and why it was
        // unusable, rather than a bare "no usable key" string.
        let sender = "did:example:sender-nosecret";
        let snd_x_kid = format!("{sender}#key-1");
        let snd_x = Secret::generate_x25519(Some(&snd_x_kid), None).unwrap();

        let client = "did:example:client-authcrypt";
        let cli_p_kid = format!("{client}#key-p256");
        let cli_p = Secret::generate_p256(Some(&cli_p_kid), None).unwrap();

        let sender_doc = json!({
            "id": sender,
            "verificationMethod": [ka_vm(&snd_x_kid, sender, &snd_x)],
            "keyAgreement": [snd_x_kid],
        });
        let client_doc = json!({
            "id": client,
            "verificationMethod": [ka_vm(&cli_p_kid, client, &cli_p)],
            "keyAgreement": [cli_p_kid],
        });

        let resolver = example_resolver(&[sender_doc, client_doc]).await;
        // No sender secret registered → the advertised key is unusable.
        let no_secrets: [Secret; 0] = [];
        let secrets = SimpleSecretsResolver::new(&no_secrets).await;

        let msg = status_message(sender, client, "regression-unusable-sender");
        let err = pack_encrypted(&msg, client, Some(sender), &resolver, &secrets)
            .await
            .expect_err("a sender with no held secret must fail to authcrypt");

        assert!(
            err.contains("no usable key-agreement key"),
            "expected the no-usable-key error, got: {err}"
        );
        assert!(
            err.contains(&snd_x_kid),
            "error must name the advertised sender kid: {err}"
        );
        assert!(
            err.contains("no secret held"),
            "error must explain why the advertised key was unusable: {err}"
        );
    }
}
