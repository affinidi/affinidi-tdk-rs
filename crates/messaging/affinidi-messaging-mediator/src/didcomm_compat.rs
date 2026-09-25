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
    jwe::{
        decrypt::{SenderKey, decrypt_bound},
        envelope::ProtectedHeader,
    },
    jws::verify::{VerifiedJws, verify_ed25519, verify_p256, verify_secp256k1},
    message::{
        Message,
        pack::{pack_encrypted_anoncrypt, pack_encrypted_authcrypt},
    },
};
use affinidi_messaging_sdk::messages::compat::{PackEncryptedMetadata, UnpackMetadata};
use affinidi_messaging_sdk::messages::wrapping::{CryptoLayer, EncLayerKind, MessageWrappingType};
use affinidi_secrets_resolver::SecretsResolver;
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use tracing::warn;

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
    /// The sender's specific key id (full `skid`) for ECDH-1PU key resolution
    sender_kid: Option<String>,
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
            let mut sender_kid: Option<String> = None;
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

            // An authcrypt envelope names its sender by `skid`, which must be
            // bound to the `apu` the key derivation uses; one naming two
            // senders, or none, is refused here rather than routed on.
            if let Some(protected_b64) = value.get("protected").and_then(|p| p.as_str())
                && let Ok(protected_bytes) = BASE64_URL_SAFE_NO_PAD.decode(protected_b64)
                && let Ok(header) = serde_json::from_slice::<serde_json::Value>(&protected_bytes)
                && let Some(alg) = header.get("alg").and_then(|a| a.as_str())
                && alg.contains("1PU")
            {
                authenticated = true;
                let skid = authcrypt_skid(protected_b64)?;
                from_did = Some(did_part(&skid));
                sender_kid = Some(skid);
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
                sender_kid,
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
                sender_kid: None,
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
                sender_kid: None,
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
            let mut metadata = UnpackMetadata::default();
            metadata.sha256_hash = self.sha256_hash.clone();
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

        // The sender key is resolved for exactly the `skid` the header binds,
        // and `decrypt` is told which key id it belongs to, so the key used and
        // the sender reported are the same.
        let sender_public = match &self.sender_kid {
            Some(skid) => resolve_did_key_agreement_by_skid(skid, did_resolver).await,
            None => None,
        };
        let sender = self
            .sender_kid
            .as_deref()
            .zip(sender_public.as_ref())
            .map(|(kid, public)| SenderKey::new(kid, public));

        let decrypted = decrypt_bound(&self.raw, &recipient_kid_str, &recipient_private, sender)
            .map_err(|e| format!("Couldn't decrypt message: {e}"))?;

        // Seed metadata from the OUTER JWE layer. `authenticated`/`sign_from`
        // may be promoted below if the decrypted plaintext is itself a signed
        // JWS or a nested authcrypt JWE (the regression this fixes: the old
        // shim stopped here and mis-classified those as anonymous).
        let mut metadata = UnpackMetadata::default();
        metadata.encrypted = true;
        metadata.authenticated = decrypted.authenticated;
        metadata.anonymous_sender = !decrypted.authenticated;
        metadata.encrypted_from_kid = decrypted.sender_kid;
        metadata.encrypted_to_kids = vec![decrypted.recipient_kid];
        metadata.sha256_hash = self.sha256_hash.clone();

        // Record the outer encryption layer, then let the recursion append any
        // nested ones, so the whole stack can be classified once at the end.
        let mut layers = vec![CryptoLayer::Encrypted(if decrypted.authenticated {
            EncLayerKind::Authcrypt
        } else {
            EncLayerKind::Anoncrypt
        })];

        let msg = recurse_decrypted_plaintext(
            &decrypted.plaintext,
            &recipient_kid_str,
            &recipient_private,
            did_resolver,
            &mut metadata,
            0,
            &mut layers,
        )
        .await?;

        self.report_wrapping(&layers, &msg);

        Ok((msg, metadata))
    }

    /// Classify the envelope's layer stack and **warn** when it falls outside
    /// the DIDComm-defined wrapping taxonomy.
    ///
    /// Observability only — nothing is rejected here. The mediator relays for
    /// third-party senders whose layering it does not control, so rejecting a
    /// non-conformant envelope would drop traffic that works today. Logging it
    /// first shows what is actually in flight; enforcement can follow once the
    /// picture is known.
    ///
    /// The warning names *what* is wrong (the observed layer stack, outermost
    /// first) and *who* it is between, so an operator can act on it without
    /// having to correlate against anything else.
    fn report_wrapping(&self, layers: &[CryptoLayer], msg: &Message) {
        if MessageWrappingType::classify(layers).is_some() {
            return;
        }

        // Prefer the cryptographically-evidenced sender (the authcrypt `skid`)
        // over the message's self-asserted `from`, and say which one is shown —
        // on a non-conformant envelope the difference is exactly what matters.
        let (sender, sender_source) = match (self.from_did.as_deref(), msg.from.as_deref()) {
            (Some(skid_did), _) => (skid_did, "authcrypt skid"),
            (None, Some(from)) => (from, "unauthenticated `from` claim"),
            (None, None) => ("<anonymous>", "no sender evidence"),
        };

        warn!(
            sender = %sender,
            sender_source = %sender_source,
            recipient = %self.to_did.as_deref().unwrap_or("<unknown>"),
            message_id = %msg.id,
            message_type = %msg.typ,
            layers = %describe_layers(layers),
            sha256_hash = %self.sha256_hash,
            "Non-conformant DIDComm envelope layering accepted (observability only, not \
             rejected): the layer stack above is outside the DIDComm v2 wrapping taxonomy, \
             so this message does not correspond to any defined combination of \
             authcrypt/anoncrypt/sign. Defined forms are authcrypt(plaintext), \
             anoncrypt(plaintext), sign(plaintext), authcrypt(sign(plaintext)), \
             anoncrypt(sign(plaintext)) and anoncrypt(authcrypt(plaintext)). Common causes: \
             a signature applied outside the encryption instead of inside, a repeated \
             encryption layer, or nesting deeper than two crypto layers"
        );
    }
}

/// Render a layer stack outermost-first as `anoncrypt(authcrypt(sign(...)))`,
/// so a warning shows the actual shape rather than a debug dump.
fn describe_layers(layers: &[CryptoLayer]) -> String {
    if layers.is_empty() {
        return "plaintext".to_string();
    }
    let mut out = String::new();
    for layer in layers {
        out.push_str(match layer {
            CryptoLayer::Sign => "sign(",
            CryptoLayer::Encrypted(EncLayerKind::Authcrypt) => "authcrypt(",
            CryptoLayer::Encrypted(EncLayerKind::Anoncrypt) => "anoncrypt(",
        });
    }
    out.push_str("plaintext");
    out.push_str(&")".repeat(layers.len()));
    out
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
    layers: &mut Vec<CryptoLayer>,
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
        // signer's resolved key (Ed25519/EdDSA, P-256/ES256, or
        // secp256k1/ES256K) and attribute non-repudiation. Never trust the
        // kid without verifying — a bad signature must error.
        let jws_str = std::str::from_utf8(plaintext)
            .map_err(|e| format!("Inner JWS is not valid UTF-8: {e}"))?;
        layers.push(CryptoLayer::Sign);

        let (signer_kid, kid_from_protected) = extract_jws_signer_kid_with_provenance(&value)
            .ok_or("Inner JWS has no signer kid to resolve a verification key")?;
        // Refuse an in-transit-rewritable kid before it can steer an outbound
        // DID resolution (SSRF) — see `signer_kid_is_resolvable`.
        if !signer_kid_is_resolvable(&value, &signer_kid, kid_from_protected) {
            return Err(format!(
                "Inner JWS carries its signer kid only in the unprotected header, and \
                 '{signer_kid}' does not match the message `from`; refusing to resolve it"
            ));
        }
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
        let inner_sender_kid = inner_jwe_sender_kid(&value)?;
        let inner_sender_public = match &inner_sender_kid {
            Some(skid) => resolve_did_key_agreement_by_skid(skid, did_resolver).await,
            None => None,
        };
        let inner_sender = inner_sender_kid
            .as_deref()
            .zip(inner_sender_public.as_ref())
            .map(|(kid, public)| SenderKey::new(kid, public));
        let inner = decrypt_bound(inner_str, recipient_kid, recipient_private, inner_sender)
            .map_err(|e| format!("Couldn't decrypt nested JWE: {e}"))?;

        layers.push(CryptoLayer::Encrypted(if inner.authenticated {
            EncLayerKind::Authcrypt
        } else {
            EncLayerKind::Anoncrypt
        }));

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
            layers,
        ))
        .await;
    }

    // Plaintext DIDComm message (`type`), or a best-effort parse otherwise.
    Message::from_json(plaintext).map_err(|e| format!("Cannot parse decrypted message: {e}"))
}

/// Extract the signer kid from a parsed JWS (General JSON Serialization).
/// Prefers the integrity-protected header, falling back to the per-signature
/// unprotected header (where credo-ts / didcomm-python place the kid).
/// Extract the signer kid from a parsed JWS (General JSON Serialization),
/// reporting whether it came from the **integrity-protected** header (`true`) or
/// the per-signature *unprotected* one (`false`). The protected header takes
/// precedence.
///
/// SECURITY: the unprotected header is outside the JWS signing input, so **any
/// intermediary** — a relay, a peer mediator — can rewrite it in transit without
/// invalidating the signature. Since resolving a signer DID is an outbound
/// network fetch for `did:web`, and it happens *before* the signature is
/// verified, an unprotected kid is an SSRF primitive: it lets a party who cannot
/// forge a signature at all choose which host this mediator contacts. Callers
/// must therefore gate resolution on the provenance — see
/// [`signer_kid_is_resolvable`].
fn extract_jws_signer_kid_with_provenance(jws: &serde_json::Value) -> Option<(String, bool)> {
    let sig = jws.get("signatures")?.as_array()?.first()?;

    // Protected header (base64url-encoded JSON) takes precedence.
    if let Some(protected_b64) = sig.get("protected").and_then(|p| p.as_str())
        && let Ok(bytes) = BASE64_URL_SAFE_NO_PAD.decode(protected_b64)
        && let Ok(header) = serde_json::from_slice::<serde_json::Value>(&bytes)
        && let Some(kid) = header.get("kid").and_then(|k| k.as_str())
    {
        return Some((kid.to_string(), true));
    }

    // Fall back to the unprotected per-signature header.
    sig.get("header")
        .and_then(|h| h.get("kid"))
        .and_then(|k| k.as_str())
        .map(|s| (s.to_string(), false))
}

/// The `from` DID of a JWS payload, if the payload is a readable DIDComm
/// plaintext. The payload *is* covered by the signature, so unlike the
/// unprotected header it cannot be rewritten in transit.
fn jws_payload_from(jws: &serde_json::Value) -> Option<String> {
    let payload_b64 = jws.get("payload")?.as_str()?;
    let bytes = BASE64_URL_SAFE_NO_PAD.decode(payload_b64).ok()?;
    let msg: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    msg.get("from")?.as_str().map(|s| s.to_string())
}

/// Whether a signer kid may be turned into a (networked) DID resolution.
///
/// A **protected** kid always may: it is inside the signing input, so it is the
/// original sender's own choice and cannot be altered in transit. That a claimed
/// sender causes its own DID to be resolved is inherent to DID messaging.
///
/// An **unprotected** kid may only when it names the same DID as the signed
/// payload's `from`. That binding is what removes the SSRF: an intermediary
/// rewriting the kid no longer redirects the fetch, it merely makes the
/// signature unattributable and the message is rejected — at zero outbound
/// requests. A payload with no readable `from` offers nothing to bind against,
/// so an unprotected kid is refused there too.
fn signer_kid_is_resolvable(
    jws: &serde_json::Value,
    signer_kid: &str,
    from_protected: bool,
) -> bool {
    if from_protected {
        return true;
    }
    jws_payload_from(jws).is_some_and(|from| did_part(&from) == did_part(signer_kid))
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
/// `EdDSA`/`Ed25519` (Ed25519), `ES256` (P-256), or `ES256K` (secp256k1).
/// Resolves the signer's verification key from their DID document and
/// verifies the signature. Any other `alg` (including a missing/undecodable
/// one) is rejected rather than assumed.
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
        "ES256K" => {
            let pubkey =
                resolve_did_secp256k1_verification(signer_did, Some(signer_kid), did_resolver)
                    .await
                    .ok_or_else(|| {
                        format!(
                            "Could not resolve secp256k1 verification key for signer {signer_kid}"
                        )
                    })?;
            verify_secp256k1(jws_str, &pubkey).map_err(|e| e.to_string())
        }
        other => Err(format!(
            "Unsupported JWS signature algorithm {other:?} (expected EdDSA/Ed25519, ES256, or ES256K)"
        )),
    }
}

/// The inner JWE's sender DID, from its bound `skid`.
#[cfg(test)]
fn inner_jwe_sender_did(jwe: &serde_json::Value) -> Result<Option<String>, String> {
    Ok(inner_jwe_sender_kid(jwe)?.map(|kid| did_part(&kid)))
}

/// The inner JWE's sender key id: its `skid` for authcrypt, once bound to its
/// `apu`; `None` for anoncrypt.
fn inner_jwe_sender_kid(jwe: &serde_json::Value) -> Result<Option<String>, String> {
    let protected_b64 = jwe
        .get("protected")
        .and_then(|p| p.as_str())
        .ok_or("Nested JWE has no protected header")?;
    let header =
        ProtectedHeader::from_base64url(protected_b64).map_err(|e| format!("Nested JWE: {e}"))?;
    header
        .authcrypt_sender_kid()
        .map(|skid| skid.map(str::to_string))
        .map_err(|e| format!("Nested JWE: {e}"))
}

/// The `skid` of an authcrypt protected header, once checked against its
/// `apu`. Any other authcrypt `alg` is refused.
fn authcrypt_skid(protected_b64: &str) -> Result<String, String> {
    ProtectedHeader::from_base64url(protected_b64)
        .and_then(|header| {
            header
                .authcrypt_sender_kid()
                .map(|skid| skid.map(str::to_string))
        })
        .map_err(|e| format!("Rejected authcrypt envelope: {e}"))?
        .ok_or_else(|| "Rejected authcrypt envelope: unsupported authcrypt alg".to_string())
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

    let (signer_kid, kid_from_protected) = extract_jws_signer_kid_with_provenance(&value)
        .ok_or("JWS has no signer kid to resolve a key")?;
    // This path is reachable *pre-authentication* (the mediator's
    // `/authenticate/*` handlers unpack before a session exists), so an
    // unprotected kid here would let any unauthenticated peer aim the mediator's
    // outbound DID resolution at a host of its choosing. Gate it on provenance
    // before resolving anything — see `signer_kid_is_resolvable`.
    if !signer_kid_is_resolvable(&value, &signer_kid, kid_from_protected) {
        return Err(format!(
            "JWS carries its signer kid only in the unprotected header, and \
             '{signer_kid}' does not match the message `from`; refusing to resolve it"
        ));
    }
    let signer_did = did_part(&signer_kid);
    let alg = extract_jws_alg(&value).unwrap_or_default();
    let verified = verify_inner_jws(msg_string, &alg, &signer_did, &signer_kid, did_resolver)
        .await
        .map_err(|e| format!("JWS signature verification failed: {e}"))?;

    let msg = Message::from_json(&verified.payload)
        .map_err(|e| format!("Cannot parse JWS payload: {e}"))?;

    let mut metadata = UnpackMetadata::default();
    metadata.non_repudiation = true;
    metadata.sign_from = verified.signer_kid.or(Some(signer_kid));
    metadata.sha256_hash = sha256_hash.to_string();

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

/// Resolve a DID's ECDSA verification (signing) public key as SEC1 bytes,
/// shared by the ES256 (P-256) and ES256K (secp256k1) paths — the curves
/// differ only in multicodec and JOSE `crv` name.
///
/// Supports `publicKeyMultibase` (multikey, `multicodec` — compressed SEC1)
/// and `publicKeyJwk` (`EC`/`jose_crv` — assembled into uncompressed SEC1).
async fn resolve_did_ecdsa_verification(
    did: &str,
    prefer_kid: Option<&str>,
    did_resolver: &DIDCacheClient,
    multicodec: u64,
    jose_crv: &str,
) -> Option<Vec<u8>> {
    let vm = resolve_authentication_vm(did, prefer_kid, did_resolver).await?;

    if let Some(multibase_value) = vm.property_set.get("publicKeyMultibase")
        && let Some(multibase_str) = multibase_value.as_str()
        && let Ok((codec, key_bytes)) = affinidi_encoding::decode_multikey_with_codec(multibase_str)
        && codec == multicodec
    {
        // Multikey ECDSA points are compressed SEC1 (33 bytes).
        return Some(key_bytes);
    }

    if let Some(jwk_value) = vm.property_set.get("publicKeyJwk")
        && jwk_value.get("kty").and_then(|v| v.as_str()) == Some("EC")
        && jwk_value.get("crv").and_then(|v| v.as_str()) == Some(jose_crv)
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

/// Resolve a DID's ECDSA P-256 verification (signing) public key as SEC1
/// bytes (JWS `alg: ES256`).
async fn resolve_did_p256_verification(
    did: &str,
    prefer_kid: Option<&str>,
    did_resolver: &DIDCacheClient,
) -> Option<Vec<u8>> {
    resolve_did_ecdsa_verification(
        did,
        prefer_kid,
        did_resolver,
        affinidi_encoding::P256_PUB,
        "P-256",
    )
    .await
}

/// Resolve a DID's ECDSA secp256k1 verification (signing) public key as SEC1
/// bytes (JWS `alg: ES256K`).
async fn resolve_did_secp256k1_verification(
    did: &str,
    prefer_kid: Option<&str>,
    did_resolver: &DIDCacheClient,
) -> Option<Vec<u8>> {
    resolve_did_ecdsa_verification(
        did,
        prefer_kid,
        did_resolver,
        affinidi_encoding::SECP256K1_PUB,
        "secp256k1",
    )
    .await
}

/// Resolve the sender's key-agreement public key named by `skid` (a full DID
/// URL with `#fragment`). Only a key listed in the sender's `keyAgreement` is
/// accepted, and there is no fallback to another key: the key returned is the
/// one `skid` names, or none.
async fn resolve_did_key_agreement_by_skid(
    skid: &str,
    did_resolver: &DIDCacheClient,
) -> Option<PublicKeyAgreement> {
    let (did, fragment) = skid.split_once('#')?;
    if did.is_empty() || fragment.is_empty() {
        return None;
    }
    let doc = did_resolver.resolve(did).await.ok()?;
    resolve_public_key(&doc.doc, skid)
}

/// The public key of the `keyAgreement` entry `kid` names, embedded or by
/// reference, absolute or as a `#fragment` relative to the document.
fn resolve_public_key(
    doc: &affinidi_did_common::Document,
    kid: &str,
) -> Option<PublicKeyAgreement> {
    let relative = kid.find('#').map(|pos| &kid[pos..]);
    let names_kid = |id: &str| id == kid || Some(id) == relative;
    let vm = doc.key_agreement.iter().find_map(|ka| match ka {
        VerificationRelationship::VerificationMethod(vm) if names_kid(vm.id.as_str()) => {
            Some(vm.as_ref())
        }
        VerificationRelationship::Reference(id) if names_kid(id) => doc
            .get_verification_method(kid)
            .or_else(|| relative.and_then(|relative| doc.get_verification_method(relative))),
        _ => None,
    })?;
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
            extract_jws_signer_kid_with_provenance(&jws),
            Some(("did:example:alice#protected".to_string(), true)),
            "integrity-protected kid must win over the unprotected one, and be \
             reported as protected"
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
            extract_jws_signer_kid_with_provenance(&jws),
            Some(("did:example:alice#unprotected".to_string(), false)),
            "the unprotected fallback must be reported as NOT integrity-protected, \
             so callers can refuse to resolve it"
        );
    }

    /// SSRF guard. The per-signature unprotected header is outside the signing
    /// input, so any intermediary can rewrite the signer kid in transit without
    /// invalidating the signature. Resolving a signer DID is an outbound
    /// `did:web` fetch and happens *before* verification — and this path is
    /// reachable pre-authentication — so an unprotected kid may only be resolved
    /// when it names the same DID as the signed payload's `from`.
    #[test]
    fn unprotected_signer_kid_is_only_resolvable_when_it_matches_from() {
        // Payload is signed over, so `from` cannot be rewritten in transit.
        let payload = BASE64_URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&json!({"from": "did:example:alice", "type": "x"})).unwrap(),
        );
        let jws = json!({
            "payload": payload,
            "signatures": [{
                "protected": protected_b64(&json!({"alg": "EdDSA"})),
                "header": {"kid": "did:web:attacker.example.com#key-1"},
                "signature": "AA"
            }]
        });

        assert!(
            !signer_kid_is_resolvable(&jws, "did:web:attacker.example.com#key-1", false),
            "a rewritten unprotected kid must not be resolvable — that is the SSRF"
        );
        assert!(
            signer_kid_is_resolvable(&jws, "did:example:alice#key-1", false),
            "an unprotected kid matching the signed `from` stays resolvable (interop)"
        );
        assert!(
            signer_kid_is_resolvable(&jws, "did:web:attacker.example.com#key-1", true),
            "a protected kid is inside the signing input and is always resolvable"
        );
    }

    /// A payload with no readable `from` gives nothing to bind an unprotected
    /// kid against, so it must be refused rather than resolved optimistically.
    #[test]
    fn unprotected_signer_kid_refused_when_payload_has_no_from() {
        let payload =
            BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!({"type": "x"})).unwrap());
        let jws = json!({
            "payload": payload,
            "signatures": [{
                "protected": protected_b64(&json!({"alg": "EdDSA"})),
                "header": {"kid": "did:web:attacker.example.com#key-1"},
                "signature": "AA"
            }]
        });
        assert!(!signer_kid_is_resolvable(
            &jws,
            "did:web:attacker.example.com#key-1",
            false
        ));
        // A non-JSON / undecodable payload likewise yields no `from`.
        let opaque = json!({
            "payload": "!!not-base64!!",
            "signatures": [{
                "protected": protected_b64(&json!({"alg": "EdDSA"})),
                "header": {"kid": "did:web:attacker.example.com#key-1"},
                "signature": "AA"
            }]
        });
        assert!(!signer_kid_is_resolvable(
            &opaque,
            "did:web:attacker.example.com#key-1",
            false
        ));
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

    fn jwe_header(alg: &str, skid: Option<&str>, apu: Option<&str>) -> serde_json::Value {
        let mut header = json!({
            "alg": alg,
            "enc": "A256CBC-HS512",
            "apv": "YXB2",
            "epk": {"kty": "OKP", "crv": "X25519", "x": "AA"},
        });
        if let Some(skid) = skid {
            header["skid"] = json!(skid);
        }
        if let Some(apu) = apu {
            header["apu"] = json!(BASE64_URL_SAFE_NO_PAD.encode(apu));
        }
        json!({"protected": protected_b64(&header), "ciphertext": "x", "recipients": []})
    }

    #[test]
    fn inner_jwe_sender_did_from_bound_skid() {
        let kid = "did:example:bob#key-x25519";
        let jwe = jwe_header("ECDH-1PU+A256KW", Some(kid), Some(kid));
        assert_eq!(
            inner_jwe_sender_did(&jwe).unwrap().as_deref(),
            Some("did:example:bob")
        );
    }

    #[test]
    fn inner_jwe_without_skid_is_rejected() {
        let jwe = jwe_header("ECDH-1PU+A256KW", None, Some("did:example:carol#key-1"));
        assert!(inner_jwe_sender_did(&jwe).is_err());
    }

    #[test]
    fn inner_jwe_without_apu_is_rejected() {
        let jwe = jwe_header("ECDH-1PU+A256KW", Some("did:example:carol#key-1"), None);
        assert!(inner_jwe_sender_did(&jwe).is_err());
    }

    #[test]
    fn inner_jwe_with_skid_and_apu_naming_different_senders_is_rejected() {
        let jwe = jwe_header(
            "ECDH-1PU+A256KW",
            Some("did:example:mallory#key-1"),
            Some("did:example:alice#key-1"),
        );
        assert!(inner_jwe_sender_did(&jwe).is_err());
    }

    #[test]
    fn inner_jwe_sender_did_none_for_anoncrypt() {
        let jwe = jwe_header("ECDH-ES+A256KW", None, None);
        assert_eq!(inner_jwe_sender_did(&jwe).unwrap(), None);
    }

    #[tokio::test]
    async fn envelope_with_skid_and_apu_naming_different_senders_is_rejected() {
        let jwe = jwe_header(
            "ECDH-1PU+A256KW",
            Some("did:example:mallory#key-1"),
            Some("did:example:alice#key-1"),
        );
        let resolver = example_resolver(&[]).await;
        assert!(
            MetaEnvelope::new(&jwe.to_string(), &resolver)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn envelope_reports_the_bound_skid_as_sender() {
        let kid = "did:example:alice#key-1";
        let jwe = jwe_header("ECDH-1PU+A256KW", Some(kid), Some(kid));
        let resolver = example_resolver(&[]).await;
        let envelope = MetaEnvelope::new(&jwe.to_string(), &resolver)
            .await
            .unwrap();
        assert_eq!(envelope.from_did.as_deref(), Some("did:example:alice"));
        assert!(envelope.metadata.authenticated);
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

    // ---------------------------------------------------------------------
    // Regression: `unpack` must resolve the sender's key-agreement key named
    // by the JWE `skid`, not the sender's *first* advertised key. A sender
    // that lists secp256k1 before P-256 and authcrypts on the shared P-256
    // curve previously failed the mediator's decrypt with
    //   "curve mismatch between private and public keys"
    // (ProblemReport `e.p.message.unpack`) because the mediator paired its
    // P-256 secret with the sender's *first* (secp256k1) public key.
    // ---------------------------------------------------------------------
    #[tokio::test]
    async fn unpack_authcrypt_resolves_sender_key_by_skid_not_first() {
        // Mediator offers only P-256 key agreement.
        let mediator = "did:example:medskid";
        let med_p_kid = format!("{mediator}#key-p256");
        let med_p = Secret::generate_p256(Some(&med_p_kid), None).unwrap();

        // Sender advertises secp256k1 FIRST, then P-256 (the shared curve).
        let sender = "did:example:sndskid";
        let snd_k_kid = format!("{sender}#key-secp256k1");
        let snd_p_kid = format!("{sender}#key-p256");
        let snd_k = Secret::generate_secp256k1(Some(&snd_k_kid), None).unwrap();
        let snd_p = Secret::generate_p256(Some(&snd_p_kid), None).unwrap();

        let mediator_doc = json!({
            "id": mediator,
            "verificationMethod": [ka_vm(&med_p_kid, mediator, &med_p)],
            "keyAgreement": [med_p_kid],
        });
        let sender_doc = json!({
            "id": sender,
            "verificationMethod": [
                ka_vm(&snd_k_kid, sender, &snd_k), // secp256k1 first
                ka_vm(&snd_p_kid, sender, &snd_p),
            ],
            "keyAgreement": [snd_k_kid.clone(), snd_p_kid.clone()],
        });

        let resolver = example_resolver(&[mediator_doc, sender_doc]).await;

        // Sender packs authcrypt to the mediator; negotiation picks the shared
        // P-256 curve, so `skid` is the sender's P-256 key (the SECOND one).
        let sender_secrets = SimpleSecretsResolver::new(&[snd_k, snd_p]).await;
        let msg = status_message(sender, mediator, "skid-multicurve");
        let (packed, pack_meta) =
            pack_encrypted(&msg, mediator, Some(sender), &resolver, &sender_secrets)
                .await
                .expect("sender packs authcrypt on the shared P-256 curve");
        assert_eq!(
            pack_meta.from_kid.as_deref(),
            Some(snd_p_kid.as_str()),
            "authcrypt skid must be the sender's P-256 key, not the first secp256k1 key"
        );
        assert_eq!(jwe_epk_crv(&packed).as_deref(), Some("P-256"));

        // Mediator unpacks: it must resolve the sender's P-256 key via skid.
        let mediator_secrets = SimpleSecretsResolver::new(&[med_p]).await;
        let envelope = MetaEnvelope::new(&packed, &resolver)
            .await
            .expect("parse the JWE envelope");
        let (out, unpack_meta) = envelope
            .unpack(&resolver, &mediator_secrets)
            .await
            .expect("mediator must unpack authcrypt from a secp256k1-first sender via skid");

        assert!(unpack_meta.authenticated, "authcrypt must be authenticated");
        assert_eq!(out.from.as_deref(), Some(sender));
    }

    #[test]
    fn describe_layers_renders_the_stack_outermost_first() {
        assert_eq!(describe_layers(&[]), "plaintext");
        assert_eq!(
            describe_layers(&[CryptoLayer::Encrypted(EncLayerKind::Authcrypt)]),
            "authcrypt(plaintext)"
        );
        assert_eq!(
            describe_layers(&[
                CryptoLayer::Encrypted(EncLayerKind::Anoncrypt),
                CryptoLayer::Encrypted(EncLayerKind::Authcrypt),
                CryptoLayer::Sign,
            ]),
            "anoncrypt(authcrypt(sign(plaintext)))",
            "the warning must show the real shape, not a debug dump"
        );
    }

    /// The stacks the mediator can actually build, checked against the taxonomy
    /// so the warning fires on exactly the wrong ones. `authcrypt(authcrypt(..))`
    /// and `authcrypt(anoncrypt(..))` are undefined; the rest are legitimate and
    /// must stay silent.
    #[test]
    fn classification_flags_only_non_conformant_stacks() {
        use CryptoLayer::{Encrypted, Sign};
        use EncLayerKind::{Anoncrypt, Authcrypt};

        for (stack, conformant) in [
            (vec![Encrypted(Authcrypt)], true),
            (vec![Encrypted(Anoncrypt)], true),
            (vec![Encrypted(Authcrypt), Sign], true),
            (vec![Encrypted(Anoncrypt), Sign], true),
            (vec![Encrypted(Anoncrypt), Encrypted(Authcrypt)], true),
            // Undefined combinations the mediator can nonetheless peel.
            (vec![Encrypted(Authcrypt), Encrypted(Authcrypt)], false),
            (vec![Encrypted(Authcrypt), Encrypted(Anoncrypt)], false),
            (vec![Encrypted(Anoncrypt), Encrypted(Anoncrypt)], false),
            (
                vec![Encrypted(Anoncrypt), Encrypted(Authcrypt), Sign],
                false,
            ),
        ] {
            assert_eq!(
                MessageWrappingType::classify(&stack).is_some(),
                conformant,
                "{} classified wrongly",
                describe_layers(&stack)
            );
        }
    }

    /// End-to-end: `authcrypt(authcrypt(plaintext))` is outside the taxonomy, so
    /// it is *reported*, but it must still **unpack successfully** — this change
    /// is observability only. The mediator relays for third-party senders whose
    /// layering it does not control, so rejecting here would drop traffic that
    /// works today.
    #[tokio::test]
    async fn non_conformant_double_authcrypt_is_reported_but_still_accepted() {
        use affinidi_messaging_didcomm::jwe::encrypt::authcrypt as authcrypt_bytes;

        let mediator = "did:example:medwrap";
        let med_kid = format!("{mediator}#key-x25519");
        let med = Secret::generate_x25519(Some(&med_kid), None).unwrap();

        let sender = "did:example:sndwrap";
        let snd_kid = format!("{sender}#key-x25519");
        let snd = Secret::generate_x25519(Some(&snd_kid), None).unwrap();

        let resolver = example_resolver(&[
            json!({
                "id": mediator,
                "verificationMethod": [ka_vm(&med_kid, mediator, &med)],
                "keyAgreement": [med_kid.clone()],
            }),
            json!({
                "id": sender,
                "verificationMethod": [ka_vm(&snd_kid, sender, &snd)],
                "keyAgreement": [snd_kid.clone()],
            }),
        ])
        .await;

        let sender_secrets = SimpleSecretsResolver::new(std::slice::from_ref(&snd)).await;
        let msg = status_message(sender, mediator, "double-authcrypt");

        // Inner authcrypt, then authcrypt the resulting JWE again — a repeated
        // encryption kind, which the taxonomy does not define.
        let (inner, _) = pack_encrypted(&msg, mediator, Some(sender), &resolver, &sender_secrets)
            .await
            .expect("inner authcrypt");

        let snd_priv = PrivateKeyAgreement::from_raw_bytes(
            snd.get_key_type().key_agreement_curve().unwrap(),
            snd.get_private_bytes(),
        )
        .unwrap();
        let med_pub = resolve_did_key_agreement_by_skid(&med_kid, &resolver)
            .await
            .expect("mediator key agreement key");
        let outer = authcrypt_bytes(
            inner.as_bytes(),
            &snd_kid,
            &snd_priv,
            &[(&med_kid, &med_pub)],
        )
        .expect("outer authcrypt over the inner JWE");

        let mediator_secrets = SimpleSecretsResolver::new(&[med]).await;
        let envelope = MetaEnvelope::new(&outer, &resolver)
            .await
            .expect("parse the outer JWE");
        let (out, meta) = envelope
            .unpack(&resolver, &mediator_secrets)
            .await
            .expect("a non-conformant envelope must still unpack — reporting only");

        assert_eq!(out.from.as_deref(), Some(sender));
        assert!(meta.authenticated, "both layers were authcrypt");
    }

    /// An authcrypt JWE whose `skid` and `apu` are written independently, with
    /// the key derivation run over `apu` as the header claims.
    fn authcrypt_with_party_info(
        plaintext: &[u8],
        skid: &str,
        apu: &str,
        sender_private: &PrivateKeyAgreement,
        recipient_kid: &str,
        recipient_public: &PublicKeyAgreement,
    ) -> String {
        use affinidi_crypto::jose::{
            aes_kw, content_encryption, ecdh, key_agreement::EphemeralKeyPair,
        };

        let ephemeral = EphemeralKeyPair::generate(recipient_public.curve());
        let apv = b"apv";
        let protected = protected_b64(&json!({
            "typ": "application/didcomm-encrypted+json",
            "alg": "ECDH-1PU+A256KW",
            "enc": "A256CBC-HS512",
            "skid": skid,
            "apu": BASE64_URL_SAFE_NO_PAD.encode(apu),
            "apv": BASE64_URL_SAFE_NO_PAD.encode(apv),
            "epk": ephemeral.public.to_jwk(),
        }));
        let cek = content_encryption::generate_cek();
        let iv = content_encryption::generate_iv();
        let (ciphertext, tag) =
            content_encryption::encrypt(plaintext, &cek, &iv, protected.as_bytes()).unwrap();
        let kek = ecdh::derive_sender_key_1pu(
            &ephemeral,
            sender_private,
            recipient_public,
            apu.as_bytes(),
            apv,
            &tag,
        )
        .unwrap();
        json!({
            "protected": protected,
            "recipients": [{
                "header": { "kid": recipient_kid },
                "encrypted_key": BASE64_URL_SAFE_NO_PAD.encode(aes_kw::wrap(&kek, &cek).unwrap()),
            }],
            "iv": BASE64_URL_SAFE_NO_PAD.encode(iv),
            "ciphertext": BASE64_URL_SAFE_NO_PAD.encode(ciphertext),
            "tag": BASE64_URL_SAFE_NO_PAD.encode(tag),
        })
        .to_string()
    }

    /// Mallory authcrypts with her own key but writes Alice into `apu` and
    /// `from`. Refused both as the outer envelope and nested inside an
    /// anoncrypt layer; Alice is never reported as the sender.
    #[tokio::test]
    async fn authcrypt_with_apu_naming_another_did_is_rejected() {
        use affinidi_messaging_didcomm::jwe::encrypt::anoncrypt;

        let mediator = "did:example:medforge";
        let med_kid = format!("{mediator}#key-x25519");
        let med = Secret::generate_x25519(Some(&med_kid), None).unwrap();
        let mallory = "did:example:mallory";
        let mal_kid = format!("{mallory}#key-x25519");
        let mal = Secret::generate_x25519(Some(&mal_kid), None).unwrap();
        let alice = "did:example:alice";
        let alice_kid = format!("{alice}#key-x25519");
        let ali = Secret::generate_x25519(Some(&alice_kid), None).unwrap();

        let resolver = example_resolver(&[
            json!({
                "id": mediator,
                "verificationMethod": [ka_vm(&med_kid, mediator, &med)],
                "keyAgreement": [med_kid.clone()],
            }),
            json!({
                "id": mallory,
                "verificationMethod": [ka_vm(&mal_kid, mallory, &mal)],
                "keyAgreement": [mal_kid.clone()],
            }),
            json!({
                "id": alice,
                "verificationMethod": [ka_vm(&alice_kid, alice, &ali)],
                "keyAgreement": [alice_kid.clone()],
            }),
        ])
        .await;
        let med_pub = resolve_did_key_agreement_by_skid(&med_kid, &resolver)
            .await
            .expect("mediator key agreement key");
        let mal_priv =
            PrivateKeyAgreement::from_raw_bytes(Curve::X25519, mal.get_private_bytes()).unwrap();
        let mediator_secrets = SimpleSecretsResolver::new(&[med]).await;

        let msg = serde_json::to_string(&status_message(alice, mediator, "forged")).unwrap();
        let forged = authcrypt_with_party_info(
            msg.as_bytes(),
            &mal_kid,
            &alice_kid,
            &mal_priv,
            &med_kid,
            &med_pub,
        );

        assert!(MetaEnvelope::new(&forged, &resolver).await.is_err());

        let wrapped = anoncrypt(forged.as_bytes(), &[(&med_kid, &med_pub)]).unwrap();
        let envelope = MetaEnvelope::new(&wrapped, &resolver).await.unwrap();
        let err = envelope
            .unpack(&resolver, &mediator_secrets)
            .await
            .unwrap_err();
        assert!(err.contains("apu"), "unexpected error: {err}");
    }

    // ---------------------------------------------------------------------
    // ES256K inner-JWS verification: `verify_inner_jws` must resolve the
    // signer's secp256k1 key from the DID document — both `publicKeyMultibase`
    // (Multikey, compressed SEC1) and `publicKeyJwk` (EC/secp256k1) encodings
    // — and actually verify the signature with it.
    // ---------------------------------------------------------------------

    /// Build an ES256K JWS (General JSON Serialization) over `payload`,
    /// signed with `sk`, with `kid` in the protected header.
    fn build_es256k_jws(payload: &[u8], kid: &str, sk: &k256::ecdsa::SigningKey) -> String {
        use k256::ecdsa::signature::Signer as _;
        let protected = protected_b64(&json!({
            "typ": "application/didcomm-signed+json",
            "alg": "ES256K",
            "kid": kid,
        }));
        let payload_b64 = BASE64_URL_SAFE_NO_PAD.encode(payload);
        let signing_input = format!("{protected}.{payload_b64}");
        let sig: k256::ecdsa::Signature = sk.sign(signing_input.as_bytes());
        let sig_bytes: [u8; 64] = sig.to_bytes().into();
        json!({
            "payload": payload_b64,
            "signatures": [{
                "protected": protected,
                "signature": BASE64_URL_SAFE_NO_PAD.encode(sig_bytes),
            }]
        })
        .to_string()
    }

    #[tokio::test]
    async fn verify_inner_jws_es256k_from_multikey() {
        let signer = "did:example:k256multikey";
        let kid = format!("{signer}#key-1");
        let sk = k256::ecdsa::SigningKey::from_slice(&[0x42u8; 32]).unwrap();
        // Advertise the same key as a Multikey (compressed SEC1) authentication VM.
        let secret = Secret::generate_secp256k1(Some(&kid), Some(&[0x42u8; 32])).unwrap();
        let doc = json!({
            "id": signer,
            "verificationMethod": [{
                "id": &kid,
                "type": "Multikey",
                "controller": signer,
                "publicKeyMultibase": secret.get_public_keymultibase().unwrap(),
            }],
            "authentication": [&kid],
        });
        let resolver = example_resolver(&[doc]).await;

        let payload = br#"{"type":"https://didcomm.org/test/1.0/msg"}"#;
        let jws = build_es256k_jws(payload, &kid, &sk);

        let verified = verify_inner_jws(&jws, "ES256K", signer, &kid, &resolver)
            .await
            .expect("ES256K signer key must resolve from publicKeyMultibase");
        assert_eq!(verified.payload, payload);
        assert_eq!(verified.signer_kid.as_deref(), Some(kid.as_str()));
    }

    #[tokio::test]
    async fn verify_inner_jws_es256k_from_jwk() {
        let signer = "did:example:k256jwk";
        let kid = format!("{signer}#key-1");
        let sk = k256::ecdsa::SigningKey::from_slice(&[0x43u8; 32]).unwrap();
        let point = sk.verifying_key().to_sec1_point(false);
        let doc = json!({
            "id": signer,
            "verificationMethod": [{
                "id": &kid,
                "type": "JsonWebKey2020",
                "controller": signer,
                "publicKeyJwk": {
                    "kty": "EC",
                    "crv": "secp256k1",
                    "x": BASE64_URL_SAFE_NO_PAD.encode(&point.as_bytes()[1..33]),
                    "y": BASE64_URL_SAFE_NO_PAD.encode(&point.as_bytes()[33..65]),
                },
            }],
            "authentication": [&kid],
        });
        let resolver = example_resolver(&[doc]).await;

        let payload = br#"{"type":"https://didcomm.org/test/1.0/msg"}"#;
        let jws = build_es256k_jws(payload, &kid, &sk);

        let verified = verify_inner_jws(&jws, "ES256K", signer, &kid, &resolver)
            .await
            .expect("ES256K signer key must resolve from publicKeyJwk");
        assert_eq!(verified.payload, payload);
    }

    /// A well-formed ES256K JWS signed by a key the DID document does NOT
    /// advertise must fail — the resolved (advertised) key won't verify it.
    #[tokio::test]
    async fn verify_inner_jws_es256k_wrong_key_fails() {
        let signer = "did:example:k256wrong";
        let kid = format!("{signer}#key-1");
        let advertised = Secret::generate_secp256k1(Some(&kid), Some(&[0x44u8; 32])).unwrap();
        let doc = json!({
            "id": signer,
            "verificationMethod": [{
                "id": &kid,
                "type": "Multikey",
                "controller": signer,
                "publicKeyMultibase": advertised.get_public_keymultibase().unwrap(),
            }],
            "authentication": [&kid],
        });
        let resolver = example_resolver(&[doc]).await;

        // Sign with a DIFFERENT key than the document advertises.
        let rogue = k256::ecdsa::SigningKey::from_slice(&[0x45u8; 32]).unwrap();
        let jws = build_es256k_jws(b"{}", &kid, &rogue);

        assert!(
            verify_inner_jws(&jws, "ES256K", signer, &kid, &resolver)
                .await
                .is_err(),
            "signature by an unadvertised key must not verify"
        );
    }
}
