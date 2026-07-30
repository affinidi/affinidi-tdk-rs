use crate::{ATM, SharedState, errors::ATMError, messages::compat::UnpackMetadata};
use affinidi_messaging_didcomm::message::Message;
use affinidi_secrets_resolver::SecretsResolver;
use base64::{Engine, prelude::BASE64_URL_SAFE};
use tracing::{Instrument, Level, debug, span, warn};

use crate::config::UnpackPolicy;
use crate::messages::wrapping::{CryptoLayer, EncLayerKind, MessageWrappingType};

impl ATM {
    pub async fn unpack(&self, message: &str) -> Result<(Message, UnpackMetadata), ATMError> {
        let _span = span!(Level::DEBUG, "unpack",);

        async move { self.inner.unpack(message).await }
            .instrument(_span)
            .await
    }

    /// Tries to process a mesage that contains a forwarded message (raw envelope).
    pub async fn unpack_forward(
        &self,
        message: &Message,
    ) -> Result<(Message, UnpackMetadata), ATMError> {
        let _span = span!(Level::DEBUG, "unpack_forward",);

        async move { self.inner.unpack_forward(message).await }
            .instrument(_span)
            .await
    }
}

/// Maximum number of forward message layers that will be unwrapped.
/// Prevents denial-of-service via deeply nested forward envelopes.
const MAX_FORWARD_DEPTH: usize = 10;

/// Maximum number of cryptographic envelope layers (JWE/JWS) a single message
/// may nest. Every DIDComm-defined wrapping reaches at most **two** crypto
/// layers — `anoncrypt(authcrypt(plaintext))`, `authcrypt(sign(plaintext))`,
/// or `anoncrypt(sign(plaintext))`. The spec forbids deeper nesting (e.g.
/// `anoncrypt(authcrypt(sign(plaintext)))`), so enforcing the cap *before*
/// removing a third layer both rejects non-conformant stacks and bounds
/// decrypt/verify work against a nested-envelope DoS.
const MAX_CRYPTO_LAYERS: usize = 2;

/// Default signature cap (`5`) for [`crate::config::UnpackPolicy::default`] —
/// what an application `unpack` (and the message-pickup drain, which shares the
/// configured policy) gets out of the box. Bounds the signature *count* before
/// any signer DID is resolved, guarding against a resolution-amplification DoS.
/// This is a **default, not an absolute ceiling**: applications may raise
/// `UnpackPolicy::max_signatures` to any value.
pub(crate) const DEFAULT_MAX_SIGNATURES: usize = 5;

/// Default recipient cap (`100`) for a single JWE layer, used by
/// [`crate::config::UnpackPolicy::default`]. Bounds the recipient *count*
/// before the recipient-matching loop, guarding against a parse/allocation DoS.
/// This is a **default, not an absolute ceiling**: applications may raise
/// `UnpackPolicy::max_recipients` to any value. Mirrors the mediator's
/// `to_recipients` default.
pub(crate) const DEFAULT_MAX_RECIPIENTS: usize = 100;

/// One cryptographic layer removed while unwrapping a message, recorded
/// outermost-first so the stack can be classified into a
/// [`MessageWrappingType`] and checked for addressing consistency.
enum EnvLayer {
    /// An encryption layer (JWE). `skid` is the authcrypt sender key id
    /// (`None` for anoncrypt).
    Encrypted {
        kind: EncLayerKind,
        skid: Option<String>,
    },
    /// A signature layer (JWS). The verified signer `kid`s are recorded in
    /// [`UnpackMetadata::signers`].
    Signed,
}

impl SharedState {
    pub async fn unpack(&self, message: &str) -> Result<(Message, UnpackMetadata), ATMError> {
        let _span = span!(Level::DEBUG, "unpack",);

        async move { self.unpack_with(message, self.config.unpack_policy()).await }
            .instrument(_span)
            .await
    }

    /// Unpack a message enforcing an explicit [`UnpackPolicy`]. Used internally
    /// so the message-pickup drain can pass the configured policy explicitly;
    /// application code goes through [`Self::unpack`], which applies
    /// `config.unpack_policy`.
    pub(crate) async fn unpack_with(
        &self,
        message: &str,
        policy: &UnpackPolicy,
    ) -> Result<(Message, UnpackMetadata), ATMError> {
        let mut msg_string = message.to_string();
        let mut forward_depth: usize = 0;

        loop {
            // Compute SHA-256 hash of the packed message
            let sha256_hash = sha256::digest(&msg_string);

            // Unwrap every cryptographic layer (JWE/JWS), building the layer
            // stack and metadata.
            let (msg, mut metadata, layers) = self
                .unpack_layers(&msg_string, &sha256_hash, policy)
                .await?;

            if self.config.unpack_forwards && msg.typ == "https://didcomm.org/routing/2.0/forward" {
                forward_depth += 1;
                if forward_depth > MAX_FORWARD_DEPTH {
                    return Err(ATMError::MsgReceiveError(format!(
                        "Forward message nesting depth exceeded maximum of {MAX_FORWARD_DEPTH}"
                    )));
                }
                // Extract the inner message and loop to unpack it
                msg_string = Self::extract_forward_payload(&msg, self.config.clock().unix_secs())?;
                continue;
            }

            // Classify the wrapping, enforce the policy's allow-list, and
            // (optionally) enforce message-layer addressing consistency. This
            // also binds `sign_from` to the verified signer that matches `from`.
            Self::enforce_policy(&msg, &mut metadata, &layers, policy)?;

            return Ok((msg, metadata));
        }
    }

    /// Iteratively remove cryptographic layers (JWE → decrypt, JWS → verify all
    /// signatures) from `input` until a plaintext DIDComm message remains,
    /// returning it with populated [`UnpackMetadata`] and the ordered layer
    /// stack (outermost first).
    async fn unpack_layers(
        &self,
        input: &str,
        sha256_hash: &str,
        policy: &UnpackPolicy,
    ) -> Result<(Message, UnpackMetadata, Vec<EnvLayer>), ATMError> {
        let mut current = input.to_string();
        let mut layers: Vec<EnvLayer> = Vec::new();

        let mut encrypted = false;
        let mut authenticated = false;
        let mut non_repudiation = false;
        let mut encrypted_from_kid: Option<String> = None;
        let mut encrypted_to_kids: Vec<String> = Vec::new();
        let mut signers: Vec<String> = Vec::new();

        loop {
            let value: serde_json::Value = serde_json::from_str(&current).map_err(|e| {
                ATMError::DidcommError("Cannot parse message as JSON".into(), e.to_string())
            })?;

            let is_jwe = value.get("ciphertext").is_some() && value.get("recipients").is_some();
            let is_jws = value.get("payload").is_some() && value.get("signatures").is_some();

            // Reject a third (or deeper) cryptographic layer *before* removing
            // it: no DIDComm-defined wrapping nests more than two crypto layers,
            // so anything deeper is non-conformant — and refusing it here also
            // bounds decrypt/verify work against a nested-envelope DoS.
            if (is_jwe || is_jws) && layers.len() >= MAX_CRYPTO_LAYERS {
                return Err(ATMError::UnexpectedEnvelope(format!(
                    "message nests more than the maximum of {MAX_CRYPTO_LAYERS} \
                     cryptographic layers"
                )));
            }

            if is_jwe {
                // JWE — decrypt one encryption layer.
                let (plaintext, kind, skid, recipient_kid) =
                    self.decrypt_layer(&current, &value, policy).await?;
                encrypted = true;
                if kind == EncLayerKind::Authcrypt {
                    authenticated = true;
                    // Innermost authcrypt is the authoritative sender key; only
                    // set it once (the first authcrypt layer encountered).
                    if encrypted_from_kid.is_none() {
                        encrypted_from_kid = skid.clone();
                    }
                }
                encrypted_to_kids.push(recipient_kid);
                layers.push(EnvLayer::Encrypted { kind, skid });
                current = plaintext;
                continue;
            } else if is_jws {
                // JWS — verify every signature and attribute each signer.
                let (payload, signer_kids) = self.verify_all_signatures(&current, policy).await?;
                non_repudiation = true;
                // Accumulate across layers (outermost first) rather than
                // overwrite — a second JWS layer must not erase the outer
                // signer from metadata. (Such a stack is rejected by the
                // wrapping taxonomy in `enforce_policy`, but the metadata must
                // still be faithful.)
                signers.extend(signer_kids);
                layers.push(EnvLayer::Signed);
                current = payload;
                continue;
            } else if value.get("type").is_some() {
                // Plaintext DIDComm message — the innermost payload.
                let msg = Message::from_json(current.as_bytes()).map_err(|e| {
                    ATMError::DidcommError("Cannot parse plaintext message".into(), e.to_string())
                })?;
                debug!("message unpacked:\n{:#?}", msg);

                let metadata = UnpackMetadata {
                    encrypted,
                    authenticated,
                    non_repudiation,
                    // A message is "anonymous" when encrypted without any
                    // authcrypt layer (anoncrypt-only) and unsigned.
                    anonymous_sender: encrypted && !authenticated && signers.is_empty(),
                    encrypted_from_kid,
                    encrypted_to_kids,
                    signers,
                    sha256_hash: sha256_hash.to_string(),
                    ..Default::default()
                };
                return Ok((msg, metadata, layers));
            } else {
                return Err(ATMError::DidcommError(
                    "Cannot detect message format".into(),
                    "expected JWE, JWS, or plaintext".into(),
                ));
            }
        }
    }

    /// Unpack a JWE (encrypted) message
    /// Decrypt a single JWE encryption layer, returning the decrypted payload
    /// (as a UTF-8 string, which may itself be another envelope), the layer's
    /// authentication kind, the authcrypt sender `skid` (`None` for anoncrypt),
    /// and the recipient `kid` that decrypted it.
    async fn decrypt_layer(
        &self,
        jwe_str: &str,
        value: &serde_json::Value,
        policy: &UnpackPolicy,
    ) -> Result<(String, EncLayerKind, Option<String>, String), ATMError> {
        use affinidi_crypto::jose::key_agreement::PrivateKeyAgreement;
        use affinidi_messaging_didcomm::jwe::decrypt::decrypt;

        // Extract recipient KIDs from the JWE
        let recipients = value["recipients"].as_array().ok_or_else(|| {
            ATMError::DidcommError("Invalid JWE".into(), "no recipients array".into())
        })?;

        // Bound the recipient count before the match loop, mirroring how the
        // signature cap is enforced where signatures are seen: the policy is the
        // single knob (callers may raise it to any value they expect).
        if recipients.len() > policy.max_recipients {
            return Err(ATMError::UnexpectedEnvelope(format!(
                "JWE addresses {} recipients, exceeding the policy maximum of {}",
                recipients.len(),
                policy.max_recipients
            )));
        }

        // Find a local secret matching one of the recipient KIDs
        let mut recipient_kid_str = String::new();
        let mut recipient_private: Option<PrivateKeyAgreement> = None;

        for recipient in recipients {
            if let Some(kid) = recipient["header"]["kid"].as_str()
                && let Some(secret) = self.tdk_common.secrets_resolver().get_secret(kid).await
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

        let recipient_private = recipient_private.ok_or_else(|| {
            ATMError::DidcommError(
                "Couldn't unpack incoming message".into(),
                "no local secret matches any JWE recipient".into(),
            )
        })?;

        // Try to detect sender for authcrypt
        // Check if there is a skid (sender key ID) in the protected header
        let sender_public = self.try_resolve_sender_public(jwe_str).await;

        let decrypted = decrypt(
            jwe_str,
            &recipient_kid_str,
            &recipient_private,
            sender_public.as_ref(),
        )
        .map_err(|e| {
            ATMError::DidcommError("Couldn't unpack incoming message".into(), e.to_string())
        })?;

        let plaintext = String::from_utf8(decrypted.plaintext).map_err(|e| {
            ATMError::DidcommError("Decrypted payload is not valid UTF-8".into(), e.to_string())
        })?;

        let kind = if decrypted.authenticated {
            EncLayerKind::Authcrypt
        } else {
            EncLayerKind::Anoncrypt
        };

        Ok((
            plaintext,
            kind,
            decrypted.sender_kid,
            decrypted.recipient_kid,
        ))
    }

    /// Try to resolve the sender's public key from the JWE protected header's `skid` field
    async fn try_resolve_sender_public(
        &self,
        jwe_str: &str,
    ) -> Option<affinidi_crypto::jose::key_agreement::PublicKeyAgreement> {
        use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};

        // Parse to get the protected header
        let jwe: serde_json::Value = serde_json::from_str(jwe_str).ok()?;
        let protected_b64 = jwe.get("protected")?.as_str()?;
        let protected_bytes = BASE64_URL_SAFE_NO_PAD.decode(protected_b64).ok()?;
        let header: serde_json::Value = serde_json::from_slice(&protected_bytes).ok()?;

        // Check algorithm — only authcrypt (ECDH-1PU) has a sender key
        let alg = header.get("alg")?.as_str()?;
        if !alg.contains("1PU") {
            return None;
        }

        let skid = header.get("skid")?.as_str()?;

        // Extract the DID from the skid (everything before the #fragment)
        let sender_did = if let Some(hash_pos) = skid.find('#') {
            &skid[..hash_pos]
        } else {
            skid
        };

        // Resolve the sender DID document
        let sender_doc = self
            .tdk_common
            .did_resolver()
            .resolve(sender_did)
            .await
            .ok()?;

        use affinidi_did_common::{
            document::DocumentExt, verification_method::VerificationRelationship,
        };

        // Use the full skid (with fragment) to look up the specific key that was
        // used to encrypt. Only fall back to the first key_agreement key when the
        // skid has no fragment (bare DID).
        let sender_kid_owned: String;
        let sender_kid: &str = if skid.contains('#') {
            skid
        } else {
            let kids = sender_doc.doc.find_key_agreement(None);
            sender_kid_owned = kids.first()?.to_string();
            &sender_kid_owned
        };

        let vm = sender_doc
            .doc
            .key_agreement
            .iter()
            .filter_map(|ka| match ka {
                VerificationRelationship::VerificationMethod(vm)
                    if vm.id.as_str() == sender_kid =>
                {
                    Some(vm.as_ref())
                }
                _ => None,
            })
            .next()
            .or_else(|| sender_doc.doc.get_verification_method(sender_kid))?;

        // Single source of truth for verification-material parsing lives
        // in `affinidi-did-common` (`decode_public_key`); map its
        // `(multicodec, bytes)` onto a key-agreement key here.
        use affinidi_crypto::jose::key_agreement::{Curve, PublicKeyAgreement};
        let (codec, key_bytes) = vm.decode_public_key().ok()?;
        let curve = match codec {
            affinidi_encoding::X25519_PUB => Curve::X25519,
            affinidi_encoding::P256_PUB => Curve::P256,
            affinidi_encoding::SECP256K1_PUB => Curve::K256,
            _ => return None,
        };
        PublicKeyAgreement::from_raw_bytes(curve, &key_bytes).ok()
    }

    /// Verify **every** signature on a JWS layer, resolving each signer's key
    /// (Ed25519 / P-256 / secp256k1) from its DID document. Strict: any
    /// signature that lacks a `kid`, whose key cannot be resolved, or whose
    /// signature is invalid, fails the whole unpack. Returns the decoded
    /// payload (which may be a further envelope) and every verified signer
    /// `kid`.
    async fn verify_all_signatures(
        &self,
        jws_str: &str,
        policy: &UnpackPolicy,
    ) -> Result<(String, Vec<String>), ATMError> {
        use affinidi_messaging_didcomm::jws::verify::{parse_jws, verify_parsed_signature};

        let parsed = parse_jws(jws_str)
            .map_err(|e| ATMError::DidcommError("Invalid JWS".into(), e.to_string()))?;

        // Enforce the policy's signature cap *before* resolving any signer key,
        // so a message stuffed with more signatures than the policy allows is
        // rejected without amplifying (possibly networked) DID resolution.
        if parsed.signatures.len() > policy.max_signatures {
            return Err(ATMError::UnexpectedEnvelope(format!(
                "JWS carries {} signatures, exceeding the policy maximum of {}",
                parsed.signatures.len(),
                policy.max_signatures
            )));
        }

        let mut signer_kids = Vec::with_capacity(parsed.signatures.len());
        for sig in &parsed.signatures {
            let kid = sig.kid.clone().ok_or_else(|| {
                ATMError::DidcommError(
                    "Invalid JWS".into(),
                    "a signature is missing its signer kid".into(),
                )
            })?;
            let key = self.resolve_verify_key(&kid).await.ok_or_else(|| {
                ATMError::DidcommError(
                    "Couldn't verify JWS".into(),
                    format!("could not resolve a verification key for '{kid}'"),
                )
            })?;
            verify_parsed_signature(sig, &key).map_err(|e| {
                ATMError::DidcommError(
                    "JWS signature verification failed".into(),
                    format!("signer '{kid}': {e}"),
                )
            })?;
            // Prefer the kid the signature actually carried.
            signer_kids.push(kid);
        }

        let payload = String::from_utf8(parsed.payload).map_err(|e| {
            ATMError::DidcommError("JWS payload is not valid UTF-8".into(), e.to_string())
        })?;

        Ok((payload, signer_kids))
    }

    /// Resolve a signer's public verification key for a `kid` by resolving its
    /// DID document, returning it tagged by curve family so the correct
    /// signature algorithm is used. Looks in the `authentication` relationship
    /// first (where DIDComm signing keys live), then any verification method.
    /// Supports Ed25519 (`EdDSA`), P-256 (`ES256`), and secp256k1 (`ES256K`).
    async fn resolve_verify_key(
        &self,
        kid: &str,
    ) -> Option<affinidi_messaging_didcomm::jws::verify::VerifyKey> {
        use affinidi_did_common::{
            document::DocumentExt, verification_method::VerificationRelationship,
        };
        use affinidi_messaging_didcomm::jws::verify::VerifyKey;

        let did = kid.split('#').next().unwrap_or(kid);
        let doc = self.tdk_common.did_resolver().resolve(did).await.ok()?;

        // Fragment-qualified kid → that exact key; bare DID → first
        // authentication key.
        let lookup_owned: String;
        let lookup_kid: &str = if kid.contains('#') {
            kid
        } else {
            let auth = doc.doc.find_authentication(None);
            lookup_owned = auth.first()?.to_string();
            &lookup_owned
        };

        let vm = doc
            .doc
            .authentication
            .iter()
            .filter_map(|a| match a {
                VerificationRelationship::VerificationMethod(vm)
                    if vm.id.as_str() == lookup_kid =>
                {
                    Some(vm.as_ref())
                }
                _ => None,
            })
            .next()
            .or_else(|| doc.doc.get_verification_method(lookup_kid))?;

        let (codec, bytes) = vm.decode_public_key().ok()?;
        match codec {
            affinidi_encoding::ED25519_PUB => Some(VerifyKey::Ed25519(bytes.try_into().ok()?)),
            affinidi_encoding::P256_PUB => Some(VerifyKey::P256(bytes)),
            affinidi_encoding::SECP256K1_PUB => Some(VerifyKey::Secp256k1(bytes)),
            _ => None,
        }
    }

    /// The base DID of a DID URL (everything before the `#fragment`).
    fn base_did(did_url: &str) -> &str {
        did_url.split_once('#').map(|(d, _)| d).unwrap_or(did_url)
    }

    /// Classify the unwrapped layer stack, enforce the policy's accepted
    /// wrapping types, and (when enabled) enforce message-layer addressing
    /// consistency:
    /// - a signed layer requires a verified signer whose DID equals the inner
    ///   `from` DID (that signer becomes `metadata.sign_from`);
    /// - an authcrypt layer requires its `skid` DID to equal the inner `from`
    ///   DID.
    ///
    /// Together these bind `from` == signer == authcrypt sender across up to
    /// three layers.
    fn enforce_policy(
        msg: &Message,
        metadata: &mut UnpackMetadata,
        layers: &[EnvLayer],
        policy: &UnpackPolicy,
    ) -> Result<(), ATMError> {
        // Rebuild the ordered layer stack (outermost-first), preserving each
        // signature's position relative to the encryption layers — the wrapping
        // taxonomy depends on it (`sign(authcrypt(pt))` is not the same as
        // `authcrypt(sign(pt))`). Also capture the authcrypt sender `skid` for
        // the addressing-consistency check below.
        let mut crypto_layers: Vec<CryptoLayer> = Vec::with_capacity(layers.len());
        let mut authcrypt_skid: Option<String> = None;
        for layer in layers {
            match layer {
                EnvLayer::Encrypted { kind, skid } => {
                    crypto_layers.push(CryptoLayer::Encrypted(*kind));
                    if *kind == EncLayerKind::Authcrypt && authcrypt_skid.is_none() {
                        authcrypt_skid = skid.clone();
                    }
                }
                EnvLayer::Signed => crypto_layers.push(CryptoLayer::Sign),
            }
        }

        let wrapping = MessageWrappingType::classify(&crypto_layers).ok_or_else(|| {
            ATMError::UnexpectedEnvelope(
                "message envelope layering is outside the DIDComm-defined wrapping taxonomy".into(),
            )
        })?;
        metadata.wrapping = wrapping;

        if !policy.accepts(wrapping) {
            return Err(ATMError::UnexpectedEnvelope(format!(
                "envelope wrapping {wrapping:?} is not in the accepted set {:?}",
                policy.expected
            )));
        }

        // (The signature-count cap is enforced earlier, in
        // `verify_all_signatures`, before any signer key is resolved.)

        let from = msg.from.as_deref().map(Self::base_did);

        // Attribute a signer to `sign_from` (best-effort): prefer the signature
        // whose DID matches `from`, else the first signer.
        if wrapping.is_signed() {
            let matching = from.and_then(|f| {
                metadata
                    .signers
                    .iter()
                    .find(|kid| Self::base_did(kid) == f)
                    .cloned()
            });
            metadata.sign_from = matching
                .clone()
                .or_else(|| metadata.signers.first().cloned());

            if policy.validate_addressing_consistency && matching.is_none() {
                return Err(ATMError::AddressingMismatch(format!(
                    "no signature matches the message `from` ({}); signers: {:?}",
                    from.unwrap_or("<none>"),
                    metadata.signers
                )));
            }
        }

        if policy.validate_addressing_consistency {
            // Authcrypt layer → its skid DID must match `from`.
            if let Some(skid) = &authcrypt_skid {
                let from_did = from.ok_or_else(|| {
                    ATMError::AddressingMismatch(
                        "authcrypt message has no `from` to bind the sender to".into(),
                    )
                })?;
                if Self::base_did(skid) != from_did {
                    return Err(ATMError::AddressingMismatch(format!(
                        "authcrypt sender key ({skid}) does not match the message `from` ({from_did})"
                    )));
                }
            }

            // Anoncrypt-only (anonymous, unsigned) → there is no authenticated
            // sender, so a `from` claim cannot be backed. The spec makes such a
            // message anonymous; require `from` to be absent.
            if wrapping == MessageWrappingType::AnoncryptPlaintext
                && let Some(from_did) = from
            {
                return Err(ATMError::AddressingMismatch(format!(
                    "anoncrypt message declares a `from` ({from_did}) but anonymous \
                     encryption provides no authenticated sender to back it"
                )));
            }
        }

        Ok(())
    }

    pub async fn unpack_forward(
        &self,
        message: &Message,
    ) -> Result<(Message, UnpackMetadata), ATMError> {
        let _span = span!(Level::DEBUG, "unpack_forward",);

        async move {
            debug!("Attempting to unpack a forwarded message");
            let inner = Self::extract_forward_payload(message, self.config.clock().unix_secs())?;
            self.unpack(&inner).await
        }
        .instrument(_span)
        .await
    }

    /// Extracts the inner message string from a forward message's attachment.
    /// Checks expiry (against the caller-supplied `now`, sourced from the SDK's
    /// injected clock) and supports JSON and Base64 attachment formats.
    pub(crate) fn extract_forward_payload(message: &Message, now: u64) -> Result<String, ATMError> {
        debug!("Extracting payload from forwarded message");

        // Check expiry time if it exists
        if let Some(expires_time) = message.expires_time
            && expires_time <= now
        {
            return Err(ATMError::MsgReceiveError(String::from(
                "Forwarded Message has expired and cannot be processed",
            )));
        }

        if let Some(attachments) = &message.attachments
            && !attachments.is_empty()
        {
            if attachments.len() > 1 {
                warn!(
                    "There is more than one attachment, only unpacking the first forwarded \
                     attachment. Total attachments ({})",
                    attachments.len()
                );
            }
            if let Some(attachment) = attachments.first() {
                // New AttachmentData is a struct with optional fields
                if let Some(json_value) = &attachment.data.json {
                    serde_json::to_string(json_value).map_err(|e| {
                        ATMError::MsgReceiveError(format!(
                            "Attachment data is in JSON format, but cannot be converted \
                             to string: {e}"
                        ))
                    })
                } else if let Some(base64_value) = &attachment.data.base64 {
                    let bytes = BASE64_URL_SAFE.decode(base64_value).map_err(|e| {
                        ATMError::MsgReceiveError(format!(
                            "Attachment data is in Base64 format, but cannot be decoded: {e}"
                        ))
                    })?;
                    String::from_utf8(bytes).map_err(|e| {
                        ATMError::MsgReceiveError(format!(
                            "Attachment data is in Base64 format and can be decoded, but \
                             the decoded data cannot be converted to a UTF-8 string: {e}"
                        ))
                    })
                } else {
                    Err(ATMError::MsgReceiveError(String::from(
                        "Attachment data is not in a supported format \
                         (only JSON and Base64 are supported)",
                    )))
                }
            } else {
                Err(ATMError::MsgReceiveError(String::from(
                    "Message has attachments, but cannot access the first attachment",
                )))
            }
        } else {
            Err(ATMError::MsgReceiveError(String::from(
                "Trying to unpack a forwarded message, though there are no attachments!",
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ATMConfig;
    use affinidi_messaging_didcomm::message::Attachment;
    use affinidi_tdk_common::TDKSharedState;
    use serde_json::json;
    use std::sync::Arc;

    /// Fixed "current time" for the `extract_forward_payload` expiry tests — the
    /// `now` the SDK would source from its injected clock.
    const NOW_SECS: u64 = 1_000_000_000;

    use affinidi_did_common::{DID, PeerCreateKey, PeerKeyPurpose, PeerKeyType};
    use affinidi_messaging_didcomm::message::Message as DcMessage;
    use affinidi_secrets_resolver::SecretsResolver;
    use affinidi_secrets_resolver::secrets::Secret;

    /// Helper: generate a did:peer:2 with Ed25519 (V) + X25519 (E) keys,
    /// returning (did_string, x25519_secret_with_correct_kid).
    fn generate_peer_did_with_x25519() -> (String, Secret) {
        // Generate an X25519 key pair for key agreement
        let x25519_secret = Secret::generate_x25519(Some("temp"), None).unwrap();
        let x25519_multibase = x25519_secret.get_public_keymultibase().unwrap();

        // Create did:peer:2 with V (Ed25519, auto-generated) + E (X25519, pre-existing)
        let keys = vec![
            PeerCreateKey::new(PeerKeyPurpose::Verification, PeerKeyType::Ed25519),
            PeerCreateKey::from_multibase(PeerKeyPurpose::Encryption, x25519_multibase),
        ];
        let (did, _created_keys) = DID::generate_peer(&keys, None).unwrap();
        let did_string = did.to_string();

        // The E key is the second key in the did:peer, so it gets #key-2
        let correct_kid = format!("{did_string}#key-2");
        let mut secret = x25519_secret;
        secret.id = correct_kid;

        (did_string, secret)
    }

    /// Helper: create an ATM instance with secrets pre-loaded for the given
    /// party, using the **secure default** unpack policy (authenticated
    /// encryption only). Tests
    /// that exercise other wrappings pass an explicit minimal policy via
    /// `create_atm_with_policy`.
    async fn create_atm_with_secrets(secrets: Vec<Secret>) -> ATM {
        use affinidi_tdk_common::config::TDKConfig;
        let config = ATMConfig::builder().build().unwrap();
        let tdk_cfg = TDKConfig::headless().unwrap();
        let tdk = Arc::new(TDKSharedState::new(tdk_cfg).await.unwrap());
        for secret in &secrets {
            tdk.secrets_resolver().insert(secret.clone()).await;
        }
        ATM::new(config, tdk).await.unwrap()
    }

    /// Test: authcrypt pack/unpack round-trip with did:peer:2 (Ed25519 + X25519).
    /// This verifies the basic encrypted messaging flow works end-to-end.
    #[tokio::test]
    async fn authcrypt_roundtrip_did_peer_x25519() {
        let (sender_did, sender_secret) = generate_peer_did_with_x25519();
        let (recipient_did, recipient_secret) = generate_peer_did_with_x25519();

        // Sender ATM: needs sender's private key to encrypt
        let sender_atm = create_atm_with_secrets(vec![sender_secret.clone()]).await;

        // Recipient ATM: needs recipient's private key to decrypt
        let recipient_atm = create_atm_with_secrets(vec![recipient_secret.clone()]).await;

        // Build a DIDComm message
        let msg = DcMessage::build(
            "test-encrypted-1".to_string(),
            "example/v1".to_string(),
            json!({"hello": "encrypted world"}),
        )
        .from(sender_did.clone())
        .to(recipient_did.clone())
        .finalize();

        // Pack with authcrypt (sender → recipient)
        let (packed, pack_meta) = sender_atm
            .pack_encrypted(&msg, &recipient_did, Some(&sender_did), None)
            .await
            .expect("pack_encrypted should succeed");

        assert!(
            pack_meta.from_kid.is_some(),
            "authcrypt should have from_kid"
        );

        // Unpack on recipient side
        let (unpacked, unpack_meta) = recipient_atm
            .unpack(&packed)
            .await
            .expect("unpack should succeed");

        assert_eq!(unpacked.id, "test-encrypted-1");
        assert_eq!(unpacked.typ, "example/v1");
        assert_eq!(unpacked.body, json!({"hello": "encrypted world"}));
        assert!(unpack_meta.encrypted);
        assert!(
            unpack_meta.authenticated,
            "authcrypt should be authenticated"
        );
    }

    /// Test: verifies the skid bug — when the sender has multiple keys (V + E),
    /// unpack must use the specific key from the JWE skid header, not blindly
    /// pick the first key_agreement key from the resolved DID document.
    ///
    /// This test would FAIL before the fix because try_resolve_sender_public()
    /// stripped the #fragment from skid and picked the first key_agreement key,
    /// which could be a different key than the one actually used to encrypt.
    #[tokio::test]
    async fn authcrypt_sender_skid_resolves_correct_key() {
        let (sender_did, sender_secret) = generate_peer_did_with_x25519();
        let (recipient_did, recipient_secret) = generate_peer_did_with_x25519();

        // Verify sender DID has multiple keys (V=key-1, E=key-2)
        let sender_did_parsed: DID = sender_did.parse().unwrap();
        let sender_doc = sender_did_parsed.resolve().unwrap();
        assert!(
            sender_doc.verification_method.len() >= 2,
            "sender should have at least 2 verification methods (V + E)"
        );

        let sender_atm = create_atm_with_secrets(vec![sender_secret.clone()]).await;
        let recipient_atm = create_atm_with_secrets(vec![recipient_secret.clone()]).await;

        let msg = DcMessage::build(
            "test-skid-1".to_string(),
            "example/v1".to_string(),
            json!({"test": "skid resolution"}),
        )
        .from(sender_did.clone())
        .to(recipient_did.clone())
        .finalize();

        let (packed, _) = sender_atm
            .pack_encrypted(&msg, &recipient_did, Some(&sender_did), None)
            .await
            .expect("pack should succeed");

        // Verify the JWE contains the correct skid with #key-2 fragment
        let jwe: serde_json::Value = serde_json::from_str(&packed).unwrap();
        let protected_b64 = jwe["protected"].as_str().unwrap();
        let protected_bytes = base64::prelude::BASE64_URL_SAFE_NO_PAD
            .decode(protected_b64)
            .unwrap();
        let header: serde_json::Value = serde_json::from_slice(&protected_bytes).unwrap();
        let skid = header["skid"].as_str().unwrap();
        assert!(
            skid.contains("#key-2"),
            "skid should reference the X25519 key (#key-2), got: {skid}"
        );

        // This is the critical test: unpack must use skid to find the correct
        // sender public key, not just pick the first key from the DID document
        let (unpacked, meta) = recipient_atm
            .unpack(&packed)
            .await
            .expect("unpack should succeed with correct skid resolution");

        assert_eq!(unpacked.id, "test-skid-1");
        assert!(meta.authenticated, "should be authenticated (authcrypt)");
        assert!(
            meta.encrypted_from_kid.is_some(),
            "should have sender kid from skid"
        );
    }

    /// Helper: generate a did:peer:2 with TWO X25519 encryption keys (E + E),
    /// returning (did_string, first_x25519_secret, second_x25519_secret).
    /// The first E key gets #key-1, the second gets #key-2.
    fn generate_peer_did_with_two_x25519() -> (String, Secret, Secret) {
        let x25519_secret_1 = Secret::generate_x25519(Some("temp1"), None).unwrap();
        let x25519_multibase_1 = x25519_secret_1.get_public_keymultibase().unwrap();

        let x25519_secret_2 = Secret::generate_x25519(Some("temp2"), None).unwrap();
        let x25519_multibase_2 = x25519_secret_2.get_public_keymultibase().unwrap();

        let keys = vec![
            PeerCreateKey::from_multibase(PeerKeyPurpose::Encryption, x25519_multibase_1),
            PeerCreateKey::from_multibase(PeerKeyPurpose::Encryption, x25519_multibase_2),
        ];
        let (did, _) = DID::generate_peer(&keys, None).unwrap();
        let did_string = did.to_string();

        let mut secret_1 = x25519_secret_1;
        secret_1.id = format!("{did_string}#key-1");

        let mut secret_2 = x25519_secret_2;
        secret_2.id = format!("{did_string}#key-2");

        (did_string, secret_1, secret_2)
    }

    /// Test: when a sender DID has multiple encryption keys, the pack uses the
    /// first key (#key-1) but the skid in the JWE header references that key.
    /// If we encrypt using the SECOND key (#key-2) instead, the unpack side
    /// must resolve the correct key from skid, not blindly pick the first.
    ///
    /// This test creates a sender with two encryption keys, packs using the
    /// second key, and verifies unpack resolves the correct sender public key.
    #[tokio::test]
    async fn authcrypt_multi_key_sender_skid_must_match() {
        let (sender_did, _sender_secret_1, sender_secret_2) = generate_peer_did_with_two_x25519();
        let (recipient_did, recipient_secret) = generate_peer_did_with_x25519();

        // Verify sender has 2 key_agreement keys
        let sender_did_parsed: DID = sender_did.parse().unwrap();
        let sender_doc = sender_did_parsed.resolve().unwrap();
        use affinidi_did_common::DocumentExt;
        let ka_kids = sender_doc.find_key_agreement(None);
        assert_eq!(ka_kids.len(), 2, "sender should have 2 key agreement keys");

        let recipient_atm = create_atm_with_secrets(vec![recipient_secret.clone()]).await;

        // We can't use pack_encrypted directly because it picks the first key
        // agreement key. Instead, build the JWE manually using the second key.
        use affinidi_crypto::jose::key_agreement::{
            Curve, PrivateKeyAgreement, PublicKeyAgreement,
        };
        use affinidi_messaging_didcomm::message::pack;

        let msg = DcMessage::build(
            "test-multi-key-1".to_string(),
            "example/v1".to_string(),
            json!({"test": "multi key skid"}),
        )
        .from(sender_did.clone())
        .to(recipient_did.clone())
        .finalize();

        // Resolve recipient's public key
        let recipient_did_parsed: DID = recipient_did.parse().unwrap();
        let recipient_doc = recipient_did_parsed.resolve().unwrap();
        let recipient_ka_kids = recipient_doc.find_key_agreement(None);
        let recipient_kid = recipient_ka_kids.first().unwrap();
        let recipient_vm = recipient_doc
            .get_verification_method(recipient_kid)
            .unwrap();
        let recipient_multibase = recipient_vm
            .property_set
            .get("publicKeyMultibase")
            .unwrap()
            .as_str()
            .unwrap();
        let (codec, key_bytes) =
            affinidi_encoding::decode_multikey_with_codec(recipient_multibase).unwrap();
        assert_eq!(codec, affinidi_encoding::X25519_PUB);
        let recipient_pub = PublicKeyAgreement::from_raw_bytes(Curve::X25519, &key_bytes).unwrap();

        // Use sender's SECOND key (#key-2) to pack
        let sender_kid_2 = &format!("{sender_did}#key-2");
        let sender_private_2 =
            PrivateKeyAgreement::from_raw_bytes(Curve::X25519, sender_secret_2.get_private_bytes())
                .unwrap();

        let packed = pack::pack_encrypted_authcrypt(
            &msg,
            sender_kid_2,
            &sender_private_2,
            &[(recipient_kid, &recipient_pub)],
        )
        .expect("manual authcrypt pack should succeed");

        // Verify skid references #key-2
        let jwe: serde_json::Value = serde_json::from_str(&packed).unwrap();
        let protected_b64 = jwe["protected"].as_str().unwrap();
        let protected_bytes = base64::prelude::BASE64_URL_SAFE_NO_PAD
            .decode(protected_b64)
            .unwrap();
        let header: serde_json::Value = serde_json::from_slice(&protected_bytes).unwrap();
        let skid = header["skid"].as_str().unwrap();
        assert!(
            skid.contains("#key-2"),
            "skid should reference #key-2, got: {skid}"
        );

        // NOW: unpack on recipient side. This is where the bug manifests.
        // If try_resolve_sender_public strips the fragment and picks first key,
        // it would use #key-1's public key (DIFFERENT from #key-2 that was used
        // to encrypt), causing a key mismatch in ECDH-1PU derivation.
        let result = recipient_atm.unpack(&packed).await;

        match &result {
            Ok((unpacked, meta)) => {
                assert_eq!(unpacked.id, "test-multi-key-1");
                assert!(meta.authenticated, "should be authenticated (authcrypt)");
            }
            Err(e) => {
                panic!(
                    "BUG CONFIRMED: unpack failed because try_resolve_sender_public \
                     picks the wrong key when sender has multiple encryption keys. \
                     Error: {e}"
                );
            }
        }
    }

    /// Test: anoncrypt pack/unpack round-trip (no sender key).
    #[tokio::test]
    async fn anoncrypt_roundtrip_did_peer_x25519() {
        let (recipient_did, recipient_secret) = generate_peer_did_with_x25519();

        let sender_atm = create_atm_with_secrets(vec![]).await;
        let recipient_atm = create_atm_with_policy(
            vec![recipient_secret.clone()],
            UnpackPolicy {
                expected: vec![MessageWrappingType::AnoncryptPlaintext],
                validate_addressing_consistency: true,
                max_signatures: 1,
                max_recipients: 2,
            },
        )
        .await;

        let msg = DcMessage::build(
            "test-anon-1".to_string(),
            "example/v1".to_string(),
            json!({"hello": "anonymous"}),
        )
        .to(recipient_did.clone())
        .finalize();

        // Pack with anoncrypt (no sender)
        let (packed, pack_meta) = sender_atm
            .pack_encrypted(&msg, &recipient_did, None, None)
            .await
            .expect("anoncrypt pack should succeed");

        assert!(
            pack_meta.from_kid.is_none(),
            "anoncrypt should have no from_kid"
        );

        let (unpacked, meta) = recipient_atm
            .unpack(&packed)
            .await
            .expect("anoncrypt unpack should succeed");

        assert_eq!(unpacked.id, "test-anon-1");
        assert!(meta.encrypted);
        assert!(!meta.authenticated, "anoncrypt should not be authenticated");
        assert!(meta.anonymous_sender);
    }

    /// Helper: generate a did:peer:2 with Ed25519 (V) + P-256 (E) keys.
    fn generate_peer_did_with_p256() -> (String, Secret) {
        let p256_secret = Secret::generate_p256(Some("temp"), None).unwrap();
        let p256_multibase = p256_secret.get_public_keymultibase().unwrap();

        let keys = vec![
            PeerCreateKey::new(PeerKeyPurpose::Verification, PeerKeyType::Ed25519),
            PeerCreateKey::from_multibase(PeerKeyPurpose::Encryption, p256_multibase),
        ];
        let (did, _created_keys) = DID::generate_peer(&keys, None).unwrap();
        let did_string = did.to_string();

        let correct_kid = format!("{did_string}#key-2");
        let mut secret = p256_secret;
        secret.id = correct_kid;

        (did_string, secret)
    }

    /// Helper: generate a did:peer:2 with Ed25519 (V) + secp256k1 (E) keys.
    fn generate_peer_did_with_secp256k1() -> (String, Secret) {
        let k256_secret = Secret::generate_secp256k1(Some("temp"), None).unwrap();
        let k256_multibase = k256_secret.get_public_keymultibase().unwrap();

        let keys = vec![
            PeerCreateKey::new(PeerKeyPurpose::Verification, PeerKeyType::Ed25519),
            PeerCreateKey::from_multibase(PeerKeyPurpose::Encryption, k256_multibase),
        ];
        let (did, _created_keys) = DID::generate_peer(&keys, None).unwrap();
        let did_string = did.to_string();

        let correct_kid = format!("{did_string}#key-2");
        let mut secret = k256_secret;
        secret.id = correct_kid;

        (did_string, secret)
    }

    /// Test: authcrypt pack/unpack round-trip with P-256 keys.
    #[tokio::test]
    async fn authcrypt_roundtrip_did_peer_p256() {
        let (sender_did, sender_secret) = generate_peer_did_with_p256();
        let (recipient_did, recipient_secret) = generate_peer_did_with_p256();

        let sender_atm = create_atm_with_secrets(vec![sender_secret.clone()]).await;
        let recipient_atm = create_atm_with_secrets(vec![recipient_secret.clone()]).await;

        let msg = DcMessage::build(
            "test-p256-authcrypt-1".to_string(),
            "example/v1".to_string(),
            json!({"hello": "P-256 encrypted"}),
        )
        .from(sender_did.clone())
        .to(recipient_did.clone())
        .finalize();

        let (packed, pack_meta) = sender_atm
            .pack_encrypted(&msg, &recipient_did, Some(&sender_did), None)
            .await
            .expect("P-256 authcrypt pack should succeed");

        assert!(
            pack_meta.from_kid.is_some(),
            "authcrypt should have from_kid"
        );

        let (unpacked, unpack_meta) = recipient_atm
            .unpack(&packed)
            .await
            .expect("P-256 authcrypt unpack should succeed");

        assert_eq!(unpacked.id, "test-p256-authcrypt-1");
        assert_eq!(unpacked.body, json!({"hello": "P-256 encrypted"}));
        assert!(unpack_meta.encrypted);
        assert!(
            unpack_meta.authenticated,
            "authcrypt should be authenticated"
        );
    }

    /// Test: anoncrypt pack/unpack round-trip with P-256 keys.
    #[tokio::test]
    async fn anoncrypt_roundtrip_did_peer_p256() {
        let (recipient_did, recipient_secret) = generate_peer_did_with_p256();

        let sender_atm = create_atm_with_secrets(vec![]).await;
        let recipient_atm = create_atm_with_policy(
            vec![recipient_secret.clone()],
            UnpackPolicy {
                expected: vec![MessageWrappingType::AnoncryptPlaintext],
                validate_addressing_consistency: true,
                max_signatures: 1,
                max_recipients: 2,
            },
        )
        .await;

        let msg = DcMessage::build(
            "test-p256-anon-1".to_string(),
            "example/v1".to_string(),
            json!({"hello": "P-256 anonymous"}),
        )
        .to(recipient_did.clone())
        .finalize();

        let (packed, _) = sender_atm
            .pack_encrypted(&msg, &recipient_did, None, None)
            .await
            .expect("P-256 anoncrypt pack should succeed");

        let (unpacked, meta) = recipient_atm
            .unpack(&packed)
            .await
            .expect("P-256 anoncrypt unpack should succeed");

        assert_eq!(unpacked.id, "test-p256-anon-1");
        assert!(meta.encrypted);
        assert!(!meta.authenticated);
    }

    /// Test: authcrypt pack/unpack round-trip with secp256k1 keys.
    #[tokio::test]
    async fn authcrypt_roundtrip_did_peer_secp256k1() {
        let (sender_did, sender_secret) = generate_peer_did_with_secp256k1();
        let (recipient_did, recipient_secret) = generate_peer_did_with_secp256k1();

        let sender_atm = create_atm_with_secrets(vec![sender_secret.clone()]).await;
        let recipient_atm = create_atm_with_secrets(vec![recipient_secret.clone()]).await;

        let msg = DcMessage::build(
            "test-k256-authcrypt-1".to_string(),
            "example/v1".to_string(),
            json!({"hello": "secp256k1 encrypted"}),
        )
        .from(sender_did.clone())
        .to(recipient_did.clone())
        .finalize();

        let (packed, pack_meta) = sender_atm
            .pack_encrypted(&msg, &recipient_did, Some(&sender_did), None)
            .await
            .expect("secp256k1 authcrypt pack should succeed");

        assert!(pack_meta.from_kid.is_some());

        let (unpacked, unpack_meta) = recipient_atm
            .unpack(&packed)
            .await
            .expect("secp256k1 authcrypt unpack should succeed");

        assert_eq!(unpacked.id, "test-k256-authcrypt-1");
        assert_eq!(unpacked.body, json!({"hello": "secp256k1 encrypted"}));
        assert!(unpack_meta.encrypted);
        assert!(unpack_meta.authenticated);
    }

    /// Test: anoncrypt pack/unpack round-trip with secp256k1 keys.
    #[tokio::test]
    async fn anoncrypt_roundtrip_did_peer_secp256k1() {
        let (recipient_did, recipient_secret) = generate_peer_did_with_secp256k1();

        let sender_atm = create_atm_with_secrets(vec![]).await;
        let recipient_atm = create_atm_with_policy(
            vec![recipient_secret.clone()],
            UnpackPolicy {
                expected: vec![MessageWrappingType::AnoncryptPlaintext],
                validate_addressing_consistency: true,
                max_signatures: 1,
                max_recipients: 2,
            },
        )
        .await;

        let msg = DcMessage::build(
            "test-k256-anon-1".to_string(),
            "example/v1".to_string(),
            json!({"hello": "secp256k1 anonymous"}),
        )
        .to(recipient_did.clone())
        .finalize();

        let (packed, _) = sender_atm
            .pack_encrypted(&msg, &recipient_did, None, None)
            .await
            .expect("secp256k1 anoncrypt pack should succeed");

        let (unpacked, meta) = recipient_atm
            .unpack(&packed)
            .await
            .expect("secp256k1 anoncrypt unpack should succeed");

        assert_eq!(unpacked.id, "test-k256-anon-1");
        assert!(meta.encrypted);
        assert!(!meta.authenticated);
    }

    /// Generate a did:peer:2 with an Ed25519 signing key (V, #key-1) and
    /// an X25519 key-agreement key (E, #key-2). Returns the DID, the
    /// Ed25519 private key, the signer kid, and the X25519 secret.
    fn generate_peer_did_signing_and_x25519() -> (String, [u8; 32], String, Secret) {
        use base64::prelude::BASE64_URL_SAFE_NO_PAD;
        let x25519_secret = Secret::generate_x25519(Some("temp"), None).unwrap();
        let x25519_multibase = x25519_secret.get_public_keymultibase().unwrap();

        let keys = vec![
            PeerCreateKey::new(PeerKeyPurpose::Verification, PeerKeyType::Ed25519),
            PeerCreateKey::from_multibase(PeerKeyPurpose::Encryption, x25519_multibase),
        ];
        let (did, created) = DID::generate_peer(&keys, None).unwrap();
        let did_string = did.to_string();

        // V (Ed25519) is the first created key; `d` is its base64url private.
        let v_priv: [u8; 32] = BASE64_URL_SAFE_NO_PAD
            .decode(&created[0].d)
            .unwrap()
            .try_into()
            .expect("Ed25519 private key is 32 bytes");
        let signer_kid = format!("{did_string}#key-1");

        let mut secret = x25519_secret;
        secret.id = format!("{did_string}#key-2");

        (did_string, v_priv, signer_kid, secret)
    }

    /// #323: a top-level signed (JWS) message must be cryptographically
    /// verified — and the signer attributed — not parsed blindly. (The
    /// prior behaviour returned the payload unverified with
    /// `non_repudiation: true`.)
    #[tokio::test]
    async fn unpack_signed_jws_verifies_and_attributes() {
        use affinidi_messaging_didcomm::message::pack;

        let (did, v_priv, signer_kid, _x) = generate_peer_did_signing_and_x25519();
        // No secrets needed to *verify* — the signer's key is resolved.
        let atm = create_atm().await;

        let msg = DcMessage::build(
            "sig-1".to_string(),
            "example/v1".to_string(),
            json!({"signed": true}),
        )
        .from(did.clone())
        .finalize();
        let jws = pack::pack_signed(&msg, &signer_kid, &v_priv).unwrap();

        let (unpacked, meta) = atm
            .unpack(&jws)
            .await
            .expect("a validly-signed JWS should verify");
        assert_eq!(unpacked.id, "sig-1");
        assert!(!meta.encrypted);
        assert!(
            meta.non_repudiation,
            "verified signature => non_repudiation"
        );
        assert_eq!(meta.sign_from.as_deref(), Some(signer_kid.as_str()));
    }

    /// #323 security: a JWS whose payload was tampered after signing must
    /// be REJECTED, not accepted as non-repudiable.
    #[tokio::test]
    async fn unpack_signed_jws_tampered_payload_is_rejected() {
        use affinidi_messaging_didcomm::message::pack;
        use base64::prelude::BASE64_URL_SAFE_NO_PAD;

        let (did, v_priv, signer_kid, _x) = generate_peer_did_signing_and_x25519();
        let atm = create_atm().await;

        let msg = DcMessage::build("sig-ok".to_string(), "example/v1".to_string(), json!({}))
            .from(did.clone())
            .finalize();
        let jws = pack::pack_signed(&msg, &signer_kid, &v_priv).unwrap();

        // Swap the payload for a different message; the signature no
        // longer covers it.
        let mut v: serde_json::Value = serde_json::from_str(&jws).unwrap();
        v["payload"] = json!(
            BASE64_URL_SAFE_NO_PAD
                .encode(br#"{"id":"evil","typ":"example/v1","type":"example/v1","body":{"x":1}}"#)
        );
        let tampered = serde_json::to_string(&v).unwrap();

        assert!(
            atm.unpack(&tampered).await.is_err(),
            "a tampered JWS must fail verification, not be trusted"
        );
    }

    /// #324: DIDComm v2.1 sign-then-encrypt through the SDK — the inner
    /// JWS is verified after decryption, surfacing non-repudiation + the
    /// signer.
    #[tokio::test]
    async fn unpack_sign_then_encrypt() {
        use affinidi_crypto::jose::key_agreement::{
            Curve, PrivateKeyAgreement, PublicKeyAgreement,
        };
        use affinidi_messaging_didcomm::jwe::encrypt;
        use affinidi_messaging_didcomm::message::pack;

        let (sender_did, v_priv, signer_kid, sender_x) = generate_peer_did_signing_and_x25519();
        let (recipient_did, recipient_secret) = generate_peer_did_with_x25519();
        let recipient_atm = create_atm_with_secrets(vec![recipient_secret.clone()]).await;

        let msg = DcMessage::build(
            "ste-1".to_string(),
            "example/v1".to_string(),
            json!({"v": 7}),
        )
        .from(sender_did.clone())
        .to(recipient_did.clone())
        .finalize();

        // Sign first, then authcrypt the JWS bytes (sign-then-encrypt).
        let jws = pack::pack_signed(&msg, &signer_kid, &v_priv).unwrap();

        let sender_priv =
            PrivateKeyAgreement::from_raw_bytes(Curve::X25519, sender_x.get_private_bytes())
                .unwrap();
        let (_, rpub) = affinidi_encoding::decode_multikey_with_codec(
            &recipient_secret.get_public_keymultibase().unwrap(),
        )
        .unwrap();
        let recipient_pub = PublicKeyAgreement::from_raw_bytes(Curve::X25519, &rpub).unwrap();

        let jwe = encrypt::authcrypt(
            jws.as_bytes(),
            &format!("{sender_did}#key-2"),
            &sender_priv,
            &[(&format!("{recipient_did}#key-2"), &recipient_pub)],
        )
        .unwrap();

        let (unpacked, meta) = recipient_atm
            .unpack(&jwe)
            .await
            .expect("sign-then-encrypt should decrypt and verify");
        assert_eq!(unpacked.id, "ste-1");
        assert_eq!(unpacked.body, json!({"v": 7}));
        assert!(meta.encrypted);
        assert!(meta.authenticated, "authcrypt => authenticated");
        assert!(
            meta.non_repudiation,
            "inner JWS verified => non_repudiation"
        );
        assert_eq!(meta.sign_from.as_deref(), Some(signer_kid.as_str()));
        assert_eq!(meta.wrapping, MessageWrappingType::AuthcryptSignPlaintext);
    }

    const FORWARD_TYPE: &str = "https://didcomm.org/routing/2.0/forward";

    /// Creates an ATM instance with default config (unpack_forwards=true).
    async fn create_atm() -> ATM {
        // Plaintext + signed only — the wrappings the forward / plaintext /
        // signed tests below exercise (no accept-all preset).
        let config = ATMConfig::builder()
            .with_unpack_policy(UnpackPolicy {
                expected: vec![
                    MessageWrappingType::Plaintext,
                    MessageWrappingType::SignedPlaintext,
                ],
                validate_addressing_consistency: false,
                max_signatures: DEFAULT_MAX_SIGNATURES,
                max_recipients: DEFAULT_MAX_RECIPIENTS,
            })
            .build()
            .unwrap();
        let tdk_cfg = affinidi_tdk_common::config::TDKConfig::headless().unwrap();
        let tdk = Arc::new(TDKSharedState::new(tdk_cfg).await.unwrap());
        ATM::new(config, tdk).await.unwrap()
    }

    /// Creates an ATM instance with unpack_forwards disabled.
    async fn create_atm_no_unpack_forwards() -> ATM {
        let config = ATMConfig::builder()
            .with_unpack_forwards(false)
            .with_unpack_policy(UnpackPolicy {
                expected: vec![MessageWrappingType::Plaintext],
                validate_addressing_consistency: false,
                max_signatures: DEFAULT_MAX_SIGNATURES,
                max_recipients: DEFAULT_MAX_RECIPIENTS,
            })
            .build()
            .unwrap();
        let tdk_cfg = affinidi_tdk_common::config::TDKConfig::headless().unwrap();
        let tdk = Arc::new(TDKSharedState::new(tdk_cfg).await.unwrap());
        ATM::new(config, tdk).await.unwrap()
    }

    /// Builds a simple plaintext test message.
    fn make_inner_message() -> Message {
        Message::build(
            "test-msg-1".to_string(),
            "example/v1".to_string(),
            json!({"hello": "world"}),
        )
        .from("did:example:sender".to_string())
        .to("did:example:recipient".to_string())
        .finalize()
    }

    /// Serializes a Message to a JSON string.
    fn make_plaintext_json(msg: &Message) -> String {
        serde_json::to_string(msg).unwrap()
    }

    /// Wraps inner_json in a forward envelope with a JSON attachment.
    fn wrap_in_forward_json(inner_json: &str, expires_time: Option<u64>) -> Message {
        let inner_value: serde_json::Value = serde_json::from_str(inner_json).unwrap();
        let attachment = Attachment::json(inner_value)
            .id("fwd-1".to_string())
            .finalize();
        let mut builder = Message::build(
            "fwd-msg-1".to_string(),
            FORWARD_TYPE.to_string(),
            json!({"next": "did:example:recipient"}),
        )
        .attachment(attachment);
        if let Some(exp) = expires_time {
            builder = builder.expires_time(exp);
        }
        builder.finalize()
    }

    /// Wraps inner_json in a forward envelope with a Base64 attachment.
    fn wrap_in_forward_base64(inner_json: &str, expires_time: Option<u64>) -> Message {
        let encoded = BASE64_URL_SAFE.encode(inner_json.as_bytes());
        let attachment = Attachment::base64(encoded)
            .id("fwd-1".to_string())
            .finalize();
        let mut builder = Message::build(
            "fwd-msg-1".to_string(),
            FORWARD_TYPE.to_string(),
            json!({"next": "did:example:recipient"}),
        )
        .attachment(attachment);
        if let Some(exp) = expires_time {
            builder = builder.expires_time(exp);
        }
        builder.finalize()
    }

    // ---- ATM::unpack tests ----

    #[tokio::test]
    async fn unpack_plaintext_message() {
        let atm = create_atm().await;
        let msg = make_inner_message();
        let json_str = make_plaintext_json(&msg);

        let (unpacked, metadata) = atm.unpack(&json_str).await.unwrap();

        assert_eq!(unpacked.id, "test-msg-1");
        assert_eq!(unpacked.typ, "example/v1");
        assert_eq!(unpacked.body, json!({"hello": "world"}));
        assert_eq!(unpacked.from.as_deref(), Some("did:example:sender"));
        assert!(!metadata.encrypted);
        assert!(!metadata.authenticated);
        assert!(!metadata.non_repudiation);
    }

    #[tokio::test]
    async fn unpack_forward_json_attachment() {
        let atm = create_atm().await;
        let inner = make_inner_message();
        let inner_json = make_plaintext_json(&inner);
        let forward = wrap_in_forward_json(&inner_json, None);
        let forward_json = make_plaintext_json(&forward);

        let (unpacked, _metadata) = atm.unpack(&forward_json).await.unwrap();

        assert_eq!(unpacked.id, "test-msg-1");
        assert_eq!(unpacked.typ, "example/v1");
        assert_eq!(unpacked.body, json!({"hello": "world"}));
    }

    #[tokio::test]
    async fn unpack_forward_base64_attachment() {
        let atm = create_atm().await;
        let inner = make_inner_message();
        let inner_json = make_plaintext_json(&inner);
        let forward = wrap_in_forward_base64(&inner_json, None);
        let forward_json = make_plaintext_json(&forward);

        let (unpacked, _metadata) = atm.unpack(&forward_json).await.unwrap();

        assert_eq!(unpacked.id, "test-msg-1");
        assert_eq!(unpacked.typ, "example/v1");
        assert_eq!(unpacked.body, json!({"hello": "world"}));
    }

    #[tokio::test]
    async fn unpack_forward_disabled() {
        let atm = create_atm_no_unpack_forwards().await;
        let inner = make_inner_message();
        let inner_json = make_plaintext_json(&inner);
        let forward = wrap_in_forward_json(&inner_json, None);
        let forward_json = make_plaintext_json(&forward);

        let (unpacked, _metadata) = atm.unpack(&forward_json).await.unwrap();

        // Should return the forward envelope itself, not the inner message
        assert_eq!(unpacked.typ, FORWARD_TYPE);
        assert_eq!(unpacked.id, "fwd-msg-1");
    }

    #[tokio::test]
    async fn unpack_forward_nested() {
        let atm = create_atm().await;
        let inner = make_inner_message();
        let inner_json = make_plaintext_json(&inner);
        let forward1 = wrap_in_forward_json(&inner_json, None);
        let forward1_json = make_plaintext_json(&forward1);
        let forward2 = wrap_in_forward_base64(&forward1_json, None);
        let forward2_json = make_plaintext_json(&forward2);

        let (unpacked, _metadata) = atm.unpack(&forward2_json).await.unwrap();

        assert_eq!(unpacked.id, "test-msg-1");
        assert_eq!(unpacked.typ, "example/v1");
        assert_eq!(unpacked.body, json!({"hello": "world"}));
    }

    #[tokio::test]
    async fn unpack_forward_method() {
        let atm = create_atm().await;
        let inner = make_inner_message();
        let inner_json = make_plaintext_json(&inner);
        let forward = wrap_in_forward_json(&inner_json, None);

        let (unpacked, _metadata) = atm.unpack_forward(&forward).await.unwrap();

        assert_eq!(unpacked.id, "test-msg-1");
        assert_eq!(unpacked.typ, "example/v1");
    }

    #[tokio::test]
    async fn unpack_invalid_message() {
        let atm = create_atm().await;
        let result = atm.unpack("not a valid message").await;

        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), ATMError::DidcommError(_, _)),
            "Expected DidcommError"
        );
    }

    // ---- SharedState::extract_forward_payload tests ----

    #[test]
    fn extract_forward_payload_json() {
        let inner = make_inner_message();
        let inner_json = make_plaintext_json(&inner);
        let forward = wrap_in_forward_json(&inner_json, None);

        let extracted = SharedState::extract_forward_payload(&forward, NOW_SECS).unwrap();

        let extracted_value: serde_json::Value = serde_json::from_str(&extracted).unwrap();
        let inner_value: serde_json::Value = serde_json::from_str(&inner_json).unwrap();
        assert_eq!(extracted_value, inner_value);
    }

    #[test]
    fn extract_forward_payload_base64() {
        let inner = make_inner_message();
        let inner_json = make_plaintext_json(&inner);
        let forward = wrap_in_forward_base64(&inner_json, None);

        let extracted = SharedState::extract_forward_payload(&forward, NOW_SECS).unwrap();

        assert_eq!(extracted, inner_json);
    }

    #[test]
    fn extract_forward_payload_expired() {
        let inner = make_inner_message();
        let inner_json = make_plaintext_json(&inner);
        let forward = wrap_in_forward_json(&inner_json, Some(1));

        let result = SharedState::extract_forward_payload(&forward, NOW_SECS);

        assert!(result.is_err());
        assert!(
            matches!(&result.unwrap_err(), ATMError::MsgReceiveError(msg) if msg.contains("expired")),
            "Expected MsgReceiveError mentioning expiry"
        );
    }

    #[test]
    fn extract_forward_payload_not_expired() {
        let inner = make_inner_message();
        let inner_json = make_plaintext_json(&inner);
        let future = NOW_SECS + 3600;
        let forward = wrap_in_forward_json(&inner_json, Some(future));

        let result = SharedState::extract_forward_payload(&forward, NOW_SECS);

        assert!(result.is_ok());
    }

    #[test]
    fn extract_forward_payload_no_attachments() {
        let msg = Message::build(
            "fwd-no-attach".to_string(),
            FORWARD_TYPE.to_string(),
            json!({"next": "did:example:recipient"}),
        )
        .finalize();

        let result = SharedState::extract_forward_payload(&msg, NOW_SECS);

        assert!(result.is_err());
        assert!(
            matches!(&result.unwrap_err(), ATMError::MsgReceiveError(msg) if msg.contains("no attachments")),
            "Expected MsgReceiveError mentioning no attachments"
        );
    }

    #[test]
    fn extract_forward_payload_empty_attachments() {
        let mut msg = Message::build(
            "fwd-empty-attach".to_string(),
            FORWARD_TYPE.to_string(),
            json!({"next": "did:example:recipient"}),
        )
        .finalize();
        msg.attachments = Some(vec![]);

        let result = SharedState::extract_forward_payload(&msg, NOW_SECS);

        assert!(result.is_err());
        assert!(
            matches!(&result.unwrap_err(), ATMError::MsgReceiveError(msg) if msg.contains("no attachments")),
            "Expected MsgReceiveError mentioning no attachments"
        );
    }

    #[test]
    fn extract_forward_payload_unsupported_format() {
        let attachment = Attachment::links(
            vec!["https://example.com/msg".to_string()],
            "abc123hash".to_string(),
        )
        .id("fwd-link".to_string())
        .finalize();
        let msg = Message::build(
            "fwd-links".to_string(),
            FORWARD_TYPE.to_string(),
            json!({"next": "did:example:recipient"}),
        )
        .attachment(attachment)
        .finalize();

        let result = SharedState::extract_forward_payload(&msg, NOW_SECS);

        assert!(result.is_err());
        assert!(
            matches!(&result.unwrap_err(), ATMError::MsgReceiveError(msg) if msg.contains("not in a supported format")),
            "Expected MsgReceiveError mentioning unsupported format"
        );
    }

    #[test]
    fn extract_forward_payload_invalid_base64() {
        let attachment = Attachment::base64("!!!not-valid-base64!!!".to_string())
            .id("fwd-bad-b64".to_string())
            .finalize();
        let msg = Message::build(
            "fwd-bad-b64".to_string(),
            FORWARD_TYPE.to_string(),
            json!({"next": "did:example:recipient"}),
        )
        .attachment(attachment)
        .finalize();

        let result = SharedState::extract_forward_payload(&msg, NOW_SECS);

        assert!(result.is_err());
        assert!(
            matches!(&result.unwrap_err(), ATMError::MsgReceiveError(msg) if msg.contains("cannot be decoded")),
            "Expected MsgReceiveError mentioning decode failure"
        );
    }

    #[tokio::test]
    async fn unpack_forward_depth_exceeded() {
        let atm = create_atm().await;
        let inner = make_inner_message();
        let mut json_str = make_plaintext_json(&inner);

        // Nest forward messages deeper than the limit
        for _ in 0..=super::MAX_FORWARD_DEPTH {
            let forward = wrap_in_forward_json(&json_str, None);
            json_str = make_plaintext_json(&forward);
        }

        let result = atm.unpack(&json_str).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(&err, ATMError::MsgReceiveError(msg) if msg.contains("nesting depth exceeded")),
            "Expected MsgReceiveError about nesting depth, got: {err:?}"
        );
    }

    #[test]
    fn extract_forward_payload_base64_invalid_utf8() {
        let invalid_utf8: [u8; 4] = [0xFF, 0xFE, 0xFD, 0xFC];
        let encoded = BASE64_URL_SAFE.encode(invalid_utf8);
        let attachment = Attachment::base64(encoded)
            .id("fwd-bad-utf8".to_string())
            .finalize();
        let msg = Message::build(
            "fwd-bad-utf8".to_string(),
            FORWARD_TYPE.to_string(),
            json!({"next": "did:example:recipient"}),
        )
        .attachment(attachment)
        .finalize();

        let result = SharedState::extract_forward_payload(&msg, NOW_SECS);

        assert!(result.is_err());
        assert!(
            matches!(&result.unwrap_err(), ATMError::MsgReceiveError(msg) if msg.contains("cannot be converted to a UTF-8 string")),
            "Expected MsgReceiveError mentioning UTF-8 conversion failure"
        );
    }

    // ─── Secure-default policy, addressing consistency, and layered envelopes ─

    use crate::config::{MessageWrappingType, UnpackPolicy};
    use affinidi_crypto::jose::key_agreement::{Curve, PrivateKeyAgreement, PublicKeyAgreement};
    use affinidi_messaging_didcomm::jwe::encrypt::{anoncrypt, authcrypt};
    use affinidi_messaging_didcomm::jws::sign::{JwsSigner, sign_multi};

    /// A did:peer:2 whose Ed25519 signing key (#key-1) and X25519 key-agreement
    /// key (#key-2) are both controlled by the test. Returns
    /// (did, ed_signing_secret, x25519_secret).
    fn generate_peer_did_full() -> (String, Secret, Secret) {
        let ed = Secret::generate_ed25519(Some("temp"), None);
        let ed_mb = ed.get_public_keymultibase().unwrap();
        let x = Secret::generate_x25519(Some("temp"), None).unwrap();
        let x_mb = x.get_public_keymultibase().unwrap();
        let keys = vec![
            PeerCreateKey::from_multibase(PeerKeyPurpose::Verification, ed_mb),
            PeerCreateKey::from_multibase(PeerKeyPurpose::Encryption, x_mb),
        ];
        let (did, _created) = DID::generate_peer(&keys, None).unwrap();
        let did_string = did.to_string();
        let mut ed = ed;
        ed.id = format!("{did_string}#key-1");
        let mut x = x;
        x.id = format!("{did_string}#key-2");
        (did_string, ed, x)
    }

    async fn create_atm_with_policy(secrets: Vec<Secret>, policy: UnpackPolicy) -> ATM {
        use affinidi_tdk_common::config::TDKConfig;
        let config = ATMConfig::builder()
            .with_unpack_policy(policy)
            .build()
            .unwrap();
        let tdk = Arc::new(
            TDKSharedState::new(TDKConfig::headless().unwrap())
                .await
                .unwrap(),
        );
        for s in &secrets {
            tdk.secrets_resolver().insert(s.clone()).await;
        }
        ATM::new(config, tdk).await.unwrap()
    }

    fn x25519_priv(s: &Secret) -> PrivateKeyAgreement {
        PrivateKeyAgreement::from_raw_bytes(Curve::X25519, s.get_private_bytes()).unwrap()
    }
    fn x25519_pub(s: &Secret) -> PublicKeyAgreement {
        PublicKeyAgreement::from_raw_bytes(Curve::X25519, s.get_public_bytes()).unwrap()
    }

    fn build_plaintext(from: &str, to: &str) -> String {
        let msg = DcMessage::build(
            "layered-1".to_string(),
            "example/v1".to_string(),
            json!({"hello": "layered"}),
        )
        .from(from.to_string())
        .to(to.to_string())
        .finalize();
        serde_json::to_string(&msg).unwrap()
    }

    /// The secure default policy accepts an authcrypt message whose inner
    /// `from` matches the authcrypt `skid`, and binds the sender.
    #[tokio::test]
    async fn default_policy_accepts_matching_authcrypt() {
        let (sender_did, _sed, sx) = generate_peer_did_full();
        let (recipient_did, _red, rx) = generate_peer_did_full();
        let recipient = create_atm_with_policy(vec![rx.clone()], UnpackPolicy::default()).await;

        let plaintext = build_plaintext(&sender_did, &recipient_did);
        let jwe = authcrypt(
            plaintext.as_bytes(),
            &format!("{sender_did}#key-2"),
            &x25519_priv(&sx),
            &[(&format!("{recipient_did}#key-2"), &x25519_pub(&rx))],
        )
        .unwrap();

        let (msg, meta) = recipient.unpack(&jwe).await.expect("authcrypt accepted");
        assert_eq!(meta.wrapping, MessageWrappingType::AuthcryptPlaintext);
        assert!(meta.authenticated);
        assert_eq!(msg.from.as_deref(), Some(sender_did.as_str()));
        assert_eq!(
            meta.encrypted_from_kid.as_deref(),
            Some(format!("{sender_did}#key-2").as_str())
        );
    }

    /// The secure default also accepts `authcrypt(sign(plaintext))` — the second
    /// authenticated wrapping — binding both the authcrypt sender (`skid`) and
    /// the verified signer to the inner `from`.
    #[tokio::test]
    async fn default_policy_accepts_authcrypt_sign() {
        let (sender_did, sed, sx) = generate_peer_did_full();
        let (recipient_did, _red, rx) = generate_peer_did_full();
        let recipient = create_atm_with_policy(vec![rx.clone()], UnpackPolicy::default()).await;

        let plaintext = build_plaintext(&sender_did, &recipient_did);
        let sed_priv: [u8; 32] = sed.get_private_bytes().try_into().unwrap();
        let signed = sign_multi(
            plaintext.as_bytes(),
            &[JwsSigner::Ed25519 {
                kid: &format!("{sender_did}#key-1"),
                private: &sed_priv,
            }],
        )
        .unwrap();
        let jwe = authcrypt(
            signed.as_bytes(),
            &format!("{sender_did}#key-2"),
            &x25519_priv(&sx),
            &[(&format!("{recipient_did}#key-2"), &x25519_pub(&rx))],
        )
        .unwrap();

        let (msg, meta) = recipient
            .unpack(&jwe)
            .await
            .expect("authcrypt(sign) accepted by the default policy");
        assert_eq!(meta.wrapping, MessageWrappingType::AuthcryptSignPlaintext);
        assert!(meta.authenticated && meta.non_repudiation);
        assert_eq!(msg.from.as_deref(), Some(sender_did.as_str()));
        assert_eq!(
            meta.sign_from.as_deref(),
            Some(format!("{sender_did}#key-1").as_str())
        );
        assert_eq!(
            meta.encrypted_from_kid.as_deref(),
            Some(format!("{sender_did}#key-2").as_str())
        );
    }

    /// The forged-sender bypass: authcrypted by one key but the inner `from`
    /// claims a different DID. The secure default must reject it.
    #[tokio::test]
    async fn default_policy_rejects_forged_from_authcrypt() {
        let (sender_did, _sed, sx) = generate_peer_did_full();
        let (recipient_did, _red, rx) = generate_peer_did_full();
        let (victim_did, _ved, _vx) = generate_peer_did_full();
        let recipient = create_atm_with_policy(vec![rx.clone()], UnpackPolicy::default()).await;

        // Encrypted with the sender's key, but `from` claims the victim.
        let plaintext = build_plaintext(&victim_did, &recipient_did);
        let jwe = authcrypt(
            plaintext.as_bytes(),
            &format!("{sender_did}#key-2"),
            &x25519_priv(&sx),
            &[(&format!("{recipient_did}#key-2"), &x25519_pub(&rx))],
        )
        .unwrap();

        let err = recipient.unpack(&jwe).await.unwrap_err();
        assert!(
            matches!(err, ATMError::AddressingMismatch(_)),
            "forged `from` must be an AddressingMismatch, got: {err:?}"
        );
    }

    /// The impostor wrapping `sign(authcrypt(plaintext))` — signature *outside*
    /// the encryption — must be rejected, even though `authcrypt(sign(pt))`
    /// (signature inside) is accepted by the same default policy. The two are
    /// not equivalent: with the signature outside, any intermediary can strip
    /// the outer JWS and forward the bare authcrypt. Classification is
    /// layer-order sensitive, so this lands as `UnexpectedEnvelope` (outside the
    /// taxonomy), not as the `AuthcryptSignPlaintext` it superficially resembles.
    #[tokio::test]
    async fn default_policy_rejects_sign_over_authcrypt() {
        let (sender_did, sed, sx) = generate_peer_did_full();
        let (recipient_did, _red, rx) = generate_peer_did_full();
        let recipient = create_atm_with_policy(vec![rx.clone()], UnpackPolicy::default()).await;

        // authcrypt first, then sign the JWE — i.e. sign(authcrypt(pt)).
        let plaintext = build_plaintext(&sender_did, &recipient_did);
        let jwe = authcrypt(
            plaintext.as_bytes(),
            &format!("{sender_did}#key-2"),
            &x25519_priv(&sx),
            &[(&format!("{recipient_did}#key-2"), &x25519_pub(&rx))],
        )
        .unwrap();
        let sed_priv: [u8; 32] = sed.get_private_bytes().try_into().unwrap();
        let outer_signed = sign_multi(
            jwe.as_bytes(),
            &[JwsSigner::Ed25519 {
                kid: &format!("{sender_did}#key-1"),
                private: &sed_priv,
            }],
        )
        .unwrap();

        let err = recipient.unpack(&outer_signed).await.unwrap_err();
        assert!(
            matches!(err, ATMError::UnexpectedEnvelope(_)),
            "sign-over-authcrypt must be rejected as outside the taxonomy, got: {err:?}"
        );
    }

    /// The secure default rejects anoncrypt, plaintext, and signed-only
    /// (downgrade guard).
    #[tokio::test]
    async fn default_policy_rejects_weaker_wrappings() {
        let (sender_did, sed, _sx) = generate_peer_did_full();
        let (recipient_did, _red, rx) = generate_peer_did_full();
        let recipient = create_atm_with_policy(vec![rx.clone()], UnpackPolicy::default()).await;
        let plaintext = build_plaintext(&sender_did, &recipient_did);

        // anoncrypt
        let anon = anoncrypt(
            plaintext.as_bytes(),
            &[(&format!("{recipient_did}#key-2"), &x25519_pub(&rx))],
        )
        .unwrap();
        assert!(matches!(
            recipient.unpack(&anon).await.unwrap_err(),
            ATMError::UnexpectedEnvelope(_)
        ));

        // plaintext
        assert!(matches!(
            recipient.unpack(&plaintext).await.unwrap_err(),
            ATMError::UnexpectedEnvelope(_)
        ));

        // signed-only
        let sed_priv: [u8; 32] = sed.get_private_bytes().try_into().unwrap();
        let signed = sign_multi(
            plaintext.as_bytes(),
            &[JwsSigner::Ed25519 {
                kid: &format!("{sender_did}#key-1"),
                private: &sed_priv,
            }],
        )
        .unwrap();
        assert!(matches!(
            recipient.unpack(&signed).await.unwrap_err(),
            ATMError::UnexpectedEnvelope(_)
        ));
    }

    /// A policy whose `expected` set lists **more than one** wrapping accepts
    /// *any* of the listed wrappings and rejects one that is not listed. Here
    /// the set is `[AnoncryptPlaintext, AuthcryptPlaintext]`: both are accepted
    /// (and classified correctly), while a `sign(plaintext)` — absent from the
    /// set — is rejected.
    #[tokio::test]
    async fn policy_with_multiple_expected_accepts_any_listed() {
        let (sender_did, sed, sx) = generate_peer_did_full();
        let (recipient_did, _red, rx) = generate_peer_did_full();

        let policy = UnpackPolicy {
            expected: vec![
                MessageWrappingType::AnoncryptPlaintext,
                MessageWrappingType::AuthcryptPlaintext,
            ],
            validate_addressing_consistency: false,
            max_signatures: 1,
            max_recipients: 2,
        };
        let recipient = create_atm_with_policy(vec![rx.clone()], policy).await;

        let plaintext = build_plaintext(&sender_did, &recipient_did);
        let recipient_kid = format!("{recipient_did}#key-2");

        // First listed wrapping: anoncrypt(plaintext) is accepted.
        let anon = anoncrypt(plaintext.as_bytes(), &[(&recipient_kid, &x25519_pub(&rx))]).unwrap();
        let (_msg, meta) = recipient
            .unpack(&anon)
            .await
            .expect("anoncrypt is one of the expected wrappings");
        assert_eq!(meta.wrapping, MessageWrappingType::AnoncryptPlaintext);

        // Second listed wrapping: authcrypt(plaintext) is also accepted.
        let auth = authcrypt(
            plaintext.as_bytes(),
            &format!("{sender_did}#key-2"),
            &x25519_priv(&sx),
            &[(&recipient_kid, &x25519_pub(&rx))],
        )
        .unwrap();
        let (_msg, meta) = recipient
            .unpack(&auth)
            .await
            .expect("authcrypt is one of the expected wrappings");
        assert_eq!(meta.wrapping, MessageWrappingType::AuthcryptPlaintext);

        // A wrapping absent from the set (signed-only) is still rejected.
        let sed_priv: [u8; 32] = sed.get_private_bytes().try_into().unwrap();
        let signed = sign_multi(
            plaintext.as_bytes(),
            &[JwsSigner::Ed25519 {
                kid: &format!("{sender_did}#key-1"),
                private: &sed_priv,
            }],
        )
        .unwrap();
        assert!(
            matches!(
                recipient.unpack(&signed).await.unwrap_err(),
                ATMError::UnexpectedEnvelope(_)
            ),
            "a wrapping not in the expected set must be rejected"
        );
    }

    /// Double encryption `anoncrypt(authcrypt(plaintext))` unpacks under a
    /// policy that accepts it, classifies correctly, and binds the authcrypt
    /// sender across both layers.
    #[tokio::test]
    async fn double_encryption_anoncrypt_authcrypt() {
        let (sender_did, _sed, sx) = generate_peer_did_full();
        let (recipient_did, _red, rx) = generate_peer_did_full();

        let plaintext = build_plaintext(&sender_did, &recipient_did);
        let inner = authcrypt(
            plaintext.as_bytes(),
            &format!("{sender_did}#key-2"),
            &x25519_priv(&sx),
            &[(&format!("{recipient_did}#key-2"), &x25519_pub(&rx))],
        )
        .unwrap();
        let outer = anoncrypt(
            inner.as_bytes(),
            &[(&format!("{recipient_did}#key-2"), &x25519_pub(&rx))],
        )
        .unwrap();

        let policy = UnpackPolicy {
            expected: vec![MessageWrappingType::AnoncryptAuthcryptPlaintext],
            validate_addressing_consistency: true,
            max_signatures: 1,
            max_recipients: 2,
        };
        let recipient = create_atm_with_policy(vec![rx.clone()], policy).await;

        let (_msg, meta) = recipient.unpack(&outer).await.expect("double-enc accepted");
        assert_eq!(
            meta.wrapping,
            MessageWrappingType::AnoncryptAuthcryptPlaintext
        );
        assert!(meta.encrypted && meta.authenticated);
        assert_eq!(
            meta.encrypted_from_kid.as_deref(),
            Some(format!("{sender_did}#key-2").as_str())
        );

        // The secure default also accepts it: it is authenticated encryption
        // (the inner authcrypt binds the sender) and strictly more private than
        // bare authcrypt, so it is in the default allow-list.
        let strict = create_atm_with_policy(vec![rx], UnpackPolicy::default()).await;
        let (_msg, meta) = strict
            .unpack(&outer)
            .await
            .expect("anoncrypt(authcrypt) is in the secure default set");
        assert_eq!(
            meta.wrapping,
            MessageWrappingType::AnoncryptAuthcryptPlaintext
        );
    }

    /// `anoncrypt(sign(plaintext))` (a DIDComm-defined wrapping) with two
    /// signatures: every signature verifies, the signer matching `from` is
    /// bound to `sign_from`, and non-repudiation is surfaced. The inner `from`
    /// remains available (it is authenticated by the signature layer, not the
    /// anoncrypt), even though anoncrypt is the outermost wrapping. anoncrypt
    /// has no authenticated sender, so `encrypted_from_kid` is `None`.
    #[tokio::test]
    async fn anoncrypt_sign_multi_sig_consistency() {
        let (sender_did, sed, _sx) = generate_peer_did_full();
        let (cosigner_did, ced, _cx) = generate_peer_did_full();
        let (recipient_did, _red, rx) = generate_peer_did_full();

        let plaintext = build_plaintext(&sender_did, &recipient_did);

        // Two signatures: the sender (matches `from`) and a co-signer.
        let sed_priv: [u8; 32] = sed.get_private_bytes().try_into().unwrap();
        let ced_priv: [u8; 32] = ced.get_private_bytes().try_into().unwrap();
        let signed = sign_multi(
            plaintext.as_bytes(),
            &[
                JwsSigner::Ed25519 {
                    kid: &format!("{sender_did}#key-1"),
                    private: &sed_priv,
                },
                JwsSigner::Ed25519 {
                    kid: &format!("{cosigner_did}#key-1"),
                    private: &ced_priv,
                },
            ],
        )
        .unwrap();
        let outer = anoncrypt(
            signed.as_bytes(),
            &[(&format!("{recipient_did}#key-2"), &x25519_pub(&rx))],
        )
        .unwrap();

        let policy = UnpackPolicy {
            expected: vec![MessageWrappingType::AnoncryptSignPlaintext],
            validate_addressing_consistency: true,
            max_signatures: 2,
            max_recipients: 2,
        };
        let recipient = create_atm_with_policy(vec![rx], policy).await;

        let (msg, meta) = recipient
            .unpack(&outer)
            .await
            .expect("anoncrypt(sign) accepted");
        assert_eq!(meta.wrapping, MessageWrappingType::AnoncryptSignPlaintext);
        // The signature layer authenticates the sender, so the inner `from`
        // remains available even under the outer anoncrypt wrapping.
        assert_eq!(
            msg.from.as_deref(),
            Some(sender_did.as_str()),
            "the signed `from` must survive the anoncrypt wrapping"
        );
        assert!(meta.encrypted && !meta.authenticated && meta.non_repudiation);
        assert_eq!(meta.signers.len(), 2, "both signatures verified");
        assert!(meta.signers.contains(&format!("{sender_did}#key-1")));
        assert!(meta.signers.contains(&format!("{cosigner_did}#key-1")));
        // The signer matching `from` is bound; the co-signer is not.
        assert_eq!(
            meta.sign_from.as_deref(),
            Some(format!("{sender_did}#key-1").as_str())
        );
        assert!(
            meta.encrypted_from_kid.is_none(),
            "anoncrypt => no authenticated sender key"
        );
    }

    /// `anoncrypt(authcrypt(sign(plaintext)))` is explicitly a MUST NOT in the
    /// DIDComm v2 spec (§IANA Media Types). It is not part of the wrapping
    /// taxonomy, so `unpack` rejects it as an unexpected envelope even under a
    /// policy that accepts layered wrappings.
    #[tokio::test]
    async fn triple_anoncrypt_authcrypt_sign_is_rejected() {
        let (sender_did, sed, sx) = generate_peer_did_full();
        let (recipient_did, _red, rx) = generate_peer_did_full();

        let plaintext = build_plaintext(&sender_did, &recipient_did);
        let sed_priv: [u8; 32] = sed.get_private_bytes().try_into().unwrap();
        let signed = sign_multi(
            plaintext.as_bytes(),
            &[JwsSigner::Ed25519 {
                kid: &format!("{sender_did}#key-1"),
                private: &sed_priv,
            }],
        )
        .unwrap();
        let inner = authcrypt(
            signed.as_bytes(),
            &format!("{sender_did}#key-2"),
            &x25519_priv(&sx),
            &[(&format!("{recipient_did}#key-2"), &x25519_pub(&rx))],
        )
        .unwrap();
        let outer = anoncrypt(
            inner.as_bytes(),
            &[(&format!("{recipient_did}#key-2"), &x25519_pub(&rx))],
        )
        .unwrap();

        let recipient = create_atm_with_policy(
            vec![rx],
            UnpackPolicy {
                expected: vec![
                    MessageWrappingType::AnoncryptAuthcryptPlaintext,
                    MessageWrappingType::AnoncryptSignPlaintext,
                ],
                validate_addressing_consistency: false,
                max_signatures: 1,
                max_recipients: 2,
            },
        )
        .await;
        let err = recipient.unpack(&outer).await.unwrap_err();
        assert!(
            matches!(err, ATMError::UnexpectedEnvelope(_)),
            "the spec-forbidden triple must be rejected, got: {err:?}"
        );
    }

    /// More than two cryptographic layers (of any kind) is non-conformant and
    /// rejected — here three nested anoncrypt layers. The third layer is refused
    /// *before* it is decrypted (the cap is checked before removal), so only two
    /// decryptions ever run.
    #[tokio::test]
    async fn more_than_two_crypto_layers_is_rejected() {
        let (sender_did, _sed, _sx) = generate_peer_did_full();
        let (recipient_did, _red, rx) = generate_peer_did_full();

        let plaintext = build_plaintext(&sender_did, &recipient_did);
        let rk = format!("{recipient_did}#key-2");
        let l1 = anoncrypt(plaintext.as_bytes(), &[(&rk, &x25519_pub(&rx))]).unwrap();
        let l2 = anoncrypt(l1.as_bytes(), &[(&rk, &x25519_pub(&rx))]).unwrap();
        let l3 = anoncrypt(l2.as_bytes(), &[(&rk, &x25519_pub(&rx))]).unwrap();

        let recipient = create_atm_with_policy(
            vec![rx],
            UnpackPolicy {
                expected: vec![MessageWrappingType::AnoncryptPlaintext],
                validate_addressing_consistency: false,
                max_signatures: 1,
                max_recipients: 2,
            },
        )
        .await;
        let err = recipient.unpack(&l3).await.unwrap_err();
        assert!(
            matches!(&err, ATMError::UnexpectedEnvelope(m) if m.contains("cryptographic layers")),
            "3+ crypto layers must be rejected, got: {err:?}"
        );
    }

    /// The `ATMConfigBuilder` default — when `with_unpack_policy` is *omitted* —
    /// must be the secure authcrypt-only policy: a matching `authcrypt(plaintext)`
    /// is accepted (and binds the sender), while a downgraded `anoncrypt` is
    /// rejected. Guards against the builder default drifting from
    /// `UnpackPolicy::default()`.
    #[tokio::test]
    async fn builder_default_policy_is_secure_authcrypt_only() {
        use affinidi_tdk_common::config::TDKConfig;
        let (sender_did, _sed, sx) = generate_peer_did_full();
        let (recipient_did, _red, rx) = generate_peer_did_full();

        // No `with_unpack_policy` call — exercise the builder default.
        let config = ATMConfig::builder().build().unwrap();
        let tdk = Arc::new(
            TDKSharedState::new(TDKConfig::headless().unwrap())
                .await
                .unwrap(),
        );
        tdk.secrets_resolver().insert(rx.clone()).await;
        let recipient = ATM::new(config, tdk).await.unwrap();

        let plaintext = build_plaintext(&sender_did, &recipient_did);

        // authcrypt(plaintext) is accepted by default and binds the sender.
        let jwe = authcrypt(
            plaintext.as_bytes(),
            &format!("{sender_did}#key-2"),
            &x25519_priv(&sx),
            &[(&format!("{recipient_did}#key-2"), &x25519_pub(&rx))],
        )
        .unwrap();
        let (msg, meta) = recipient
            .unpack(&jwe)
            .await
            .expect("builder default must accept authcrypt(plaintext)");
        assert_eq!(meta.wrapping, MessageWrappingType::AuthcryptPlaintext);
        assert!(meta.authenticated);
        assert_eq!(msg.from.as_deref(), Some(sender_did.as_str()));
        assert_eq!(
            meta.encrypted_from_kid.as_deref(),
            Some(format!("{sender_did}#key-2").as_str())
        );

        // A downgraded anoncrypt(plaintext) is rejected by that same default.
        let anon = anoncrypt(
            plaintext.as_bytes(),
            &[(&format!("{recipient_did}#key-2"), &x25519_pub(&rx))],
        )
        .unwrap();
        assert!(matches!(
            recipient.unpack(&anon).await.unwrap_err(),
            ATMError::UnexpectedEnvelope(_)
        ));
    }

    /// When a signed message's signatures all verify but none matches `from`,
    /// addressing-consistency rejects it.
    #[tokio::test]
    async fn signed_but_no_signer_matches_from_is_rejected() {
        let (sender_did, _sed, _sx) = generate_peer_did_full();
        let (cosigner_did, ced, _cx) = generate_peer_did_full();
        let (recipient_did, _red, _rx) = generate_peer_did_full();

        // `from` is the sender, but only the co-signer signs.
        let plaintext = build_plaintext(&sender_did, &recipient_did);
        let ced_priv: [u8; 32] = ced.get_private_bytes().try_into().unwrap();
        let signed = sign_multi(
            plaintext.as_bytes(),
            &[JwsSigner::Ed25519 {
                kid: &format!("{cosigner_did}#key-1"),
                private: &ced_priv,
            }],
        )
        .unwrap();

        let policy = UnpackPolicy {
            expected: vec![MessageWrappingType::SignedPlaintext],
            validate_addressing_consistency: true,
            max_signatures: 1,
            max_recipients: 2,
        };
        let recipient = create_atm_with_policy(vec![], policy).await;

        let err = recipient.unpack(&signed).await.unwrap_err();
        assert!(
            matches!(err, ATMError::AddressingMismatch(_)),
            "signer not matching `from` must be an AddressingMismatch, got: {err:?}"
        );
    }

    /// Addressing consistency (authcrypt branch): an authcrypt message with no
    /// inner `from` has nothing to bind the authcrypt sender (`skid`) to, so it
    /// is rejected as an `AddressingMismatch`.
    #[tokio::test]
    async fn authcrypt_without_from_is_rejected() {
        let (sender_did, _sed, sx) = generate_peer_did_full();
        let (recipient_did, _red, rx) = generate_peer_did_full();

        // Plaintext with no `from` — nothing to bind the authcrypt sender to.
        let msg = DcMessage::build(
            "no-from-authcrypt".to_string(),
            "example/v1".to_string(),
            json!({"hello": "layered"}),
        )
        .to(recipient_did.clone())
        .finalize();
        let plaintext = serde_json::to_string(&msg).unwrap();

        let jwe = authcrypt(
            plaintext.as_bytes(),
            &format!("{sender_did}#key-2"),
            &x25519_priv(&sx),
            &[(&format!("{recipient_did}#key-2"), &x25519_pub(&rx))],
        )
        .unwrap();

        let policy = UnpackPolicy {
            expected: vec![MessageWrappingType::AuthcryptPlaintext],
            validate_addressing_consistency: true,
            max_signatures: 1,
            max_recipients: 2,
        };
        let recipient = create_atm_with_policy(vec![rx], policy).await;

        let err = recipient.unpack(&jwe).await.unwrap_err();
        assert!(
            matches!(&err, ATMError::AddressingMismatch(m) if m.contains("no `from`")),
            "authcrypt with no `from` must be an AddressingMismatch, got: {err:?}"
        );
    }

    /// Addressing consistency (signed branch): a signed message with no inner
    /// `from` has no address for any signer to match, so it is rejected as an
    /// `AddressingMismatch`.
    #[tokio::test]
    async fn signed_without_from_is_rejected() {
        let (sender_did, sed, _sx) = generate_peer_did_full();

        // Signed plaintext with no `from` — no signer can be bound to it.
        let msg = DcMessage::build(
            "no-from-signed".to_string(),
            "example/v1".to_string(),
            json!({"signed": true}),
        )
        .to("did:example:recipient".to_string())
        .finalize();
        let plaintext = serde_json::to_string(&msg).unwrap();

        let sed_priv: [u8; 32] = sed.get_private_bytes().try_into().unwrap();
        let signed = sign_multi(
            plaintext.as_bytes(),
            &[JwsSigner::Ed25519 {
                kid: &format!("{sender_did}#key-1"),
                private: &sed_priv,
            }],
        )
        .unwrap();

        let policy = UnpackPolicy {
            expected: vec![MessageWrappingType::SignedPlaintext],
            validate_addressing_consistency: true,
            max_signatures: 1,
            max_recipients: 2,
        };
        let recipient = create_atm_with_policy(vec![], policy).await;

        let err = recipient.unpack(&signed).await.unwrap_err();
        assert!(
            matches!(&err, ATMError::AddressingMismatch(m) if m.contains("no signature matches")),
            "signed with no `from` must be an AddressingMismatch, got: {err:?}"
        );
    }

    /// Addressing consistency (anoncrypt branch, negative): a pure anoncrypt
    /// message is anonymous — it carries no authenticated sender — so a non-null
    /// inner `from` cannot be backed and is rejected as an `AddressingMismatch`.
    #[tokio::test]
    async fn anoncrypt_with_from_is_rejected() {
        let (sender_did, _sed, _sx) = generate_peer_did_full();
        let (recipient_did, _red, rx) = generate_peer_did_full();

        // Pure anoncrypt, but the inner plaintext declares a `from`.
        let plaintext = build_plaintext(&sender_did, &recipient_did);
        let anon = anoncrypt(
            plaintext.as_bytes(),
            &[(&format!("{recipient_did}#key-2"), &x25519_pub(&rx))],
        )
        .unwrap();

        let policy = UnpackPolicy {
            expected: vec![MessageWrappingType::AnoncryptPlaintext],
            validate_addressing_consistency: true,
            max_signatures: 1,
            max_recipients: 2,
        };
        let recipient = create_atm_with_policy(vec![rx], policy).await;

        let err = recipient.unpack(&anon).await.unwrap_err();
        assert!(
            matches!(&err, ATMError::AddressingMismatch(m) if m.contains("anoncrypt")),
            "anoncrypt declaring a `from` must be an AddressingMismatch, got: {err:?}"
        );
    }

    /// Addressing consistency (anoncrypt branch, positive): a pure anoncrypt
    /// message with no `from` is anonymous and accepted under a
    /// consistency-enforcing policy.
    #[tokio::test]
    async fn anoncrypt_without_from_is_accepted() {
        let (recipient_did, _red, rx) = generate_peer_did_full();

        // Anonymous plaintext (no `from`).
        let msg = DcMessage::build(
            "anon-no-from".to_string(),
            "example/v1".to_string(),
            json!({"hello": "anonymous"}),
        )
        .to(recipient_did.clone())
        .finalize();
        let plaintext = serde_json::to_string(&msg).unwrap();
        let anon = anoncrypt(
            plaintext.as_bytes(),
            &[(&format!("{recipient_did}#key-2"), &x25519_pub(&rx))],
        )
        .unwrap();

        let policy = UnpackPolicy {
            expected: vec![MessageWrappingType::AnoncryptPlaintext],
            validate_addressing_consistency: true,
            max_signatures: 1,
            max_recipients: 2,
        };
        let recipient = create_atm_with_policy(vec![rx], policy).await;

        let (msg, meta) = recipient
            .unpack(&anon)
            .await
            .expect("anonymous anoncrypt (no `from`) is accepted");
        assert_eq!(meta.wrapping, MessageWrappingType::AnoncryptPlaintext);
        assert!(meta.anonymous_sender);
        assert!(msg.from.is_none());
    }

    /// A did:peer:2 whose signing key (#key-1) is of the requested type
    /// (Ed25519 / P-256 / secp256k1). Returns (did, signing_secret).
    fn generate_peer_did_signing(sign_type: PeerKeyType) -> (String, Secret) {
        let signing = match sign_type {
            PeerKeyType::Ed25519 => Secret::generate_ed25519(Some("temp"), None),
            PeerKeyType::P256 => Secret::generate_p256(Some("temp"), None).unwrap(),
            PeerKeyType::Secp256k1 => Secret::generate_secp256k1(Some("temp"), None).unwrap(),
        };
        let sign_mb = signing.get_public_keymultibase().unwrap();
        let x = Secret::generate_x25519(Some("temp"), None).unwrap();
        let x_mb = x.get_public_keymultibase().unwrap();
        let keys = vec![
            PeerCreateKey::from_multibase(PeerKeyPurpose::Verification, sign_mb),
            PeerCreateKey::from_multibase(PeerKeyPurpose::Encryption, x_mb),
        ];
        let (did, _created) = DID::generate_peer(&keys, None).unwrap();
        let did_string = did.to_string();
        let mut signing = signing;
        signing.id = format!("{did_string}#key-1");
        (did_string, signing)
    }

    /// End-to-end signer verification through `atm.unpack` for every supported
    /// signing curve (Ed25519 / P-256 / secp256k1) — exercises
    /// `resolve_verify_key`'s per-curve arms and the `ES256`/`ES256K` verify
    /// paths, not just the didcomm-primitive unit tests.
    #[tokio::test]
    async fn signed_verifies_across_all_signer_curves() {
        for sign_type in [
            PeerKeyType::Ed25519,
            PeerKeyType::P256,
            PeerKeyType::Secp256k1,
        ] {
            let (signer_did, signer_secret) = generate_peer_did_signing(sign_type);
            let signer_kid = format!("{signer_did}#key-1");
            let priv32: [u8; 32] = signer_secret.get_private_bytes().try_into().unwrap();

            let plaintext = build_plaintext(&signer_did, "did:example:recipient");
            let jws_signer = match sign_type {
                PeerKeyType::Ed25519 => JwsSigner::Ed25519 {
                    kid: &signer_kid,
                    private: &priv32,
                },
                PeerKeyType::P256 => JwsSigner::P256 {
                    kid: &signer_kid,
                    private: &priv32,
                },
                PeerKeyType::Secp256k1 => JwsSigner::Secp256k1 {
                    kid: &signer_kid,
                    private: &priv32,
                },
            };
            let signed = sign_multi(plaintext.as_bytes(), &[jws_signer]).unwrap();

            let policy = UnpackPolicy {
                expected: vec![MessageWrappingType::SignedPlaintext],
                validate_addressing_consistency: true,
                max_signatures: 1,
                max_recipients: 2,
            };
            let recipient = create_atm_with_policy(vec![], policy).await;

            let (_msg, meta) = recipient
                .unpack(&signed)
                .await
                .unwrap_or_else(|e| panic!("{sign_type:?} signer should verify: {e:?}"));
            assert_eq!(meta.wrapping, MessageWrappingType::SignedPlaintext);
            assert_eq!(meta.signers, vec![signer_kid.clone()]);
            assert_eq!(meta.sign_from.as_deref(), Some(signer_kid.as_str()));
        }
    }

    /// Strict "verify all": in a multi-signature message where every signer
    /// resolves but ONE signature is corrupted, the whole unpack must fail
    /// (no partial trust). Consistency is off to isolate signature validity.
    #[tokio::test]
    async fn multi_sig_one_invalid_signature_rejects_whole_unpack() {
        let (sender_did, sed, _sx) = generate_peer_did_full();
        let (cosigner_did, ced, _cx) = generate_peer_did_full();

        let plaintext = build_plaintext(&sender_did, "did:example:recipient");
        let sed_priv: [u8; 32] = sed.get_private_bytes().try_into().unwrap();
        let ced_priv: [u8; 32] = ced.get_private_bytes().try_into().unwrap();
        let signed = sign_multi(
            plaintext.as_bytes(),
            &[
                JwsSigner::Ed25519 {
                    kid: &format!("{sender_did}#key-1"),
                    private: &sed_priv,
                },
                JwsSigner::Ed25519 {
                    kid: &format!("{cosigner_did}#key-1"),
                    private: &ced_priv,
                },
            ],
        )
        .unwrap();

        // Corrupt the SECOND signature's bytes (keep it valid base64url length).
        let mut v: serde_json::Value = serde_json::from_str(&signed).unwrap();
        let sig = v["signatures"][1]["signature"]
            .as_str()
            .unwrap()
            .to_string();
        let first = sig.chars().next().unwrap();
        let replacement = if first == 'A' { 'B' } else { 'A' };
        let corrupted: String = std::iter::once(replacement)
            .chain(sig.chars().skip(1))
            .collect();
        v["signatures"][1]["signature"] = serde_json::Value::String(corrupted);
        let tampered = serde_json::to_string(&v).unwrap();

        let policy = UnpackPolicy {
            expected: vec![MessageWrappingType::SignedPlaintext],
            validate_addressing_consistency: false,
            max_signatures: 2,
            max_recipients: 2,
        };
        let recipient = create_atm_with_policy(vec![], policy).await;

        let err = recipient.unpack(&tampered).await.unwrap_err();
        assert!(
            matches!(err, ATMError::DidcommError(_, _)),
            "one invalid signature must fail the whole unpack, got: {err:?}"
        );
    }

    /// DoS guard: a JWS carrying more signatures than the policy allows is
    /// rejected *before* any signer's DID is resolved, so an attacker cannot
    /// amplify resolution work by stuffing signature entries. The policy cap is
    /// the single effective bound — there is no separate absolute ceiling.
    #[tokio::test]
    async fn too_many_signatures_are_rejected() {
        let (sender_did, sed, _sx) = generate_peer_did_full();

        let plaintext = build_plaintext(&sender_did, "did:example:recipient");
        let sed_priv: [u8; 32] = sed.get_private_bytes().try_into().unwrap();
        let signed = sign_multi(
            plaintext.as_bytes(),
            &[JwsSigner::Ed25519 {
                kid: &format!("{sender_did}#key-1"),
                private: &sed_priv,
            }],
        )
        .unwrap();

        // Stuff duplicate signature entries past the policy cap. The bound is
        // checked on the entry count before verification, so the duplicates
        // never need to be resolved or re-verified.
        let cap = 5;
        let mut v: serde_json::Value = serde_json::from_str(&signed).unwrap();
        let entry = v["signatures"][0].clone();
        let sigs = v["signatures"].as_array_mut().unwrap();
        while sigs.len() <= cap {
            sigs.push(entry.clone());
        }
        let stuffed = serde_json::to_string(&v).unwrap();

        let policy = UnpackPolicy {
            expected: vec![MessageWrappingType::SignedPlaintext],
            validate_addressing_consistency: false,
            max_signatures: cap,
            max_recipients: 2,
        };
        let recipient = create_atm_with_policy(vec![], policy).await;

        let err = recipient.unpack(&stuffed).await.unwrap_err();
        assert!(
            matches!(&err, ATMError::UnexpectedEnvelope(m) if m.contains("policy maximum")),
            "too many signatures must be rejected on count, got: {err:?}"
        );
    }

    /// The `max_signatures` policy cap (default 1) rejects a message carrying
    /// more verified signers than allowed; raising the cap accepts it. Every
    /// signature is still verified — this only bounds how many are permitted.
    #[tokio::test]
    async fn max_signatures_policy_caps_signer_count() {
        let (sender_did, sed, _sx) = generate_peer_did_full();
        let (cosigner_did, ced, _cx) = generate_peer_did_full();

        let plaintext = build_plaintext(&sender_did, "did:example:recipient");
        let sed_priv: [u8; 32] = sed.get_private_bytes().try_into().unwrap();
        let ced_priv: [u8; 32] = ced.get_private_bytes().try_into().unwrap();
        let signed = sign_multi(
            plaintext.as_bytes(),
            &[
                JwsSigner::Ed25519 {
                    kid: &format!("{sender_did}#key-1"),
                    private: &sed_priv,
                },
                JwsSigner::Ed25519 {
                    kid: &format!("{cosigner_did}#key-1"),
                    private: &ced_priv,
                },
            ],
        )
        .unwrap();

        // A cap of 1 (the default) rejects the two-signer message — after both
        // signatures verified, before it is handed back.
        let strict = create_atm_with_policy(
            vec![],
            UnpackPolicy {
                expected: vec![MessageWrappingType::SignedPlaintext],
                validate_addressing_consistency: false,
                max_signatures: 1,
                max_recipients: 2,
            },
        )
        .await;
        let err = strict.unpack(&signed).await.unwrap_err();
        assert!(
            matches!(&err, ATMError::UnexpectedEnvelope(m) if m.contains("policy maximum")),
            "two signers must exceed a max_signatures=1 policy, got: {err:?}"
        );

        // Raising the cap to 2 accepts the same message (both verified).
        let lenient = create_atm_with_policy(
            vec![],
            UnpackPolicy {
                expected: vec![MessageWrappingType::SignedPlaintext],
                validate_addressing_consistency: false,
                max_signatures: 2,
                max_recipients: 2,
            },
        )
        .await;
        let (_msg, meta) = lenient
            .unpack(&signed)
            .await
            .expect("a cap of 2 accepts two signers");
        assert_eq!(meta.signers.len(), 2);
    }

    /// DoS guard: a JWE addressing more recipients than the policy allows is
    /// rejected before the recipient-matching loop, so an attacker cannot force
    /// unbounded parsing/allocation. The policy cap is the single effective
    /// bound — there is no separate absolute ceiling.
    #[tokio::test]
    async fn too_many_recipients_are_rejected() {
        let (sender_did, _sed, _sx) = generate_peer_did_full();
        let (recipient_did, _red, rx) = generate_peer_did_full();

        let plaintext = build_plaintext(&sender_did, &recipient_did);
        let anon = anoncrypt(
            plaintext.as_bytes(),
            &[(&format!("{recipient_did}#key-2"), &x25519_pub(&rx))],
        )
        .unwrap();

        // Stuff duplicate recipient entries past the policy cap. The bound is
        // checked on the entry count before the match loop, so the duplicates
        // never need to be usable.
        let cap = super::DEFAULT_MAX_RECIPIENTS;
        let mut v: serde_json::Value = serde_json::from_str(&anon).unwrap();
        let entry = v["recipients"][0].clone();
        let recips = v["recipients"].as_array_mut().unwrap();
        while recips.len() <= cap {
            recips.push(entry.clone());
        }
        let stuffed = serde_json::to_string(&v).unwrap();

        let recipient = create_atm_with_policy(
            vec![rx],
            UnpackPolicy {
                expected: vec![MessageWrappingType::AnoncryptPlaintext],
                validate_addressing_consistency: false,
                max_signatures: 1,
                max_recipients: cap,
            },
        )
        .await;

        let err = recipient.unpack(&stuffed).await.unwrap_err();
        assert!(
            matches!(&err, ATMError::UnexpectedEnvelope(m) if m.contains("policy maximum")),
            "too many recipients must be rejected on count, got: {err:?}"
        );
    }

    /// The `max_recipients` policy cap rejects a JWE addressing more recipients
    /// than allowed; raising the cap accepts and decrypts it.
    #[tokio::test]
    async fn max_recipients_policy_caps_count() {
        let (sender_did, _sed, _sx) = generate_peer_did_full();
        let (recipient_did, _red, rx) = generate_peer_did_full();

        let plaintext = build_plaintext(&sender_did, &recipient_did);
        let anon = anoncrypt(
            plaintext.as_bytes(),
            &[(&format!("{recipient_did}#key-2"), &x25519_pub(&rx))],
        )
        .unwrap();

        // Duplicate the (valid) recipient entry so the JWE lists two recipients.
        let mut v: serde_json::Value = serde_json::from_str(&anon).unwrap();
        let entry = v["recipients"][0].clone();
        v["recipients"].as_array_mut().unwrap().push(entry);
        let two_recipients = serde_json::to_string(&v).unwrap();

        // A cap of 1 rejects the two-recipient message.
        let strict = create_atm_with_policy(
            vec![rx.clone()],
            UnpackPolicy {
                expected: vec![MessageWrappingType::AnoncryptPlaintext],
                validate_addressing_consistency: false,
                max_signatures: 1,
                max_recipients: 1,
            },
        )
        .await;
        let err = strict.unpack(&two_recipients).await.unwrap_err();
        assert!(
            matches!(&err, ATMError::UnexpectedEnvelope(m) if m.contains("policy maximum")),
            "two recipients must exceed a max_recipients=1 policy, got: {err:?}"
        );

        // Raising the cap to 2 accepts and decrypts the same message.
        let lenient = create_atm_with_policy(
            vec![rx],
            UnpackPolicy {
                expected: vec![MessageWrappingType::AnoncryptPlaintext],
                validate_addressing_consistency: false,
                max_signatures: 1,
                max_recipients: 2,
            },
        )
        .await;
        let (_msg, meta) = lenient
            .unpack(&two_recipients)
            .await
            .expect("a cap of 2 accepts two recipients");
        assert_eq!(meta.wrapping, MessageWrappingType::AnoncryptPlaintext);
    }

    /// EXPERIMENT (not committed): unpack Dart-generated messages for every
    /// IANA wrapping type. Requires files under /tmp/didcomm-interop produced
    /// by the Dart `tool/interop_gen.dart`. Run with:
    ///   cargo test -p affinidi-messaging-sdk dart_interop_unpack_all -- --nocapture --ignored
    #[tokio::test]
    #[ignore = "manual cross-impl interop experiment"]
    async fn dart_interop_unpack_all() {
        use std::fs;
        let dir = "/tmp/didcomm-interop";
        let keys: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(format!("{dir}/keys.json")).unwrap()).unwrap();
        let kid = keys["recipient_ka_kid"].as_str().unwrap();
        let jwk = &keys["recipient_private_jwk"];
        let secret = Secret::from_str(kid, jwk).expect("import recipient JWK");
        println!("imported recipient secret id={}", secret.id);

        // Cross-impl *crypto* interop: accept every wrapping so this exercises
        // decrypt/verify for all 7 IANA types (the secure default's wrapping
        // allow-list is covered by dedicated tests, not this experiment).
        let atm = create_atm_with_policy(
            vec![secret],
            UnpackPolicy {
                expected: vec![
                    MessageWrappingType::Plaintext,
                    MessageWrappingType::SignedPlaintext,
                    MessageWrappingType::AnoncryptPlaintext,
                    MessageWrappingType::AuthcryptPlaintext,
                    MessageWrappingType::AnoncryptSignPlaintext,
                    MessageWrappingType::AuthcryptSignPlaintext,
                    MessageWrappingType::AnoncryptAuthcryptPlaintext,
                ],
                validate_addressing_consistency: false,
                max_signatures: 5,
                max_recipients: 100,
            },
        )
        .await;

        let files = [
            "1_plaintext",
            "2_signed",
            "3_anoncrypt",
            "4_authcrypt",
            "5_anoncrypt_sign",
            "6_authcrypt_sign",
            "7_anoncrypt_authcrypt",
        ];
        let mut ok = 0;
        for f in files {
            let msg = fs::read_to_string(format!("{dir}/{f}.json")).unwrap();
            match atm.unpack(&msg).await {
                Ok((m, meta)) => {
                    ok += 1;
                    println!(
                        "OK   {f:22} wrapping={:?} enc={} auth={} non_repud={} anon_sender={} signers={:?} body={}",
                        meta.wrapping,
                        meta.encrypted,
                        meta.authenticated,
                        meta.non_repudiation,
                        meta.anonymous_sender,
                        meta.signers,
                        m.body,
                    );
                }
                Err(e) => println!("FAIL {f:22} {e}"),
            }
        }
        println!("=== {ok}/{} unpacked ===", files.len());
    }

    /// EXPERIMENT (not committed): Rust generates one DIDComm message per IANA
    /// wrapping type addressed to a Dart-generated recipient did:peer, for
    /// cross-validation by the Dart lib. Reads /tmp/didcomm-interop-rev/
    /// recipient.json (written by the Dart `tool/interop_rev.dart gen`) and
    /// writes the packed messages + sender_did back to the same directory.
    /// Run with:
    ///   cargo test -p affinidi-messaging-sdk rust_interop_generate_all -- --nocapture --ignored
    #[tokio::test]
    #[ignore = "manual cross-impl interop experiment"]
    async fn rust_interop_generate_all() {
        use affinidi_did_common::DocumentExt;
        use std::fs;

        let dir = "/tmp/didcomm-interop-rev";
        let recipient: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(format!("{dir}/recipient.json")).unwrap())
                .unwrap();
        let recipient_did = recipient["recipient_did"].as_str().unwrap().to_string();

        // Resolve the recipient's P-256 key-agreement key from its DID document.
        let recipient_doc = recipient_did.parse::<DID>().unwrap().resolve().unwrap();
        let recipient_kid = recipient_doc
            .find_key_agreement(None)
            .first()
            .copied()
            .expect("recipient has a key-agreement key")
            .to_string();
        let recipient_vm = recipient_doc
            .get_verification_method(&recipient_kid)
            .unwrap();
        let recipient_mb = recipient_vm
            .property_set
            .get("publicKeyMultibase")
            .unwrap()
            .as_str()
            .unwrap();
        let (codec, recipient_key_bytes) =
            affinidi_encoding::decode_multikey_with_codec(recipient_mb).unwrap();
        assert_eq!(
            codec,
            affinidi_encoding::P256_PUB,
            "recipient KA must be P-256"
        );
        let recipient_pub =
            PublicKeyAgreement::from_raw_bytes(Curve::P256, &recipient_key_bytes).unwrap();

        // Generate a P-256 sender did:peer: V (#key-1, ES256 signing) +
        // E (#key-2, ECDH key agreement).
        let v = Secret::generate_p256(Some("temp"), None).unwrap();
        let e = Secret::generate_p256(Some("temp"), None).unwrap();
        let keys = vec![
            PeerCreateKey::from_multibase(
                PeerKeyPurpose::Verification,
                v.get_public_keymultibase().unwrap(),
            ),
            PeerCreateKey::from_multibase(
                PeerKeyPurpose::Encryption,
                e.get_public_keymultibase().unwrap(),
            ),
        ];
        let (sender_did_parsed, _) = DID::generate_peer(&keys, None).unwrap();
        let sender_did = sender_did_parsed.to_string();
        let sign_kid = format!("{sender_did}#key-1");
        let skid = format!("{sender_did}#key-2");
        let sender_ka_priv =
            PrivateKeyAgreement::from_raw_bytes(Curve::P256, e.get_private_bytes()).unwrap();
        let sign_priv: [u8; 32] = v.get_private_bytes().try_into().unwrap();
        let signer = JwsSigner::P256 {
            kid: &sign_kid,
            private: &sign_priv,
        };

        let plaintext = build_plaintext(&sender_did, &recipient_did);
        // Anoncrypt is anonymous: the DIDComm spec (and the Dart lib) require
        // the inner plaintext `from` to be absent for a pure anoncrypt wrapping.
        let plaintext_anon = {
            let msg = DcMessage::build(
                "layered-1".to_string(),
                "example/v1".to_string(),
                json!({"hello": "layered"}),
            )
            .to(recipient_did.clone())
            .finalize();
            serde_json::to_string(&msg).unwrap()
        };
        let recips: &[(&str, &PublicKeyAgreement)] = &[(&recipient_kid, &recipient_pub)];

        let write = |name: &str, contents: &str| {
            fs::write(format!("{dir}/{name}.json"), contents).unwrap();
            println!("wrote {name}");
        };

        // 1. plaintext
        write("1_plaintext", &plaintext);
        // 2. signed(plaintext) — `sign_multi` now emits `kid` in both the
        // protected and the unprotected header, so the Dart lib (which reads
        // the unprotected `header.kid`) can attribute the signer with no
        // post-processing.
        let signed = sign_multi(plaintext.as_bytes(), &[signer]).unwrap();
        write("2_signed", &signed);
        // 3. anoncrypt(plaintext) — anonymous, so `from` is omitted.
        write(
            "3_anoncrypt",
            &anoncrypt(plaintext_anon.as_bytes(), recips).unwrap(),
        );
        // 4. authcrypt(plaintext)
        write(
            "4_authcrypt",
            &authcrypt(plaintext.as_bytes(), &skid, &sender_ka_priv, recips).unwrap(),
        );
        // 5. anoncrypt(sign(plaintext))
        write(
            "5_anoncrypt_sign",
            &anoncrypt(signed.as_bytes(), recips).unwrap(),
        );
        // 6. authcrypt(sign(plaintext))
        write(
            "6_authcrypt_sign",
            &authcrypt(signed.as_bytes(), &skid, &sender_ka_priv, recips).unwrap(),
        );
        // 7. anoncrypt(authcrypt(plaintext))
        let inner = authcrypt(plaintext.as_bytes(), &skid, &sender_ka_priv, recips).unwrap();
        write(
            "7_anoncrypt_authcrypt",
            &anoncrypt(inner.as_bytes(), recips).unwrap(),
        );

        fs::write(
            format!("{dir}/sender.json"),
            serde_json::to_string(&json!({"sender_did": sender_did})).unwrap(),
        )
        .unwrap();
        println!("sender_did={sender_did}");
        println!("recipient_kid={recipient_kid}");
        println!("GENERATE DONE");
    }
}
