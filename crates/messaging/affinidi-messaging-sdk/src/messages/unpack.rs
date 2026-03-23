use crate::{ATM, SharedState, errors::ATMError, messages::compat::UnpackMetadata};
use affinidi_messaging_didcomm::message::Message;
use affinidi_secrets_resolver::SecretsResolver;
use base64::{Engine, prelude::BASE64_URL_SAFE};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{Instrument, Level, debug, span, warn};

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

impl SharedState {
    pub async fn unpack(&self, message: &str) -> Result<(Message, UnpackMetadata), ATMError> {
        let _span = span!(Level::DEBUG, "unpack",);

        async move {
            let mut msg_string = message.to_string();

            loop {
                // Compute SHA-256 hash of the packed message
                let sha256_hash = sha256::digest(&msg_string);

                // Parse as JSON to detect format
                let value: serde_json::Value =
                    serde_json::from_str(&msg_string).map_err(|e| {
                        ATMError::DidcommError(
                            "Cannot parse message as JSON".into(),
                            e.to_string(),
                        )
                    })?;

                let (msg, metadata) = if value.get("ciphertext").is_some()
                    && value.get("recipients").is_some()
                {
                    // JWE — encrypted message
                    self.unpack_jwe(&msg_string, &value, &sha256_hash).await?
                } else if value.get("payload").is_some() && value.get("signatures").is_some()
                {
                    // JWS — signed message (not yet fully supported, parse plaintext from payload)
                    self.unpack_jws(&msg_string, &sha256_hash)?
                } else if value.get("type").is_some() {
                    // Plaintext DIDComm message
                    let msg = Message::from_json(msg_string.as_bytes()).map_err(|e| {
                        ATMError::DidcommError(
                            "Cannot parse plaintext message".into(),
                            e.to_string(),
                        )
                    })?;
                    let metadata = UnpackMetadata {
                        sha256_hash,
                        ..Default::default()
                    };
                    (msg, metadata)
                } else {
                    return Err(ATMError::DidcommError(
                        "Cannot detect message format".into(),
                        "expected JWE, JWS, or plaintext".into(),
                    ));
                };

                debug!("message unpacked:\n{:#?}", msg);

                if self.config.unpack_forwards
                    && msg.typ == "https://didcomm.org/routing/2.0/forward"
                {
                    // Extract the inner message and loop to unpack it
                    msg_string = Self::extract_forward_payload(&msg)?;
                } else {
                    return Ok((msg, metadata));
                }
            }
        }
        .instrument(_span)
        .await
    }

    /// Unpack a JWE (encrypted) message
    async fn unpack_jwe(
        &self,
        msg_string: &str,
        value: &serde_json::Value,
        sha256_hash: &str,
    ) -> Result<(Message, UnpackMetadata), ATMError> {
        use affinidi_messaging_didcomm::crypto::key_agreement::{Curve, PrivateKeyAgreement};
        use affinidi_messaging_didcomm::jwe::decrypt::decrypt;

        // Extract recipient KIDs from the JWE
        let recipients = value["recipients"]
            .as_array()
            .ok_or_else(|| {
                ATMError::DidcommError(
                    "Invalid JWE".into(),
                    "no recipients array".into(),
                )
            })?;

        // Find a local secret matching one of the recipient KIDs
        let mut recipient_kid_str = String::new();
        let mut recipient_private: Option<PrivateKeyAgreement> = None;

        for recipient in recipients {
            if let Some(kid) = recipient["header"]["kid"].as_str() {
                if let Some(secret) = self
                    .tdk_common
                    .secrets_resolver
                    .get_secret(kid)
                    .await
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
        }

        let recipient_private = recipient_private.ok_or_else(|| {
            ATMError::DidcommError(
                "Couldn't unpack incoming message".into(),
                "no local secret matches any JWE recipient".into(),
            )
        })?;

        // Try to detect sender for authcrypt
        // Check if there is a skid (sender key ID) in the protected header
        let sender_public = self.try_resolve_sender_public(msg_string).await;

        let decrypted = decrypt(
            msg_string,
            &recipient_kid_str,
            &recipient_private,
            sender_public.as_ref(),
        )
        .map_err(|e| {
            ATMError::DidcommError(
                "Couldn't unpack incoming message".into(),
                e.to_string(),
            )
        })?;

        let msg = Message::from_json(&decrypted.plaintext).map_err(|e| {
            ATMError::DidcommError(
                "Cannot parse decrypted message".into(),
                e.to_string(),
            )
        })?;

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

    /// Try to resolve the sender's public key from the JWE protected header's `skid` field
    async fn try_resolve_sender_public(
        &self,
        jwe_str: &str,
    ) -> Option<affinidi_messaging_didcomm::crypto::key_agreement::PublicKeyAgreement> {
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

        // Resolve the sender DID and get their key agreement public key
        let sender_doc = self.tdk_common.did_resolver.resolve(sender_did).await.ok()?;
        let sender_ka_kids = sender_doc.doc.find_key_agreement(None);
        let sender_kid = sender_ka_kids.first()?;

        // Use the resolve_public_key_agreement logic inline
        use affinidi_did_common::{document::DocumentExt, verification_method::VerificationRelationship};

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
            return affinidi_messaging_didcomm::crypto::key_agreement::PublicKeyAgreement::from_jwk(jwk_value).ok();
        }

        if let Some(multibase_value) = vm.property_set.get("publicKeyMultibase")
            && let Some(multibase_str) = multibase_value.as_str()
        {
            let (codec, key_bytes) = affinidi_encoding::decode_multikey_with_codec(multibase_str).ok()?;
            let curve = match codec {
                affinidi_encoding::X25519_PUB => affinidi_messaging_didcomm::crypto::key_agreement::Curve::X25519,
                affinidi_encoding::P256_PUB => affinidi_messaging_didcomm::crypto::key_agreement::Curve::P256,
                affinidi_encoding::SECP256K1_PUB => affinidi_messaging_didcomm::crypto::key_agreement::Curve::K256,
                _ => return None,
            };
            return affinidi_messaging_didcomm::crypto::key_agreement::PublicKeyAgreement::from_raw_bytes(curve, &key_bytes).ok();
        }

        None
    }

    /// Unpack a JWS (signed) message — basic support
    fn unpack_jws(
        &self,
        _msg_string: &str,
        sha256_hash: &str,
    ) -> Result<(Message, UnpackMetadata), ATMError> {
        // For JWS, we parse the payload directly without verification for now
        // Full JWS verification would require resolving the signer's public key
        let value: serde_json::Value = serde_json::from_str(_msg_string).map_err(|e| {
            ATMError::DidcommError("Cannot parse JWS".into(), e.to_string())
        })?;

        let payload_b64 = value["payload"]
            .as_str()
            .ok_or_else(|| {
                ATMError::DidcommError("Invalid JWS".into(), "missing payload".into())
            })?;

        use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
        let payload_bytes = BASE64_URL_SAFE_NO_PAD.decode(payload_b64).map_err(|e| {
            ATMError::DidcommError("Invalid JWS".into(), format!("invalid payload base64: {e}"))
        })?;

        let msg = Message::from_json(&payload_bytes).map_err(|e| {
            ATMError::DidcommError("Cannot parse JWS payload".into(), e.to_string())
        })?;

        let metadata = UnpackMetadata {
            non_repudiation: true,
            sha256_hash: sha256_hash.to_string(),
            ..Default::default()
        };

        Ok((msg, metadata))
    }

    pub async fn unpack_forward(
        &self,
        message: &Message,
    ) -> Result<(Message, UnpackMetadata), ATMError> {
        let _span = span!(Level::DEBUG, "unpack_forward",);

        async move {
            debug!("Attempting to unpack a forwarded message");
            let inner = Self::extract_forward_payload(message)?;
            self.unpack(&inner).await
        }
        .instrument(_span)
        .await
    }

    /// Extracts the inner message string from a forward message's attachment.
    /// Checks expiry and supports JSON and Base64 attachment formats.
    pub(crate) fn extract_forward_payload(message: &Message) -> Result<String, ATMError> {
        debug!("Extracting payload from forwarded message");

        // Check expiry time if it exists
        if let Some(expires_time) = message.expires_time {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            if expires_time <= now {
                return Err(ATMError::MsgReceiveError(String::from(
                    "Forwarded Message has expired and cannot be processed",
                )));
            }
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
    use affinidi_messaging_didcomm::message::{Attachment, AttachmentData};
    use affinidi_tdk_common::TDKSharedState;
    use serde_json::json;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    const FORWARD_TYPE: &str = "https://didcomm.org/routing/2.0/forward";

    /// Creates an ATM instance with default config (unpack_forwards=true).
    async fn create_atm() -> ATM {
        let config = ATMConfig::builder().build().unwrap();
        let tdk = Arc::new(TDKSharedState::default().await);
        ATM::new(config, tdk).await.unwrap()
    }

    /// Creates an ATM instance with unpack_forwards disabled.
    async fn create_atm_no_unpack_forwards() -> ATM {
        let config = ATMConfig::builder()
            .with_unpack_forwards(false)
            .build()
            .unwrap();
        let tdk = Arc::new(TDKSharedState::default().await);
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
        let attachment = Attachment::json(inner_value).id("fwd-1".to_string()).finalize();
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
        let attachment = Attachment::base64(encoded).id("fwd-1".to_string()).finalize();
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

        let extracted = SharedState::extract_forward_payload(&forward).unwrap();

        let extracted_value: serde_json::Value = serde_json::from_str(&extracted).unwrap();
        let inner_value: serde_json::Value = serde_json::from_str(&inner_json).unwrap();
        assert_eq!(extracted_value, inner_value);
    }

    #[test]
    fn extract_forward_payload_base64() {
        let inner = make_inner_message();
        let inner_json = make_plaintext_json(&inner);
        let forward = wrap_in_forward_base64(&inner_json, None);

        let extracted = SharedState::extract_forward_payload(&forward).unwrap();

        assert_eq!(extracted, inner_json);
    }

    #[test]
    fn extract_forward_payload_expired() {
        let inner = make_inner_message();
        let inner_json = make_plaintext_json(&inner);
        let forward = wrap_in_forward_json(&inner_json, Some(1));

        let result = SharedState::extract_forward_payload(&forward);

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
        let future = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        let forward = wrap_in_forward_json(&inner_json, Some(future));

        let result = SharedState::extract_forward_payload(&forward);

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

        let result = SharedState::extract_forward_payload(&msg);

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

        let result = SharedState::extract_forward_payload(&msg);

        assert!(result.is_err());
        assert!(
            matches!(&result.unwrap_err(), ATMError::MsgReceiveError(msg) if msg.contains("no attachments")),
            "Expected MsgReceiveError mentioning no attachments"
        );
    }

    #[test]
    fn extract_forward_payload_unsupported_format() {
        let attachment =
            Attachment::links(vec!["https://example.com/msg".to_string()], "abc123hash".to_string())
                .id("fwd-link".to_string())
                .finalize();
        let msg = Message::build(
            "fwd-links".to_string(),
            FORWARD_TYPE.to_string(),
            json!({"next": "did:example:recipient"}),
        )
        .attachment(attachment)
        .finalize();

        let result = SharedState::extract_forward_payload(&msg);

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

        let result = SharedState::extract_forward_payload(&msg);

        assert!(result.is_err());
        assert!(
            matches!(&result.unwrap_err(), ATMError::MsgReceiveError(msg) if msg.contains("cannot be decoded")),
            "Expected MsgReceiveError mentioning decode failure"
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

        let result = SharedState::extract_forward_payload(&msg);

        assert!(result.is_err());
        assert!(
            matches!(&result.unwrap_err(), ATMError::MsgReceiveError(msg) if msg.contains("cannot be converted to a UTF-8 string")),
            "Expected MsgReceiveError mentioning UTF-8 conversion failure"
        );
    }
}
