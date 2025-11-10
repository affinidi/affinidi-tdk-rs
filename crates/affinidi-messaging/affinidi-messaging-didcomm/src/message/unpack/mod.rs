use crate::{
    FromPrior, Message,
    algorithms::{AnonCryptAlg, AuthCryptAlg, SignAlg},
    document::did_or_url,
    envelope::{Envelope, MetaEnvelope, ParsedEnvelope},
    error::{ErrorKind, Result, ResultExt, err_msg},
    jws::Jws,
    message::unpack::plaintext::_try_unpack_plaintext,
    protocols::routing::try_parse_forward,
};
use affinidi_did_common::verification_method::VerificationRelationship;
use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_secrets_resolver::SecretsResolver;
use anoncrypt::_try_unpack_anoncrypt;
use authcrypt::_try_unpack_authcrypt;
use serde::{Deserialize, Serialize};
use sign::_try_unpack_sign;
use std::str::FromStr;
use tracing::debug;

mod anoncrypt;
mod authcrypt;
mod plaintext;
mod sign;

impl Message {
    pub async fn unpack_string<T>(
        msg: &str,
        did_resolver: &DIDCacheClient,
        secrets_resolver: &T,
        options: &UnpackOptions,
    ) -> Result<(Message, UnpackMetadata)>
    where
        T: SecretsResolver,
    {
        let mut envelope = MetaEnvelope::new(msg, did_resolver).await?;

        Self::unpack(&mut envelope, did_resolver, secrets_resolver, options).await
    }
    /// Unpacks the packed message by doing decryption and verifying the signatures.
    /// This method supports all DID Comm message types (encrypted, signed, plaintext).
    ///
    /// If unpack options expect a particular property (for example that a message is encrypted)
    /// and the packed message doesn't meet the criteria (it's not encrypted), then a MessageUntrusted
    /// error will be returned.
    ///
    /// # Params
    /// - `packed_msg` the message as JSON string to be unpacked
    /// - `did_resolver` instance of `DIDResolver` to resolve DIDs
    /// - `secrets_resolver` instance of SecretsResolver` to resolve sender DID keys secrets
    /// - `options` allow fine configuration of unpacking process and imposing additional restrictions
    ///   to message to be trusted.
    ///
    /// # Returns
    /// Tuple `(message, metadata)`.
    /// - `message` plain message instance
    /// - `metadata` additional metadata about this `unpack` execution like used keys identifiers,
    ///   trust context, algorithms and etc.
    ///
    /// # Errors
    /// - `DIDNotResolved` Sender or recipient DID not found.
    /// - `DIDUrlNotFound` DID doesn't contain mentioned DID Urls (for ex., key id)
    /// - `MessageMalformed` message doesn't correspond to DID Comm or has invalid encryption or signatures.
    /// - `Unsupported` Used crypto or method is unsupported.
    /// - `SecretNotFound` No recipient secrets found.
    /// - `InvalidState` Indicates library error.
    /// - `IOError` IO error during DID or secrets resolving.
    ///
    /// TODO: verify and update errors list
    pub async fn unpack<T>(
        envelope: &mut MetaEnvelope,
        did_resolver: &DIDCacheClient,
        secrets_resolver: &T,
        options: &UnpackOptions,
    ) -> Result<(Message, UnpackMetadata)>
    where
        T: SecretsResolver,
    {
        let mut anoncrypted: Option<ParsedEnvelope>;

        let mut parsed_jwe = if let Some(parsed) = &envelope.parsed_envelope {
            parsed.clone()
        } else {
            return Err(err_msg(
                ErrorKind::InvalidState,
                "Parsed envelope not found",
            ));
        };

        let mut crypto_operations_count: usize = 0;

        loop {
            crypto_operations_count += 1;
            if crypto_operations_count >= options.crypto_operations_limit_per_message {
                return Err(err_msg(
                    ErrorKind::TooManyCryptoOperations,
                    format!(
                        "Limit is reached. limit = {}, executed crypto operations {}",
                        options.crypto_operations_limit_per_message, crypto_operations_count
                    ),
                ));
            }
            anoncrypted =
                _try_unpack_anoncrypt(&parsed_jwe, secrets_resolver, options, envelope).await?;

            if options.unwrap_re_wrapping_forward && anoncrypted.is_some() {
                let forwarded_msg_opt = Self::_try_unwrap_forwarded_message(
                    &anoncrypted.clone().unwrap(),
                    did_resolver,
                    secrets_resolver,
                )
                .await?;

                if let Some(forwarded_msg) = forwarded_msg_opt {
                    envelope.metadata.re_wrapped_in_forward = true;

                    parsed_jwe = Envelope::from_str(&forwarded_msg)?
                        .parse()?
                        .verify_didcomm()?;
                    continue;
                }
            }

            break;
        }

        let parsed_jwe = anoncrypted.clone().unwrap_or(parsed_jwe);

        debug!("metadata = {:#?}", envelope.metadata);

        let authcrypted = _try_unpack_authcrypt(
            &parsed_jwe,
            did_resolver,
            secrets_resolver,
            options,
            envelope,
            crypto_operations_count,
        )
        .await?;

        let parsed_jwe = authcrypted.unwrap_or(parsed_jwe);

        let signed = _try_unpack_sign(&parsed_jwe, did_resolver, options, envelope).await?;
        let parsed_jwe = signed.unwrap_or(parsed_jwe);

        let msg = _try_unpack_plaintext(&parsed_jwe, did_resolver, envelope)
            .await?
            .ok_or_else(|| {
                err_msg(
                    ErrorKind::Malformed,
                    "Message is not a valid JWE, JWS or JWM",
                )
            })?;

        // Check Message Layer Addressing Consistency
        if let Some(skid) = envelope.metadata.encrypted_from_kid.as_ref() {
            // Encrypted message, must have a from field
            if let Some(from) = msg.from.as_ref() {
                if !skid.starts_with(from) {
                    return Err(err_msg(
                        ErrorKind::InvalidState,
                        format!(
                            "Message 'from' ({from}) doesn't match encrypted_from_kid ({skid})"
                        ),
                    ));
                }
            } else {
                return Err(err_msg(
                    ErrorKind::InvalidState,
                    "Encrypted message must have 'from' field",
                ));
            }
        }

        if envelope.metadata.encrypted {
            let Some(to) = msg.to.as_ref() else {
                return Err(err_msg(
                    ErrorKind::InvalidState,
                    "Encrypted message must have 'to' field",
                ));
            };
            let mut found_flag = false;
            for kid in envelope.metadata.encrypted_to_kids.iter() {
                let Some((did, _)) = kid.split_once("#") else {
                    return Err(err_msg(
                        ErrorKind::InvalidState,
                        format!("Invalid encrypted_to_kids ({kid})"),
                    ));
                };

                if to.contains(&did.to_string()) {
                    found_flag = true;
                    break;
                }
            }
            if !found_flag {
                return Err(err_msg(
                    ErrorKind::InvalidState,
                    format!(
                        "Message 'to' doesn't match encrypted_to_kids ({})",
                        envelope.metadata.encrypted_to_kids.join(", ")
                    ),
                ));
            }
        }

        if let Some(skid) = envelope.metadata.sign_from.as_ref() {
            // Signed message, must have a from field
            if let Some(from) = msg.from.as_ref() {
                if !skid.starts_with(from) {
                    return Err(err_msg(
                        ErrorKind::InvalidState,
                        format!(
                            "Message 'from' ({from}) doesn't match sign_from ({skid})"
                        ),
                    ));
                }
            } else {
                return Err(err_msg(
                    ErrorKind::InvalidState,
                    "Signed message must have 'from' field",
                ));
            }
        }

        envelope.metadata.sha256_hash = envelope.sha256_hash.clone();

        Ok((msg, envelope.metadata.to_owned()))
    }

    async fn _try_unwrap_forwarded_message<T>(
        msg: &ParsedEnvelope,
        did_resolver: &DIDCacheClient,
        secrets_resolver: &T,
    ) -> Result<Option<String>>
    where
        T: SecretsResolver,
    {
        let plaintext = match msg {
            ParsedEnvelope::Message(m) => m.clone(),
            _ => return Ok(None),
        };

        if let Some(forward_msg) = try_parse_forward(&plaintext)
            && has_key_agreement_secret(&forward_msg.next, did_resolver, secrets_resolver).await?
        {
            // TODO: Think how to avoid extra serialization of forwarded_msg here.
            // (This serializtion is a double work because forwarded_msg will then
            // be deserialized in _try_unpack_anoncrypt.)
            let forwarded_msg = serde_json::to_string(&forward_msg.forwarded_msg).kind(
                ErrorKind::InvalidState,
                "Unable serialize forwarded message",
            )?;

            return Ok(Some(forwarded_msg));
        }
        Ok(None)
    }
}

/// Allows fine customization of unpacking process
#[derive(Debug, PartialEq, Eq, Deserialize, Clone)]
pub struct UnpackOptions {
    /// Whether the plaintext must be decryptable by all keys resolved by the secrets resolver. False by default.
    #[serde(default)]
    pub expect_decrypt_by_all_keys: bool,

    /// If `true` and the packed message is a `Forward`
    /// wrapping a plaintext packed for the given recipient, then both Forward and packed plaintext are unpacked automatically,
    /// and the unpacked plaintext will be returned instead of unpacked Forward.
    /// False by default.
    #[serde(default)]
    pub unwrap_re_wrapping_forward: bool,

    /// the amount of crypto operations per unpack operation
    /// default is 1_000 but can be updated
    pub crypto_operations_limit_per_message: usize,
}

impl Default for UnpackOptions {
    fn default() -> Self {
        UnpackOptions {
            expect_decrypt_by_all_keys: false,
            unwrap_re_wrapping_forward: true,
            crypto_operations_limit_per_message: 1_000,
        }
    }
}

/// Additional metadata about this `unpack` method execution like trust predicates
/// and used keys identifiers.
#[derive(Debug, Default, PartialEq, Eq, Clone, Deserialize, Serialize)]
pub struct UnpackMetadata {
    /// Whether the plaintext has been encrypted
    pub encrypted: bool,

    /// Whether the plaintext has been authenticated
    pub authenticated: bool,

    /// Whether the plaintext has been signed
    pub non_repudiation: bool,

    /// Whether the sender ID was hidden or protected
    pub anonymous_sender: bool,

    /// Whether the plaintext was re-wrapped in a forward message by a mediator
    pub re_wrapped_in_forward: bool,

    /// Sha256 hash of the original message, used by mediators when they can't see message.id's
    pub sha256_hash: String,

    /// Key ID of the sender used for authentication encryption if the plaintext has been authenticated and encrypted
    pub encrypted_from_kid: Option<String>,

    /// Target key IDS for encryption if the plaintext has been encrypted
    pub encrypted_to_kids: Vec<String>,

    /// Key ID used for signature if the plaintext has been signed
    pub sign_from: Option<String>,

    /// Key ID used for from_prior header signature if from_prior header is present
    pub from_prior_issuer_kid: Option<String>,

    /// Algorithm used for authenticated encryption
    pub enc_alg_auth: Option<AuthCryptAlg>,

    /// Algorithm used for anonymous encryption
    pub enc_alg_anon: Option<AnonCryptAlg>,

    /// Algorithm used for message signing
    pub sign_alg: Option<SignAlg>,

    /// If the plaintext has been signed, the JWS is returned for non-repudiation purposes
    pub signed_message: Option<Jws>,

    /// If plaintext contains from_prior header, its unpacked value is returned
    pub from_prior: Option<FromPrior>,
}

async fn has_key_agreement_secret<T>(
    did_or_kid: &str,
    did_resolver: &DIDCacheClient,
    secrets_resolver: &T,
) -> Result<bool>
where
    T: SecretsResolver,
{
    let kids = match did_or_url(did_or_kid) {
        (_, Some(kid)) => {
            vec![kid.to_string()]
        }
        (did, None) => {
            let did_doc = match did_resolver.resolve(did).await {
                Ok(result) => result.doc,
                Err(e) => {
                    return Err(err_msg(
                        ErrorKind::DIDNotResolved,
                        format!("Couldn't resolve did({did}). Reason: {e}"),
                    ));
                }
            };
            did_doc
                .key_agreement
                .iter()
                .map(|key| match key {
                    VerificationRelationship::Reference(url) => url.to_string(),
                    VerificationRelationship::VerificationMethod(vm) => vm.id.to_string(),
                })
                .collect()
        }
    };

    let secrets_ids = secrets_resolver.find_secrets(&kids).await;
    Ok(!secrets_ids.is_empty())
}

/*
#[cfg(test)]
mod test {
    use tracing::debug;
    use tracing_test::traced_test;

    use crate::{
        did::resolvers::ExampleDIDResolver,
        message::MessagingServiceMetadata,
        protocols::routing::wrap_in_forward,
        secrets::resolvers::ExampleSecretsResolver,
        test_vectors::{
            remove_field, remove_protected_field, update_field, update_protected_field,
            ALICE_AUTH_METHOD_25519, ALICE_AUTH_METHOD_P256, ALICE_AUTH_METHOD_SECPP256K1,
            ALICE_DID, ALICE_DID_DOC, ALICE_SECRETS, ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256,
            ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519, BOB_DID, BOB_DID_COMM_MESSAGING_SERVICE,
            BOB_DID_DOC, BOB_SECRETS, BOB_SECRET_KEY_AGREEMENT_KEY_P256_1,
            BOB_SECRET_KEY_AGREEMENT_KEY_P256_2, BOB_SECRET_KEY_AGREEMENT_KEY_X25519_1,
            BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2, BOB_SECRET_KEY_AGREEMENT_KEY_X25519_3,
            BOB_SERVICE, CHARLIE_AUTH_METHOD_25519, CHARLIE_DID_DOC, ENCRYPTED_MSG_ANON_XC20P_1,
            ENCRYPTED_MSG_ANON_XC20P_2, ENCRYPTED_MSG_AUTH_P256, ENCRYPTED_MSG_AUTH_P256_SIGNED,
            ENCRYPTED_MSG_AUTH_X25519, FROM_PRIOR_FULL,
            INVALID_ENCRYPTED_MSG_ANON_P256_EPK_WRONG_POINT,
            INVALID_PLAINTEXT_MSG_ATTACHMENTS_AS_INT_ARRAY,
            INVALID_PLAINTEXT_MSG_ATTACHMENTS_AS_STRING,
            INVALID_PLAINTEXT_MSG_ATTACHMENTS_EMPTY_DATA,
            INVALID_PLAINTEXT_MSG_ATTACHMENTS_LINKS_NO_HASH,
            INVALID_PLAINTEXT_MSG_ATTACHMENTS_NO_DATA, INVALID_PLAINTEXT_MSG_ATTACHMENTS_NULL_DATA,
            INVALID_PLAINTEXT_MSG_ATTACHMENTS_WRONG_DATA,
            INVALID_PLAINTEXT_MSG_ATTACHMENTS_WRONG_ID, INVALID_PLAINTEXT_MSG_EMPTY,
            INVALID_PLAINTEXT_MSG_EMPTY_ATTACHMENTS, INVALID_PLAINTEXT_MSG_NO_BODY,
            INVALID_PLAINTEXT_MSG_NO_ID, INVALID_PLAINTEXT_MSG_NO_TYPE,
            INVALID_PLAINTEXT_MSG_STRING, INVALID_PLAINTEXT_MSG_WRONG_TYP, MEDIATOR1_DID_DOC,
            MEDIATOR1_SECRETS, MESSAGE_ATTACHMENT_BASE64, MESSAGE_ATTACHMENT_JSON,
            MESSAGE_ATTACHMENT_LINKS, MESSAGE_ATTACHMENT_MULTI_1, MESSAGE_ATTACHMENT_MULTI_2,
            MESSAGE_FROM_PRIOR_FULL, MESSAGE_MINIMAL, MESSAGE_SIMPLE, PLAINTEXT_FROM_PRIOR,
            PLAINTEXT_FROM_PRIOR_INVALID_SIGNATURE, PLAINTEXT_INVALID_FROM_PRIOR,
            PLAINTEXT_MSG_ATTACHMENT_BASE64, PLAINTEXT_MSG_ATTACHMENT_JSON,
            PLAINTEXT_MSG_ATTACHMENT_LINKS, PLAINTEXT_MSG_ATTACHMENT_MULTI_1,
            PLAINTEXT_MSG_ATTACHMENT_MULTI_2, PLAINTEXT_MSG_MINIMAL, PLAINTEXT_MSG_SIMPLE,
            PLAINTEXT_MSG_SIMPLE_NO_TYP, SIGNED_MSG_ALICE_KEY_1, SIGNED_MSG_ALICE_KEY_2,
            SIGNED_MSG_ALICE_KEY_3,
        },
        PackEncryptedOptions,
    };

    use super::*;

    #[tokio::test]
    async fn unpack_works_plaintext() {
        let plaintext_metadata = UnpackMetadata {
            anonymous_sender: false,
            authenticated: false,
            non_repudiation: false,
            encrypted: false,
            enc_alg_auth: None,
            enc_alg_anon: None,
            sign_alg: None,
            encrypted_from_kid: None,
            encrypted_to_kids: None,
            sign_from: None,
            signed_message: None,
            from_prior_issuer_kid: None,
            from_prior: None,
            re_wrapped_in_forward: false,
        };

        _verify_unpack(PLAINTEXT_MSG_SIMPLE, &MESSAGE_SIMPLE, &plaintext_metadata).await;
        _verify_unpack(
            PLAINTEXT_MSG_SIMPLE_NO_TYP,
            &MESSAGE_SIMPLE,
            &plaintext_metadata,
        )
        .await;

        _verify_unpack(PLAINTEXT_MSG_MINIMAL, &MESSAGE_MINIMAL, &plaintext_metadata).await;

        _verify_unpack(
            PLAINTEXT_MSG_ATTACHMENT_BASE64,
            &MESSAGE_ATTACHMENT_BASE64,
            &plaintext_metadata,
        )
        .await;

        _verify_unpack(
            PLAINTEXT_MSG_ATTACHMENT_JSON,
            &MESSAGE_ATTACHMENT_JSON,
            &plaintext_metadata,
        )
        .await;

        _verify_unpack(
            PLAINTEXT_MSG_ATTACHMENT_LINKS,
            &MESSAGE_ATTACHMENT_LINKS,
            &plaintext_metadata,
        )
        .await;

        _verify_unpack(
            PLAINTEXT_MSG_ATTACHMENT_MULTI_1,
            &MESSAGE_ATTACHMENT_MULTI_1,
            &plaintext_metadata,
        )
        .await;

        _verify_unpack(
            PLAINTEXT_MSG_ATTACHMENT_MULTI_2,
            &MESSAGE_ATTACHMENT_MULTI_2,
            &plaintext_metadata,
        )
        .await;
    }

    #[tokio::test]
    async fn unpack_works_plaintext_2way() {
        _unpack_works_plaintext_2way(&MESSAGE_SIMPLE).await;
        _unpack_works_plaintext_2way(&MESSAGE_MINIMAL).await;
        _unpack_works_plaintext_2way(&MESSAGE_ATTACHMENT_BASE64).await;
        _unpack_works_plaintext_2way(&MESSAGE_ATTACHMENT_JSON).await;
        _unpack_works_plaintext_2way(&MESSAGE_ATTACHMENT_LINKS).await;
        _unpack_works_plaintext_2way(&MESSAGE_ATTACHMENT_MULTI_1).await;
        _unpack_works_plaintext_2way(&MESSAGE_ATTACHMENT_MULTI_2).await;

        async fn _unpack_works_plaintext_2way(msg: &Message) {
            let did_resolver = ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone()]);

            let packed = msg
                .pack_plaintext(&did_resolver)
                .await
                .expect("Unable pack_plaintext");

            _verify_unpack(
                &packed,
                msg,
                &UnpackMetadata {
                    anonymous_sender: false,
                    authenticated: false,
                    non_repudiation: false,
                    encrypted: false,
                    enc_alg_auth: None,
                    enc_alg_anon: None,
                    sign_alg: None,
                    encrypted_from_kid: None,
                    encrypted_to_kids: None,
                    sign_from: None,
                    signed_message: None,
                    from_prior_issuer_kid: None,
                    from_prior: None,
                    re_wrapped_in_forward: false,
                },
            )
            .await;
        }
    }

    #[tokio::test]
    async fn unpack_works_signed() {
        let sign_metadata = UnpackMetadata {
            anonymous_sender: false,
            authenticated: true,
            non_repudiation: true,
            encrypted: false,
            enc_alg_auth: None,
            enc_alg_anon: None,
            sign_alg: None,
            encrypted_from_kid: None,
            encrypted_to_kids: None,
            sign_from: None,
            signed_message: None,
            from_prior_issuer_kid: None,
            from_prior: None,
            re_wrapped_in_forward: false,
        };

        _verify_unpack(
            SIGNED_MSG_ALICE_KEY_1,
            &MESSAGE_SIMPLE,
            &UnpackMetadata {
                sign_from: Some("did:example:alice#key-1".into()),
                sign_alg: Some(SignAlg::EdDSA),
                signed_message: Some(serde_json::from_str(SIGNED_MSG_ALICE_KEY_1).unwrap()),
                ..sign_metadata.clone()
            },
        )
        .await;

        _verify_unpack(
            SIGNED_MSG_ALICE_KEY_2,
            &MESSAGE_SIMPLE,
            &UnpackMetadata {
                sign_from: Some("did:example:alice#key-2".into()),
                sign_alg: Some(SignAlg::ES256),
                signed_message: Some(serde_json::from_str(SIGNED_MSG_ALICE_KEY_2).unwrap()),
                ..sign_metadata.clone()
            },
        )
        .await;

        _verify_unpack(
            SIGNED_MSG_ALICE_KEY_3,
            &MESSAGE_SIMPLE,
            &UnpackMetadata {
                sign_from: Some("did:example:alice#key-3".into()),
                sign_alg: Some(SignAlg::ES256K),
                signed_message: Some(serde_json::from_str(SIGNED_MSG_ALICE_KEY_3).unwrap()),
                ..sign_metadata.clone()
            },
        )
        .await;
    }

    #[tokio::test]
    async fn unpack_works_signed_2way() {
        _unpack_works_signed_2way(
            &MESSAGE_SIMPLE,
            ALICE_DID,
            &ALICE_AUTH_METHOD_25519.id,
            SignAlg::EdDSA,
        )
        .await;

        _unpack_works_signed_2way(
            &MESSAGE_SIMPLE,
            &ALICE_AUTH_METHOD_25519.id,
            &ALICE_AUTH_METHOD_25519.id,
            SignAlg::EdDSA,
        )
        .await;

        _unpack_works_signed_2way(
            &MESSAGE_SIMPLE,
            &ALICE_AUTH_METHOD_P256.id,
            &ALICE_AUTH_METHOD_P256.id,
            SignAlg::ES256,
        )
        .await;

        _unpack_works_signed_2way(
            &MESSAGE_SIMPLE,
            &ALICE_AUTH_METHOD_SECPP256K1.id,
            &ALICE_AUTH_METHOD_SECPP256K1.id,
            SignAlg::ES256K,
        )
        .await;

        async fn _unpack_works_signed_2way(
            message: &Message,
            sign_by: &str,
            sign_by_kid: &str,
            sign_alg: SignAlg,
        ) {
            let did_resolver = ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone()]);
            let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

            let (msg, _) = message
                .pack_signed(sign_by, &did_resolver, &secrets_resolver)
                .await
                .expect("Unable pack_signed");

            _verify_unpack(
                &msg,
                &MESSAGE_SIMPLE,
                &UnpackMetadata {
                    sign_from: Some(sign_by_kid.into()),
                    sign_alg: Some(sign_alg),
                    signed_message: Some(serde_json::from_str(&msg).unwrap()),
                    anonymous_sender: false,
                    authenticated: true,
                    non_repudiation: true,
                    encrypted: false,
                    enc_alg_auth: None,
                    enc_alg_anon: None,
                    encrypted_from_kid: None,
                    encrypted_to_kids: None,
                    from_prior_issuer_kid: None,
                    from_prior: None,
                    re_wrapped_in_forward: false,
                },
            )
            .await;
        }
    }

    #[tokio::test]
    async fn unpack_works_anoncrypt() {
        let metadata = UnpackMetadata {
            anonymous_sender: true,
            authenticated: false,
            non_repudiation: false,
            encrypted: true,
            enc_alg_auth: None,
            enc_alg_anon: None,
            sign_alg: None,
            encrypted_from_kid: None,
            encrypted_to_kids: None,
            sign_from: None,
            signed_message: None,
            from_prior_issuer_kid: None,
            from_prior: None,
            re_wrapped_in_forward: false,
        };

        _verify_unpack(
            ENCRYPTED_MSG_ANON_XC20P_1,
            &MESSAGE_SIMPLE,
            &UnpackMetadata {
                enc_alg_anon: Some(AnonCryptAlg::Xc20pEcdhEsA256kw),
                encrypted_to_kids: Some(vec![
                    "did:example:bob#key-x25519-1".into(),
                    "did:example:bob#key-x25519-2".into(),
                    "did:example:bob#key-x25519-3".into(),
                ]),
                ..metadata.clone()
            },
        )
        .await;

        _verify_unpack(
            ENCRYPTED_MSG_ANON_XC20P_2,
            &MESSAGE_SIMPLE,
            &UnpackMetadata {
                enc_alg_anon: Some(AnonCryptAlg::Xc20pEcdhEsA256kw),
                encrypted_to_kids: Some(vec![
                    "did:example:bob#key-p256-1".into(),
                    "did:example:bob#key-p256-2".into(),
                ]),
                ..metadata.clone()
            },
        )
        .await;

        // TODO: Check P-384 curve support
        // TODO: Check P-521 curve support
    }

    #[tokio::test]
    async fn unpack_works_unwrap_re_wrapping_forward_on() {
        _unpack_works_unwrap_re_wrapping_forward_on(BOB_DID, None, None).await;

        _unpack_works_unwrap_re_wrapping_forward_on(BOB_DID, None, Some(ALICE_DID)).await;

        _unpack_works_unwrap_re_wrapping_forward_on(BOB_DID, Some(ALICE_DID), None).await;

        _unpack_works_unwrap_re_wrapping_forward_on(BOB_DID, Some(ALICE_DID), Some(ALICE_DID))
            .await;

        _unpack_works_unwrap_re_wrapping_forward_on(
            &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
            None,
            None,
        )
        .await;

        _unpack_works_unwrap_re_wrapping_forward_on(
            &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
            None,
            Some(ALICE_DID),
        )
        .await;

        _unpack_works_unwrap_re_wrapping_forward_on(
            &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
            Some(ALICE_DID),
            None,
        )
        .await;

        _unpack_works_unwrap_re_wrapping_forward_on(
            &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
            Some(ALICE_DID),
            Some(ALICE_DID),
        )
        .await;

        async fn _unpack_works_unwrap_re_wrapping_forward_on(
            to: &str,
            from: Option<&str>,
            sign_by: Option<&str>,
        ) {
            let mut did_resolver = ExampleDIDResolver::new(vec![
                ALICE_DID_DOC.clone(),
                BOB_DID_DOC.clone(),
                MEDIATOR1_DID_DOC.clone(),
            ]);

            let alice_secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

            let bob_secrets_resolver = ExampleSecretsResolver::new(BOB_SECRETS.clone());

            let mediator1_secrets_resolver = ExampleSecretsResolver::new(MEDIATOR1_SECRETS.clone());

            let (msg, pack_metadata) = MESSAGE_SIMPLE
                .pack_encrypted(
                    to,
                    from,
                    sign_by,
                    &did_resolver,
                    &alice_secrets_resolver,
                    &PackEncryptedOptions::default(),
                )
                .await
                .expect("Unable encrypt");

            assert_eq!(
                pack_metadata.messaging_service.as_ref(),
                Some(&MessagingServiceMetadata {
                    id: BOB_SERVICE.id.clone(),
                    service_endpoint: BOB_DID_COMM_MESSAGING_SERVICE.uri.clone(),
                })
            );

            let did_method_resolver = DIDMethods::default();
            let (unpacked_msg_mediator1, unpack_metadata_mediator1) = Message::unpack_string(
                &msg,
                &mut did_resolver,
                &did_method_resolver,
                &mediator1_secrets_resolver,
                &UnpackOptions::default(),
            )
            .await
            .expect("Unable unpack");

            let forward =
                try_parse_forward(&unpacked_msg_mediator1).expect("Message is not Forward");

            assert_eq!(forward.msg, &unpacked_msg_mediator1);
            assert_eq!(&forward.next, to);

            assert!(unpack_metadata_mediator1.encrypted);
            assert!(!unpack_metadata_mediator1.authenticated);
            assert!(!unpack_metadata_mediator1.non_repudiation);
            assert!(unpack_metadata_mediator1.anonymous_sender);
            assert!(!unpack_metadata_mediator1.re_wrapped_in_forward);

            let forwarded_msg = serde_json::to_string(&forward.forwarded_msg)
                .expect("Unable serialize forwarded message");

            let re_wrapping_forward_msg = wrap_in_forward(
                &forwarded_msg,
                None,
                to,
                &[to.to_owned()],
                &AnonCryptAlg::default(),
                &did_resolver,
            )
            .await
            .expect("Unable wrap in forward");

            let (unpacked_msg, unpack_metadata) = Message::unpack_string(
                &re_wrapping_forward_msg,
                &mut did_resolver,
                &did_method_resolver,
                &bob_secrets_resolver,
                &UnpackOptions::default(),
            )
            .await
            .expect("Unable unpack");

            assert_eq!(&unpacked_msg, &*MESSAGE_SIMPLE);
            assert!(unpack_metadata.re_wrapped_in_forward);
        }
    }

    #[tokio::test]
    async fn unpack_works_unwrap_re_wrapping_forward_off() {
        _unpack_works_unwrap_re_wrapping_forward_off(BOB_DID, None, None).await;

        _unpack_works_unwrap_re_wrapping_forward_off(BOB_DID, None, Some(ALICE_DID)).await;

        _unpack_works_unwrap_re_wrapping_forward_off(BOB_DID, Some(ALICE_DID), None).await;

        _unpack_works_unwrap_re_wrapping_forward_off(BOB_DID, Some(ALICE_DID), Some(ALICE_DID))
            .await;

        _unpack_works_unwrap_re_wrapping_forward_off(
            &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
            None,
            None,
        )
        .await;

        _unpack_works_unwrap_re_wrapping_forward_off(
            &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
            None,
            Some(ALICE_DID),
        )
        .await;

        _unpack_works_unwrap_re_wrapping_forward_off(
            &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
            Some(ALICE_DID),
            None,
        )
        .await;

        _unpack_works_unwrap_re_wrapping_forward_off(
            &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
            Some(ALICE_DID),
            Some(ALICE_DID),
        )
        .await;

        async fn _unpack_works_unwrap_re_wrapping_forward_off(
            to: &str,
            from: Option<&str>,
            sign_by: Option<&str>,
        ) {
            let mut did_resolver = ExampleDIDResolver::new(vec![
                ALICE_DID_DOC.clone(),
                BOB_DID_DOC.clone(),
                MEDIATOR1_DID_DOC.clone(),
            ]);

            let alice_secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

            let bob_secrets_resolver = ExampleSecretsResolver::new(BOB_SECRETS.clone());

            let mediator1_secrets_resolver = ExampleSecretsResolver::new(MEDIATOR1_SECRETS.clone());

            let (msg, pack_metadata) = MESSAGE_SIMPLE
                .pack_encrypted(
                    to,
                    from,
                    sign_by,
                    &did_resolver,
                    &alice_secrets_resolver,
                    &PackEncryptedOptions::default(),
                )
                .await
                .expect("Unable encrypt");

            assert_eq!(
                pack_metadata.messaging_service.as_ref(),
                Some(&MessagingServiceMetadata {
                    id: BOB_SERVICE.id.clone(),
                    service_endpoint: BOB_DID_COMM_MESSAGING_SERVICE.uri.clone(),
                })
            );

            let did_method_resolver = DIDMethods::default();
            let (unpacked_msg_mediator1, unpack_metadata_mediator1) = Message::unpack_string(
                &msg,
                &mut did_resolver,
                &did_method_resolver,
                &mediator1_secrets_resolver,
                &UnpackOptions {
                    unwrap_re_wrapping_forward: false,
                    ..UnpackOptions::default()
                },
            )
            .await
            .expect("Unable unpack");

            let forward_at_mediator1 =
                try_parse_forward(&unpacked_msg_mediator1).expect("Message is not Forward");

            assert_eq!(forward_at_mediator1.msg, &unpacked_msg_mediator1);
            assert_eq!(&forward_at_mediator1.next, to);

            assert!(unpack_metadata_mediator1.encrypted);
            assert!(!unpack_metadata_mediator1.authenticated);
            assert!(!unpack_metadata_mediator1.non_repudiation);
            assert!(unpack_metadata_mediator1.anonymous_sender);
            assert!(!unpack_metadata_mediator1.re_wrapped_in_forward);

            let forwarded_msg_at_mediator1 =
                serde_json::to_string(&forward_at_mediator1.forwarded_msg)
                    .expect("Unable serialize forwarded message");

            let re_wrapping_forward_msg = wrap_in_forward(
                &forwarded_msg_at_mediator1,
                None,
                to,
                &[to.to_owned()],
                &AnonCryptAlg::default(),
                &did_resolver,
            )
            .await
            .expect("Unable wrap in forward");

            let (unpacked_once_msg, unpack_once_metadata) = Message::unpack_string(
                &re_wrapping_forward_msg,
                &mut did_resolver,
                &did_method_resolver,
                &bob_secrets_resolver,
                &UnpackOptions {
                    unwrap_re_wrapping_forward: false,
                    ..UnpackOptions::default()
                },
            )
            .await
            .expect("Unable unpack");

            let forward_at_bob =
                try_parse_forward(&unpacked_once_msg).expect("Message is not Forward");

            assert_eq!(forward_at_bob.msg, &unpacked_once_msg);
            assert_eq!(&forward_at_bob.next, to);

            assert!(unpack_once_metadata.encrypted);
            assert!(!unpack_once_metadata.authenticated);
            assert!(!unpack_once_metadata.non_repudiation);
            assert!(unpack_once_metadata.anonymous_sender);
            assert!(!unpack_once_metadata.re_wrapped_in_forward);

            let forwarded_msg_at_bob = serde_json::to_string(&forward_at_bob.forwarded_msg)
                .expect("Unable serialize forwarded message");

            let (unpacked_twice_msg, unpack_twice_metadata) = Message::unpack_string(
                &forwarded_msg_at_bob,
                &mut did_resolver,
                &did_method_resolver,
                &bob_secrets_resolver,
                &UnpackOptions {
                    unwrap_re_wrapping_forward: false,
                    ..UnpackOptions::default()
                },
            )
            .await
            .expect("Unable unpack");

            assert_eq!(&unpacked_twice_msg, &*MESSAGE_SIMPLE);

            assert!(unpack_twice_metadata.encrypted);
            assert_eq!(
                unpack_twice_metadata.authenticated,
                from.is_some() || sign_by.is_some()
            );
            assert_eq!(unpack_twice_metadata.non_repudiation, sign_by.is_some());
            assert_eq!(unpack_twice_metadata.anonymous_sender, from.is_none());
            assert!(!unpack_twice_metadata.re_wrapped_in_forward);
        }
    }

    #[tokio::test]
    async fn unpack_works_anoncrypted_2way() {
        _unpack_works_anoncrypted_2way(
            &MESSAGE_SIMPLE,
            BOB_DID,
            &[
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_1.id,
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_3.id,
            ],
            AnonCryptAlg::A256cbcHs512EcdhEsA256kw,
        )
        .await;

        _unpack_works_anoncrypted_2way(
            &MESSAGE_SIMPLE,
            BOB_DID,
            &[
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_1.id,
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_3.id,
            ],
            AnonCryptAlg::Xc20pEcdhEsA256kw,
        )
        .await;

        _unpack_works_anoncrypted_2way(
            &MESSAGE_SIMPLE,
            &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
            &[&BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id],
            AnonCryptAlg::A256cbcHs512EcdhEsA256kw,
        )
        .await;

        _unpack_works_anoncrypted_2way(
            &MESSAGE_SIMPLE,
            &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
            &[&BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id],
            AnonCryptAlg::A256gcmEcdhEsA256kw,
        )
        .await;

        _unpack_works_anoncrypted_2way(
            &MESSAGE_SIMPLE,
            &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
            &[&BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id],
            AnonCryptAlg::Xc20pEcdhEsA256kw,
        )
        .await;

        _unpack_works_anoncrypted_2way(
            &MESSAGE_SIMPLE,
            &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
            &[&BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id],
            AnonCryptAlg::A256cbcHs512EcdhEsA256kw,
        )
        .await;

        _unpack_works_anoncrypted_2way(
            &MESSAGE_SIMPLE,
            &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
            &[&BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id],
            AnonCryptAlg::A256gcmEcdhEsA256kw,
        )
        .await;

        _unpack_works_anoncrypted_2way(
            &MESSAGE_SIMPLE,
            &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
            &[&BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id],
            AnonCryptAlg::Xc20pEcdhEsA256kw,
        )
        .await;

        _unpack_works_anoncrypted_2way(
            &MESSAGE_SIMPLE,
            &BOB_SECRET_KEY_AGREEMENT_KEY_P256_1.id,
            &[&BOB_SECRET_KEY_AGREEMENT_KEY_P256_1.id],
            AnonCryptAlg::A256cbcHs512EcdhEsA256kw,
        )
        .await;

        _unpack_works_anoncrypted_2way(
            &MESSAGE_SIMPLE,
            &BOB_SECRET_KEY_AGREEMENT_KEY_P256_1.id,
            &[&BOB_SECRET_KEY_AGREEMENT_KEY_P256_1.id],
            AnonCryptAlg::A256gcmEcdhEsA256kw,
        )
        .await;

        _unpack_works_anoncrypted_2way(
            &MESSAGE_SIMPLE,
            &BOB_SECRET_KEY_AGREEMENT_KEY_P256_1.id,
            &[&BOB_SECRET_KEY_AGREEMENT_KEY_P256_1.id],
            AnonCryptAlg::Xc20pEcdhEsA256kw,
        )
        .await;

        _unpack_works_anoncrypted_2way(
            &MESSAGE_SIMPLE,
            &BOB_SECRET_KEY_AGREEMENT_KEY_P256_1.id,
            &[&BOB_SECRET_KEY_AGREEMENT_KEY_P256_1.id],
            AnonCryptAlg::A256cbcHs512EcdhEsA256kw,
        )
        .await;

        _unpack_works_anoncrypted_2way(
            &MESSAGE_SIMPLE,
            &BOB_SECRET_KEY_AGREEMENT_KEY_P256_2.id,
            &[&BOB_SECRET_KEY_AGREEMENT_KEY_P256_2.id],
            AnonCryptAlg::A256gcmEcdhEsA256kw,
        )
        .await;

        _unpack_works_anoncrypted_2way(
            &MESSAGE_SIMPLE,
            &BOB_SECRET_KEY_AGREEMENT_KEY_P256_2.id,
            &[&BOB_SECRET_KEY_AGREEMENT_KEY_P256_2.id],
            AnonCryptAlg::Xc20pEcdhEsA256kw,
        )
        .await;

        async fn _unpack_works_anoncrypted_2way(
            msg: &Message,
            to: &str,
            to_kids: &[&str],
            enc_alg: AnonCryptAlg,
        ) {
            let did_resolver =
                ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);

            let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

            let (packed, _) = msg
                .pack_encrypted(
                    to,
                    None,
                    None,
                    &did_resolver,
                    &secrets_resolver,
                    &PackEncryptedOptions {
                        forward: false,
                        enc_alg_anon: enc_alg.clone(),
                        ..PackEncryptedOptions::default()
                    },
                )
                .await
                .expect("Unable pack_encrypted");

            _verify_unpack(
                &packed,
                msg,
                &UnpackMetadata {
                    sign_from: None,
                    sign_alg: None,
                    signed_message: None,
                    anonymous_sender: true,
                    authenticated: false,
                    non_repudiation: false,
                    encrypted: true,
                    enc_alg_auth: None,
                    enc_alg_anon: Some(enc_alg),
                    encrypted_from_kid: None,
                    encrypted_to_kids: Some(to_kids.iter().map(|&k| k.to_owned()).collect()),
                    from_prior_issuer_kid: None,
                    from_prior: None,
                    re_wrapped_in_forward: false,
                },
            )
            .await;
        }
    }

    #[tokio::test]
    async fn pack_encrypted_works_anoncrypted_signed() {
        _pack_encrypted_works_anoncrypted_signed(
            &MESSAGE_SIMPLE,
            BOB_DID,
            &[
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_1.id,
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_3.id,
            ],
            ALICE_DID,
            &ALICE_AUTH_METHOD_25519.id,
            AnonCryptAlg::A256cbcHs512EcdhEsA256kw,
            SignAlg::EdDSA,
        )
        .await;

        _pack_encrypted_works_anoncrypted_signed(
            &MESSAGE_SIMPLE,
            BOB_DID,
            &[
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_1.id,
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_3.id,
            ],
            ALICE_DID,
            &ALICE_AUTH_METHOD_25519.id,
            AnonCryptAlg::A256gcmEcdhEsA256kw,
            SignAlg::EdDSA,
        )
        .await;

        _pack_encrypted_works_anoncrypted_signed(
            &MESSAGE_SIMPLE,
            BOB_DID,
            &[
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_1.id,
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_3.id,
            ],
            ALICE_DID,
            &ALICE_AUTH_METHOD_25519.id,
            AnonCryptAlg::Xc20pEcdhEsA256kw,
            SignAlg::EdDSA,
        )
        .await;

        _pack_encrypted_works_anoncrypted_signed(
            &MESSAGE_SIMPLE,
            &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
            &[&BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id],
            &ALICE_AUTH_METHOD_25519.id,
            &ALICE_AUTH_METHOD_25519.id,
            AnonCryptAlg::A256cbcHs512EcdhEsA256kw,
            SignAlg::EdDSA,
        )
        .await;

        _pack_encrypted_works_anoncrypted_signed(
            &MESSAGE_SIMPLE,
            &BOB_SECRET_KEY_AGREEMENT_KEY_P256_1.id,
            &[&BOB_SECRET_KEY_AGREEMENT_KEY_P256_1.id],
            &ALICE_AUTH_METHOD_P256.id,
            &ALICE_AUTH_METHOD_P256.id,
            AnonCryptAlg::A256cbcHs512EcdhEsA256kw,
            SignAlg::ES256,
        )
        .await;

        _pack_encrypted_works_anoncrypted_signed(
            &MESSAGE_SIMPLE,
            &BOB_SECRET_KEY_AGREEMENT_KEY_P256_1.id,
            &[&BOB_SECRET_KEY_AGREEMENT_KEY_P256_1.id],
            &ALICE_AUTH_METHOD_SECPP256K1.id,
            &ALICE_AUTH_METHOD_SECPP256K1.id,
            AnonCryptAlg::A256cbcHs512EcdhEsA256kw,
            SignAlg::ES256K,
        )
        .await;

        async fn _pack_encrypted_works_anoncrypted_signed(
            msg: &Message,
            to: &str,
            to_kids: &[&str],
            sign_by: &str,
            sign_by_kid: &str,
            enc_alg: AnonCryptAlg,
            sign_alg: SignAlg,
        ) {
            let did_resolver =
                ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);

            let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

            let (packed, _) = msg
                .pack_encrypted(
                    to,
                    None,
                    Some(sign_by),
                    &did_resolver,
                    &secrets_resolver,
                    &PackEncryptedOptions {
                        forward: false,
                        enc_alg_anon: enc_alg.clone(),
                        ..PackEncryptedOptions::default()
                    },
                )
                .await
                .expect("Unable pack_encrypted");

            _verify_unpack_undeterministic(
                &packed,
                msg,
                &UnpackMetadata {
                    sign_from: Some(sign_by_kid.into()),
                    sign_alg: Some(sign_alg),
                    signed_message: None,
                    anonymous_sender: true,
                    authenticated: true,
                    non_repudiation: true,
                    encrypted: true,
                    enc_alg_auth: None,
                    enc_alg_anon: Some(enc_alg),
                    encrypted_from_kid: None,
                    encrypted_to_kids: Some(to_kids.iter().map(|&k| k.to_owned()).collect()),
                    from_prior_issuer_kid: None,
                    from_prior: None,
                    re_wrapped_in_forward: false,
                },
            )
            .await;
        }
    }

    #[traced_test]
    #[tokio::test]
    async fn unpack_works_authcrypt() {
        let metadata = UnpackMetadata {
            anonymous_sender: false,
            authenticated: true,
            non_repudiation: false,
            encrypted: true,
            enc_alg_auth: None,
            enc_alg_anon: None,
            sign_alg: None,
            encrypted_from_kid: None,
            encrypted_to_kids: None,
            sign_from: None,
            signed_message: None,
            from_prior_issuer_kid: None,
            from_prior: None,
            re_wrapped_in_forward: false,
        };

        debug!("testing ENCRYPTED_MSG_AUTH_X25519");
        _verify_unpack(
            ENCRYPTED_MSG_AUTH_X25519,
            &MESSAGE_SIMPLE,
            &UnpackMetadata {
                enc_alg_auth: Some(AuthCryptAlg::A256cbcHs512Ecdh1puA256kw),
                encrypted_from_kid: Some("did:example:alice#key-x25519-1".into()),
                encrypted_to_kids: Some(vec![
                    "did:example:bob#key-x25519-1".into(),
                    "did:example:bob#key-x25519-2".into(),
                    "did:example:bob#key-x25519-3".into(),
                ]),
                ..metadata.clone()
            },
        )
        .await;

        debug!("testing ENCRYPTED_MSG_AUTH_P256");
        _verify_unpack(
            ENCRYPTED_MSG_AUTH_P256,
            &MESSAGE_SIMPLE,
            &UnpackMetadata {
                enc_alg_auth: Some(AuthCryptAlg::A256cbcHs512Ecdh1puA256kw),
                encrypted_from_kid: Some("did:example:alice#key-p256-1".into()),
                encrypted_to_kids: Some(vec![
                    "did:example:bob#key-p256-1".into(),
                    "did:example:bob#key-p256-2".into(),
                ]),
                non_repudiation: true,
                sign_from: Some("did:example:alice#key-1".into()),
                sign_alg: Some(SignAlg::EdDSA),
                signed_message: Some(serde_json::from_str(ENCRYPTED_MSG_AUTH_P256_SIGNED).unwrap()),
                ..metadata.clone()
            },
        )
        .await;

        // TODO: Check hidden sender case
        // TODO: Check P-384 curve support
        // TODO: Check P-521 curve support
    }

    #[tokio::test]
    async fn unpack_works_authcrypted_2way() {
        _unpack_works_authcrypted_2way(
            &MESSAGE_SIMPLE,
            BOB_DID,
            &[
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_1.id,
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_3.id,
            ],
            ALICE_DID,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519.id,
            AuthCryptAlg::A256cbcHs512Ecdh1puA256kw,
        )
        .await;

        _unpack_works_authcrypted_2way(
            &MESSAGE_SIMPLE,
            &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
            &[&BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id],
            ALICE_DID,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519.id,
            AuthCryptAlg::A256cbcHs512Ecdh1puA256kw,
        )
        .await;

        _unpack_works_authcrypted_2way(
            &MESSAGE_SIMPLE,
            &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
            &[&BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id],
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519.id,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519.id,
            AuthCryptAlg::A256cbcHs512Ecdh1puA256kw,
        )
        .await;

        _unpack_works_authcrypted_2way(
            &MESSAGE_SIMPLE,
            BOB_DID,
            &[
                &BOB_SECRET_KEY_AGREEMENT_KEY_P256_1.id,
                &BOB_SECRET_KEY_AGREEMENT_KEY_P256_2.id,
            ],
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256.id,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256.id,
            AuthCryptAlg::A256cbcHs512Ecdh1puA256kw,
        )
        .await;

        _unpack_works_authcrypted_2way(
            &MESSAGE_SIMPLE,
            &BOB_SECRET_KEY_AGREEMENT_KEY_P256_1.id,
            &[&BOB_SECRET_KEY_AGREEMENT_KEY_P256_1.id],
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256.id,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256.id,
            AuthCryptAlg::A256cbcHs512Ecdh1puA256kw,
        )
        .await;

        _unpack_works_authcrypted_2way(
            &MESSAGE_SIMPLE,
            &BOB_SECRET_KEY_AGREEMENT_KEY_P256_2.id,
            &[&BOB_SECRET_KEY_AGREEMENT_KEY_P256_2.id],
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256.id,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256.id,
            AuthCryptAlg::A256cbcHs512Ecdh1puA256kw,
        )
        .await;

        _unpack_works_authcrypted_2way(
            &MESSAGE_SIMPLE,
            &BOB_SECRET_KEY_AGREEMENT_KEY_P256_2.id,
            &[&BOB_SECRET_KEY_AGREEMENT_KEY_P256_2.id],
            ALICE_DID,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256.id,
            AuthCryptAlg::A256cbcHs512Ecdh1puA256kw,
        )
        .await;

        async fn _unpack_works_authcrypted_2way(
            msg: &Message,
            to: &str,
            to_kids: &[&str],
            from: &str,
            from_kid: &str,
            enc_alg: AuthCryptAlg,
        ) {
            let did_resolver =
                ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);

            let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

            let (packed, _) = msg
                .pack_encrypted(
                    to,
                    Some(from),
                    None,
                    &did_resolver,
                    &secrets_resolver,
                    &PackEncryptedOptions {
                        forward: false,
                        ..PackEncryptedOptions::default()
                    },
                )
                .await
                .expect("Unable pack_encrypted");

            _verify_unpack(
                &packed,
                msg,
                &UnpackMetadata {
                    sign_from: None,
                    sign_alg: None,
                    signed_message: None,
                    anonymous_sender: false,
                    authenticated: true,
                    non_repudiation: false,
                    encrypted: true,
                    enc_alg_auth: Some(enc_alg),
                    enc_alg_anon: None,
                    encrypted_from_kid: Some(from_kid.into()),
                    encrypted_to_kids: Some(to_kids.iter().map(|&k| k.to_owned()).collect()),
                    from_prior_issuer_kid: None,
                    from_prior: None,
                    re_wrapped_in_forward: false,
                },
            )
            .await;
        }
    }

    #[tokio::test]
    async fn unpack_works_authcrypted_protected_sender_2way() {
        debug!("testing anonCryptAlg(A256cbcHs512EcdhEsA256kw) authCryptAlg(A256cbcHs512Ecdh1puA256kw)");
        _unpack_works_authcrypted_protected_sender_2way(
            &MESSAGE_SIMPLE,
            BOB_DID,
            &[
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_1.id,
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_3.id,
            ],
            ALICE_DID,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519.id,
            AnonCryptAlg::A256cbcHs512EcdhEsA256kw,
            AuthCryptAlg::A256cbcHs512Ecdh1puA256kw,
        )
        .await;

        _unpack_works_authcrypted_protected_sender_2way(
            &MESSAGE_SIMPLE,
            BOB_DID,
            &[
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_1.id,
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_3.id,
            ],
            ALICE_DID,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519.id,
            AnonCryptAlg::A256gcmEcdhEsA256kw,
            AuthCryptAlg::A256cbcHs512Ecdh1puA256kw,
        )
        .await;

        _unpack_works_authcrypted_protected_sender_2way(
            &MESSAGE_SIMPLE,
            BOB_DID,
            &[
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_1.id,
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_3.id,
            ],
            ALICE_DID,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519.id,
            AnonCryptAlg::Xc20pEcdhEsA256kw,
            AuthCryptAlg::A256cbcHs512Ecdh1puA256kw,
        )
        .await;

        _unpack_works_authcrypted_protected_sender_2way(
            &MESSAGE_SIMPLE,
            &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
            &[&BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id],
            ALICE_DID,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519.id,
            AnonCryptAlg::A256cbcHs512EcdhEsA256kw,
            AuthCryptAlg::A256cbcHs512Ecdh1puA256kw,
        )
        .await;

        _unpack_works_authcrypted_protected_sender_2way(
            &MESSAGE_SIMPLE,
            BOB_DID,
            &[
                &BOB_SECRET_KEY_AGREEMENT_KEY_P256_1.id,
                &BOB_SECRET_KEY_AGREEMENT_KEY_P256_2.id,
            ],
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256.id,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256.id,
            AnonCryptAlg::A256cbcHs512EcdhEsA256kw,
            AuthCryptAlg::A256cbcHs512Ecdh1puA256kw,
        )
        .await;

        _unpack_works_authcrypted_protected_sender_2way(
            &MESSAGE_SIMPLE,
            BOB_DID,
            &[
                &BOB_SECRET_KEY_AGREEMENT_KEY_P256_1.id,
                &BOB_SECRET_KEY_AGREEMENT_KEY_P256_2.id,
            ],
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256.id,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256.id,
            AnonCryptAlg::A256gcmEcdhEsA256kw,
            AuthCryptAlg::A256cbcHs512Ecdh1puA256kw,
        )
        .await;

        _unpack_works_authcrypted_protected_sender_2way(
            &MESSAGE_SIMPLE,
            BOB_DID,
            &[
                &BOB_SECRET_KEY_AGREEMENT_KEY_P256_1.id,
                &BOB_SECRET_KEY_AGREEMENT_KEY_P256_2.id,
            ],
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256.id,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256.id,
            AnonCryptAlg::Xc20pEcdhEsA256kw,
            AuthCryptAlg::A256cbcHs512Ecdh1puA256kw,
        )
        .await;

        _unpack_works_authcrypted_protected_sender_2way(
            &MESSAGE_SIMPLE,
            &BOB_SECRET_KEY_AGREEMENT_KEY_P256_1.id,
            &[&BOB_SECRET_KEY_AGREEMENT_KEY_P256_1.id],
            ALICE_DID,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256.id,
            AnonCryptAlg::Xc20pEcdhEsA256kw,
            AuthCryptAlg::A256cbcHs512Ecdh1puA256kw,
        )
        .await;

        _unpack_works_authcrypted_protected_sender_2way(
            &MESSAGE_SIMPLE,
            &BOB_SECRET_KEY_AGREEMENT_KEY_P256_2.id,
            &[&BOB_SECRET_KEY_AGREEMENT_KEY_P256_2.id],
            ALICE_DID,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256.id,
            AnonCryptAlg::A256cbcHs512EcdhEsA256kw,
            AuthCryptAlg::A256cbcHs512Ecdh1puA256kw,
        )
        .await;

        async fn _unpack_works_authcrypted_protected_sender_2way(
            msg: &Message,
            to: &str,
            to_kids: &[&str],
            from: &str,
            from_kid: &str,
            enc_alg_anon: AnonCryptAlg,
            enc_alg_auth: AuthCryptAlg,
        ) {
            let did_resolver =
                ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);

            let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

            let (packed, _) = msg
                .pack_encrypted(
                    to,
                    Some(from),
                    None,
                    &did_resolver,
                    &secrets_resolver,
                    &PackEncryptedOptions {
                        forward: false,
                        protect_sender: true,
                        enc_alg_anon: enc_alg_anon.clone(),
                        ..PackEncryptedOptions::default()
                    },
                )
                .await
                .expect("Unable pack_encrypted");

            _verify_unpack(
                &packed,
                msg,
                &UnpackMetadata {
                    sign_from: None,
                    sign_alg: None,
                    signed_message: None,
                    anonymous_sender: true,
                    authenticated: true,
                    non_repudiation: false,
                    encrypted: true,
                    enc_alg_auth: Some(enc_alg_auth),
                    enc_alg_anon: Some(enc_alg_anon),
                    encrypted_from_kid: Some(from_kid.into()),
                    encrypted_to_kids: Some(to_kids.iter().map(|&k| k.to_owned()).collect()),
                    from_prior_issuer_kid: None,
                    from_prior: None,
                    re_wrapped_in_forward: false,
                },
            )
            .await;
        }
    }

    #[tokio::test]
    async fn unpack_works_authcrypted_protected_sender_signed_2way() {
        _unpack_works_authcrypted_protected_sender_signed_2way(
            &MESSAGE_SIMPLE,
            BOB_DID,
            &[
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_1.id,
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_3.id,
            ],
            ALICE_DID,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519.id,
            &ALICE_AUTH_METHOD_P256.id,
            &ALICE_AUTH_METHOD_P256.id,
            AnonCryptAlg::A256cbcHs512EcdhEsA256kw,
            AuthCryptAlg::A256cbcHs512Ecdh1puA256kw,
            SignAlg::ES256,
        )
        .await;

        _unpack_works_authcrypted_protected_sender_signed_2way(
            &MESSAGE_SIMPLE,
            BOB_DID,
            &[
                &BOB_SECRET_KEY_AGREEMENT_KEY_P256_1.id,
                &BOB_SECRET_KEY_AGREEMENT_KEY_P256_2.id,
            ],
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256.id,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256.id,
            &ALICE_AUTH_METHOD_25519.id,
            &ALICE_AUTH_METHOD_25519.id,
            AnonCryptAlg::A256cbcHs512EcdhEsA256kw,
            AuthCryptAlg::A256cbcHs512Ecdh1puA256kw,
            SignAlg::EdDSA,
        )
        .await;

        _unpack_works_authcrypted_protected_sender_signed_2way(
            &MESSAGE_SIMPLE,
            BOB_DID,
            &[
                &BOB_SECRET_KEY_AGREEMENT_KEY_P256_1.id,
                &BOB_SECRET_KEY_AGREEMENT_KEY_P256_2.id,
            ],
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256.id,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256.id,
            &ALICE_AUTH_METHOD_SECPP256K1.id,
            &ALICE_AUTH_METHOD_SECPP256K1.id,
            AnonCryptAlg::A256cbcHs512EcdhEsA256kw,
            AuthCryptAlg::A256cbcHs512Ecdh1puA256kw,
            SignAlg::ES256K,
        )
        .await;

        #[allow(clippy::too_many_arguments)]
        async fn _unpack_works_authcrypted_protected_sender_signed_2way(
            msg: &Message,
            to: &str,
            _: &[&str],
            from: &str,
            _: &str,
            sign_by: &str,
            _: &str,
            enc_alg_anon: AnonCryptAlg,
            _: AuthCryptAlg,
            _: SignAlg,
        ) {
            let did_resolver =
                ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);

            let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

            let (_, _) = msg
                .pack_encrypted(
                    to,
                    Some(from),
                    Some(sign_by),
                    &did_resolver,
                    &secrets_resolver,
                    &PackEncryptedOptions {
                        forward: false,
                        protect_sender: true,
                        enc_alg_anon: enc_alg_anon.clone(),
                        ..PackEncryptedOptions::default()
                    },
                )
                .await
                .expect("Unable pack_encrypted");
        }
    }

    #[tokio::test]
    async fn unpack_works_authcrypted_signed_2way() {
        _unpack_works_authcrypted_signed_2way(
            &MESSAGE_SIMPLE,
            BOB_DID,
            &[
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_1.id,
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
                &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_3.id,
            ],
            ALICE_DID,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519.id,
            ALICE_DID,
            &ALICE_AUTH_METHOD_25519.id,
            AuthCryptAlg::A256cbcHs512Ecdh1puA256kw,
            SignAlg::EdDSA,
        )
        .await;

        _unpack_works_authcrypted_signed_2way(
            &MESSAGE_SIMPLE,
            &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
            &[&BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id],
            ALICE_DID,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519.id,
            &ALICE_AUTH_METHOD_25519.id,
            &ALICE_AUTH_METHOD_25519.id,
            AuthCryptAlg::A256cbcHs512Ecdh1puA256kw,
            SignAlg::EdDSA,
        )
        .await;

        _unpack_works_authcrypted_signed_2way(
            &MESSAGE_SIMPLE,
            &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id,
            &[&BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id],
            ALICE_DID,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519.id,
            &ALICE_AUTH_METHOD_P256.id,
            &ALICE_AUTH_METHOD_P256.id,
            AuthCryptAlg::A256cbcHs512Ecdh1puA256kw,
            SignAlg::ES256,
        )
        .await;

        _unpack_works_authcrypted_signed_2way(
            &MESSAGE_SIMPLE,
            BOB_DID,
            &[
                &BOB_SECRET_KEY_AGREEMENT_KEY_P256_1.id,
                &BOB_SECRET_KEY_AGREEMENT_KEY_P256_2.id,
            ],
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256.id,
            &ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256.id,
            &ALICE_AUTH_METHOD_SECPP256K1.id,
            &ALICE_AUTH_METHOD_SECPP256K1.id,
            AuthCryptAlg::A256cbcHs512Ecdh1puA256kw,
            SignAlg::ES256K,
        )
        .await;

        #[allow(clippy::too_many_arguments)]
        async fn _unpack_works_authcrypted_signed_2way(
            msg: &Message,
            to: &str,
            _: &[&str],
            from: &str,
            _: &str,
            sign_by: &str,
            _: &str,
            _: AuthCryptAlg,
            _: SignAlg,
        ) {
            let did_resolver =
                ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);

            let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

            let (_, _) = msg
                .pack_encrypted(
                    to,
                    Some(from),
                    Some(sign_by),
                    &did_resolver,
                    &secrets_resolver,
                    &PackEncryptedOptions {
                        forward: false,
                        ..PackEncryptedOptions::default()
                    },
                )
                .await
                .expect("encrypt is ok.");
        }
    }

    #[tokio::test]
    async fn unpack_works_invalid_epk_point() {
        _verify_unpack_malformed(
            INVALID_ENCRYPTED_MSG_ANON_P256_EPK_WRONG_POINT,
            "Malformed: Unable instantiate epk: Unable produce jwk: Invalid key data",
        )
        .await;
    }

    #[tokio::test]
    async fn unpack_works_malformed_anoncrypt_msg() {
        _verify_unpack_malformed(
            update_field(ENCRYPTED_MSG_ANON_XC20P_1, "protected", "invalid").as_str(),
            "Malformed: Unable decode protected header: Invalid last symbol 100, offset 6.",
        )
        .await;

        _verify_unpack_malformed(
            remove_field(ENCRYPTED_MSG_ANON_XC20P_1, "protected").as_str(),
            "Malformed: Unable deserialize envelope: data did not match any variant of untagged enum Envelope",
        )
        .await;

        _verify_unpack_malformed(
            update_field(ENCRYPTED_MSG_ANON_XC20P_1, "iv", "invalid").as_str(),
            "Malformed: Unable decode iv: Invalid last symbol 100, offset 6.",
        )
        .await;

        _verify_unpack_malformed(
            remove_field(ENCRYPTED_MSG_ANON_XC20P_1, "iv").as_str(),
            "Malformed: Unable deserialize envelope: data did not match any variant of untagged enum Envelope",
        )
        .await;

        _verify_unpack_malformed(
            update_field(ENCRYPTED_MSG_ANON_XC20P_1, "ciphertext", "invalid").as_str(),
            "Malformed: Unable decode ciphertext: Invalid last symbol 100, offset 6.",
        )
        .await;

        _verify_unpack_malformed(
            remove_field(ENCRYPTED_MSG_ANON_XC20P_1, "ciphertext").as_str(),
            "Malformed: Unable deserialize envelope: data did not match any variant of untagged enum Envelope",
        )
        .await;

        _verify_unpack_malformed(
            update_field(ENCRYPTED_MSG_ANON_XC20P_1, "tag", "invalid").as_str(),
            "Malformed: Unable decode tag: Invalid last symbol 100, offset 6.",
        )
        .await;

        _verify_unpack_malformed(
            remove_field(ENCRYPTED_MSG_ANON_XC20P_1, "tag").as_str(),
            "Malformed: Unable deserialize envelope: data did not match any variant of untagged enum Envelope",
        )
        .await;

        _verify_unpack_malformed(
            update_protected_field(ENCRYPTED_MSG_ANON_XC20P_1, "apv", "invalid").as_str(),
            "Malformed: Unable decode apv: Invalid last symbol 100, offset 6.",
        )
        .await;

        _verify_unpack_malformed(
            remove_protected_field(ENCRYPTED_MSG_ANON_XC20P_1, "apv").as_str(),
            "Malformed: Unable parse protected header: missing field `apv` at line 1 column 166",
        )
        .await;
    }

    #[tokio::test]
    async fn unpack_works_malformed_authcrypt_msg() {
        _verify_unpack_malformed(
            update_field(ENCRYPTED_MSG_AUTH_X25519, "protected", "invalid").as_str(),
            "Malformed: Unable decode protected header: Invalid last symbol 100, offset 6.",
        )
        .await;

        _verify_unpack_malformed(
            remove_field(ENCRYPTED_MSG_AUTH_X25519, "protected").as_str(),
            "Malformed: Unable deserialize envelope: data did not match any variant of untagged enum Envelope",
        )
        .await;

        _verify_unpack_malformed(
            update_field(ENCRYPTED_MSG_AUTH_X25519, "iv", "invalid").as_str(),
            "Malformed: Unable decode iv: Invalid last symbol 100, offset 6.",
        )
        .await;

        _verify_unpack_malformed(
            remove_field(ENCRYPTED_MSG_AUTH_X25519, "iv").as_str(),
            "Malformed: Unable deserialize envelope: data did not match any variant of untagged enum Envelope",
        )
        .await;

        _verify_unpack_malformed(
            update_field(ENCRYPTED_MSG_AUTH_X25519, "ciphertext", "invalid").as_str(),
            "Malformed: Unable decode ciphertext: Invalid last symbol 100, offset 6.",
        )
        .await;

        _verify_unpack_malformed(
            remove_field(ENCRYPTED_MSG_AUTH_X25519, "ciphertext").as_str(),
            "Malformed: Unable deserialize envelope: data did not match any variant of untagged enum Envelope",
        )
        .await;

        _verify_unpack_malformed(
            update_field(ENCRYPTED_MSG_AUTH_X25519, "tag", "invalid").as_str(),
            "Malformed: Unable decode tag: Invalid last symbol 100, offset 6.",
        )
        .await;

        _verify_unpack_malformed(
            remove_field(ENCRYPTED_MSG_AUTH_X25519, "tag").as_str(),
            "Malformed: Unable deserialize envelope: data did not match any variant of untagged enum Envelope",
        )
        .await;

        _verify_unpack_malformed(
            update_protected_field(ENCRYPTED_MSG_AUTH_X25519, "apv", "invalid").as_str(),
            "Malformed: Unable decode apv: Invalid last symbol 100, offset 6.",
        )
        .await;

        _verify_unpack_malformed(
            remove_protected_field(ENCRYPTED_MSG_AUTH_X25519, "apv").as_str(),
            "Malformed: Unable parse protected header: missing field `apv` at line 1 column 264",
        )
        .await;

        _verify_unpack_malformed(
            update_protected_field(ENCRYPTED_MSG_AUTH_X25519, "apu", "invalid").as_str(),
            "Malformed: Unable decode apu: Invalid last symbol 100, offset 6.",
        )
        .await;

        _verify_unpack_malformed(
            remove_protected_field(ENCRYPTED_MSG_AUTH_X25519, "apu").as_str(),
            "Malformed: SKID present, but no apu",
        )
        .await;
    }

    #[tokio::test]
    async fn unpack_works_malformed_signed_msg() {
        _verify_unpack_malformed(
            update_field(SIGNED_MSG_ALICE_KEY_1, "payload", "invalid").as_str(),
            "Malformed: Wrong signature",
        )
        .await;

        _verify_unpack_malformed(
            remove_field(SIGNED_MSG_ALICE_KEY_1, "payload").as_str(),
            "Malformed: Unable deserialize envelope: data did not match any variant of untagged enum Envelope",
        )
        .await;

        _verify_unpack_malformed(
            update_field(SIGNED_MSG_ALICE_KEY_1, "signatures", "invalid").as_str(),
            "Malformed: Unable deserialize envelope: data did not match any variant of untagged enum Envelope",
        )
        .await;

        _verify_unpack_malformed(
            remove_field(SIGNED_MSG_ALICE_KEY_1, "signatures").as_str(),
            "Malformed: Unable deserialize envelope: data did not match any variant of untagged enum Envelope",
        )
        .await;
    }

    #[tokio::test]
    async fn unpack_works_malformed_plaintext_msg() {
        _verify_unpack_malformed(
            INVALID_PLAINTEXT_MSG_EMPTY,
            "Malformed: Unable deserialize envelope: data did not match any variant of untagged enum Envelope",
        )
        .await;

        _verify_unpack_malformed(
            INVALID_PLAINTEXT_MSG_STRING,
            "Malformed: Unable deserialize envelope: expected value at line 2 column 1",
        )
        .await;

        _verify_unpack_malformed(
            INVALID_PLAINTEXT_MSG_NO_ID,
            "Malformed: Unable deserialize envelope: data did not match any variant of untagged enum Envelope",
        )
        .await;

        _verify_unpack_malformed(
            INVALID_PLAINTEXT_MSG_NO_TYPE,
            "Malformed: Unable deserialize envelope: data did not match any variant of untagged enum Envelope",
        )
        .await;

        _verify_unpack_malformed(
            INVALID_PLAINTEXT_MSG_NO_BODY,
            "Malformed: Unable deserialize envelope: data did not match any variant of untagged enum Envelope",
        )
        .await;

        _verify_unpack_malformed(
            INVALID_PLAINTEXT_MSG_WRONG_TYP,
            "Malformed: `typ` must be \"application/didcomm-plain+json\"",
        )
        .await;

        _verify_unpack_malformed(
            INVALID_PLAINTEXT_MSG_EMPTY_ATTACHMENTS,
            "Malformed: Unable deserialize envelope: data did not match any variant of untagged enum Envelope",
        )
        .await;

        _verify_unpack_malformed(
            INVALID_PLAINTEXT_MSG_ATTACHMENTS_NO_DATA,
            "Malformed: Unable deserialize envelope: data did not match any variant of untagged enum Envelope",
        )
        .await;

        _verify_unpack_malformed(
            INVALID_PLAINTEXT_MSG_ATTACHMENTS_EMPTY_DATA,
            "Malformed: Unable deserialize envelope: data did not match any variant of untagged enum Envelope",
        )
        .await;

        _verify_unpack_malformed(
            INVALID_PLAINTEXT_MSG_ATTACHMENTS_LINKS_NO_HASH,
            "Malformed: Unable deserialize envelope: data did not match any variant of untagged enum Envelope",
        )
        .await;

        _verify_unpack_malformed(
            INVALID_PLAINTEXT_MSG_ATTACHMENTS_AS_STRING,
            "Malformed: Unable deserialize envelope: data did not match any variant of untagged enum Envelope",
        )
        .await;

        _verify_unpack_malformed(
            INVALID_PLAINTEXT_MSG_ATTACHMENTS_AS_INT_ARRAY,
            "Malformed: Unable deserialize envelope: data did not match any variant of untagged enum Envelope",
        )
        .await;

        _verify_unpack_malformed(
            INVALID_PLAINTEXT_MSG_ATTACHMENTS_WRONG_DATA,
            "Malformed: Unable deserialize envelope: data did not match any variant of untagged enum Envelope",
        )
        .await;

        _verify_unpack_malformed(
            INVALID_PLAINTEXT_MSG_ATTACHMENTS_WRONG_ID,
            "Malformed: Unable deserialize envelope: data did not match any variant of untagged enum Envelope",
        )
        .await;

        _verify_unpack_malformed(
            INVALID_PLAINTEXT_MSG_ATTACHMENTS_NULL_DATA,
            "Malformed: Unable deserialize envelope: data did not match any variant of untagged enum Envelope",
        )
        .await;
    }

    #[tokio::test]
    async fn unpack_plaintext_works_from_prior() {
        let exp_metadata = UnpackMetadata {
            anonymous_sender: false,
            authenticated: false,
            non_repudiation: false,
            encrypted: false,
            enc_alg_auth: None,
            enc_alg_anon: None,
            sign_alg: None,
            encrypted_from_kid: None,
            encrypted_to_kids: None,
            sign_from: None,
            signed_message: None,
            from_prior_issuer_kid: Some(CHARLIE_AUTH_METHOD_25519.id.clone()),
            from_prior: Some(FROM_PRIOR_FULL.clone()),
            re_wrapped_in_forward: false,
        };

        _verify_unpack(
            PLAINTEXT_FROM_PRIOR,
            &MESSAGE_FROM_PRIOR_FULL,
            &exp_metadata,
        )
        .await;
    }

    #[tokio::test]
    async fn unpack_plaintext_works_invalid_from_prior() {
        _verify_unpack_returns_error(
            PLAINTEXT_INVALID_FROM_PRIOR,
            ErrorKind::Malformed,
            "Malformed: Unable to parse compactly serialized JWS",
        )
        .await;
    }

    #[tokio::test]
    async fn unpack_plaintext_works_invalid_from_prior_signature() {
        _verify_unpack_returns_error(
            PLAINTEXT_FROM_PRIOR_INVALID_SIGNATURE,
            ErrorKind::Malformed,
            "Malformed: Unable to verify from_prior signature: Unable decode signature: Invalid last symbol 66, offset 85.",
        )
            .await;
    }

    async fn _verify_unpack(msg: &str, exp_msg: &Message, exp_metadata: &UnpackMetadata) {
        let mut did_resolver = ExampleDIDResolver::new(vec![
            ALICE_DID_DOC.clone(),
            BOB_DID_DOC.clone(),
            CHARLIE_DID_DOC.clone(),
        ]);

        let secrets_resolver = ExampleSecretsResolver::new(BOB_SECRETS.clone());

        let did_method_resolver = DIDMethods::default();
        let (msg, metadata) = Message::unpack_string(
            msg,
            &mut did_resolver,
            &did_method_resolver,
            &secrets_resolver,
            &UnpackOptions::default(),
        )
        .await
        .expect("unpack is ok.");

        assert_eq!(&msg, exp_msg);
        assert_eq!(&metadata, exp_metadata);
    }

    // Same as `_verify_unpack`, but skips indeterministic values from metadata checking
    async fn _verify_unpack_undeterministic(
        msg: &str,
        exp_msg: &Message,
        exp_metadata: &UnpackMetadata,
    ) {
        let mut did_resolver = ExampleDIDResolver::new(vec![
            ALICE_DID_DOC.clone(),
            BOB_DID_DOC.clone(),
            CHARLIE_DID_DOC.clone(),
        ]);

        let secrets_resolver = ExampleSecretsResolver::new(BOB_SECRETS.clone());
        let did_method_resolver = DIDMethods::default();
        let (msg, mut metadata) = Message::unpack_string(
            msg,
            &mut did_resolver,
            &did_method_resolver,
            &secrets_resolver,
            &UnpackOptions::default(),
        )
        .await
        .expect("unpack is ok.");

        assert_eq!(&msg, exp_msg);

        metadata
            .signed_message
            .clone_from(&exp_metadata.signed_message);
        assert_eq!(&metadata, exp_metadata);
    }

    async fn _verify_unpack_malformed(msg: &str, exp_error_str: &str) {
        _verify_unpack_returns_error(msg, ErrorKind::Malformed, exp_error_str).await
    }

    async fn _verify_unpack_returns_error(msg: &str, exp_err_kind: ErrorKind, exp_err_msg: &str) {
        let mut did_resolver = ExampleDIDResolver::new(vec![
            ALICE_DID_DOC.clone(),
            BOB_DID_DOC.clone(),
            CHARLIE_DID_DOC.clone(),
        ]);

        let secrets_resolver = ExampleSecretsResolver::new(BOB_SECRETS.clone());

        let did_method_resolver = DIDMethods::default();
        let err = Message::unpack_string(
            msg,
            &mut did_resolver,
            &did_method_resolver,
            &secrets_resolver,
            &UnpackOptions::default(),
        )
        .await
        .expect_err("res is ok");

        assert_eq!(err.kind(), exp_err_kind);
        assert_eq!(format!("{}", err), exp_err_msg);
    }
}
*/
