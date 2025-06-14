use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_secrets_resolver::SecretsResolver;

use crate::{
    FromPrior,
    document::{did_or_url, is_did},
    error::{ErrorKind, Result, ResultContext, ResultExt, err_msg},
    jws::{self, Algorithm},
    message::from_prior::JWT_TYP,
    utils::crypto::{AsKnownKeyPairSecret, KnownKeyPair},
};

impl FromPrior {
    /// Packs a plaintext `from_prior` value into a signed JWT.
    /// https://identity.foundation/didcomm-messaging/spec/#did-rotation
    ///
    /// # Parameters
    /// - `issuer_kid` (optional) identifier of the issuer key being used to sign `from_prior` JWT value.
    /// - `did_resolver` instance of `DIDResolver` to resolve DIDs.
    /// - `secrets_resolver` instance of `SecretsResolver` to resolve issuer DID keys secrets.
    ///
    /// # Returns
    /// Tuple (signed `from_prior` JWT, identifier of the issuer key actually used to sign `from_prior`)
    ///
    /// # Errors
    /// - `Malformed` `from_prior` plaintext value has invalid format.
    /// - `IllegalArgument` `issuer_kid` is invalid or does not consist with `from_prior` plaintext value.
    /// - `DIDNotResolved` Issuer DID not found.
    /// - `DIDUrlNotFound` Issuer authentication verification method is not found.
    /// - `SecretNotFound` Issuer secret is not found.
    /// - `Unsupported` Used crypto or method is unsupported.
    /// - `InvalidState` Indicates a library error.
    pub async fn pack<T>(
        &self,
        issuer_kid: Option<&str>,
        did_resolver: &DIDCacheClient,
        secrets_resolver: &T,
    ) -> Result<(String, String)>
    where
        T: SecretsResolver,
    {
        self.validate_pack(issuer_kid)?;

        let from_prior_str = serde_json::to_string(self)
            .kind(ErrorKind::InvalidState, "Unable serialize message")?;

        let did_doc = match did_resolver.resolve(&self.iss).await {
            Ok(result) => result.doc,
            Err(err) => {
                return Err(err_msg(
                    ErrorKind::DIDNotResolved,
                    format!("from_prior issuer DIDDoc is not found. Reason: {}", err),
                ));
            }
        };

        let authentication_kids: Vec<String> = if let Some(issuer_kid) = issuer_kid {
            let (did, kid) = did_or_url(issuer_kid);

            let kid = kid.ok_or_else(|| {
                err_msg(
                    ErrorKind::IllegalArgument,
                    "issuer_kid content is not DID URL",
                )
            })?;

            if did != self.iss {
                Err(err_msg(
                    ErrorKind::IllegalArgument,
                    "from_prior issuer kid does not belong to from_prior `iss`",
                ))?
            }

            let kid = did_doc
                .verification_relationships
                .authentication
                .iter()
                .find(|a| a.id().resolve(did_doc.id.as_did()).to_string() == kid)
                .ok_or_else(|| {
                    err_msg(
                        ErrorKind::DIDUrlNotFound,
                        "Provided issuer_kid is not found in DIDDoc",
                    )
                })?;

            vec![kid.id().resolve(did_doc.id.as_did()).to_string()]
        } else {
            did_doc
                .verification_relationships
                .authentication
                .iter()
                .map(|s| s.id().resolve(did_doc.id.as_did()).to_string())
                .collect()
        };

        let kid = secrets_resolver
            .find_secrets(&authentication_kids)
            .await
            .first()
            .ok_or_else(|| {
                err_msg(
                    ErrorKind::SecretNotFound,
                    "No from_prior issuer secrets found",
                )
            })?
            .to_string();

        let secret = secrets_resolver.get_secret(&kid).await.ok_or_else(|| {
            err_msg(
                ErrorKind::SecretNotFound,
                "from_prior issuer secret not found",
            )
        })?;

        let sign_key = secret
            .as_key_pair()
            .context("Unable to instantiate from_prior issuer key")?;

        let from_prior_jwt = match sign_key {
            KnownKeyPair::Ed25519(ref key) => jws::sign_compact(
                from_prior_str.as_bytes(),
                (&kid, key),
                JWT_TYP,
                Algorithm::EdDSA,
            ),
            KnownKeyPair::P256(ref key) => jws::sign_compact(
                from_prior_str.as_bytes(),
                (&kid, key),
                JWT_TYP,
                Algorithm::Es256,
            ),
            KnownKeyPair::K256(ref key) => jws::sign_compact(
                from_prior_str.as_bytes(),
                (&kid, key),
                JWT_TYP,
                Algorithm::Es256K,
            ),
            _ => Err(err_msg(ErrorKind::Unsupported, "Unsupported signature alg"))?,
        }
        .context("Unable to produce signature")?;

        Ok((from_prior_jwt, kid))
    }

    pub(crate) fn validate_pack(&self, issuer_kid: Option<&str>) -> Result<()> {
        if !is_did(&self.iss) || did_or_url(&self.iss).1.is_some() {
            Err(err_msg(
                ErrorKind::Malformed,
                "from_prior `iss` must be a non-fragment DID",
            ))?;
        }

        if !is_did(&self.sub) || did_or_url(&self.sub).1.is_some() {
            Err(err_msg(
                ErrorKind::Malformed,
                "from_prior `sub` must be a non-fragment DID",
            ))?;
        }

        if self.iss == self.sub {
            Err(err_msg(
                ErrorKind::Malformed,
                "from_prior `iss` and `sub` values must not be equal",
            ))?;
        }

        if let Some(issuer_kid) = issuer_kid {
            let (did, kid) = did_or_url(issuer_kid);

            if kid.is_none() {
                Err(err_msg(
                    ErrorKind::IllegalArgument,
                    "issuer_kid content is not DID URL",
                ))?;
            };

            if did != self.iss {
                Err(err_msg(
                    ErrorKind::IllegalArgument,
                    "from_prior issuer kid does not belong to from_prior `iss`",
                ))?;
            }
        }

        Ok(())
    }
}

// The following needs to be refactored to work with new DID Document model

#[cfg(test)]
mod tests {
    use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
    use affinidi_secrets_resolver::SimpleSecretsResolver;

    use crate::{
        FromPrior,
        document::did_or_url,
        error::ErrorKind,
        test_vectors::{
            ALICE_DID, ALICE_SECRET_AUTH_KEY_ED25519, ALICE_SECRETS, CHARLIE_DID,
            CHARLIE_ROTATED_TO_ALICE_SECRETS, CHARLIE_SECRET_AUTH_KEY_ED25519, FROM_PRIOR_FULL,
            FROM_PRIOR_INVALID_EQUAL_ISS_AND_SUB, FROM_PRIOR_INVALID_ISS, FROM_PRIOR_INVALID_SUB,
            FROM_PRIOR_MINIMAL,
        },
    };

    #[ignore]
    #[tokio::test]
    async fn from_prior_pack_works_with_issuer_kid() {
        _from_prior_pack_works_with_issuer_kid(&FROM_PRIOR_MINIMAL).await;
        _from_prior_pack_works_with_issuer_kid(&FROM_PRIOR_FULL).await;

        async fn _from_prior_pack_works_with_issuer_kid(from_prior: &FromPrior) {
            let did_resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
                .await
                .unwrap();
            let charlie_rotated_to_alice_secrets_resolver =
                SimpleSecretsResolver::new(&CHARLIE_ROTATED_TO_ALICE_SECRETS.clone()).await;

            let (from_prior_jwt, pack_kid) = from_prior
                .pack(
                    Some(&CHARLIE_SECRET_AUTH_KEY_ED25519.id),
                    &did_resolver,
                    &charlie_rotated_to_alice_secrets_resolver,
                )
                .await
                .expect("Unable to pack FromPrior");

            assert_eq!(pack_kid, CHARLIE_SECRET_AUTH_KEY_ED25519.id);

            let (unpacked_from_prior, unpack_kid) =
                FromPrior::unpack(&from_prior_jwt, &did_resolver)
                    .await
                    .expect("Unable to unpack FromPrior JWT");

            assert_eq!(&unpacked_from_prior, from_prior);
            assert_eq!(unpack_kid, CHARLIE_SECRET_AUTH_KEY_ED25519.id);
        }
    }

    #[ignore]
    #[tokio::test]
    async fn from_prior_pack_works_without_issuer_kid() {
        _from_prior_pack_works_without_issuer_kid(&FROM_PRIOR_MINIMAL).await;
        _from_prior_pack_works_without_issuer_kid(&FROM_PRIOR_FULL).await;

        async fn _from_prior_pack_works_without_issuer_kid(from_prior: &FromPrior) {
            let did_resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
                .await
                .unwrap();
            let charlie_rotated_to_alice_secrets_resolver =
                SimpleSecretsResolver::new(&CHARLIE_ROTATED_TO_ALICE_SECRETS.clone()).await;

            let (from_prior_jwt, pack_kid) = from_prior
                .pack(
                    None,
                    &did_resolver,
                    &charlie_rotated_to_alice_secrets_resolver,
                )
                .await
                .expect("Unable to pack FromPrior");

            let (did, kid) = did_or_url(&pack_kid);
            assert!(kid.is_some());
            assert_eq!(did, CHARLIE_DID);

            let (unpacked_from_prior, unpack_kid) =
                FromPrior::unpack(&from_prior_jwt, &did_resolver)
                    .await
                    .expect("Unable to unpack FromPrior JWT");

            assert_eq!(&unpacked_from_prior, from_prior);
            assert_eq!(unpack_kid, pack_kid);
        }
    }

    #[ignore]
    #[tokio::test]
    async fn from_prior_pack_works_wrong_issuer_kid() {
        _from_prior_pack_works_wrong_issuer_kid(
            &FROM_PRIOR_FULL,
            &ALICE_SECRET_AUTH_KEY_ED25519.id,
            ErrorKind::IllegalArgument,
            "Illegal argument: from_prior issuer kid does not belong to from_prior `iss`",
        )
        .await;

        _from_prior_pack_works_wrong_issuer_kid(
            &FROM_PRIOR_FULL,
            ALICE_DID,
            ErrorKind::IllegalArgument,
            "Illegal argument: issuer_kid content is not DID URL",
        )
        .await;

        _from_prior_pack_works_wrong_issuer_kid(
            &FROM_PRIOR_FULL,
            "invalid",
            ErrorKind::IllegalArgument,
            "Illegal argument: issuer_kid content is not DID URL",
        )
        .await;

        async fn _from_prior_pack_works_wrong_issuer_kid(
            from_prior: &FromPrior,
            issuer_kid: &str,
            err_kind: ErrorKind,
            err_mgs: &str,
        ) {
            let did_resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
                .await
                .unwrap();
            let alice_secrets_resolver = SimpleSecretsResolver::new(&ALICE_SECRETS.clone()).await;

            let err = from_prior
                .pack(Some(issuer_kid), &did_resolver, &alice_secrets_resolver)
                .await
                .expect_err("res is ok");

            assert_eq!(err.kind(), err_kind);
            assert_eq!(format!("{}", err), err_mgs);
        }
    }

    #[ignore]
    #[tokio::test]
    async fn from_prior_pack_works_invalid() {
        _from_prior_pack_works_invalid(
            &FROM_PRIOR_INVALID_ISS,
            ErrorKind::Malformed,
            "Malformed: from_prior `iss` must be a non-fragment DID",
        )
        .await;

        _from_prior_pack_works_invalid(
            &FROM_PRIOR_INVALID_SUB,
            ErrorKind::Malformed,
            "Malformed: from_prior `sub` must be a non-fragment DID",
        )
        .await;

        _from_prior_pack_works_invalid(
            &FROM_PRIOR_INVALID_EQUAL_ISS_AND_SUB,
            ErrorKind::Malformed,
            "Malformed: from_prior `iss` and `sub` values must not be equal",
        )
        .await;

        async fn _from_prior_pack_works_invalid(
            from_prior: &FromPrior,
            err_kind: ErrorKind,
            err_mgs: &str,
        ) {
            let did_resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
                .await
                .unwrap();
            let charlie_rotated_to_alice_secrets_resolver =
                SimpleSecretsResolver::new(&CHARLIE_ROTATED_TO_ALICE_SECRETS.clone()).await;

            let err = from_prior
                .pack(
                    None,
                    &did_resolver,
                    &charlie_rotated_to_alice_secrets_resolver,
                )
                .await
                .expect_err("res is ok");

            assert_eq!(err.kind(), err_kind);
            assert_eq!(format!("{}", err), err_mgs);
        }
    }
}
