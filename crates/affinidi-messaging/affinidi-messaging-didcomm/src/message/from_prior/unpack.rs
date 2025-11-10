use crate::{
    FromPrior,
    document::{DIDCommVerificationMethodExt, did_or_url},
    error::{ErrorKind, Result, ResultContext, ResultExt, err_msg},
    jws,
    utils::crypto::AsKnownKeyPair,
};
use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use askar_crypto::alg::{ed25519::Ed25519KeyPair, k256::K256KeyPair, p256::P256KeyPair};
use base64::prelude::*;

impl FromPrior {
    /// Unpacks a plaintext value from a signed `from_prior` JWT.
    /// https://identity.foundation/didcomm-messaging/spec/#did-rotation
    ///
    /// # Parameters
    /// - `from_prior_jwt` signed `from_prior` JWT.
    /// - `did_resolver` instance of `DIDResolver` to resolve DIDs.
    ///
    /// # Returns
    /// Tuple (plaintext `from_prior` value, identifier of the issuer key used to sign `from_prior`)
    ///
    /// # Errors
    /// - `Malformed` Signed `from_prior` JWT is malformed.
    /// - `DIDNotResolved` Issuer DID not found.
    /// - `DIDUrlNotFound` Issuer authentication verification method is not found.
    /// - `Unsupported` Used crypto or method is unsupported.
    pub async fn unpack(
        from_prior_jwt: &str,
        did_resolver: &DIDCacheClient,
    ) -> Result<(FromPrior, String)> {
        let parsed = jws::parse_compact(from_prior_jwt)?;

        let typ = &parsed.parsed_header.typ;
        let alg = parsed.parsed_header.alg.clone();
        let kid = &parsed.parsed_header.kid;

        if typ != "JWT" {
            Err(err_msg(
                ErrorKind::Malformed,
                "from_prior is malformed: typ is not JWT",
            ))?;
        }

        let (did, did_url) = did_or_url(kid);

        if did_url.is_none() {
            Err(err_msg(
                ErrorKind::Malformed,
                "from_prior kid is not DID URL",
            ))?
        }

        let did_doc = match did_resolver.resolve(did).await {
            Ok(response) => response.doc,
            Err(err) => {
                return Err(err_msg(
                    ErrorKind::DIDNotResolved,
                    format!(
                        "from_prior issuer DID ({did}) couldn't be resolved. Reason: {err}"
                    ),
                ));
            }
        };

        let kid = did_doc
            .authentication
            .iter()
            .find(|a| a.get_id() == kid)
            .ok_or_else(|| {
                err_msg(
                    ErrorKind::DIDUrlNotFound,
                    "Provided issuer_kid is not found in DIDDoc",
                )
            })?;

        let kid = kid.get_id();

        let key = did_doc
            .verification_method
            .iter()
            .find(|&vm| vm.id.as_str() == kid)
            .ok_or_else(|| {
                err_msg(
                    ErrorKind::DIDUrlNotFound,
                    "from_prior issuer verification method not found in DIDDoc",
                )
            })?;

        let jwk = key
            .get_jwk()
            .ok_or_else(|| err_msg(ErrorKind::Unsupported, "Couldn't convert key to jwk"))?;

        let valid = match alg {
            jws::Algorithm::EdDSA => {
                let key = key
                    .as_ed25519(&jwk)
                    .context("Unable to instantiate from_prior issuer key")?;
                parsed
                    .verify::<Ed25519KeyPair>(&key)
                    .context("Unable to verify from_prior signature")?
            }
            jws::Algorithm::Es256 => {
                let key = key
                    .as_p256(&jwk)
                    .context("Unable to instantiate from_prior issuer key")?;

                parsed
                    .verify::<P256KeyPair>(&key)
                    .context("Unable to verify from_prior signature")?
            }
            jws::Algorithm::Es256K => {
                let key = key
                    .as_k256(&jwk)
                    .context("Unable to instantiate from_prior issuer key")?;

                parsed
                    .verify::<K256KeyPair>(&key)
                    .context("Unable to verify from_prior signature")?
            }
            jws::Algorithm::Other(_) => Err(err_msg(
                ErrorKind::Unsupported,
                "Unsupported signature algorithm",
            ))?,
        };

        if !valid {
            Err(err_msg(ErrorKind::Malformed, "Wrong from_prior signature"))?
        }

        let payload = BASE64_URL_SAFE_NO_PAD.decode(parsed.payload).kind(
            ErrorKind::Malformed,
            "from_prior payload is not a valid base64",
        )?;

        let payload = String::from_utf8(payload).kind(
            ErrorKind::Malformed,
            "Decoded from_prior payload is not a valid UTF-8",
        )?;

        let from_prior: FromPrior = serde_json::from_str(&payload)
            .kind(ErrorKind::Malformed, "Unable to parse from_prior")?;

        Ok((from_prior, kid.into()))
    }
}

#[cfg(test)]
mod tests {
    use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};

    use crate::{
        FromPrior,
        error::ErrorKind,
        test_vectors::{
            CHARLIE_SECRET_AUTH_KEY_ED25519, FROM_PRIOR_FULL, FROM_PRIOR_JWT_FULL,
            FROM_PRIOR_JWT_INVALID, FROM_PRIOR_JWT_INVALID_SIGNATURE,
        },
    };

    #[tokio::test]
    async fn from_prior_unpack_works() {
        let did_resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .unwrap();

        let (from_prior, issuer_kid) = FromPrior::unpack(FROM_PRIOR_JWT_FULL, &did_resolver)
            .await
            .expect("unpack FromPrior failed");

        assert_eq!(&from_prior, &*FROM_PRIOR_FULL);
        assert_eq!(issuer_kid, CHARLIE_SECRET_AUTH_KEY_ED25519.id);
    }

    #[tokio::test]
    async fn from_prior_unpack_works_invalid() {
        let did_resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .unwrap();

        let err = FromPrior::unpack(FROM_PRIOR_JWT_INVALID, &did_resolver)
            .await
            .expect_err("res is ok");

        assert_eq!(err.kind(), ErrorKind::Malformed);
        assert_eq!(
            format!("{}", err),
            "Malformed: Unable to parse compactly serialized JWS"
        );
    }

    #[tokio::test]
    async fn from_prior_unpack_works_invalid_signature() {
        let did_resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .unwrap();

        let err = FromPrior::unpack(FROM_PRIOR_JWT_INVALID_SIGNATURE, &did_resolver)
            .await
            .expect_err("res is ok");

        assert_eq!(err.kind(), ErrorKind::Malformed);
        assert_eq!(
            format!("{}", err),
            "Malformed: Unable to verify from_prior signature: Unable decode signature: Invalid last symbol 104, offset 85."
        );
    }
}
