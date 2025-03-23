use affinidi_did_resolver_cache_sdk::{DIDCacheClient, document::DocumentExt};
use affinidi_secrets_resolver::SecretsResolver;
use askar_crypto::{
    alg::{
        aes::{A256CbcHs512, A256Gcm, A256Kw, AesKey},
        chacha20::{Chacha20Key, XC20P},
        k256::K256KeyPair,
        p256::P256KeyPair,
        x25519::X25519KeyPair,
    },
    kdf::{ecdh_1pu::Ecdh1PU, ecdh_es::EcdhEs},
};

use crate::{
    algorithms::{AnonCryptAlg, AuthCryptAlg},
    document::{DIDCommVerificationMethodExt, did_or_url},
    error::{ErrorKind, Result, ResultContext, err_msg},
    jwe,
    utils::crypto::{AsKnownKeyPair, AsKnownKeyPairSecret, KnownKeyAlg},
};

#[allow(clippy::too_many_arguments)]
pub(crate) async fn authcrypt<T>(
    to: &str,
    from: &str,
    did_resolver: &DIDCacheClient,
    secrets_resolver: &T,
    msg: &[u8],
    enc_alg_auth: &AuthCryptAlg,
    enc_alg_anon: &AnonCryptAlg,
    protect_sender: bool,
    to_kids_limit: usize,
) -> Result<(String, String, Vec<String>)>
/* (msg, from_kid, to_kids) */
where
    T: SecretsResolver,
{
    let (to_did, to_kid) = did_or_url(to);

    // TODO: Avoid resolving of same dids multiple times
    // Now we resolve separately in authcrypt, anoncrypt and sign
    let to_ddoc = match did_resolver.resolve(to_did).await {
        Ok(response) => response.doc,
        Err(_) => {
            return Err(err_msg(
                ErrorKind::DIDNotResolved,
                "Recipient did not found",
            ));
        }
    };

    let (from_did, from_kid) = did_or_url(from);

    let from_ddoc = match did_resolver.resolve(from_did).await {
        Ok(response) => response.doc,
        Err(_) => {
            return Err(err_msg(ErrorKind::DIDNotResolved, "Sender did not found"));
        }
    };

    // Initial list of sender keys is all key_agreements of sender did doc
    // or filtered to keep only provided key
    let from_kids = from_ddoc.find_key_agreement(from_kid);

    if from_kids.is_empty() {
        Err(err_msg(
            ErrorKind::DIDUrlNotFound,
            "No sender key agreements found",
        ))?
    }

    // Keep only sender keys present in the wallet
    let from_kids = secrets_resolver.find_secrets(&from_kids).await;

    if from_kids.is_empty() {
        Err(err_msg(
            ErrorKind::SecretNotFound,
            "No sender secrets found",
        ))?
    }

    // Resolve materials for sender keys
    let from_keys = from_kids
        .into_iter()
        .map(|kid| {
            from_ddoc.get_verification_method(&kid).ok_or_else(|| {
                // TODO: support external keys
                err_msg(
                    ErrorKind::Malformed,
                    format!(
                        "No verification material found for sender key agreement {}",
                        kid
                    ),
                )
            })
        })
        .collect::<Result<Vec<_>>>()?;
    /*
     let from_keys = from_kids
        .into_iter()
        .map(|kid| {
            from_ddoc
                .verification_method
                .iter()
                .find(|vm| {
                    println!("vm.id: {}", vm.id);
                    vm.id == kid
                })
                .ok_or_else(|| {
                    // TODO: support external keys
                    err_msg(
                        ErrorKind::Malformed,
                        format!(
                            "No verification material found for sender key agreement {}",
                            kid
                        ),
                    )
                })
        })
        .collect::<Result<Vec<_>>>()?;
    */

    // Initial list of recipient keys is all key_agreements of recipient did doc
    // or filtered to keep only provided key
    let to_kids = to_ddoc.find_key_agreement(to_kid);

    if to_kids.is_empty() {
        Err(err_msg(
            ErrorKind::DIDUrlNotFound,
            "No recipient key agreements found",
        ))?
    }

    if to_kids.len() > to_kids_limit {
        Err(err_msg(
            ErrorKind::TooManyCryptoOperations,
            format!(
                "Too many keys in did. Keys limit is '{}' but found '{}' key(s).",
                to_kids_limit,
                to_kids.len()
            ),
        ))?
    }

    // Resolve materials for recipient keys
    let to_keys = to_kids
        .into_iter()
        .map(|kid| {
            to_ddoc.get_verification_method(&kid).ok_or_else(|| {
                // TODO: support external keys
                err_msg(
                    ErrorKind::Malformed,
                    format!(
                        "No verification material found for recipient key agreement {}",
                        kid
                    ),
                )
            })
        })
        .collect::<Result<Vec<_>>>()?;

    // Looking for first sender key that has supported crypto and intersects with recipient keys
    // by key alg
    let from_key = from_keys
        .iter()
        .filter(|key| {
            if let Some(jwk) = key.get_jwk() {
                key.key_alg(&jwk) != KnownKeyAlg::Unsupported
            } else {
                false
            }
        })
        .find(|from_key| {
            if let Some(from_jwk) = from_key.get_jwk() {
                to_keys.iter().any(|to_key| {
                    if let Some(to_jwk) = to_key.get_jwk() {
                        to_key.key_alg(&to_jwk) == from_key.key_alg(&from_jwk)
                    } else {
                        false
                    }
                })
            } else {
                false
            }
        })
        .copied()
        .ok_or_else(|| {
            err_msg(
                ErrorKind::NoCompatibleCrypto,
                "No common keys between sender and recipient found",
            )
        })?;

    // Resolve secret for found sender key
    let from_priv_key = secrets_resolver
        .get_secret(&from_key.id)
        .await
        .ok_or_else(|| err_msg(ErrorKind::InvalidState, "Sender secret not found"))?;

    let from_jwk = from_key.get_jwk().unwrap();
    let key_alg = from_key.key_alg(&from_jwk);

    // Keep only recipient keys compatible with sender key
    let to_keys: Vec<_> = to_keys
        .into_iter()
        .filter(|key| {
            if let Some(jwk) = key.get_jwk() {
                key.key_alg(&jwk) == key_alg
            } else {
                false
            }
        })
        .collect();

    let msg = match key_alg {
        KnownKeyAlg::X25519 => {
            let _to_keys = to_keys
                .iter()
                .map(|vm| {
                    if let Some(jwk) = vm.get_jwk() {
                        vm.as_x25519(&jwk).map(|k| (&vm.id, k))
                    } else {
                        Err(err_msg(
                            ErrorKind::NoCompatibleCrypto,
                            "Couldn't create JWK for x25519",
                        ))
                    }
                })
                .collect::<Result<Vec<_>>>()?;

            let to_keys: Vec<_> = _to_keys
                .iter()
                .map(|(id, key)| (id.as_str(), key))
                .collect();

            let msg = match enc_alg_auth {
                AuthCryptAlg::A256cbcHs512Ecdh1puA256kw => jwe::encrypt::<
                    AesKey<A256CbcHs512>,
                    Ecdh1PU<'_, X25519KeyPair>,
                    X25519KeyPair,
                    AesKey<A256Kw>,
                >(
                    msg,
                    jwe::Algorithm::Ecdh1puA256kw,
                    jwe::EncAlgorithm::A256cbcHs512,
                    Some((&from_key.id, &from_priv_key.as_x25519()?)),
                    &to_keys,
                )
                .context("Unable produce authcrypt envelope")?,
            };

            if protect_sender {
                match enc_alg_anon {
                    AnonCryptAlg::A256cbcHs512EcdhEsA256kw => jwe::encrypt::<
                        AesKey<A256CbcHs512>,
                        EcdhEs<'_, X25519KeyPair>,
                        X25519KeyPair,
                        AesKey<A256Kw>,
                    >(
                        msg.as_bytes(),
                        jwe::Algorithm::EcdhEsA256kw,
                        jwe::EncAlgorithm::A256cbcHs512,
                        None,
                        &to_keys,
                    )
                    .context("Unable produce authcrypt envelope")?,
                    AnonCryptAlg::Xc20pEcdhEsA256kw => jwe::encrypt::<
                        Chacha20Key<XC20P>,
                        EcdhEs<'_, X25519KeyPair>,
                        X25519KeyPair,
                        AesKey<A256Kw>,
                    >(
                        msg.as_bytes(),
                        jwe::Algorithm::EcdhEsA256kw,
                        jwe::EncAlgorithm::Xc20P,
                        None,
                        &to_keys,
                    )
                    .context("Unable produce authcrypt envelope")?,
                    AnonCryptAlg::A256gcmEcdhEsA256kw => jwe::encrypt::<
                        AesKey<A256Gcm>,
                        EcdhEs<'_, X25519KeyPair>,
                        X25519KeyPair,
                        AesKey<A256Kw>,
                    >(
                        msg.as_bytes(),
                        jwe::Algorithm::EcdhEsA256kw,
                        jwe::EncAlgorithm::A256Gcm,
                        None,
                        &to_keys,
                    )
                    .context("Unable produce authcrypt envelope")?,
                }
            } else {
                msg
            }
        }
        KnownKeyAlg::P256 => {
            let _to_keys = to_keys
                .iter()
                .map(|vm| {
                    if let Some(jwk) = vm.get_jwk() {
                        vm.as_p256(&jwk).map(|k| (&vm.id, k))
                    } else {
                        Err(err_msg(
                            ErrorKind::NoCompatibleCrypto,
                            "Couldn't create JWK for p_256",
                        ))
                    }
                })
                .collect::<Result<Vec<_>>>()?;

            let to_keys: Vec<_> = _to_keys
                .iter()
                .map(|(id, key)| (id.as_str(), key))
                .collect();

            let msg = match enc_alg_auth {
                AuthCryptAlg::A256cbcHs512Ecdh1puA256kw => jwe::encrypt::<
                    AesKey<A256CbcHs512>,
                    Ecdh1PU<'_, P256KeyPair>,
                    P256KeyPair,
                    AesKey<A256Kw>,
                >(
                    msg,
                    jwe::Algorithm::Ecdh1puA256kw,
                    jwe::EncAlgorithm::A256cbcHs512,
                    Some((&from_key.id, &from_priv_key.as_p256()?)),
                    &to_keys,
                )
                .context("Unable produce authcrypt envelope")?,
            };

            if protect_sender {
                match enc_alg_anon {
                    AnonCryptAlg::A256cbcHs512EcdhEsA256kw => jwe::encrypt::<
                        AesKey<A256CbcHs512>,
                        EcdhEs<'_, P256KeyPair>,
                        P256KeyPair,
                        AesKey<A256Kw>,
                    >(
                        msg.as_bytes(),
                        jwe::Algorithm::EcdhEsA256kw,
                        jwe::EncAlgorithm::A256cbcHs512,
                        None,
                        &to_keys,
                    )
                    .context("Unable produce authcrypt envelope")?,
                    AnonCryptAlg::Xc20pEcdhEsA256kw => jwe::encrypt::<
                        Chacha20Key<XC20P>,
                        EcdhEs<'_, P256KeyPair>,
                        P256KeyPair,
                        AesKey<A256Kw>,
                    >(
                        msg.as_bytes(),
                        jwe::Algorithm::EcdhEsA256kw,
                        jwe::EncAlgorithm::Xc20P,
                        None,
                        &to_keys,
                    )
                    .context("Unable produce authcrypt envelope")?,
                    AnonCryptAlg::A256gcmEcdhEsA256kw => jwe::encrypt::<
                        AesKey<A256Gcm>,
                        EcdhEs<'_, P256KeyPair>,
                        P256KeyPair,
                        AesKey<A256Kw>,
                    >(
                        msg.as_bytes(),
                        jwe::Algorithm::EcdhEsA256kw,
                        jwe::EncAlgorithm::A256Gcm,
                        None,
                        &to_keys,
                    )
                    .context("Unable produce authcrypt envelope")?,
                }
            } else {
                msg
            }
        }
        KnownKeyAlg::K256 => {
            let _to_keys = to_keys
                .iter()
                .map(|vm| {
                    if let Some(jwk) = vm.get_jwk() {
                        vm.as_k256(&jwk).map(|k| (&vm.id, k))
                    } else {
                        Err(err_msg(
                            ErrorKind::NoCompatibleCrypto,
                            "Couldn't create JWK for k_256",
                        ))
                    }
                })
                .collect::<Result<Vec<_>>>()?;

            let to_keys: Vec<_> = _to_keys
                .iter()
                .map(|(id, key)| (id.as_str(), key))
                .collect();

            let msg = match enc_alg_auth {
                AuthCryptAlg::A256cbcHs512Ecdh1puA256kw => jwe::encrypt::<
                    AesKey<A256CbcHs512>,
                    Ecdh1PU<'_, K256KeyPair>,
                    K256KeyPair,
                    AesKey<A256Kw>,
                >(
                    msg,
                    jwe::Algorithm::Ecdh1puA256kw,
                    jwe::EncAlgorithm::A256cbcHs512,
                    Some((&from_key.id, &from_priv_key.as_k256()?)),
                    &to_keys,
                )
                .context("Unable produce authcrypt envelope")?,
            };

            if protect_sender {
                match enc_alg_anon {
                    AnonCryptAlg::A256cbcHs512EcdhEsA256kw => jwe::encrypt::<
                        AesKey<A256CbcHs512>,
                        EcdhEs<'_, K256KeyPair>,
                        K256KeyPair,
                        AesKey<A256Kw>,
                    >(
                        msg.as_bytes(),
                        jwe::Algorithm::EcdhEsA256kw,
                        jwe::EncAlgorithm::A256cbcHs512,
                        None,
                        &to_keys,
                    )
                    .context("Unable produce authcrypt envelope")?,
                    AnonCryptAlg::Xc20pEcdhEsA256kw => jwe::encrypt::<
                        Chacha20Key<XC20P>,
                        EcdhEs<'_, K256KeyPair>,
                        K256KeyPair,
                        AesKey<A256Kw>,
                    >(
                        msg.as_bytes(),
                        jwe::Algorithm::EcdhEsA256kw,
                        jwe::EncAlgorithm::Xc20P,
                        None,
                        &to_keys,
                    )
                    .context("Unable produce authcrypt envelope")?,
                    AnonCryptAlg::A256gcmEcdhEsA256kw => jwe::encrypt::<
                        AesKey<A256Gcm>,
                        EcdhEs<'_, K256KeyPair>,
                        K256KeyPair,
                        AesKey<A256Kw>,
                    >(
                        msg.as_bytes(),
                        jwe::Algorithm::EcdhEsA256kw,
                        jwe::EncAlgorithm::A256Gcm,
                        None,
                        &to_keys,
                    )
                    .context("Unable produce authcrypt envelope")?,
                }
            } else {
                msg
            }
        }
        _ => Err(err_msg(
            ErrorKind::Unsupported,
            "Unsupported recipient key agreement method",
        ))?,
    };

    let to_kids: Vec<_> = to_keys.into_iter().map(|vm| vm.id.to_string()).collect();
    Ok((msg, from_key.id.to_string(), to_kids))
}
