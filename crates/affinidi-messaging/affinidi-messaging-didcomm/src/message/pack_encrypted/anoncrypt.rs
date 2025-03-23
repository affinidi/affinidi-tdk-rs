use affinidi_did_resolver_cache_sdk::{DIDCacheClient, document::DocumentExt};
use askar_crypto::{
    alg::{
        aes::{A256CbcHs512, A256Gcm, A256Kw, AesKey},
        chacha20::{Chacha20Key, XC20P},
        k256::K256KeyPair,
        p256::P256KeyPair,
        x25519::X25519KeyPair,
    },
    kdf::ecdh_es::EcdhEs,
};

use crate::{
    algorithms::AnonCryptAlg,
    document::{DIDCommVerificationMethodExt, did_or_url},
    error::{ErrorKind, Result, ResultContext, err_msg},
    jwe,
    utils::crypto::{AsKnownKeyPair, KnownKeyAlg},
};

pub(crate) async fn anoncrypt(
    to: &str,
    did_resolver: &DIDCacheClient,
    msg: &[u8],
    enc_alg_anon: &AnonCryptAlg,
    to_kids_limit: usize,
) -> Result<(String, Vec<String>)> /* (msg, to_kids) */ {
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

    // Initial list of recipient key ids is all key_agreements of recipient did doc
    // or one key if url was explicitly provided
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
            to_ddoc
                .verification_method
                .iter()
                .find(|vm| vm.id == kid)
                .ok_or_else(|| {
                    // TODO: support external keys
                    err_msg(
                        ErrorKind::Unsupported,
                        "External keys are unsupported in this version",
                    )
                })
        })
        .collect::<Result<Vec<_>>>()?;

    // Looking for first supported key to determine what key alg to use
    let key_alg = to_keys
        .iter()
        .filter_map(|key| {
            if let Some(jwk) = key.get_jwk() {
                match key.key_alg(&jwk) {
                    KnownKeyAlg::Unsupported => None,
                    alg => Some(alg),
                }
            } else {
                None
            }
        })
        .next()
        .ok_or_else(|| {
            err_msg(
                ErrorKind::InvalidState,
                "No key agreement keys found for recipient",
            )
        })?;

    // Keep only keys with determined key alg
    let to_keys: Vec<_> = to_keys
        .iter()
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

            match enc_alg_anon {
                AnonCryptAlg::A256cbcHs512EcdhEsA256kw => jwe::encrypt::<
                    AesKey<A256CbcHs512>,
                    EcdhEs<'_, X25519KeyPair>,
                    X25519KeyPair,
                    AesKey<A256Kw>,
                >(
                    msg,
                    jwe::Algorithm::EcdhEsA256kw,
                    jwe::EncAlgorithm::A256cbcHs512,
                    None,
                    &to_keys,
                )
                .context("Unable produce anoncrypt envelope")?,
                AnonCryptAlg::Xc20pEcdhEsA256kw => jwe::encrypt::<
                    Chacha20Key<XC20P>,
                    EcdhEs<'_, X25519KeyPair>,
                    X25519KeyPair,
                    AesKey<A256Kw>,
                >(
                    msg,
                    jwe::Algorithm::EcdhEsA256kw,
                    jwe::EncAlgorithm::Xc20P,
                    None,
                    &to_keys,
                )
                .context("Unable produce anoncrypt envelope")?,
                AnonCryptAlg::A256gcmEcdhEsA256kw => jwe::encrypt::<
                    AesKey<A256Gcm>,
                    EcdhEs<'_, X25519KeyPair>,
                    X25519KeyPair,
                    AesKey<A256Kw>,
                >(
                    msg,
                    jwe::Algorithm::EcdhEsA256kw,
                    jwe::EncAlgorithm::A256Gcm,
                    None,
                    &to_keys,
                )
                .context("Unable produce anoncrypt envelope")?,
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
                            "Couldn't create JWK for p256",
                        ))
                    }
                })
                .collect::<Result<Vec<_>>>()?;

            let to_keys: Vec<_> = _to_keys
                .iter()
                .map(|(id, key)| (id.as_str(), key))
                .collect();

            match enc_alg_anon {
                AnonCryptAlg::A256cbcHs512EcdhEsA256kw => jwe::encrypt::<
                    AesKey<A256CbcHs512>,
                    EcdhEs<'_, P256KeyPair>,
                    P256KeyPair,
                    AesKey<A256Kw>,
                >(
                    msg,
                    jwe::Algorithm::EcdhEsA256kw,
                    jwe::EncAlgorithm::A256cbcHs512,
                    None,
                    &to_keys,
                )
                .context("Unable produce anoncrypt envelope")?,
                AnonCryptAlg::Xc20pEcdhEsA256kw => jwe::encrypt::<
                    Chacha20Key<XC20P>,
                    EcdhEs<'_, P256KeyPair>,
                    P256KeyPair,
                    AesKey<A256Kw>,
                >(
                    msg,
                    jwe::Algorithm::EcdhEsA256kw,
                    jwe::EncAlgorithm::Xc20P,
                    None,
                    &to_keys,
                )
                .context("Unable produce anoncrypt envelope")?,
                AnonCryptAlg::A256gcmEcdhEsA256kw => jwe::encrypt::<
                    AesKey<A256Gcm>,
                    EcdhEs<'_, P256KeyPair>,
                    P256KeyPair,
                    AesKey<A256Kw>,
                >(
                    msg,
                    jwe::Algorithm::EcdhEsA256kw,
                    jwe::EncAlgorithm::A256Gcm,
                    None,
                    &to_keys,
                )
                .context("Unable produce anoncrypt envelope")?,
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
                            "Couldn't create JWK for k256",
                        ))
                    }
                })
                .collect::<Result<Vec<_>>>()?;

            let to_keys: Vec<_> = _to_keys
                .iter()
                .map(|(id, key)| (id.as_str(), key))
                .collect();

            match enc_alg_anon {
                AnonCryptAlg::A256cbcHs512EcdhEsA256kw => jwe::encrypt::<
                    AesKey<A256CbcHs512>,
                    EcdhEs<'_, K256KeyPair>,
                    K256KeyPair,
                    AesKey<A256Kw>,
                >(
                    msg,
                    jwe::Algorithm::EcdhEsA256kw,
                    jwe::EncAlgorithm::A256cbcHs512,
                    None,
                    &to_keys,
                )
                .context("Unable produce anoncrypt envelope")?,
                AnonCryptAlg::Xc20pEcdhEsA256kw => jwe::encrypt::<
                    Chacha20Key<XC20P>,
                    EcdhEs<'_, K256KeyPair>,
                    K256KeyPair,
                    AesKey<A256Kw>,
                >(
                    msg,
                    jwe::Algorithm::EcdhEsA256kw,
                    jwe::EncAlgorithm::Xc20P,
                    None,
                    &to_keys,
                )
                .context("Unable produce anoncrypt envelope")?,
                AnonCryptAlg::A256gcmEcdhEsA256kw => jwe::encrypt::<
                    AesKey<A256Gcm>,
                    EcdhEs<'_, K256KeyPair>,
                    K256KeyPair,
                    AesKey<A256Kw>,
                >(
                    msg,
                    jwe::Algorithm::EcdhEsA256kw,
                    jwe::EncAlgorithm::A256Gcm,
                    None,
                    &to_keys,
                )
                .context("Unable produce anoncrypt envelope")?,
            }
        }
        _ => Err(err_msg(
            ErrorKind::InvalidState,
            "Unsupported recipient key agreement alg",
        ))?,
    };

    let to_kids: Vec<_> = to_keys.into_iter().map(|vm| vm.id.to_string()).collect();
    Ok((msg, to_kids))
}
