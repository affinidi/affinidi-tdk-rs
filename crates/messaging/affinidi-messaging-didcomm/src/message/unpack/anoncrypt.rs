use crate::{
    UnpackOptions,
    algorithms::AnonCryptAlg,
    document::did_or_url,
    envelope::{Envelope, MetaEnvelope, ParsedEnvelope},
    error::{ErrorKind, Result, ResultExt, err_msg},
    jwe,
    utils::crypto::{AsKnownKeyPairSecret, KnownKeyPair},
};
use affinidi_secrets_resolver::SecretsResolver;
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
use std::str::FromStr;
use tracing::debug;

pub(crate) async fn _try_unpack_anoncrypt<T>(
    jwe: &ParsedEnvelope,
    secrets_resolver: &T,
    opts: &UnpackOptions,
    envelope: &mut MetaEnvelope,
) -> Result<Option<ParsedEnvelope>>
where
    T: SecretsResolver,
{
    let jwe = match jwe {
        ParsedEnvelope::Jwe(jwe) => jwe,
        _ => {
            debug!("Message is not JWE, therefore not ANONCRYPT");
            return Ok(None);
        }
    };

    if jwe.protected.alg != jwe::Algorithm::EcdhEsA256kw {
        debug!(
            "Expected EcdhEsA256kw algo, instead this message is using {:#?}",
            jwe.protected.alg
        );
        return Ok(None);
    }

    let to_kid = jwe
        .to_kids
        .first()
        .ok_or_else(|| err_msg(ErrorKind::Malformed, "No recipient keys found"))?;

    let (to_did, _) = did_or_url(to_kid);

    if jwe.to_kids.iter().any(|k| {
        let (k_did, k_url) = did_or_url(k);
        (k_did != to_did) || (k_url.is_none())
    }) {
        Err(err_msg(
            ErrorKind::Malformed,
            "Recipient keys are outside of one did or can't be resolved to key agreement",
        ))?;
    }

    envelope.metadata.encrypted_to_kids = jwe.to_kids.iter().map(|k| k.to_owned()).collect();
    envelope.metadata.encrypted = true;
    envelope.metadata.anonymous_sender = true;

    let to_kids_found = secrets_resolver.find_secrets(&jwe.to_kids).await;

    if to_kids_found.is_empty() {
        Err(err_msg(
            ErrorKind::SecretNotFound,
            "No recipient secrets found",
        ))?;
    }

    let mut payload: Option<Vec<u8>> = None;

    for to_kid in to_kids_found {
        let to_key = secrets_resolver.get_secret(&to_kid).await.ok_or_else(|| {
            err_msg(
                ErrorKind::InvalidState,
                "Recipient secret not found after existence checking",
            )
        })?;
        let to_key = to_key.as_key_pair()?;

        let _payload = match (to_key, &jwe.protected.enc) {
            (KnownKeyPair::X25519(ref to_key), jwe::EncAlgorithm::A256cbcHs512) => {
                envelope.metadata.enc_alg_anon = Some(AnonCryptAlg::A256cbcHs512EcdhEsA256kw);

                jwe.decrypt::<
                        AesKey<A256CbcHs512>,
                        EcdhEs<'_, X25519KeyPair>,
                        X25519KeyPair,
                        AesKey<A256Kw>,
                    >(None, (&to_kid, to_key))?
            }
            (KnownKeyPair::X25519(ref to_key), jwe::EncAlgorithm::Xc20P) => {
                envelope.metadata.enc_alg_anon = Some(AnonCryptAlg::Xc20pEcdhEsA256kw);

                jwe.decrypt::<
                        Chacha20Key<XC20P>,
                        EcdhEs<'_, X25519KeyPair>,
                        X25519KeyPair,
                        AesKey<A256Kw>,
                    >(None, (&to_kid, to_key))?
            }
            (KnownKeyPair::X25519(ref to_key), jwe::EncAlgorithm::A256Gcm) => {
                envelope.metadata.enc_alg_anon = Some(AnonCryptAlg::A256gcmEcdhEsA256kw);

                jwe.decrypt::<
                        AesKey<A256Gcm>,
                        EcdhEs<'_, X25519KeyPair>,
                        X25519KeyPair,
                        AesKey<A256Kw>,
                    >(None, (&to_kid, to_key))?
            }
            (KnownKeyPair::P256(ref to_key), jwe::EncAlgorithm::A256cbcHs512) => {
                envelope.metadata.enc_alg_anon = Some(AnonCryptAlg::A256cbcHs512EcdhEsA256kw);

                jwe.decrypt::<
                        AesKey<A256CbcHs512>,
                        EcdhEs<'_, P256KeyPair>,
                        P256KeyPair,
                        AesKey<A256Kw>,
                    >(None, (&to_kid, to_key))?
            }
            (KnownKeyPair::P256(ref to_key), jwe::EncAlgorithm::Xc20P) => {
                envelope.metadata.enc_alg_anon = Some(AnonCryptAlg::Xc20pEcdhEsA256kw);

                jwe.decrypt::<
                        Chacha20Key<XC20P>,
                        EcdhEs<'_, P256KeyPair>,
                        P256KeyPair,
                        AesKey<A256Kw>,
                    >(None, (&to_kid, to_key))?
            }
            (KnownKeyPair::P256(ref to_key), jwe::EncAlgorithm::A256Gcm) => {
                envelope.metadata.enc_alg_anon = Some(AnonCryptAlg::A256gcmEcdhEsA256kw);

                jwe.decrypt::<
                        AesKey<A256Gcm>,
                        EcdhEs<'_, P256KeyPair>,
                        P256KeyPair,
                        AesKey<A256Kw>,
                    >(None, (&to_kid, to_key))?
            }
            (KnownKeyPair::K256(ref to_key), jwe::EncAlgorithm::A256cbcHs512) => {
                envelope.metadata.enc_alg_anon = Some(AnonCryptAlg::A256cbcHs512EcdhEsA256kw);

                jwe.decrypt::<
                        AesKey<A256CbcHs512>,
                        EcdhEs<'_, K256KeyPair>,
                        K256KeyPair,
                        AesKey<A256Kw>,
                    >(None, (&to_kid, to_key))?
            }
            (KnownKeyPair::K256(ref to_key), jwe::EncAlgorithm::Xc20P) => {
                envelope.metadata.enc_alg_anon = Some(AnonCryptAlg::Xc20pEcdhEsA256kw);

                jwe.decrypt::<
                        Chacha20Key<XC20P>,
                        EcdhEs<'_, K256KeyPair>,
                        K256KeyPair,
                        AesKey<A256Kw>,
                    >(None, (&to_kid, to_key))?
            }
            (KnownKeyPair::K256(ref to_key), jwe::EncAlgorithm::A256Gcm) => {
                envelope.metadata.enc_alg_anon = Some(AnonCryptAlg::A256gcmEcdhEsA256kw);

                jwe.decrypt::<
                        AesKey<A256Gcm>,
                        EcdhEs<'_, K256KeyPair>,
                        K256KeyPair,
                        AesKey<A256Kw>,
                    >(None, (&to_kid, to_key))?
            }
            _ => Err(err_msg(
                ErrorKind::Unsupported,
                "Unsupported recipient key agreement method",
            ))?,
        };

        payload = Some(_payload);

        if !opts.expect_decrypt_by_all_keys {
            break;
        }
    }

    let payload = payload.ok_or_else(|| err_msg(ErrorKind::InvalidState, "Payload is none"))?;

    let payload = String::from_utf8(payload)
        .kind(ErrorKind::Malformed, "Anoncrypt payload is invalid utf8")?;

    let e = Envelope::from_str(&payload)?.parse()?.verify_didcomm()?;
    Ok(Some(e))
}
