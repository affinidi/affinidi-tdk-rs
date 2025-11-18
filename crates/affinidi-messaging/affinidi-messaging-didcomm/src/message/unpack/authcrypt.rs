use crate::envelope::{Envelope, MetaEnvelope, ParsedEnvelope};
use crate::{
    UnpackOptions,
    algorithms::AuthCryptAlg,
    error::{ErrorKind, Result, ResultExt, err_msg},
    jwe,
    utils::crypto::{AsKnownKeyPairSecret, KnownKeyPair},
};
use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_secrets_resolver::SecretsResolver;
use askar_crypto::{
    alg::{
        aes::{A256CbcHs512, A256Kw, AesKey},
        k256::K256KeyPair,
        p256::P256KeyPair,
        x25519::X25519KeyPair,
    },
    kdf::ecdh_1pu::Ecdh1PU,
};
use std::str::FromStr;
use tracing::{Level, debug, event};

pub(crate) async fn _try_unpack_authcrypt<T>(
    jwe: &ParsedEnvelope,
    did_resolver: &DIDCacheClient,
    secrets_resolver: &T,
    opts: &UnpackOptions,
    envelope: &mut MetaEnvelope,
    present_crypto_operations_count: usize,
) -> Result<Option<ParsedEnvelope>>
where
    T: SecretsResolver,
{
    let jwe = match jwe {
        ParsedEnvelope::Jwe(jwe) => jwe,
        _ => return Ok(None),
    };

    event!(
        Level::DEBUG,
        "expecting (ECDH-1PU+A256KW) jwe.protected.alg({})",
        jwe.protected.alg
    );
    if jwe.protected.alg != jwe::Algorithm::Ecdh1puA256kw {
        return Ok(None);
    }

    if jwe.apu.is_some() && envelope.from_kid.is_none() {
        debug!("Recalculating envelope meta-data from APU");
        jwe.fill_envelope_from(envelope, did_resolver).await?;
    }

    let mut payload: Option<Vec<u8>> = None;
    let mut crypto_operations_count = present_crypto_operations_count;

    envelope.to_kids_found = secrets_resolver
        .find_secrets(&envelope.metadata.encrypted_to_kids)
        .await;
    // Currently investigating fails here as secrets resolver does not contain the keys
    if envelope.to_kids_found.is_empty() {
        Err(err_msg(
            ErrorKind::SecretNotFound,
            "No recipient secrets found",
        ))?;
    }

    debug!("{} to_kids found", &envelope.to_kids_found.len());
    for to_kid in &envelope.to_kids_found {
        crypto_operations_count += 1;
        if crypto_operations_count >= opts.crypto_operations_limit_per_message {
            return Err(err_msg(
                ErrorKind::TooManyCryptoOperations,
                format!(
                    "Limit is reached. limit = {}, executed crypto operations {}",
                    opts.crypto_operations_limit_per_message, crypto_operations_count
                ),
            ));
        }
        let to_key = secrets_resolver
            .get_secret(to_kid)
            .await
            .ok_or_else(|| {
                err_msg(
                    ErrorKind::InvalidState,
                    "Recipient secret not found after existence checking",
                )
            })?
            .to_owned();
        let to_key = to_key.as_key_pair()?;

        let _payload = match (
            envelope.from_key.as_ref().unwrap(),
            &to_key,
            &jwe.protected.enc,
        ) {
            (
                KnownKeyPair::X25519(from_key),
                KnownKeyPair::X25519(to_key),
                jwe::EncAlgorithm::A256cbcHs512,
            ) => {
                envelope.metadata.enc_alg_auth = Some(AuthCryptAlg::A256cbcHs512Ecdh1puA256kw);

                jwe.decrypt::<
                    AesKey<A256CbcHs512>,
                    Ecdh1PU<'_, X25519KeyPair>,
                    X25519KeyPair,
                    AesKey<A256Kw>,
                >(Some((envelope.from_kid.as_ref().unwrap(), from_key)), (to_kid, to_key))?
            }
            (
                KnownKeyPair::P256(from_key),
                KnownKeyPair::P256(to_key),
                jwe::EncAlgorithm::A256cbcHs512,
            ) => {
                envelope.metadata.enc_alg_auth = Some(AuthCryptAlg::A256cbcHs512Ecdh1puA256kw);

                jwe.decrypt::<
                    AesKey<A256CbcHs512>,
                    Ecdh1PU<'_, P256KeyPair>,
                    P256KeyPair,
                    AesKey<A256Kw>,
                >(Some((envelope.from_kid.as_ref().unwrap(), from_key)), (to_kid, to_key))?
            }
            (KnownKeyPair::X25519(_), KnownKeyPair::P256(_), _) => Err(err_msg(
                ErrorKind::Malformed,
                "Incompatible sender and recipient key agreement curves",
            ))?,
            (KnownKeyPair::P256(_), KnownKeyPair::X25519(_), _) => Err(err_msg(
                ErrorKind::Malformed,
                "Incompatible sender and recipient key agreement curves",
            ))?,
            (
                KnownKeyPair::K256(from_key),
                KnownKeyPair::K256(to_key),
                jwe::EncAlgorithm::A256cbcHs512,
            ) => {
                envelope.metadata.enc_alg_auth = Some(AuthCryptAlg::A256cbcHs512Ecdh1puA256kw);

                jwe.decrypt::<
                    AesKey<A256CbcHs512>,
                    Ecdh1PU<'_, K256KeyPair>,
                    K256KeyPair,
                    AesKey<A256Kw>,
                >(Some((envelope.from_kid.as_ref().unwrap(), from_key)), (to_kid, to_key))?
            }
            (KnownKeyPair::X25519(_), KnownKeyPair::K256(_), _) => Err(err_msg(
                ErrorKind::Malformed,
                "Incompatible sender and recipient key agreement curves",
            ))?,
            (KnownKeyPair::K256(_), KnownKeyPair::X25519(_), _) => Err(err_msg(
                ErrorKind::Malformed,
                "Incompatible sender and recipient key agreement curves",
            ))?,
            _ => Err(err_msg(
                ErrorKind::Unsupported,
                "Unsupported key agreement method",
            ))?,
        };

        payload = Some(_payload);

        if !opts.expect_decrypt_by_all_keys {
            break;
        }
    }
    debug!("payload = {}", payload.is_some());

    let payload = payload.ok_or_else(|| err_msg(ErrorKind::InvalidState, "Payload is none"))?;

    let payload = String::from_utf8(payload)
        .kind(ErrorKind::Malformed, "Authcrypt payload is invalid utf8")?;
    debug!("payload = {}", payload);

    let e = match Envelope::from_str(&payload) {
        Ok(envelope) => envelope.parse()?.verify_didcomm()?,
        Err(e) => {
            return Err(err_msg(
                ErrorKind::Malformed,
                format!(
                    "decrypted envelope successfully, but payload contents don't match a defined DIDComm format: {e}"
                ),
            ));
        }
    };

    debug!("returning envelope type ({})", e.get_type());
    Ok(Some(e))
}
