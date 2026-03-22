use crate::document::{DIDCommVerificationMethodExt, did_or_url};
use crate::envelope::{Envelope, MetaEnvelope, ParsedEnvelope};
use crate::{
    UnpackOptions,
    algorithms::SignAlg,
    error::{ErrorKind, Result, ResultContext, ResultExt, err_msg},
    jws,
    utils::crypto::AsKnownKeyPair,
};
use affinidi_did_common::document::DocumentExt;
use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use askar_crypto::alg::{ed25519::Ed25519KeyPair, k256::K256KeyPair, p256::P256KeyPair};
use base64::prelude::*;
use std::str::FromStr;
use tracing::debug;

pub(crate) async fn _try_unpack_sign(
    msg: &ParsedEnvelope,
    did_resolver: &DIDCacheClient,
    _opts: &UnpackOptions,
    envelope: &mut MetaEnvelope,
) -> Result<Option<ParsedEnvelope>> {
    debug!(
        "Is this a signed envelope? expect(JWS) actual({})",
        msg.get_type()
    );
    let parsed_jws: &jws::ParsedJWS = match msg {
        ParsedEnvelope::Jws(jws) => jws,
        _ => {
            envelope.metadata.authenticated = false;
            return Ok(None);
        }
    };
    debug!("Trying to unpack signed envelope");

    if parsed_jws.protected.len() != 1 {
        Err(err_msg(
            ErrorKind::Malformed,
            "Wrong amount of signatures for jws",
        ))?
    }

    let alg = &parsed_jws
        .protected
        .first()
        .ok_or_else(|| {
            err_msg(
                ErrorKind::InvalidState,
                "Unexpected absence of first protected header",
            )
        })?
        .alg;

    let signer_kid = &parsed_jws
        .jws
        .signatures
        .first()
        .ok_or_else(|| {
            err_msg(
                ErrorKind::InvalidState,
                "Unexpected absence of first signature",
            )
        })?
        .header
        .kid;

    let (signer_did, signer_url) = did_or_url(signer_kid);

    if signer_url.is_none() {
        Err(err_msg(
            ErrorKind::Malformed,
            "Signer key can't be resolved to key agreement",
        ))?
    }

    let signer_ddoc = match did_resolver.resolve(signer_did).await {
        Ok(response) => response.doc,
        Err(_) => return Err(err_msg(ErrorKind::DIDNotResolved, "Signer did not found"))?,
    };

    if !signer_ddoc.contains_authentication(signer_kid) {
        return Err(err_msg(
            ErrorKind::DIDUrlNotFound,
            "Signer kid not found in did",
        ));
    }

    let Some(signer_key) = signer_ddoc.get_verification_method(signer_kid) else {
        return Err(err_msg(
            ErrorKind::DIDUrlNotFound,
            "Sender verification method not found in did",
        ));
    };

    let signer_key_jwk = if let Some(jwk) = signer_key.get_jwk() {
        jwk
    } else {
        return Err(err_msg(
            ErrorKind::NoCompatibleCrypto,
            "Couldn't convert signing key to JWK",
        ));
    };

    let valid = match alg {
        jws::Algorithm::EdDSA => {
            envelope.metadata.sign_alg = Some(SignAlg::EdDSA);

            let signer_key = signer_key
                .as_ed25519(&signer_key_jwk)
                .context("Unable instantiate signer key")?;

            parsed_jws
                .verify::<Ed25519KeyPair>((signer_kid, &signer_key))
                .context("Unable verify sign envelope")?
        }
        jws::Algorithm::Es256 => {
            envelope.metadata.sign_alg = Some(SignAlg::ES256);

            let signer_key = signer_key
                .as_p256(&signer_key_jwk)
                .context("Unable instantiate signer key")?;

            parsed_jws
                .verify::<P256KeyPair>((signer_kid, &signer_key))
                .context("Unable verify sign envelope")?
        }
        jws::Algorithm::Es256K => {
            envelope.metadata.sign_alg = Some(SignAlg::ES256K);

            let signer_key = signer_key
                .as_k256(&signer_key_jwk)
                .context("Unable instantiate signer key")?;

            parsed_jws
                .verify::<K256KeyPair>((signer_kid, &signer_key))
                .context("Unable verify sign envelope")?
        }
        jws::Algorithm::Other(_) => Err(err_msg(
            ErrorKind::Unsupported,
            "Unsupported signature algorithm",
        ))?,
    };

    if !valid {
        Err(err_msg(ErrorKind::Malformed, "Wrong signature"))?
    }

    // TODO: More precise error conversion
    let payload = BASE64_URL_SAFE_NO_PAD
        .decode(&parsed_jws.jws.payload)
        .kind(ErrorKind::Malformed, "Signed payload is invalid base64")?;

    let payload =
        String::from_utf8(payload).kind(ErrorKind::Malformed, "Signed payload is invalid utf8")?;

    envelope.metadata.authenticated = true;
    envelope.metadata.non_repudiation = true;
    envelope.metadata.sign_from = Some(signer_kid.into());
    envelope.metadata.signed_message = Some(parsed_jws.jws.clone());

    let e = Envelope::from_str(&payload)?.parse()?.verify_didcomm()?;
    Ok(Some(e))
}
