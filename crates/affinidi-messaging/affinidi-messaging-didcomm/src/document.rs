//! Extension trait for SSI Document
//! Contains various helper functions to work with DIDComm

use crate::{
    error::{Error, ErrorKind, Result, ResultExt, ToResult, err_msg},
    jwk::FromJwkValue,
    utils::crypto::{AsKnownKeyPair, AsKnownKeyPairSecret, KnownKeyAlg, KnownKeyPair},
};
use affinidi_did_common::verification_method::VerificationMethod;
use affinidi_secrets_resolver::{
    jwk::{JWK, Params},
    secrets::{KeyType, Secret, SecretMaterial, SecretType},
};
use askar_crypto::{
    alg::{ed25519::Ed25519KeyPair, k256::K256KeyPair, p256::P256KeyPair, x25519::X25519KeyPair},
    repr::{KeyPublicBytes, KeySecretBytes},
};
use base64::prelude::*;
use serde_json::{Value, json};
use std::io::Cursor;
use tracing::warn;
use varint::{VarintRead, VarintWrite};

/// Older left over functions from original DIDComm crate
pub(crate) fn did_or_url(did_or_url: &str) -> (&str, Option<&str>) {
    // TODO: does it make sense to validate DID here?

    match did_or_url.split_once('#') {
        Some((did, _)) => (did, Some(did_or_url)),
        None => (did_or_url, None),
    }
}

pub(crate) fn is_did(did: &str) -> bool {
    let parts: Vec<_> = did.split(':').collect();
    parts.len() >= 3 && parts.first().unwrap() == &"did"
}

pub(crate) trait DIDCommVerificationMethodExt {
    /// Create a JWK from the verification method
    fn get_jwk(&self) -> Option<JWK>;
}

impl DIDCommVerificationMethodExt for VerificationMethod {
    fn get_jwk(&self) -> Option<JWK> {
        match self.type_.as_str() {
            "Multikey" => {
                let key = if let Some(key) = self.property_set.get("publicKeyMultibase") {
                    key.as_str()?
                } else {
                    return None;
                };

                match JWK::from_multikey(key) {
                    Ok(jwk) => Some(jwk),
                    Err(e) => {
                        warn!("Failed to parse JWK from multicodec ({key}): {e}");
                        None
                    }
                }
            }
            "JsonWebKey2020" => {
                if let Some(key) = self.property_set.get("publicKeyJwk") {
                    match serde_json::from_value(key.clone()) {
                        Ok(jwk) => Some(jwk),
                        Err(_) => {
                            warn!("Failed to parse JWK from JsonWebKey2020 ({})", key);
                            None
                        }
                    }
                } else {
                    warn!("JsonWebKey2020 missing publicKeyJwk");
                    None
                }
            }

            "EcdsaSecp256k1VerificationKey2019" => {
                if let Some(key) = self.property_set.get("publicKeyJwk") {
                    match serde_json::from_value(key.clone()) {
                        Ok(jwk) => Some(jwk),
                        Err(_) => {
                            warn!("Failed to parse JWK from {} ({})", self.type_, key);
                            None
                        }
                    }
                } else {
                    warn!("{} missing publicKeyJwk", self.type_);
                    None
                }
            }
            _ => {
                warn!("Unsupported verification method type: {}", self.type_);
                None
            }
        }
    }
}

impl AsKnownKeyPair for VerificationMethod {
    fn key_alg(&self, jwk: &JWK) -> KnownKeyAlg {
        match &jwk.params {
            Params::EC(ec) => match ec.curve.as_str() {
                "P-256" => KnownKeyAlg::P256,
                "secp256k1" => KnownKeyAlg::K256,
                _ => KnownKeyAlg::Unsupported,
            },
            Params::OKP(okp) => match okp.curve.as_str() {
                "Ed25519" => KnownKeyAlg::Ed25519,
                "X25519" => KnownKeyAlg::X25519,
                _ => KnownKeyAlg::Unsupported,
            },
        }
    }

    fn as_key_pair(&self, jwk: &JWK) -> Result<KnownKeyPair> {
        match &jwk.params {
            Params::EC(ec) => {
                let jwk_value = json!({"kty": "EC", "crv": ec.curve, "x": ec.x ,"y": ec.y});
                match ec.curve.as_str() {
                    "P-256" => P256KeyPair::from_jwk_value(&jwk_value)
                        .kind(ErrorKind::Malformed, "Unable parse jwk")
                        .map(KnownKeyPair::P256),
                    "secp256k1" => K256KeyPair::from_jwk_value(&jwk_value)
                        .kind(ErrorKind::Malformed, "Unable parse jwk")
                        .map(KnownKeyPair::K256),
                    _ => Err(err_msg(
                        ErrorKind::Unsupported,
                        format!("Unsupported key type or curve ({})", ec.curve),
                    )),
                }
            }
            Params::OKP(okp) => {
                let jwk_value = json!({"kty": "OKP", "crv": okp.curve, "x": okp.x});
                match okp.curve.as_str() {
                    "Ed25519" => Ed25519KeyPair::from_jwk_value(&jwk_value)
                        .kind(ErrorKind::Malformed, "Unable parse jwk")
                        .map(KnownKeyPair::Ed25519),
                    "X25519" => X25519KeyPair::from_jwk_value(&jwk_value)
                        .kind(ErrorKind::Malformed, "Unable parse jwk")
                        .map(KnownKeyPair::X25519),
                    _ => Err(err_msg(
                        ErrorKind::Unsupported,
                        format!("Unsupported key type or curve ({})", okp.curve),
                    )),
                }
            }
        }
    }
}

impl AsKnownKeyPairSecret for Secret {
    fn key_alg(&self) -> KnownKeyAlg {
        match (&self.type_, &self.secret_material) {
            (SecretType::JsonWebKey2020, SecretMaterial::JWK(jwk)) => match jwk.get_key_type() {
                KeyType::P256 => KnownKeyAlg::P256,
                KeyType::Secp256k1 => KnownKeyAlg::K256,
                KeyType::Ed25519 => KnownKeyAlg::Ed25519,
                KeyType::X25519 => KnownKeyAlg::X25519,
                _ => KnownKeyAlg::Unsupported,
            },
            (
                SecretType::X25519KeyAgreementKey2019,
                SecretMaterial::Base58 {
                    private_key_base58: _,
                },
            ) => KnownKeyAlg::X25519,
            (
                SecretType::Ed25519VerificationKey2018,
                SecretMaterial::Base58 {
                    private_key_base58: _,
                },
            ) => KnownKeyAlg::Ed25519,
            (
                SecretType::X25519KeyAgreementKey2020,
                SecretMaterial::Multibase {
                    private_key_multibase: _,
                },
            ) => KnownKeyAlg::X25519,
            (
                SecretType::Ed25519VerificationKey2020,
                SecretMaterial::Multibase {
                    private_key_multibase: _,
                },
            ) => KnownKeyAlg::Ed25519,
            _ => KnownKeyAlg::Unsupported,
        }
    }

    fn as_key_pair(&self) -> Result<KnownKeyPair> {
        match (&self.type_, &self.secret_material) {
            (SecretType::JsonWebKey2020, SecretMaterial::JWK(jwk)) => match jwk.get_key_type() {
                KeyType::P256 => P256KeyPair::from_jwk_value(&serde_json::to_value(jwk)?)
                    .kind(ErrorKind::Malformed, "Unable parse jwk")
                    .map(KnownKeyPair::P256),
                KeyType::Secp256k1 => K256KeyPair::from_jwk_value(&serde_json::to_value(jwk)?)
                    .kind(ErrorKind::Malformed, "Unable parse jwk")
                    .map(KnownKeyPair::K256),
                KeyType::Ed25519 => Ed25519KeyPair::from_jwk_value(&serde_json::to_value(jwk)?)
                    .kind(ErrorKind::Malformed, "Unable parse jwk")
                    .map(KnownKeyPair::Ed25519),
                KeyType::X25519 => X25519KeyPair::from_jwk_value(&serde_json::to_value(jwk)?)
                    .kind(ErrorKind::Malformed, "Unable parse jwk")
                    .map(KnownKeyPair::X25519),
                _ => Err(err_msg(
                    ErrorKind::Unsupported,
                    format!(
                        "Unsupported key type or curve key_type({})",
                        jwk.get_key_type()
                    ),
                )),
            },

            (
                SecretType::X25519KeyAgreementKey2019,
                SecretMaterial::Base58 {
                    private_key_base58: value,
                },
            ) => {
                let decoded_value = bs58::decode(value)
                    .into_vec()
                    .to_didcomm("Wrong base58 value in secret material")?;

                let key_pair = X25519KeyPair::from_secret_bytes(&decoded_value).map_err(|err| {
                    Error::msg(
                        ErrorKind::Malformed,
                        format!(
                            "{}: {}",
                            "Unable parse x25519 secret material",
                            err.message()
                        ),
                    )
                })?;

                let mut jwk = json!({
                    "kty": "OKP",
                    "crv": "X25519",
                });

                key_pair.with_public_bytes(|buf| {
                    jwk["x"] = Value::String(BASE64_URL_SAFE_NO_PAD.encode(buf))
                });

                key_pair.with_secret_bytes(|buf| {
                    if let Some(sk) = buf {
                        jwk["d"] = Value::String(BASE64_URL_SAFE_NO_PAD.encode(sk))
                    }
                });

                X25519KeyPair::from_jwk_value(&jwk)
                    .kind(ErrorKind::Malformed, "Unable parse base58 secret material")
                    .map(KnownKeyPair::X25519)
            }

            (
                SecretType::Ed25519VerificationKey2018,
                SecretMaterial::Base58 {
                    private_key_base58: value,
                },
            ) => {
                let decoded_value = bs58::decode(value)
                    .into_vec()
                    .to_didcomm("Wrong base58 value in secret material")?;

                let curve25519_point_size = 32;
                let (d_value, x_value) = decoded_value.split_at(curve25519_point_size);
                let base64_url_d_value = BASE64_URL_SAFE_NO_PAD.encode(d_value);
                let base64_url_x_value = BASE64_URL_SAFE_NO_PAD.encode(x_value);

                let jwk = json!({"kty": "OKP",
                    "crv": "Ed25519",
                    "x": base64_url_x_value,
                    "d": base64_url_d_value
                });

                Ed25519KeyPair::from_jwk_value(&jwk)
                    .kind(ErrorKind::Malformed, "Unable parse base58 secret material")
                    .map(KnownKeyPair::Ed25519)
            }

            (
                SecretType::X25519KeyAgreementKey2020,
                SecretMaterial::Multibase {
                    private_key_multibase: value,
                },
            ) => {
                if !value.starts_with('z') {
                    Err(err_msg(
                        ErrorKind::IllegalArgument,
                        "Multibase must start with 'z'",
                    ))?
                }
                let decoded_multibase_value = bs58::decode(&value[1..])
                    .into_vec()
                    .to_didcomm("Wrong multibase value in secret material")?;

                let (codec, decoded_value) = _from_multicodec(&decoded_multibase_value)?;
                if codec != Codec::X25519Priv {
                    Err(err_msg(
                        ErrorKind::IllegalArgument,
                        "Wrong codec in multibase secret material",
                    ))?
                }

                let key_pair = X25519KeyPair::from_secret_bytes(decoded_value).map_err(|err| {
                    Error::msg(
                        ErrorKind::Malformed,
                        format!(
                            "{}: {}",
                            "Unable parse x25519 secret material",
                            err.message()
                        ),
                    )
                })?;

                let mut jwk = json!({
                    "kty": "OKP",
                    "crv": "X25519",
                });

                key_pair.with_public_bytes(|buf| {
                    jwk["x"] = Value::String(BASE64_URL_SAFE_NO_PAD.encode(buf))
                });

                key_pair.with_secret_bytes(|buf| {
                    if let Some(sk) = buf {
                        jwk["d"] = Value::String(BASE64_URL_SAFE_NO_PAD.encode(sk))
                    }
                });

                X25519KeyPair::from_jwk_value(&jwk)
                    .kind(
                        ErrorKind::Malformed,
                        "Unable parse multibase secret material",
                    )
                    .map(KnownKeyPair::X25519)
            }

            (
                SecretType::Ed25519VerificationKey2020,
                SecretMaterial::Multibase {
                    private_key_multibase: value,
                },
            ) => {
                if !value.starts_with('z') {
                    Err(err_msg(
                        ErrorKind::IllegalArgument,
                        "Multibase must start with 'z'",
                    ))?
                }
                let decoded_multibase_value = bs58::decode(&value[1..])
                    .into_vec()
                    .to_didcomm("Wrong multibase value in secret material")?;

                let (codec, decoded_value) = _from_multicodec(&decoded_multibase_value)?;
                if codec != Codec::Ed25519Priv {
                    Err(err_msg(
                        ErrorKind::IllegalArgument,
                        "Wrong codec in multibase secret material",
                    ))?
                }

                let curve25519_point_size = 32;
                let (d_value, x_value) = decoded_value.split_at(curve25519_point_size);
                let base64_url_d_value = BASE64_URL_SAFE_NO_PAD.encode(d_value);
                let base64_url_x_value = BASE64_URL_SAFE_NO_PAD.encode(x_value);

                let jwk = json!({
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": base64_url_x_value,
                    "d": base64_url_d_value
                });

                Ed25519KeyPair::from_jwk_value(&jwk)
                    .kind(
                        ErrorKind::Malformed,
                        "Unable parse multibase secret material",
                    )
                    .map(KnownKeyPair::Ed25519)
            }

            _ => Err(err_msg(
                ErrorKind::Unsupported,
                "Unsupported secret method type and material combination",
            )),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Codec {
    X25519Pub,
    Ed25519Pub,
    X25519Priv,
    Ed25519Priv,
}

impl Codec {
    fn codec_by_prefix(value: u32) -> Result<Codec> {
        match value {
            0xEC => Ok(Codec::X25519Pub),
            0xED => Ok(Codec::Ed25519Pub),
            0x1302 => Ok(Codec::X25519Priv),
            0x1300 => Ok(Codec::Ed25519Priv),
            _ => Err(err_msg(ErrorKind::IllegalArgument, "Unsupported prefix")),
        }
    }
}

fn _from_multicodec(value: &[u8]) -> Result<(Codec, &[u8])> {
    let mut val: Cursor<Vec<u8>> = Cursor::new(value.to_vec());
    let prefix_int = val
        .read_unsigned_varint_32()
        .kind(ErrorKind::InvalidState, "Cannot read varint")?;
    let codec = Codec::codec_by_prefix(prefix_int)?;

    let mut prefix: Cursor<Vec<u8>> = Cursor::new(Vec::new());
    prefix
        .write_unsigned_varint_32(prefix_int)
        .kind(ErrorKind::InvalidState, "Cannot write varint")?;

    Ok((codec, value.split_at(prefix.into_inner().len()).1))
}
