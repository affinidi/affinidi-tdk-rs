/*!
 * # Decentralized Identifiers (DIDs)
 *
 * Various helper functions for working with DIDs.
 */

use affinidi_secrets_resolver::{
    jwk::{ECParams, JWK, OctectParams, Params},
    secrets::Secret,
};
use affinidi_tdk_common::errors::{Result, TDKError};
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use did_peer::{
    DIDPeer, DIDPeerCreateKeys, DIDPeerKeys, DIDPeerService, PeerServiceEndPoint,
    PeerServiceEndPointLong, PeerServiceEndPointLongMap,
};
use ssi::{
    JWK as SSI_JWK, dids::DIDKey, jwk::Params as SSI_Params,
    verification_methods::ssi_core::OneOrMany,
};
use std::fmt::Display;

/// Supported DID Methods
pub enum DIDMethod {
    /// did:key - Simple single key method
    Key,

    /// did:peer - Allows for multiple keys and services
    Peer,

    /// did:web - Allows for a DID to be resolved to a URL
    Web,
}

/// Supported Key types
#[derive(Debug)]
pub enum KeyType {
    /// P256 - NIST P-256 curve
    P256,

    /// P384 - NIST P-384 curve
    P384,

    /// Ed25519 - EdDSA over the edwards25519 curve
    Ed25519,

    /// Secp256k1 - ECDSA over the secp256k1 curve
    Secp256k1,
}

impl Display for KeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyType::P256 => write!(f, "P-256"),
            KeyType::P384 => write!(f, "P-384"),
            KeyType::Ed25519 => write!(f, "ED25519"),
            KeyType::Secp256k1 => write!(f, "Secp256k1"),
        }
    }
}

impl TryFrom<&str> for KeyType {
    type Error = String;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        match value.to_lowercase().as_str() {
            "p-256" => Ok(KeyType::P256),
            "p-384" => Ok(KeyType::P384),
            "ed25519" => Ok(KeyType::Ed25519),
            "secp256k1" => Ok(KeyType::Secp256k1),
            _ => Err(format!("Unsupported key type: {}", value)),
        }
    }
}

pub struct DID;

impl DID {
    // Converts the SSI Library JWK to the Affinidi Secrets JWK
    // This helps with reducing the dependency on the SSI library everywhere
    fn convert(jwk: SSI_JWK) -> Result<JWK> {
        let params = match jwk.params {
            SSI_Params::EC(params) => {
                let Some(curve) = &params.curve else {
                    return Err(TDKError::Secrets(
                        "Missing curve parameter in EC JWK".to_string(),
                    ));
                };

                Params::EC(ECParams {
                    curve: curve.to_string(),
                    x: BASE64_URL_SAFE_NO_PAD.encode(
                        &params
                            .x_coordinate
                            .as_ref()
                            .ok_or_else(|| TDKError::Secrets("Missing x_coordinate".to_string()))?
                            .0,
                    ),
                    y: BASE64_URL_SAFE_NO_PAD.encode(
                        &params
                            .y_coordinate
                            .as_ref()
                            .ok_or_else(|| TDKError::Secrets("Missing y_coordinate".to_string()))?
                            .0,
                    ),
                    d: BASE64_URL_SAFE_NO_PAD.encode(
                        &params
                            .ecc_private_key
                            .as_ref()
                            .ok_or_else(|| TDKError::Secrets("Missing private bytes".to_string()))?
                            .0,
                    ),
                })
            }
            SSI_Params::OKP(params) => Params::OKP(OctectParams {
                curve: params.curve.clone(),
                x: BASE64_URL_SAFE_NO_PAD.encode(&params.public_key.0),
                d: BASE64_URL_SAFE_NO_PAD.encode(
                    &params
                        .private_key
                        .as_ref()
                        .ok_or_else(|| TDKError::Secrets("Missing private bytes!".to_string()))?
                        .0,
                ),
            }),
            _ => return Err(TDKError::Secrets("Invalid JWK Key Type".to_string())),
        };

        Ok(JWK {
            key_id: jwk.key_id,
            params,
        })
    }

    /// Generate a new DID:key
    /// Returns the DID and the associated secret
    pub fn generate_did_key(key_type: KeyType) -> Result<(String, Secret)> {
        let jwk = match key_type {
            KeyType::P256 => SSI_JWK::generate_p256(),
            KeyType::P384 => SSI_JWK::generate_p384(),
            KeyType::Ed25519 => SSI_JWK::generate_ed25519().unwrap(),
            KeyType::Secp256k1 => SSI_JWK::generate_secp256k1(),
        };

        let did = DIDKey::generate(&jwk).unwrap();
        let mut secret = Secret::from_jwk(&DID::convert(jwk)?)?;
        secret.id = [&did, "#", &did[8..]].concat();

        Ok((did.to_string(), secret))
    }

    /// Generate a new DID:peer
    pub fn generate_did_peer(
        keys: Vec<(DIDPeerKeys, KeyType)>,
        didcomm_service_uri: Option<String>,
    ) -> Result<(String, Vec<Secret>)> {
        let mut peer_keys: Vec<DIDPeerCreateKeys> = Vec::new();
        let mut secrets: Vec<Secret> = Vec::new();
        for key in keys {
            let (did, secret) = Self::generate_did_key(key.1)?;
            peer_keys.push(DIDPeerCreateKeys {
                purpose: key.0,
                type_: None,
                public_key_multibase: Some(did[8..].to_string()),
            });
            secrets.push(secret);
        }

        let services = didcomm_service_uri.map(|service_uri| {
            vec![DIDPeerService {
                _type: "dm".into(),
                service_end_point: PeerServiceEndPoint::Long(PeerServiceEndPointLong::Map(
                    OneOrMany::One(PeerServiceEndPointLongMap {
                        uri: service_uri,
                        accept: vec!["didcomm/v2".into()],
                        routing_keys: vec![],
                    }),
                )),
                id: None,
            }]
        });

        let peer = DIDPeer::create_peer_did(&peer_keys, services.as_ref())?;

        for (id, secret) in secrets.iter_mut().enumerate() {
            secret.id = [&peer.0, "#key-", (id + 1).to_string().as_str()].concat();
        }

        Ok((peer.0, secrets))
    }
}
