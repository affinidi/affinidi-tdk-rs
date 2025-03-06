/*!
 * # Decentralized Identifiers (DIDs)
 *
 * Various helper functions for working with DIDs.
 */

use affinidi_secrets_resolver::secrets::Secret;
use affinidi_tdk_common::errors::Result;
use did_peer::{
    DIDPeer, DIDPeerCreateKeys, DIDPeerKeys, DIDPeerService, PeerServiceEndPoint,
    PeerServiceEndPointLong,
};
use ssi::{JWK, dids::DIDKey};

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
pub enum KeyType {
    /// P256 - NIST P-256 curve
    P256,

    /// Ed25519 - EdDSA over the edwards25519 curve
    Ed25519,

    /// Secp256k1 - ECDSA over the secp256k1 curve
    Secp256k1,
}

pub struct DID;

impl DID {
    /// Generate a new DID:key
    /// Returns the DID and the associated secret
    pub fn generate_did_key(key_type: KeyType) -> Result<(String, Secret)> {
        let jwk = match key_type {
            KeyType::P256 => JWK::generate_p256(),
            KeyType::Ed25519 => JWK::generate_ed25519().unwrap(),
            KeyType::Secp256k1 => JWK::generate_secp256k1(),
        };

        let did = DIDKey::generate(&jwk).unwrap();
        let mut secret = Secret::from_jwk(&jwk)?;
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
                service_end_point: PeerServiceEndPoint::Long(PeerServiceEndPointLong {
                    uri: service_uri,
                    accept: vec!["didcomm/v2".into()],
                    routing_keys: vec![],
                }),
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
