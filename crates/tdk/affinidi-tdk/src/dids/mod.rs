/*!
 * # Decentralized Identifiers (DIDs)
 *
 * Various helper functions for working with DIDs.
 */

use affinidi_did_common::DID as DIDCommon;
#[cfg(feature = "did-peer")]
use affinidi_did_common::one_or_many::OneOrMany;
#[cfg(feature = "did-peer")]
use affinidi_did_common::{
    PeerCreateKey, PeerKeyPurpose, PeerService, PeerServiceEndpoint, PeerServiceEndpointLong,
};
use affinidi_secrets_resolver::secrets::{KeyType as CryptoKeyType, Secret};
use affinidi_tdk_common::errors::{Result, TDKError};
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
#[derive(Debug, Clone, Copy)]
pub enum KeyType {
    /// P256 - NIST P-256 curve
    P256,

    /// P384 - NIST P-384 curve
    P384,

    /// Ed25519 - EdDSA over the edwards25519 curve
    Ed25519,

    /// X25519 - ECDH encryption
    X25519,

    /// Secp256k1 - ECDSA over the secp256k1 curve
    Secp256k1,
}

impl Display for KeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyType::P256 => write!(f, "P-256"),
            KeyType::P384 => write!(f, "P-384"),
            KeyType::Ed25519 => write!(f, "Ed25519"),
            KeyType::X25519 => write!(f, "X25519"),
            KeyType::Secp256k1 => write!(f, "secp256k1"),
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
            "x25519" => Ok(KeyType::X25519),
            "secp256k1" => Ok(KeyType::Secp256k1),
            _ => Err(format!("Unsupported key type: {value}")),
        }
    }
}

impl KeyType {
    fn to_crypto_key_type(self) -> CryptoKeyType {
        match self {
            KeyType::P256 => CryptoKeyType::P256,
            KeyType::P384 => CryptoKeyType::P384,
            KeyType::Ed25519 => CryptoKeyType::Ed25519,
            KeyType::X25519 => CryptoKeyType::X25519,
            KeyType::Secp256k1 => CryptoKeyType::Secp256k1,
        }
    }
}

/// Purpose of a key when creating a did:peer
#[cfg(feature = "did-peer")]
#[derive(Debug, Clone, Copy)]
pub enum PeerKeyRole {
    /// Keys for authentication and assertions (V prefix in DID)
    Verification,
    /// Keys for key agreement/encryption (E prefix in DID)
    Encryption,
}

#[cfg(feature = "did-peer")]
impl PeerKeyRole {
    fn to_peer_key_purpose(self) -> PeerKeyPurpose {
        match self {
            PeerKeyRole::Verification => PeerKeyPurpose::Verification,
            PeerKeyRole::Encryption => PeerKeyPurpose::Encryption,
        }
    }
}

pub struct DID;

impl DID {
    /// Generate a new DID:key
    /// Returns the DID and the associated secret
    pub fn generate_did_key(key_type: KeyType) -> Result<(String, Secret)> {
        use affinidi_did_common::KeyMaterialFormat;

        let (did, key_material) = DIDCommon::generate_key(key_type.to_crypto_key_type())
            .map_err(|e| TDKError::DIDMethod(format!("Couldn't create did:key: {e}")))?;

        // Convert KeyMaterial to Secret via JWK
        let secret = match &key_material.format {
            KeyMaterialFormat::JWK(jwk) => {
                let mut s = Secret::from_jwk(jwk).map_err(|e| {
                    TDKError::DIDMethod(format!("Couldn't convert key to secret: {e}"))
                })?;
                s.id = key_material.id.clone();
                s
            }
            _ => {
                return Err(TDKError::DIDMethod(
                    "KeyMaterial format not supported for conversion".to_string(),
                ));
            }
        };

        Ok((did.to_string(), secret))
    }

    #[cfg(feature = "did-peer")]
    /// Generate a new DID:peer from provided secrets
    pub fn generate_did_peer_from_secrets(
        keys: &mut [(PeerKeyRole, &mut Secret)],
        didcomm_service_uri: Option<String>,
    ) -> Result<String> {
        let mut peer_keys: Vec<PeerCreateKey> = Vec::new();
        let mut secrets: Vec<&mut Secret> = Vec::new();

        for (role, secret) in keys {
            peer_keys.push(PeerCreateKey::from_multibase(
                role.to_peer_key_purpose(),
                secret.get_public_keymultibase()?,
            ));
            secrets.push(secret);
        }

        Self::complete_did_peer_creation(&mut secrets, &peer_keys, didcomm_service_uri)
    }

    #[cfg(feature = "did-peer")]
    /// Generate a new DID:peer
    /// Generates keys for you based on the provided key types and purposes
    pub fn generate_did_peer(
        keys: Vec<(PeerKeyRole, KeyType)>,
        didcomm_service_uri: Option<String>,
    ) -> Result<(String, Vec<Secret>)> {
        let mut peer_keys: Vec<PeerCreateKey> = Vec::new();
        let mut secrets: Vec<Secret> = Vec::new();

        for key in keys {
            let (did, secret) = Self::generate_did_key(key.1)?;
            // Extract multibase from did:key (skip "did:key:" prefix)
            peer_keys.push(PeerCreateKey::from_multibase(
                key.0.to_peer_key_purpose(),
                did[8..].to_string(),
            ));
            secrets.push(secret);
        }

        let mut secrets_mut: Vec<&mut Secret> = Vec::new();
        for secret in secrets.iter_mut() {
            secrets_mut.push(secret);
        }

        let peer =
            Self::complete_did_peer_creation(&mut secrets_mut, &peer_keys, didcomm_service_uri)?;
        Ok((peer, secrets))
    }

    #[cfg(feature = "did-peer")]
    /// Helper function to complete creating a DID:peer
    fn complete_did_peer_creation(
        secrets: &mut [&mut Secret],
        peer_keys: &[PeerCreateKey],
        service_uri: Option<String>,
    ) -> Result<String> {
        let services = service_uri.map(|service_uri| {
            vec![PeerService {
                type_: "dm".into(),
                endpoint: PeerServiceEndpoint::Long(OneOrMany::One(PeerServiceEndpointLong {
                    uri: service_uri,
                    accept: vec!["didcomm/v2".into()],
                    routing_keys: vec![],
                })),
                id: None,
            }]
        });

        let (peer_did, _created_keys) = DIDCommon::generate_peer(peer_keys, services.as_deref())
            .map_err(|e| TDKError::DIDMethod(e.to_string()))?;
        let peer = peer_did.to_string();

        // Change the Secret ID's to match the created did:peer
        for (id, secret) in secrets.iter_mut().enumerate() {
            secret.id = [&peer, "#key-", (id + 1).to_string().as_str()].concat();
        }

        Ok(peer)
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "did-peer")]
    #[test]
    fn did_peer_from_existing_secrets() {
        use affinidi_secrets_resolver::secrets::Secret;

        use crate::dids::{DID, PeerKeyRole};

        let mut v_secret = Secret::generate_ed25519(None, None);
        let mut e_secret =
            Secret::generate_x25519(None, None).expect("Couldn't create X25519 Secret");

        let mut keys = vec![
            (PeerKeyRole::Verification, &mut v_secret),
            (PeerKeyRole::Encryption, &mut e_secret),
        ];

        let peer =
            DID::generate_did_peer_from_secrets(&mut keys, None).expect("Creating DID failed!");

        assert_eq!(
            peer,
            [
                "did:peer:2.V",
                &keys[0].1.get_public_keymultibase().unwrap(),
                ".E",
                &keys[1].1.get_public_keymultibase().unwrap()
            ]
            .concat()
        );

        assert_eq!(keys[0].1.id, [&peer, "#key-1"].concat());
        assert_eq!(keys[1].1.id, [&peer, "#key-2"].concat());
    }

    #[cfg(feature = "did-peer")]
    #[test]
    fn did_peer_create() {
        use crate::dids::{DID, KeyType, PeerKeyRole};

        let keys = vec![
            (PeerKeyRole::Verification, KeyType::Ed25519),
            (PeerKeyRole::Encryption, KeyType::X25519),
        ];

        let (peer, secrets) = DID::generate_did_peer(keys, None).expect("Creating DID failed!");

        assert_eq!(
            peer,
            [
                "did:peer:2.V",
                &secrets[0].get_public_keymultibase().unwrap(),
                ".E",
                &secrets[1].get_public_keymultibase().unwrap()
            ]
            .concat()
        );

        assert_eq!(secrets[0].id, [&peer, "#key-1"].concat());
        assert_eq!(secrets[1].id, [&peer, "#key-2"].concat());
    }
}
