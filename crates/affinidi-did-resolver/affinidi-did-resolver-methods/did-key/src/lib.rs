//! Implementation of the did:key method
//! [https://w3c-ccg.github.io/did-key-spec/]

use crate::errors::Error;
use affinidi_did_common::{
    Document,
    verification_method::{VerificationMethod, VerificationRelationship},
};
use affinidi_secrets_resolver::{
    crypto::ed25519::ed25519_public_to_x25519_public_key,
    multicodec::{ED25519_PUB, MultiEncoded, P256_PUB, P384_PUB, SECP256K1_PUB, X25519_PUB},
};
use base58::FromBase58;
use serde_json::Value;
use std::collections::HashMap;
use url::Url;

pub mod create;
pub mod errors;

pub struct DIDKey;

impl DIDKey {
    /// Resolves a Key DID method and returns a DID Document or error
    pub fn resolve<'a>(did: &'a str) -> Result<Document, Error<'a>> {
        if !did.starts_with("did:key:z") {
            return Err(Error::InvalidDid(
                did,
                "DID Url doesn't start with did:key:z".to_string(),
            ));
        }

        let identifier = &did[8..]; // Strip the leading did:key: prefix

        // did:key only support base58 decoding as denoted by the leading z prefix
        let decoded = identifier[1..]
            .from_base58()
            .map_err(|_| Error::InvalidPublicKey("Couldn't decode base58".to_string()))?;

        let multicodec = MultiEncoded::new(decoded.as_slice())
            .map_err(|_| Error::InvalidPublicKey("Unknown multicodec value".to_string()))?;

        let vm_id = Url::parse(&[did, "#", identifier].concat())
            .map_err(|e| Error::InvalidDidUrl(did, e.to_string()))?;
        let mut vms = Vec::new();

        let mut key_agreement = Vec::new();

        // Check public key type and lengths
        match multicodec.codec() {
            P256_PUB => {
                if multicodec.data().len() != 33 {
                    return Err(Error::InvalidPublicKeyLength(multicodec.data().len()));
                }
                key_agreement.push(VerificationRelationship::Reference(vm_id.clone()));
            }
            P384_PUB => {
                if multicodec.data().len() != 49 {
                    return Err(Error::InvalidPublicKeyLength(multicodec.data().len()));
                }
                key_agreement.push(VerificationRelationship::Reference(vm_id.clone()));
            }
            SECP256K1_PUB => {
                if multicodec.data().len() != 33 {
                    return Err(Error::InvalidPublicKeyLength(multicodec.data().len()));
                }
                key_agreement.push(VerificationRelationship::Reference(vm_id.clone()));
            }
            X25519_PUB => {
                if multicodec.data().len() != 32 {
                    return Err(Error::InvalidPublicKeyLength(multicodec.data().len()));
                }
                key_agreement.push(VerificationRelationship::Reference(vm_id.clone()));
            }
            ED25519_PUB => {
                if multicodec.data().len() != 32 {
                    return Err(Error::InvalidPublicKeyLength(multicodec.data().len()));
                }

                let (x25519_encoded, _) =
                    ed25519_public_to_x25519_public_key(identifier).map_err(|e| {
                        Error::InvalidPublicKey(format!(
                            "Couldn't convert ed25519 to x25519 public-key: {e}"
                        ))
                    })?;

                let mut property_set = HashMap::new();
                property_set.insert(
                    "publicKeyMultibase".to_string(),
                    Value::String(x25519_encoded.clone()),
                );

                let x25519_vm_id =
                    Url::parse(&[did, "#", &x25519_encoded].concat()).map_err(|e| {
                        Error::InvalidPublicKey(format!(
                            "Couldn't create valid URL ID for x25519 VerificationMethod: {e}"
                        ))
                    })?;

                vms.push(VerificationMethod {
                    id: x25519_vm_id.clone(),
                    type_: "Multikey".to_string(),
                    controller: Url::parse(did)
                        .map_err(|e| Error::InvalidDidUrl(did, e.to_string()))?,
                    expires: None,
                    revoked: None,
                    property_set,
                });

                key_agreement.push(VerificationRelationship::Reference(x25519_vm_id.clone()));
            }
            _ => {
                return Err(Error::UnsupportedPublicKeyType(format!(
                    "Unknown codec: {}",
                    multicodec.codec()
                )));
            }
        }

        let mut property_set = HashMap::new();
        property_set.insert(
            "publicKeyMultibase".to_string(),
            Value::String(identifier.to_string()),
        );

        vms.push(VerificationMethod {
            id: vm_id.clone(),
            type_: "Multikey".to_string(),
            controller: Url::parse(did).map_err(|e| Error::InvalidDidUrl(did, e.to_string()))?,
            expires: None,
            revoked: None,
            property_set,
        });

        let vm_relationship = VerificationRelationship::Reference(vm_id.clone());

        Ok(Document {
            id: Url::parse(did).map_err(|e| Error::InvalidDidUrl(did, e.to_string()))?,
            context: vec![
                "https://www.w3.org/ns/did/v1".to_string(),
                "https://w3id.org/security/multikey/v1".to_string(),
            ],
            verification_method: vms,
            authentication: vec![vm_relationship.clone()],
            assertion_method: vec![vm_relationship.clone()],
            key_agreement,
            capability_invocation: vec![vm_relationship.clone()],
            capability_delegation: vec![vm_relationship.clone()],
            service: vec![],
        })
    }
}
