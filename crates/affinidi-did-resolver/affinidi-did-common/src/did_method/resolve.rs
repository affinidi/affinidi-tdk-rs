//! DID resolution for locally-resolvable methods
//!
//! This module implements resolution for methods that can be resolved
//! without network access (did:key, did:peer).
//!
//! For network-resolvable methods (did:web, did:cheqd, etc.), use a `Resolver` trait
//! implementation that handles HTTP requests and caching.

use std::collections::HashMap;

use serde_json::{Value, json};

use affinidi_crypto::ed25519::ed25519_public_to_x25519;
use affinidi_encoding::{ED25519_PUB, P256_PUB, P384_PUB, SECP256K1_PUB, X25519_PUB};

use crate::{
    DID, DIDError, Document,
    verification_method::{VerificationMethod, VerificationRelationship},
};
use super::DIDMethod;

const PUBLIC_KEY_MULTIBASE: &str = "publicKeyMultibase";
const MULTIKEY_TYPE: &str = "Multikey";

impl DIDMethod {
    /// Resolve this DID method to a DID Document
    ///
    /// Works for locally-resolvable methods (did:key, did:peer).
    /// For network methods, returns an error indicating external resolution is needed.
    pub fn resolve(&self, did: &DID) -> Result<Document, DIDError> {
        match self {
            DIDMethod::Key { identifier, .. } => resolve_key(did, identifier),
            DIDMethod::Peer { numalgo, .. } => {
                // TODO: Implement did:peer resolution
                Err(DIDError::ResolutionError(format!(
                    "did:peer numalgo {} resolution not yet implemented",
                    numalgo.to_char()
                )))
            }
            _ => Err(DIDError::ResolutionError(format!(
                "DID method '{}' requires network resolution",
                self.name()
            ))),
        }
    }
}

/// Resolve a did:key to its DID Document
fn resolve_key(did: &DID, identifier: &str) -> Result<Document, DIDError> {
    // Get the codec (already validated at parse time)
    let (codec, _) = affinidi_encoding::decode_multikey_with_codec(identifier)
        .map_err(|e| DIDError::ResolutionError(format!("Invalid multikey: {e}")))?;

    let mut vm_id = did.url();
    vm_id.set_fragment(Some(identifier));

    let mut vms = Vec::new();
    let mut key_agreement = Vec::new();

    match codec {
        ED25519_PUB => {
            // Ed25519 keys also derive an X25519 key for key agreement
            let (x25519_encoded, _) = ed25519_public_to_x25519(identifier).map_err(|e| {
                DIDError::ResolutionError(format!("Failed to derive X25519 from Ed25519: {e}"))
            })?;

            let mut x25519_vm_id = did.url();
            x25519_vm_id.set_fragment(Some(&x25519_encoded));

            vms.push(VerificationMethod {
                id: x25519_vm_id.clone(),
                type_: MULTIKEY_TYPE.to_string(),
                controller: did.url(),
                expires: None,
                revoked: None,
                property_set: HashMap::from([(
                    PUBLIC_KEY_MULTIBASE.to_string(),
                    Value::String(x25519_encoded.to_string()),
                )]),
            });

            key_agreement.push(VerificationRelationship::Reference(x25519_vm_id));
        }
        P256_PUB | P384_PUB | SECP256K1_PUB | X25519_PUB => {
            key_agreement.push(VerificationRelationship::Reference(vm_id.clone()));
        }
        _ => {
            return Err(DIDError::ResolutionError(format!(
                "Unsupported key codec: 0x{codec:x}"
            )));
        }
    }

    // Primary verification method (inserted at front)
    vms.insert(
        0,
        VerificationMethod {
            id: vm_id.clone(),
            type_: MULTIKEY_TYPE.to_string(),
            controller: did.url(),
            expires: None,
            revoked: None,
            property_set: HashMap::from([(
                PUBLIC_KEY_MULTIBASE.to_string(),
                Value::String(identifier.to_string()),
            )]),
        },
    );

    let vm_relationship = VerificationRelationship::Reference(vm_id);

    Ok(Document {
        id: did.url(),
        verification_method: vms,
        authentication: vec![vm_relationship.clone()],
        assertion_method: vec![vm_relationship.clone()],
        key_agreement,
        capability_invocation: vec![vm_relationship.clone()],
        capability_delegation: vec![vm_relationship],
        service: vec![],
        parameters_set: HashMap::from([(
            "@context".to_string(),
            json!([
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/multikey/v1",
            ]),
        )]),
    })
}

#[cfg(test)]
mod tests {
    use crate::DID;

    #[test]
    fn test_resolve_ed25519() {
        let did: DID = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
            .parse()
            .unwrap();
        let doc = did.method().resolve(&did).unwrap();

        assert_eq!(
            doc.id.as_str(),
            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
        );
        // Ed25519 should have 2 verification methods (Ed25519 + derived X25519)
        assert_eq!(doc.verification_method.len(), 2);
        assert_eq!(doc.key_agreement.len(), 1);
    }

    #[test]
    fn test_resolve_p256() {
        let did: DID = "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169"
            .parse()
            .unwrap();
        let doc = did.method().resolve(&did).unwrap();

        assert_eq!(
            doc.id.as_str(),
            "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169"
        );
        // P-256 should have 1 verification method
        assert_eq!(doc.verification_method.len(), 1);
        assert_eq!(doc.key_agreement.len(), 1);
    }

    #[test]
    fn test_resolve_secp256k1() {
        let did: DID = "did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1a7y8xs6zTcNNvoB5e"
            .parse()
            .unwrap();
        let doc = did.method().resolve(&did).unwrap();

        assert_eq!(doc.verification_method.len(), 1);
    }

    #[test]
    fn test_resolve_web_requires_network() {
        let did: DID = "did:web:example.com".parse().unwrap();
        let result = did.method().resolve(&did);

        assert!(result.is_err());
    }
}
