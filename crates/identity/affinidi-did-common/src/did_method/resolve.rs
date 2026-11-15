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

use super::DIDMethod;
use super::peer::{PeerNumAlgo, PeerPurpose, PeerService};
use crate::{
    DID, DIDError, Document,
    service::Service,
    verification_method::{VerificationMethod, VerificationRelationship},
};

const PUBLIC_KEY_MULTIBASE: &str = "publicKeyMultibase";
const MULTIKEY_TYPE: &str = "Multikey";

impl DIDMethod {
    /// Resolve this DID method to a DID Document
    ///
    /// Works for locally-resolvable methods (did:key, did:peer).
    /// For network methods, returns an error indicating external resolution is needed.
    pub fn resolve(&self, did: &DID) -> Result<Document, DIDError> {
        match self {
            DIDMethod::Key {
                identifier, codec, ..
            } => resolve_key(&did.base_url()?, identifier, codec.to_u64()),
            DIDMethod::Peer {
                numalgo,
                identifier,
            } => resolve_peer(did, numalgo, identifier),
            _ => Err(DIDError::ResolutionError(format!(
                "DID method '{}' requires network resolution",
                self.name()
            ))),
        }
    }
}

/// Build the document of a single-key DID (did:key, did:peer numalgo 0).
///
/// `subject` is the bare DID the document is for; every id, controller and
/// reference is under it. `multikey` is the public key as a multikey (the
/// did:key method-specific id), already validated at parse time, and `codec`
/// its multicodec. Each verification method's fragment is its multikey.
fn resolve_key(subject: &url::Url, multikey: &str, codec: u64) -> Result<Document, DIDError> {
    let identifier = multikey;
    let mut vm_id = subject.clone();
    vm_id.set_fragment(Some(identifier));

    let mut vms = Vec::new();
    let mut key_agreement = Vec::new();

    match codec {
        ED25519_PUB => {
            // Ed25519 keys also derive an X25519 key for key agreement
            let (x25519_encoded, _) = ed25519_public_to_x25519(identifier).map_err(|e| {
                DIDError::ResolutionError(format!("Failed to derive X25519 from Ed25519: {e}"))
            })?;

            let mut x25519_vm_id = subject.clone();
            x25519_vm_id.set_fragment(Some(&x25519_encoded));

            vms.push(VerificationMethod {
                id: x25519_vm_id.clone(),
                type_: MULTIKEY_TYPE.to_string(),
                controller: subject.clone(),
                expires: None,
                revoked: None,
                property_set: HashMap::from([(
                    PUBLIC_KEY_MULTIBASE.to_string(),
                    Value::String(x25519_encoded.to_string()),
                )]),
            });

            key_agreement.push(VerificationRelationship::Reference(
                x25519_vm_id.to_string(),
            ));
        }
        P256_PUB | P384_PUB | SECP256K1_PUB | X25519_PUB => {
            key_agreement.push(VerificationRelationship::Reference(vm_id.to_string()));
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
            controller: subject.clone(),
            expires: None,
            revoked: None,
            property_set: HashMap::from([(
                PUBLIC_KEY_MULTIBASE.to_string(),
                Value::String(identifier.to_string()),
            )]),
        },
    );

    let vm_relationship = VerificationRelationship::Reference(vm_id.to_string());

    Ok(Document {
        id: subject.clone(),
        also_known_as: vec![],
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

/// Resolve a did:peer to its DID Document
fn resolve_peer(did: &DID, numalgo: &PeerNumAlgo, identifier: &str) -> Result<Document, DIDError> {
    match numalgo {
        PeerNumAlgo::InceptionKey => {
            // Numalgo 0: the identifier after the leading '0' is a did:key
            // multikey. The document is a did:key's, built under the
            // did:peer:0 DID itself: its id, every verification method's id
            // and controller, and every reference are `did:peer:0…`, with the
            // multikey as each method's fragment as for did:key.
            let key_multibase = identifier.strip_prefix('0').unwrap_or(identifier);
            let (codec, _) = affinidi_encoding::decode_multikey_with_codec(key_multibase)
                .map_err(|e| DIDError::ResolutionError(format!("Invalid did:peer:0 key: {e}")))?;
            resolve_key(&did.base_url()?, key_multibase, codec)
        }
        PeerNumAlgo::MultipleKeys => resolve_peer_2(did, identifier),
        PeerNumAlgo::GenesisDoc => Err(DIDError::ResolutionError(
            "did:peer numalgo 1 (genesis doc) is not supported".to_string(),
        )),
    }
}

/// Resolve did:peer:2 format
///
/// Format: did:peer:2.<purpose><multibase>.<purpose><multibase>...S<base64-service>...
fn resolve_peer_2(did: &DID, identifier: &str) -> Result<Document, DIDError> {
    use std::str::FromStr;
    use url::Url;

    let subject = did.base_url()?;
    let did_string = subject.to_string();

    // Skip the leading '2' and split on '.'
    let content = identifier.strip_prefix('2').unwrap_or(identifier);
    let parts: Vec<&str> = content.split('.').filter(|s| !s.is_empty()).collect();

    let mut verification_methods: Vec<VerificationMethod> = Vec::new();
    let mut authentication: Vec<VerificationRelationship> = Vec::new();
    let mut assertion_method: Vec<VerificationRelationship> = Vec::new();
    let mut key_agreement: Vec<VerificationRelationship> = Vec::new();
    let mut capability_delegation: Vec<VerificationRelationship> = Vec::new();
    let mut capability_invocation: Vec<VerificationRelationship> = Vec::new();
    let mut services: Vec<Service> = Vec::new();

    let mut key_count: u32 = 0;
    let mut service_idx: u32 = 0;

    for part in parts {
        if part.is_empty() {
            continue;
        }

        let purpose_char = part
            .chars()
            .next()
            .ok_or_else(|| DIDError::ResolutionError("Empty part in did:peer".to_string()))?;

        let purpose = PeerPurpose::from_char(purpose_char).ok_or_else(|| {
            DIDError::ResolutionError(format!("Invalid purpose code: {purpose_char}"))
        })?;

        if purpose == PeerPurpose::Service {
            // Decode service
            let service = PeerService::decode(part)
                .map_err(|e| DIDError::ResolutionError(format!("Service decode error: {e}")))?;

            let did_service = service
                .to_did_service(&did_string, service_idx)
                .map_err(|e| DIDError::ResolutionError(format!("Service conversion error: {e}")))?;

            services.push(did_service);
            service_idx += 1;
        } else {
            // Key entry
            key_count += 1;
            let kid = format!("{did_string}#key-{key_count}");
            let public_key_multibase = &part[1..]; // Skip purpose char

            let vm = VerificationMethod {
                id: Url::from_str(&kid)
                    .map_err(|e| DIDError::ResolutionError(format!("Invalid key ID: {e}")))?,
                type_: MULTIKEY_TYPE.to_string(),
                controller: subject.clone(),
                expires: None,
                revoked: None,
                property_set: HashMap::from([(
                    PUBLIC_KEY_MULTIBASE.to_string(),
                    Value::String(public_key_multibase.to_string()),
                )]),
            };

            verification_methods.push(vm);

            let relationship = VerificationRelationship::Reference(kid);

            match purpose {
                PeerPurpose::Verification => {
                    authentication.push(relationship.clone());
                    assertion_method.push(relationship);
                }
                PeerPurpose::Encryption => {
                    key_agreement.push(relationship);
                }
                PeerPurpose::Assertion => {
                    assertion_method.push(relationship);
                }
                PeerPurpose::Delegation => {
                    capability_delegation.push(relationship);
                }
                PeerPurpose::Invocation => {
                    capability_invocation.push(relationship);
                }
                PeerPurpose::Service => unreachable!(),
            }
        }
    }

    Ok(Document {
        id: subject,
        also_known_as: vec![],
        verification_method: verification_methods,
        authentication,
        assertion_method,
        key_agreement,
        capability_delegation,
        capability_invocation,
        service: services,
        parameters_set: HashMap::from([(
            "@context".to_string(),
            json!(["https://www.w3.org/ns/did/v1.1"]),
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

    #[test]
    fn test_resolve_peer_numalgo_0() {
        // did:peer:0 wraps a did:key
        let did: DID = "did:peer:0z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
            .parse()
            .unwrap();
        let doc = did.resolve().unwrap();

        // Should resolve like did:key
        assert_eq!(doc.verification_method.len(), 2); // Ed25519 + derived X25519
        assert_eq!(doc.authentication.len(), 1);
        assert_eq!(doc.key_agreement.len(), 1);
    }

    /// The numalgo-0 document is the peer DID's, not the did:key's it wraps.
    #[test]
    fn peer_numalgo_0_document_is_under_the_peer_did() {
        let peer = "did:peer:0z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
        let did: DID = peer.parse().unwrap();
        let doc = did.resolve().unwrap();

        assert_eq!(doc.id.as_str(), peer);
        for vm in &doc.verification_method {
            assert!(vm.id.as_str().starts_with(&format!("{peer}#z")), "{vm:?}");
            assert_eq!(vm.controller.as_str(), peer);
        }
        assert_eq!(
            doc.verification_method[0].id.as_str(),
            format!("{peer}#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")
        );
        for relationship in doc
            .authentication
            .iter()
            .chain(&doc.assertion_method)
            .chain(&doc.key_agreement)
            .chain(&doc.capability_invocation)
            .chain(&doc.capability_delegation)
        {
            assert!(
                relationship.get_id().starts_with(&format!("{peer}#")),
                "{relationship:?}"
            );
        }
        assert!(!serde_json::to_string(&doc).unwrap().contains("did:key"));

        // The keys are the did:key's.
        let key: DID = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
            .parse()
            .unwrap();
        let key_doc = key.resolve().unwrap();
        assert_eq!(
            doc.verification_method[1].property_set,
            key_doc.verification_method[1].property_set
        );
    }

    /// A DID URL resolves to the document of its DID, not one whose subject
    /// carries the URL's fragment or path.
    #[test]
    fn a_did_url_resolves_under_the_bare_did() {
        let did: DID = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#frag"
            .parse()
            .unwrap();
        let doc = did.resolve().unwrap();
        assert_eq!(
            doc.id.as_str(),
            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
        );
        let did: DID = "did:peer:2.Vz6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#key-1"
            .parse()
            .unwrap();
        let doc = did.resolve().unwrap();
        assert_eq!(
            doc.verification_method[0].id.as_str(),
            "did:peer:2.Vz6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#key-1"
        );
        assert_eq!(
            doc.verification_method[0].controller.as_str(),
            "did:peer:2.Vz6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
        );
    }

    #[test]
    fn test_resolve_peer_numalgo_2() {
        // did:peer:2 with V (verification) and E (encryption) keys
        let did: DID = "did:peer:2.Vz6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc"
            .parse()
            .unwrap();
        let doc = did.resolve().unwrap();

        // Should have 2 verification methods
        assert_eq!(doc.verification_method.len(), 2);
        // V key goes to authentication and assertion
        assert_eq!(doc.authentication.len(), 1);
        assert_eq!(doc.assertion_method.len(), 1);
        // E key goes to key_agreement
        assert_eq!(doc.key_agreement.len(), 1);
    }

    #[test]
    fn test_resolve_peer_numalgo_2_with_service() {
        // did:peer:2 with service encoded
        // Service: {"t":"dm","s":"https://example.com/didcomm"}
        let did: DID = "did:peer:2.Vz6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9kaWRjb21tIn0"
            .parse()
            .unwrap();
        let doc = did.resolve().unwrap();

        assert_eq!(doc.verification_method.len(), 1);
        assert_eq!(doc.service.len(), 1);
        assert_eq!(doc.service[0].type_, vec!["DIDCommMessaging".to_string()]);
    }
}
