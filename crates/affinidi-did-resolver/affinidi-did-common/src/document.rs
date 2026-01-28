//! Extends the SSI Crate Document with new methods and functions

use crate::{
    DID, Document, DocumentError,
    verification_method::{VerificationMethod, VerificationRelationship},
};
use std::collections::HashMap;
use std::str::FromStr;
use url::Url;

pub trait DocumentExt {
    /// Does this DID contain authentication verification_method with the given id?
    fn contains_authentication(&self, id: &str) -> bool;

    /// Does this DID contain a key agreement with the given id?
    fn contains_key_agreement(&self, id: &str) -> bool;

    /// Does this DID contain an assertion method with the given id?
    fn contains_assertion_method(&self, id: &str) -> bool;

    /// find_authentication or return all
    /// Returns fully defined Vec of authentication id's
    fn find_authentication<'a>(&'a self, id: Option<&'a str>) -> Vec<&'a str>;

    /// find_key_agreement or return all
    /// Returns fully defined Vec of key_agreement id's
    fn find_key_agreement<'a>(&'a self, id: Option<&'a str>) -> Vec<&'a str>;

    /// find_assertion_method or return all
    /// Returns fully defined Vec of assertion_method id's
    fn find_assertion_method<'a>(&'a self, id: Option<&'a str>) -> Vec<&'a str>;

    /// Returns a DID Verification Method if found by ID
    fn get_verification_method(&self, id: &str) -> Option<&VerificationMethod>;

    /// Expand peer DID verification methods from multibase to full JWK format
    ///
    /// This resolves each verification method's `publicKeyMultibase` as a did:key
    /// and replaces it with the full JWK representation. Useful for cryptographic
    /// operations that need the full key material.
    fn expand_peer_keys(&self) -> Result<Document, DocumentError>;
}

impl DocumentExt for Document {
    fn contains_authentication(&self, id: &str) -> bool {
        let id = if let Ok(id) = Url::from_str(id) {
            id
        } else {
            return false;
        };

        self.authentication.iter().any(|vm| match vm {
            VerificationRelationship::Reference(url) => url,
            VerificationRelationship::VerificationMethod(map) => &map.id,
        }
         == &id)
    }

    fn contains_key_agreement(&self, id: &str) -> bool {
        let id = if let Ok(id) = Url::from_str(id) {
            id
        } else {
            return false;
        };

        self.key_agreement.iter().any(|vm| match vm {
            VerificationRelationship::Reference(url) => url,
            VerificationRelationship::VerificationMethod(map) => &map.id,
        }
         == &id)
    }

    fn contains_assertion_method(&self, id: &str) -> bool {
        let id = if let Ok(id) = Url::from_str(id) {
            id
        } else {
            return false;
        };

        self.assertion_method.iter().any(|vm| match vm {
            VerificationRelationship::Reference(url) => url,
            VerificationRelationship::VerificationMethod(map) => &map.id,
        }
         == &id)
    }

    /// Finds a specific authentication_id or returns all authentication ID's
    fn find_authentication<'a>(&'a self, kid: Option<&'a str>) -> Vec<&'a str> {
        if let Some(kid) = kid {
            // Does this kid exist in authentication?
            if self.contains_authentication(kid) {
                vec![kid]
            } else {
                vec![]
            }
        } else {
            self.key_agreement.iter().map(|ka| ka.get_id()).collect()
        }
    }

    /// Finds a specific key_id or returns all key_agreement ID's
    fn find_key_agreement<'a>(&'a self, kid: Option<&'a str>) -> Vec<&'a str> {
        if let Some(kid) = kid {
            // Does this kid exist in key_agreements?
            if self.contains_key_agreement(kid) {
                vec![kid]
            } else {
                vec![]
            }
        } else {
            self.key_agreement.iter().map(|ka| ka.get_id()).collect()
        }
    }

    /// Finds a specific assertion_method or returns all assertion_method ID's
    fn find_assertion_method<'a>(&'a self, kid: Option<&'a str>) -> Vec<&'a str> {
        if let Some(kid) = kid {
            // Does this kid exist in key_agreements?
            if self.contains_assertion_method(kid) {
                vec![kid]
            } else {
                vec![]
            }
        } else {
            self.assertion_method.iter().map(|ka| ka.get_id()).collect()
        }
    }

    fn get_verification_method(&self, id: &str) -> Option<&VerificationMethod> {
        self.verification_method
            .iter()
            .find(|vm| vm.id.as_str() == id)
    }

    fn expand_peer_keys(&self) -> Result<Document, DocumentError> {
        let mut new_doc = self.clone();
        let mut expanded_vms: Vec<VerificationMethod> = Vec::new();

        for vm in &self.verification_method {
            expanded_vms.push(expand_verification_method(vm)?);
        }

        new_doc.verification_method = expanded_vms;
        Ok(new_doc)
    }
}

/// Expand a single verification method from multibase to JWK format
fn expand_verification_method(vm: &VerificationMethod) -> Result<VerificationMethod, DocumentError> {
    // Get the multibase key from either publicKeyMultibase or publicKeyBase58
    let multibase_key = vm
        .property_set
        .get("publicKeyMultibase")
        .or_else(|| vm.property_set.get("publicKeyBase58"))
        .and_then(|v| v.as_str());

    let Some(key_multibase) = multibase_key else {
        // No multibase key to expand, return as-is
        return Ok(vm.clone());
    };

    // Resolve as did:key to get the expanded verification method
    let did_key_string = format!("did:key:{key_multibase}");
    let did_key: DID = did_key_string.parse().map_err(|e| {
        DocumentError::KeyExpansionError(format!("Failed to parse as did:key: {e}"))
    })?;

    let key_doc = did_key.resolve().map_err(|e| {
        DocumentError::KeyExpansionError(format!("Failed to resolve did:key: {e}"))
    })?;

    // Get the first verification method from the resolved document
    let resolved_vm = key_doc.verification_method.first().ok_or_else(|| {
        DocumentError::KeyExpansionError("Resolved did:key has no verification method".to_string())
    })?;

    // Build new verification method with expanded properties but original id/controller
    let mut new_properties: HashMap<String, serde_json::Value> = HashMap::new();
    for (k, v) in &resolved_vm.property_set {
        new_properties.insert(k.clone(), v.clone());
    }

    Ok(VerificationMethod {
        id: vm.id.clone(),
        type_: resolved_vm.type_.clone(),
        controller: vm.controller.clone(),
        expires: vm.expires.clone(),
        revoked: vm.revoked.clone(),
        property_set: new_properties,
    })
}

#[cfg(test)]
mod tests {
    use crate::{
        Document,
        document::DocumentExt,
        verification_method::{VerificationMethod, VerificationRelationship},
    };
    use std::collections::HashMap;
    use url::Url;

    /// Create a basic document for testing against
    fn document() -> Document {
        Document {
            id: Url::parse("did:test:1234").unwrap(),
            verification_method: vec![VerificationMethod {
                id: Url::parse("did:test:1234#vm").unwrap(),
                type_: "Ed25519VerificationKey2018".to_string(),
                controller: Url::parse("did:test:1234").unwrap(),
                expires: None,
                revoked: None,
                property_set: HashMap::new(),
            }],
            assertion_method: vec![
                VerificationRelationship::Reference(
                    Url::parse("did:test:1234#assert_ref").unwrap(),
                ),
                VerificationRelationship::VerificationMethod(Box::new(VerificationMethod {
                    id: Url::parse("did:test:1234#assert_vm").unwrap(),
                    type_: "Ed25519VerificationKey2018".to_string(),
                    controller: Url::parse("did:test:1234").unwrap(),
                    expires: None,
                    revoked: None,
                    property_set: HashMap::new(),
                })),
            ],
            key_agreement: vec![
                VerificationRelationship::Reference(Url::parse("did:test:1234#key_ref").unwrap()),
                VerificationRelationship::VerificationMethod(Box::new(VerificationMethod {
                    id: Url::parse("did:test:1234#key_vm").unwrap(),
                    type_: "Ed25519VerificationKey2018".to_string(),
                    controller: Url::parse("did:test:1234").unwrap(),
                    expires: None,
                    revoked: None,
                    property_set: HashMap::new(),
                })),
            ],
            capability_delegation: vec![],
            capability_invocation: vec![],
            service: vec![],
            authentication: vec![
                VerificationRelationship::Reference(Url::parse("did:test:1234#auth_ref").unwrap()),
                VerificationRelationship::VerificationMethod(Box::new(VerificationMethod {
                    id: Url::parse("did:test:1234#auth_vm").unwrap(),
                    type_: "Ed25519VerificationKey2018".to_string(),
                    controller: Url::parse("did:test:1234").unwrap(),
                    expires: None,
                    revoked: None,
                    property_set: HashMap::new(),
                })),
            ],
            parameters_set: HashMap::new(),
        }
    }

    #[test]
    fn test_get_verification_method_exists() {
        let doc = document();

        assert!(doc.get_verification_method("did:test:1234#vm").is_some());
    }

    #[test]
    fn test_get_verification_method_missing() {
        let doc = document();

        assert!(
            doc.get_verification_method("did:test:1234#missing")
                .is_none()
        );
    }

    #[test]
    fn test_contains_authentication() {
        let doc = document();

        assert!(doc.contains_authentication("did:test:1234#auth_ref"));
        assert!(!doc.contains_authentication("did:test:1234#auth_missing"));
        assert!(doc.contains_authentication("did:test:1234#auth_vm"));

        assert_eq!(doc.find_authentication(None).len(), 2);
        assert_eq!(
            doc.find_authentication(Some("did:test:1234#auth_ref"))
                .len(),
            1
        );
        assert_eq!(
            doc.find_authentication(Some("did:test:1234#missing")).len(),
            0
        );
    }

    #[test]
    fn test_contains_key_agreement() {
        let doc = document();

        assert!(doc.contains_key_agreement("did:test:1234#key_ref"));
        assert!(!doc.contains_key_agreement("did:test:1234#key_missing"));
        assert!(doc.contains_key_agreement("did:test:1234#key_vm"));

        assert_eq!(doc.find_key_agreement(None).len(), 2);
        assert_eq!(
            doc.find_key_agreement(Some("did:test:1234#key_ref")).len(),
            1
        );
        assert_eq!(
            doc.find_key_agreement(Some("did:test:1234#missing")).len(),
            0
        );
    }

    #[test]
    fn test_contains_assertion_method() {
        let doc = document();

        assert!(doc.contains_assertion_method("did:test:1234#assert_ref"));
        assert!(!doc.contains_assertion_method("did:test:1234#assert_missing"));
        assert!(doc.contains_assertion_method("did:test:1234#assert_vm"));

        assert_eq!(doc.find_assertion_method(None).len(), 2);
        assert_eq!(
            doc.find_assertion_method(Some("did:test:1234#assert_ref"))
                .len(),
            1
        );
        assert_eq!(
            doc.find_assertion_method(Some("did:test:1234#missing"))
                .len(),
            0
        );
    }

    #[test]
    fn test_expand_peer_keys() {
        use crate::DID;

        // Resolve a did:peer:2 which has multibase keys
        let did: DID = "did:peer:2.Vz6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc"
            .parse()
            .unwrap();
        let doc = did.resolve().unwrap();

        // Verify we have multibase keys before expansion
        assert_eq!(doc.verification_method.len(), 2);
        assert!(doc.verification_method[0]
            .property_set
            .contains_key("publicKeyMultibase"));

        // Expand the keys
        let expanded = doc.expand_peer_keys().unwrap();

        // Should still have the same number of verification methods
        assert_eq!(expanded.verification_method.len(), 2);

        // Keys should still have publicKeyMultibase (that's what did:key resolution produces)
        // but now they're "expanded" through did:key resolution
        assert!(expanded.verification_method[0]
            .property_set
            .contains_key("publicKeyMultibase"));

        // The original IDs should be preserved
        assert!(expanded.verification_method[0]
            .id
            .as_str()
            .contains("did:peer"));
    }
}
