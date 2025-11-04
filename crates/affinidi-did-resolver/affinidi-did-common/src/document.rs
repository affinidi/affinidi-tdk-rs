//! Extends the SSI Crate Document with new methods and functions

use crate::{
    Document,
    verification_method::{VerificationMethod, VerificationRelationship},
};
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
}
