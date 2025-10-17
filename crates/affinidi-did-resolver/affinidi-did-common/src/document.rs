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

    /// find_key_agreement or return all
    /// Returns fully defined Vec of key_agreement id's
    fn find_key_agreement<'a>(&'a self, id: Option<&'a str>) -> Vec<&'a str>;

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

    fn get_verification_method(&self, id: &str) -> Option<&VerificationMethod> {
        self.verification_method
            .iter()
            .find(|vm| vm.id.as_str() == id)
    }
}
