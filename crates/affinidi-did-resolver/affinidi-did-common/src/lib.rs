/*!
*   DID Document Definition
*/

use std::collections::HashMap;

use affinidi_encoding::EncodingError;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use url::Url;

use crate::{
    service::Service,
    verification_method::{VerificationMethod, VerificationRelationship},
};

pub mod did;
pub mod did_method;
pub mod document;
pub mod one_or_many;
pub mod service;
pub mod verification_method;

pub use did::{DID, DIDError};
pub use did_method::DIDMethod;
pub use did_method::key::{KeyError, KeyMaterial, KeyMaterialFormat, KeyMaterialType};

#[derive(Error, Debug)]
pub enum DocumentError {
    #[error("URL Error")]
    URL(#[from] url::ParseError),

    #[error("VerificationMethod Error: {0}")]
    VM(String),

    #[error("Encoding Error: {0}")]
    Encoding(#[from] EncodingError),
}

/// A [DID Document]
///
/// [DID Document]: https://www.w3.org/TR/did-1.1/
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Document {
    /// DID Subject Identifier
    /// <https://www.w3.org/TR/cid-1.0/#subjects>
    pub id: Url,

    /// https://www.w3.org/TR/cid-1.0/#verification-methods
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub verification_method: Vec<VerificationMethod>,

    /// https://www.w3.org/TR/cid-1.0/#authentication
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub authentication: Vec<VerificationRelationship>,

    /// https://www.w3.org/TR/cid-1.0/#assertion
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub assertion_method: Vec<VerificationRelationship>,

    /// https://www.w3.org/TR/cid-1.0/#key-agreement
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub key_agreement: Vec<VerificationRelationship>,

    /// https://www.w3.org/TR/cid-1.0/#capability-invocation
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub capability_invocation: Vec<VerificationRelationship>,

    /// https://www.w3.org/TR/cid-1.0/#capability-delegation
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub capability_delegation: Vec<VerificationRelationship>,

    /// Set of Services
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub service: Vec<Service>,

    /// Other parameters that may be in a DID Document
    #[serde(flatten)]
    pub parameters_set: HashMap<String, Value>,
}

impl Default for Document {
    /// Creates a default example DID Document that is blank except for the id field
    fn default() -> Self {
        Self {
            id: Url::parse("did:example:123456789abcdefghi").unwrap(),
            verification_method: Vec::new(),
            authentication: Vec::new(),
            assertion_method: Vec::new(),
            key_agreement: Vec::new(),
            capability_invocation: Vec::new(),
            capability_delegation: Vec::new(),
            service: Vec::new(),
            parameters_set: HashMap::new(),
        }
    }
}

impl Document {
    /// Creates a new DID Document with the given identifier
    /// Rest of the Document is blank
    pub fn new(id: &str) -> Result<Self, DocumentError> {
        Ok(Document {
            id: Url::parse(id)?,
            ..Default::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use url::Url;

    #[test]
    fn valid_id() {
        assert!(Url::parse("did:example:123456789abcdefghi").is_ok());
        assert!(Url::parse("did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs").is_ok());
    }
}
