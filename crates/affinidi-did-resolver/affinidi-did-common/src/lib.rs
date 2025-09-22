/*!
*   DID Document Definition
*/

use serde::{Deserialize, Serialize};
use url::Url;

use crate::{
    service::Service,
    verification_method::{VerificationMethod, VerificationRelationship},
};

pub mod document;
pub mod service;
pub mod verification_method;

/// A [DID Document]
///
/// [DID Document]: https://www.w3.org/TR/did-1.1/
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Document {
    /// DID Subject Identifier
    /// <https://www.w3.org/TR/cid-1.0/#subjects>
    pub id: Url,

    #[serde(rename = "@context")]
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub context: Vec<String>,

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
