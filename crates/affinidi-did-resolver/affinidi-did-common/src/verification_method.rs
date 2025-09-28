//! DID Verification Method Definition
//! <https://www.w3.org/TR/cid-1.0/#verification-methods>
use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct VerificationMethod {
    pub id: Url,

    #[serde(rename = "type")]
    pub type_: String,

    pub controller: Url,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked: Option<String>,

    /// Each Service can have multiple other properties
    #[serde(flatten)]
    pub property_set: HashMap<String, Value>,
}

/// https://www.w3.org/TR/cid-1.0/#verification-relationships
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(untagged)]
pub enum VerificationRelationship {
    /// Reference to a Verification Method
    Reference(Url),
    /// Embedded Verification Method
    VerificationMethod(Box<VerificationMethod>),
}

impl VerificationRelationship {
    /// Returns the id of the verification-method
    pub fn get_id(&self) -> &str {
        match self {
            VerificationRelationship::Reference(url) => url.as_str(),
            VerificationRelationship::VerificationMethod(map) => map.id.as_str(),
        }
    }
}
