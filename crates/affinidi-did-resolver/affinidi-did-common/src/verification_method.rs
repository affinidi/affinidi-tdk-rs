//! DID Verification Method Definition
//! <https://www.w3.org/TR/cid-1.0/#verification-methods>
use std::collections::HashMap;

use affinidi_secrets_resolver::secrets::Secret;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

use crate::DocumentError;

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

impl VerificationMethod {
    /// Attempts to extract Public Key Bytes from the Verification Method
    /// WARN: This function only supportes Multikey VM types for now
    pub fn get_public_key_bytes(&self) -> Result<Vec<u8>, DocumentError> {
        match self.type_.as_str() {
            "Multikey" => {
                // PublicKeyMultibase encoded
                if let Some(key) = self.property_set.get("publicKeyMultibase")
                    && let Some(key) = key.as_str()
                {
                    Ok(Secret::decode_multikey(key)?)
                } else {
                    Err(DocumentError::VM(
                        "Multikey type, but does not include the `publicKeyMultibase` attribute"
                            .to_string(),
                    ))
                }
            }
            _ => Err(DocumentError::VM(format!(
                "VerificationMethod type ({}) isn't supported!",
                self.type_
            ))),
        }
    }
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

#[cfg(test)]
mod tests {
    use crate::verification_method::VerificationMethod;

    #[test]
    pub fn test_multikey_vm_get_public_key_bytes() {
        let vm: VerificationMethod = serde_json::from_str(
            r#"{ "controller": "did:example:1234",
                "id": "did:example:1234#key-0",
                "publicKeyMultibase": "z6MkwdwKx2P9X13goHtcowBBrPFRwqPNcnX1qWd39CnS4yjx",
                "type": "Multikey"
            }"#,
        )
        .unwrap();

        let bytes: [u8; 32] = [
            255, 82, 230, 245, 93, 184, 94, 85, 34, 131, 163, 26, 149, 85, 166, 94, 166, 248, 49,
            62, 250, 157, 214, 128, 22, 212, 174, 75, 199, 252, 34, 131,
        ];
        let result = vm.get_public_key_bytes().unwrap();

        assert_eq!(bytes, result.as_slice());
    }
}
