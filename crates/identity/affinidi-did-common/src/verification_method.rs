//! DID Verification Method Definition
//! <https://www.w3.org/TR/cid-1.0/#verification-methods>
use std::collections::HashMap;

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
    /// WARN: This function only supports Multikey VM types for now
    pub fn get_public_key_bytes(&self) -> Result<Vec<u8>, DocumentError> {
        match self.type_.as_str() {
            "Multikey" => {
                // PublicKeyMultibase encoded
                if let Some(key) = self.property_set.get("publicKeyMultibase")
                    && let Some(key) = key.as_str()
                {
                    Ok(affinidi_encoding::decode_multikey(key)?)
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
    use crate::verification_method::{VerificationMethod, VerificationRelationship};
    use std::collections::HashMap;
    use url::Url;

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

    #[test]
    fn get_public_key_bytes_unsupported_type() {
        let vm = VerificationMethod {
            id: Url::parse("did:example:123#key-0").unwrap(),
            type_: "JsonWebKey2020".to_string(),
            controller: Url::parse("did:example:123").unwrap(),
            expires: None,
            revoked: None,
            property_set: HashMap::new(),
        };
        assert!(vm.get_public_key_bytes().is_err());
    }

    #[test]
    fn get_public_key_bytes_multikey_missing_attribute() {
        let vm = VerificationMethod {
            id: Url::parse("did:example:123#key-0").unwrap(),
            type_: "Multikey".to_string(),
            controller: Url::parse("did:example:123").unwrap(),
            expires: None,
            revoked: None,
            property_set: HashMap::new(),
        };
        assert!(vm.get_public_key_bytes().is_err());
    }

    #[test]
    fn get_id_reference() {
        let rel = VerificationRelationship::Reference(Url::parse("did:test:1234#key-1").unwrap());
        assert_eq!(rel.get_id(), "did:test:1234#key-1");
    }

    #[test]
    fn get_id_embedded() {
        let vm = VerificationMethod {
            id: Url::parse("did:test:1234#key-2").unwrap(),
            type_: "Multikey".to_string(),
            controller: Url::parse("did:test:1234").unwrap(),
            expires: None,
            revoked: None,
            property_set: HashMap::new(),
        };
        let rel = VerificationRelationship::VerificationMethod(Box::new(vm));
        assert_eq!(rel.get_id(), "did:test:1234#key-2");
    }

    #[test]
    fn verification_method_serde_roundtrip() {
        let json = r#"{
            "id": "did:example:123#key-0",
            "type": "Multikey",
            "controller": "did:example:123",
            "publicKeyMultibase": "z6MkwdwKx2P9X13goHtcowBBrPFRwqPNcnX1qWd39CnS4yjx"
        }"#;
        let vm: VerificationMethod = serde_json::from_str(json).unwrap();
        let serialized = serde_json::to_string(&vm).unwrap();
        let back: VerificationMethod = serde_json::from_str(&serialized).unwrap();
        assert_eq!(vm, back);
    }

    #[test]
    fn verification_relationship_reference_serde() {
        let rel = VerificationRelationship::Reference(Url::parse("did:test:1234#key-1").unwrap());
        let json = serde_json::to_string(&rel).unwrap();
        assert_eq!(json, "\"did:test:1234#key-1\"");
        let back: VerificationRelationship = serde_json::from_str(&json).unwrap();
        assert_eq!(rel, back);
    }

    #[test]
    fn verification_relationship_embedded_serde() {
        let vm = VerificationMethod {
            id: Url::parse("did:test:1234#key-1").unwrap(),
            type_: "Multikey".to_string(),
            controller: Url::parse("did:test:1234").unwrap(),
            expires: None,
            revoked: None,
            property_set: HashMap::new(),
        };
        let rel = VerificationRelationship::VerificationMethod(Box::new(vm));
        let json = serde_json::to_string(&rel).unwrap();
        let back: VerificationRelationship = serde_json::from_str(&json).unwrap();
        assert_eq!(rel, back);
    }

    #[test]
    fn verification_method_with_optional_fields() {
        let json = r#"{
            "id": "did:example:123#key-0",
            "type": "Multikey",
            "controller": "did:example:123",
            "expires": "2025-12-31T00:00:00Z",
            "revoked": "2025-06-01T00:00:00Z"
        }"#;
        let vm: VerificationMethod = serde_json::from_str(json).unwrap();
        assert_eq!(vm.expires.as_deref(), Some("2025-12-31T00:00:00Z"));
        assert_eq!(vm.revoked.as_deref(), Some("2025-06-01T00:00:00Z"));
    }
}
