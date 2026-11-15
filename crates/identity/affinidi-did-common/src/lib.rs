/*!
*   DID Document Definition
*/

use std::collections::HashMap;

use affinidi_encoding::EncodingError;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use thiserror::Error;
use url::Url;

use crate::{
    one_or_many::OneOrMany,
    service::Service,
    verification_method::{VerificationMethod, VerificationRelationship},
};

pub mod builder;
pub mod did;
pub mod did_method;
pub mod document;
#[cfg(feature = "key-agreement")]
pub mod key_negotiation;
pub mod network;
pub mod one_or_many;
pub mod scid;
pub mod service;
pub mod verification_method;

pub use builder::{DocumentBuilder, ServiceBuilder, VerificationMethodBuilder};
pub use did::{DID, DIDError};
pub use did_method::DIDMethod;
pub use did_method::key::{KeyError, KeyMaterial, KeyMaterialFormat, KeyMaterialType};
pub use did_method::peer::{
    PeerCreateKey, PeerCreatedKey, PeerError, PeerKeyPurpose, PeerKeyType, PeerNumAlgo,
    PeerPurpose, PeerService, PeerServiceEndpoint, PeerServiceEndpointLong,
    PeerServiceEndpointShort,
};
pub use document::DocumentExt;
pub use network::NetworkError;

/// This type is `#[non_exhaustive]`: callers must include a wildcard arm when
/// matching, so future additions do not constitute breaking changes.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum DocumentError {
    #[error("URL Error")]
    URL(#[from] url::ParseError),

    #[error("VerificationMethod Error: {0}")]
    VM(String),

    #[error("Encoding Error: {0}")]
    Encoding(#[from] EncodingError),

    #[error("Key expansion error: {0}")]
    KeyExpansionError(String),
}

/// A [DID Document]
///
/// [DID Document]: https://www.w3.org/TR/did-1.1/
/// `#[non_exhaustive]`: build via [`DocumentBuilder`] / [`Document::new`] (or
/// deserialization) rather than a struct literal. Fields stay public for reads.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Document {
    /// DID Subject Identifier
    /// <https://www.w3.org/TR/cid-1.0/#subjects>
    pub id: Url,

    /// Other identifiers the DID subject is also known by
    /// <https://www.w3.org/TR/did-1.1/#also-known-as>
    ///
    /// The DID specification defines this as a *set*, so it always serializes as
    /// a JSON array. Deserialization additionally accepts a bare string, because
    /// documents in the wild emit that form.
    ///
    /// This is the property an agent-name resolver checks to confirm that a
    /// human-readable shortcut is actually authorized by the DID it resolved to.
    #[serde(
        skip_serializing_if = "Vec::is_empty",
        default,
        deserialize_with = "deserialize_also_known_as"
    )]
    pub also_known_as: Vec<String>,

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

/// Accepts either a JSON array of strings or a single bare string.
fn deserialize_also_known_as<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(OneOrMany::<String>::deserialize(deserializer)?.into_vec())
}

impl Default for Document {
    /// A blank document whose `id` is the placeholder
    /// `did:example:123456789abcdefghi`.
    ///
    /// The placeholder is a real, parseable DID, so a document built with
    /// `..Default::default()` and no `id` of its own silently names that
    /// subject. Set `id` (or use [`Document::new`] / [`DocumentBuilder`]),
    /// never rely on the default one. It is kept for compatibility: `id` is a
    /// `Url`, which has no empty value.
    fn default() -> Self {
        Self {
            id: Url::parse("did:example:123456789abcdefghi").unwrap(),
            also_known_as: Vec::new(),
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

    /// Parse a DID document in JSON form, resolving relative ids and
    /// references against the document's own `id`.
    ///
    /// DID Core allows a verification method or service to be identified, and
    /// a verification relationship to refer to one, by a relative DID URL
    /// such as `"#key-1"`. Deserializing straight into [`Document`] refuses
    /// those (its ids are absolute URLs), and leaves a relative relationship
    /// reference that never matches its method's absolute id. This makes them
    /// absolute first; see [`document::absolutize_references`] for what is
    /// rewritten. A document whose `id` is not a string is left as it is, and
    /// fails to deserialize.
    ///
    /// # Errors
    /// The `serde_json` error when the result is not a valid [`Document`].
    pub fn from_json(mut value: Value) -> Result<Self, serde_json::Error> {
        if let Some(base) = value.get("id").and_then(Value::as_str).map(str::to_owned) {
            document::absolutize_references(&mut value, &base);
        }
        serde_json::from_value(value)
    }

    /// As [`Document::from_json`], resolving relative ids and references
    /// against `base` (the DID being resolved) rather than the document's
    /// own `id`.
    ///
    /// # Errors
    /// The `serde_json` error when the result is not a valid [`Document`].
    pub fn from_json_with_base(mut value: Value, base: &str) -> Result<Self, serde_json::Error> {
        document::absolutize_references(&mut value, base);
        serde_json::from_value(value)
    }

    /// As [`Document::from_json`], from the bytes of a JSON body.
    ///
    /// # Errors
    /// The `serde_json` error when the bytes are not JSON or the result is not
    /// a valid [`Document`].
    pub fn from_json_slice(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        Self::from_json(serde_json::from_slice(bytes)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use url::Url;

    #[test]
    fn valid_id() {
        assert!(Url::parse("did:example:123456789abcdefghi").is_ok());
        assert!(Url::parse("did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs").is_ok());
    }

    #[test]
    fn document_new_valid() {
        let doc = Document::new("did:example:123").unwrap();
        assert_eq!(doc.id.as_str(), "did:example:123");
        assert!(doc.verification_method.is_empty());
        assert!(doc.service.is_empty());
    }

    #[test]
    fn document_new_invalid() {
        assert!(Document::new("not a url").is_err());
    }

    #[test]
    fn from_json_resolves_relative_ids_and_references() {
        let value = serde_json::json!({
            "id": "did:web:example.com",
            "verificationMethod": [{
                "id": "#key-1",
                "type": "Multikey",
                "controller": "did:web:example.com",
                "publicKeyMultibase": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
            }],
            "authentication": ["#key-1"],
            "assertionMethod": ["did:web:example.com#key-1"],
            "keyAgreement": [{
                "id": "#key-2",
                "type": "Multikey",
                "controller": "#",
                "publicKeyMultibase": "z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc"
            }],
            "service": [{
                "id": "#didcomm",
                "type": "DIDCommMessaging",
                "serviceEndpoint": "https://example.com/didcomm"
            }]
        });
        assert!(
            serde_json::from_value::<Document>(value.clone()).is_err(),
            "a relative id does not deserialize directly"
        );

        let doc = Document::from_json(value).unwrap();
        assert_eq!(
            doc.verification_method[0].id.as_str(),
            "did:web:example.com#key-1"
        );
        assert!(doc.contains_authentication("did:web:example.com#key-1"));
        assert!(doc.contains_assertion_method("did:web:example.com#key-1"));
        assert!(doc.contains_key_agreement("did:web:example.com#key-2"));
        assert_eq!(
            doc.service[0].id.as_ref().map(Url::as_str),
            Some("did:web:example.com#didcomm")
        );
    }

    #[test]
    fn from_json_with_base_uses_the_base() {
        let value = serde_json::json!({
            "id": "did:web:example.com",
            "authentication": ["#key-1", "key-2", "did:web:other.example#key-3"]
        });
        let doc = Document::from_json_with_base(value, "did:web:base.example").unwrap();
        let ids: Vec<&str> = doc.authentication.iter().map(|a| a.get_id()).collect();
        assert_eq!(
            ids,
            [
                "did:web:base.example#key-1",
                "did:web:base.example#key-2",
                "did:web:other.example#key-3"
            ]
        );
    }

    #[test]
    fn absolutize_reference_forms() {
        use crate::document::absolutize_reference;
        let base = "did:example:123";
        assert_eq!(
            absolutize_reference("#k", base).as_deref(),
            Some("did:example:123#k")
        );
        assert_eq!(
            absolutize_reference("?service=x", base).as_deref(),
            Some("did:example:123?service=x")
        );
        assert_eq!(
            absolutize_reference("/p", base).as_deref(),
            Some("did:example:123/p")
        );
        assert_eq!(
            absolutize_reference("said", base).as_deref(),
            Some("did:example:123#said")
        );
        assert_eq!(absolutize_reference("did:example:9#k", base), None);
        assert_eq!(absolutize_reference("", base), None);
    }

    #[test]
    fn document_default_has_example_id() {
        let doc = Document::default();
        assert_eq!(doc.id.as_str(), "did:example:123456789abcdefghi");
    }

    #[test]
    fn document_serde_roundtrip_minimal() {
        let doc = Document::new("did:example:456").unwrap();
        let json = serde_json::to_string(&doc).unwrap();
        let back: Document = serde_json::from_str(&json).unwrap();
        assert_eq!(doc, back);
    }

    // --- alsoKnownAs ---

    #[test]
    fn also_known_as_defaults_to_empty() {
        let doc = Document::new("did:example:123").unwrap();
        assert!(doc.also_known_as.is_empty());
    }

    #[test]
    fn also_known_as_omitted_when_empty() {
        let doc = Document::new("did:example:123").unwrap();
        let json = serde_json::to_string(&doc).unwrap();
        assert!(!json.contains("alsoKnownAs"));
    }

    #[test]
    fn also_known_as_absent_from_json() {
        let doc: Document = serde_json::from_str(r#"{"id":"did:example:123"}"#).unwrap();
        assert!(doc.also_known_as.is_empty());
    }

    #[test]
    fn also_known_as_deserializes_array() {
        let doc: Document = serde_json::from_str(
            r#"{"id":"did:example:123","alsoKnownAs":["example.com/@alice","connect.me/@bob"]}"#,
        )
        .unwrap();
        assert_eq!(
            doc.also_known_as,
            vec!["example.com/@alice", "connect.me/@bob"]
        );
    }

    /// Documents in the wild emit a bare string; the DID spec says set. Accept both.
    #[test]
    fn also_known_as_deserializes_bare_string() {
        let doc: Document =
            serde_json::from_str(r#"{"id":"did:example:123","alsoKnownAs":"example.com/@alice"}"#)
                .unwrap();
        assert_eq!(doc.also_known_as, vec!["example.com/@alice"]);
    }

    /// Lenient on read, strict on write: a bare string normalizes to an array.
    #[test]
    fn also_known_as_always_serializes_as_array() {
        let doc: Document =
            serde_json::from_str(r#"{"id":"did:example:123","alsoKnownAs":"example.com/@alice"}"#)
                .unwrap();
        let json = serde_json::to_string(&doc).unwrap();
        assert!(json.contains(r#""alsoKnownAs":["example.com/@alice"]"#));
    }

    /// Regression: alsoKnownAs used to land in the flattened `parameters_set` map.
    /// It must now be a typed field and must NOT be duplicated into that map.
    #[test]
    fn also_known_as_not_captured_by_parameters_set() {
        let doc: Document = serde_json::from_str(
            r#"{"id":"did:example:123","alsoKnownAs":["example.com/@alice"]}"#,
        )
        .unwrap();
        assert_eq!(doc.also_known_as, vec!["example.com/@alice"]);
        assert!(!doc.parameters_set.contains_key("alsoKnownAs"));
    }

    #[test]
    fn also_known_as_serde_roundtrip() {
        let json = r#"{"id":"did:example:123","alsoKnownAs":["example.com/@alice"]}"#;
        let doc: Document = serde_json::from_str(json).unwrap();
        let back: Document = serde_json::from_str(&serde_json::to_string(&doc).unwrap()).unwrap();
        assert_eq!(doc, back);
    }
}
