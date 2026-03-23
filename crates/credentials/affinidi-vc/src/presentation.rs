/*!
 * Verifiable Presentation types for W3C VCDM 1.1 and 2.0.
 *
 * A Verifiable Presentation wraps one or more Verifiable Credentials
 * for submission to a verifier.
 */

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::context::CREDENTIALS_V2_CONTEXT;
use crate::credential::{ContextValue, VerifiableCredential};
use crate::error::{Result, VcError};

/// A W3C Verifiable Presentation.
///
/// Contains one or more Verifiable Credentials presented to a verifier.
/// The proof is external to the data model (JWT, DIDComm, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiablePresentation {
    /// JSON-LD context(s).
    #[serde(rename = "@context")]
    pub context: ContextValue,

    /// Optional presentation identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// Presentation type(s). MUST include "VerifiablePresentation".
    #[serde(rename = "type")]
    pub types: Vec<String>,

    /// The entity presenting the credentials (holder DID).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub holder: Option<String>,

    /// The credentials being presented.
    /// Can be serialized VC objects, JWT strings, or SD-JWT strings.
    #[serde(
        rename = "verifiableCredential",
        skip_serializing_if = "Option::is_none"
    )]
    pub verifiable_credential: Option<Vec<Value>>,

    /// Proof(s) — only present with embedded Data Integrity proofs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<Value>,

    /// Additional properties.
    #[serde(flatten)]
    pub additional: serde_json::Map<String, Value>,
}

impl VerifiablePresentation {
    /// Validate the presentation structure.
    pub fn validate(&self) -> Result<()> {
        if !self.types.iter().any(|t| t == "VerifiablePresentation") {
            return Err(VcError::InvalidPresentation(
                "type array must include \"VerifiablePresentation\"".into(),
            ));
        }
        Ok(())
    }
}

/// Builder for constructing `VerifiablePresentation` instances.
pub struct PresentationBuilder {
    context: Vec<Value>,
    id: Option<String>,
    types: Vec<String>,
    holder: Option<String>,
    credentials: Vec<Value>,
}

impl PresentationBuilder {
    /// Create a new presentation builder with VCDM 2.0 context.
    pub fn new() -> Self {
        Self {
            context: vec![Value::String(CREDENTIALS_V2_CONTEXT.to_string())],
            id: None,
            types: vec!["VerifiablePresentation".to_string()],
            holder: None,
            credentials: Vec::new(),
        }
    }

    /// Set the presentation ID.
    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    /// Set the holder DID.
    pub fn holder(mut self, holder: impl Into<String>) -> Self {
        self.holder = Some(holder.into());
        self
    }

    /// Add a credential as a JSON object.
    pub fn add_credential(mut self, credential: &VerifiableCredential) -> Result<Self> {
        let value = serde_json::to_value(credential)?;
        self.credentials.push(value);
        Ok(self)
    }

    /// Add a credential as a raw JSON value (JWT string, SD-JWT string, or JSON object).
    pub fn add_credential_value(mut self, value: Value) -> Self {
        self.credentials.push(value);
        self
    }

    /// Build the presentation.
    pub fn build(self) -> Result<VerifiablePresentation> {
        let vp = VerifiablePresentation {
            context: ContextValue::Array(self.context),
            id: self.id,
            types: self.types,
            holder: self.holder,
            verifiable_credential: if self.credentials.is_empty() {
                None
            } else {
                Some(self.credentials)
            },
            proof: None,
            additional: serde_json::Map::new(),
        };

        vp.validate()?;
        Ok(vp)
    }
}

impl Default for PresentationBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::CredentialBuilder;
    use serde_json::json;

    fn sample_subject() -> serde_json::Map<String, Value> {
        let mut m = serde_json::Map::new();
        m.insert("id".to_string(), json!("did:example:subject"));
        m.insert("name".to_string(), json!("Alice"));
        m
    }

    #[test]
    fn build_presentation() {
        let vc = CredentialBuilder::v2()
            .issuer_uri("did:example:issuer")
            .subject(sample_subject())
            .build()
            .unwrap();

        let vp = PresentationBuilder::new()
            .holder("did:example:holder")
            .add_credential(&vc)
            .unwrap()
            .build()
            .unwrap();

        assert!(vp.types.contains(&"VerifiablePresentation".to_string()));
        assert_eq!(vp.holder.as_deref(), Some("did:example:holder"));
        assert_eq!(vp.verifiable_credential.as_ref().unwrap().len(), 1);
    }

    #[test]
    fn serialize_roundtrip() {
        let vp = PresentationBuilder::new()
            .id("urn:uuid:vp-1")
            .holder("did:example:holder")
            .add_credential_value(json!("eyJ...jwt-string..."))
            .build()
            .unwrap();

        let json = serde_json::to_string(&vp).unwrap();
        let parsed: VerifiablePresentation = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, vp.id);
    }

    #[test]
    fn empty_presentation() {
        let vp = PresentationBuilder::new()
            .holder("did:example:holder")
            .build()
            .unwrap();

        assert!(vp.verifiable_credential.is_none());
    }

    #[test]
    fn presentation_with_sd_jwt_string() {
        let vp = PresentationBuilder::new()
            .holder("did:example:holder")
            .add_credential_value(json!("eyJhbGciOi...~WyJzYWx0Ii...~"))
            .build()
            .unwrap();

        let creds = vp.verifiable_credential.unwrap();
        assert_eq!(creds.len(), 1);
        assert!(creds[0].is_string());
    }
}
