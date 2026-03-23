/*!
 * Verifiable Credential types supporting both VCDM 1.1 and 2.0.
 *
 * # VCDM Version Differences
 *
 * | Property | VCDM 1.1 | VCDM 2.0 |
 * |---|---|---|
 * | Issuance time | `issuanceDate` | `validFrom` |
 * | Expiry time | `expirationDate` | `validUntil` |
 * | Issuer | string or object | string or object |
 * | Subject | `credentialSubject` | `credentialSubject` |
 * | Status | `credentialStatus` | `credentialStatus` |
 * | Schema | `credentialSchema` | `credentialSchema` |
 * | Evidence | `evidence` | `evidence` |
 * | Terms of Use | `termsOfUse` | `termsOfUse` |
 *
 * This implementation uses a unified type that accepts both versions,
 * with version detected from the `@context` array.
 */

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::context::{CREDENTIALS_V1_CONTEXT, CREDENTIALS_V2_CONTEXT, validate_contexts};
use crate::error::{Result, VcError};

/// A W3C Verifiable Credential (VCDM 1.1 or 2.0).
///
/// This is the core credential type. The proof is external to the data model —
/// it can be a Data Integrity proof, JWT envelope, SD-JWT-VC, or COSE signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiableCredential {
    /// JSON-LD context(s). First MUST be the W3C base context.
    #[serde(rename = "@context")]
    pub context: ContextValue,

    /// Optional credential identifier (URI).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// Credential type(s). MUST include "VerifiableCredential".
    #[serde(rename = "type")]
    pub types: Vec<String>,

    /// The entity that issued the credential.
    pub issuer: IssuerValue,

    /// The subject(s) of the credential.
    #[serde(rename = "credentialSubject")]
    pub credential_subject: SubjectValue,

    // ── VCDM 1.1 temporal fields ──
    /// VCDM 1.1: Date the credential was issued.
    #[serde(rename = "issuanceDate", skip_serializing_if = "Option::is_none")]
    pub issuance_date: Option<String>,

    /// VCDM 1.1: Date the credential expires.
    #[serde(rename = "expirationDate", skip_serializing_if = "Option::is_none")]
    pub expiration_date: Option<String>,

    // ── VCDM 2.0 temporal fields ──
    /// VCDM 2.0: Date from which the credential is valid.
    #[serde(rename = "validFrom", skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<String>,

    /// VCDM 2.0: Date until which the credential is valid.
    #[serde(rename = "validUntil", skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<String>,

    /// Credential status information (for revocation/suspension checking).
    #[serde(rename = "credentialStatus", skip_serializing_if = "Option::is_none")]
    pub credential_status: Option<CredentialStatus>,

    /// Credential schema(s) for validation.
    #[serde(rename = "credentialSchema", skip_serializing_if = "Option::is_none")]
    pub credential_schema: Option<Value>,

    /// Evidence supporting the credential claims.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<Value>,

    /// Terms of use for the credential.
    #[serde(rename = "termsOfUse", skip_serializing_if = "Option::is_none")]
    pub terms_of_use: Option<Value>,

    /// Proof(s) — only present when using embedded Data Integrity proofs.
    /// For JWT/SD-JWT-VC/COSE, the proof is external (the signature envelope).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<Value>,

    /// Additional properties not covered by the core fields.
    #[serde(flatten)]
    pub additional: serde_json::Map<String, Value>,
}

/// JSON-LD `@context` value — can be a single string or array of strings/objects.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ContextValue {
    /// Single context URI string.
    String(String),
    /// Array of context URI strings and/or context objects.
    Array(Vec<Value>),
}

impl ContextValue {
    /// Extract context URIs as strings (ignoring inline context objects).
    pub fn as_strings(&self) -> Vec<String> {
        match self {
            ContextValue::String(s) => vec![s.clone()],
            ContextValue::Array(arr) => arr
                .iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect(),
        }
    }
}

/// Issuer value — can be a URI string or an object with `id` and other properties.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum IssuerValue {
    /// Issuer identified by URI only.
    Uri(String),
    /// Issuer with additional properties (id, name, etc.).
    Object {
        id: String,
        #[serde(flatten)]
        properties: serde_json::Map<String, Value>,
    },
}

impl IssuerValue {
    /// Get the issuer ID (URI) regardless of format.
    pub fn id(&self) -> &str {
        match self {
            IssuerValue::Uri(uri) => uri,
            IssuerValue::Object { id, .. } => id,
        }
    }
}

/// Credential subject — can be a single object or array of objects.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SubjectValue {
    /// Single credential subject.
    Single(serde_json::Map<String, Value>),
    /// Multiple credential subjects.
    Multiple(Vec<serde_json::Map<String, Value>>),
}

/// Credential status information for revocation/suspension checking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialStatus {
    /// Status entry identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// Status type (e.g., "BitstringStatusListEntry", "StatusList2021Entry").
    #[serde(rename = "type")]
    pub status_type: String,

    /// Status purpose (e.g., "revocation", "suspension").
    #[serde(rename = "statusPurpose", skip_serializing_if = "Option::is_none")]
    pub status_purpose: Option<String>,

    /// Index in the status list.
    #[serde(rename = "statusListIndex", skip_serializing_if = "Option::is_none")]
    pub status_list_index: Option<String>,

    /// URI of the status list credential.
    #[serde(
        rename = "statusListCredential",
        skip_serializing_if = "Option::is_none"
    )]
    pub status_list_credential: Option<String>,

    /// Additional status properties.
    #[serde(flatten)]
    pub additional: serde_json::Map<String, Value>,
}

impl VerifiableCredential {
    /// Detect the VCDM version from the `@context`.
    pub fn version(&self) -> Option<u8> {
        crate::context::detect_version(&self.context.as_strings())
    }

    /// Validate the credential structure.
    ///
    /// Checks:
    /// - Base context is present and valid
    /// - "VerifiableCredential" is in the type array
    /// - Temporal fields are valid for the detected version
    pub fn validate(&self) -> Result<()> {
        let version = validate_contexts(&self.context.as_strings())?;

        // Must have "VerifiableCredential" type
        if !self.types.iter().any(|t| t == "VerifiableCredential") {
            return Err(VcError::InvalidType(
                "type array must include \"VerifiableCredential\"".into(),
            ));
        }

        // Version-specific validation
        match version {
            1 => {
                if self.issuance_date.is_none() {
                    return Err(VcError::InvalidCredential(
                        "VCDM 1.1 requires issuanceDate".into(),
                    ));
                }
            }
            2 => {
                // VCDM 2.0: validFrom is optional but recommended
            }
            _ => unreachable!(),
        }

        Ok(())
    }

    /// Check if the credential is currently valid based on temporal fields.
    ///
    /// Returns `Ok(())` if the credential is within its validity period,
    /// or an error if expired or not yet valid.
    pub fn check_validity(&self, now: &DateTime<Utc>) -> Result<()> {
        // Check expiration (VCDM 1.1: expirationDate, VCDM 2.0: validUntil)
        let expiry = self
            .valid_until
            .as_deref()
            .or(self.expiration_date.as_deref());
        if let Some(exp_str) = expiry {
            let exp = DateTime::parse_from_rfc3339(exp_str)
                .map_err(|e| VcError::InvalidDate(format!("expiry: {e}")))?;
            if now > &exp {
                return Err(VcError::Expired);
            }
        }

        // Check not-before (VCDM 1.1: issuanceDate, VCDM 2.0: validFrom)
        let not_before = self.valid_from.as_deref().or(self.issuance_date.as_deref());
        if let Some(nb_str) = not_before {
            let nb = DateTime::parse_from_rfc3339(nb_str)
                .map_err(|e| VcError::InvalidDate(format!("not-before: {e}")))?;
            if now < &nb {
                return Err(VcError::NotYetValid);
            }
        }

        Ok(())
    }
}

/// Builder for constructing `VerifiableCredential` instances.
pub struct CredentialBuilder {
    context: Vec<Value>,
    id: Option<String>,
    types: Vec<String>,
    issuer: Option<IssuerValue>,
    subjects: Vec<serde_json::Map<String, Value>>,
    issuance_date: Option<String>,
    expiration_date: Option<String>,
    valid_from: Option<String>,
    valid_until: Option<String>,
    credential_status: Option<CredentialStatus>,
    credential_schema: Option<Value>,
    evidence: Option<Value>,
    terms_of_use: Option<Value>,
    additional: serde_json::Map<String, Value>,
}

impl CredentialBuilder {
    /// Create a VCDM 1.1 credential builder.
    pub fn v1() -> Self {
        Self {
            context: vec![Value::String(CREDENTIALS_V1_CONTEXT.to_string())],
            id: None,
            types: vec!["VerifiableCredential".to_string()],
            issuer: None,
            subjects: Vec::new(),
            issuance_date: None,
            expiration_date: None,
            valid_from: None,
            valid_until: None,
            credential_status: None,
            credential_schema: None,
            evidence: None,
            terms_of_use: None,
            additional: serde_json::Map::new(),
        }
    }

    /// Create a VCDM 2.0 credential builder.
    pub fn v2() -> Self {
        Self {
            context: vec![Value::String(CREDENTIALS_V2_CONTEXT.to_string())],
            ..Self::v1()
        }
    }

    /// Add an additional JSON-LD context.
    pub fn context(mut self, ctx: impl Into<String>) -> Self {
        self.context.push(Value::String(ctx.into()));
        self
    }

    /// Set the credential ID.
    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    /// Add a credential type (in addition to "VerifiableCredential").
    pub fn add_type(mut self, credential_type: impl Into<String>) -> Self {
        self.types.push(credential_type.into());
        self
    }

    /// Set the issuer by URI.
    pub fn issuer_uri(mut self, uri: impl Into<String>) -> Self {
        self.issuer = Some(IssuerValue::Uri(uri.into()));
        self
    }

    /// Set the issuer with properties.
    pub fn issuer(mut self, issuer: IssuerValue) -> Self {
        self.issuer = Some(issuer);
        self
    }

    /// Add a credential subject.
    pub fn subject(mut self, subject: serde_json::Map<String, Value>) -> Self {
        self.subjects.push(subject);
        self
    }

    /// Set the issuance date (VCDM 1.1).
    pub fn issuance_date(mut self, date: impl Into<String>) -> Self {
        self.issuance_date = Some(date.into());
        self
    }

    /// Set the expiration date (VCDM 1.1).
    pub fn expiration_date(mut self, date: impl Into<String>) -> Self {
        self.expiration_date = Some(date.into());
        self
    }

    /// Set the valid-from date (VCDM 2.0).
    pub fn valid_from(mut self, date: impl Into<String>) -> Self {
        self.valid_from = Some(date.into());
        self
    }

    /// Set the valid-until date (VCDM 2.0).
    pub fn valid_until(mut self, date: impl Into<String>) -> Self {
        self.valid_until = Some(date.into());
        self
    }

    /// Set credential status.
    pub fn credential_status(mut self, status: CredentialStatus) -> Self {
        self.credential_status = Some(status);
        self
    }

    /// Add an additional property.
    pub fn property(mut self, key: impl Into<String>, value: Value) -> Self {
        self.additional.insert(key.into(), value);
        self
    }

    /// Build the credential, validating required fields.
    pub fn build(self) -> Result<VerifiableCredential> {
        let issuer = self
            .issuer
            .ok_or_else(|| VcError::InvalidCredential("issuer is required".into()))?;

        if self.subjects.is_empty() {
            return Err(VcError::InvalidCredential(
                "at least one credentialSubject is required".into(),
            ));
        }

        let credential_subject = if self.subjects.len() == 1 {
            SubjectValue::Single(self.subjects.into_iter().next().unwrap())
        } else {
            SubjectValue::Multiple(self.subjects)
        };

        let vc = VerifiableCredential {
            context: ContextValue::Array(self.context),
            id: self.id,
            types: self.types,
            issuer,
            credential_subject,
            issuance_date: self.issuance_date,
            expiration_date: self.expiration_date,
            valid_from: self.valid_from,
            valid_until: self.valid_until,
            credential_status: self.credential_status,
            credential_schema: self.credential_schema,
            evidence: self.evidence,
            terms_of_use: self.terms_of_use,
            proof: None,
            additional: self.additional,
        };

        vc.validate()?;
        Ok(vc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_subject() -> serde_json::Map<String, Value> {
        let mut m = serde_json::Map::new();
        m.insert("id".to_string(), json!("did:example:subject"));
        m.insert("name".to_string(), json!("Alice"));
        m
    }

    #[test]
    fn build_v1_credential() {
        let vc = CredentialBuilder::v1()
            .id("urn:uuid:12345")
            .add_type("ExampleCredential")
            .issuer_uri("did:example:issuer")
            .subject(sample_subject())
            .issuance_date("2024-01-01T00:00:00Z")
            .build()
            .unwrap();

        assert_eq!(vc.version(), Some(1));
        assert_eq!(vc.issuer.id(), "did:example:issuer");
        assert!(vc.types.contains(&"VerifiableCredential".to_string()));
        assert!(vc.types.contains(&"ExampleCredential".to_string()));
    }

    #[test]
    fn build_v2_credential() {
        let vc = CredentialBuilder::v2()
            .add_type("ExampleCredential")
            .issuer_uri("did:example:issuer")
            .subject(sample_subject())
            .valid_from("2024-01-01T00:00:00Z")
            .valid_until("2025-01-01T00:00:00Z")
            .build()
            .unwrap();

        assert_eq!(vc.version(), Some(2));
    }

    #[test]
    fn v1_requires_issuance_date() {
        let result = CredentialBuilder::v1()
            .issuer_uri("did:example:issuer")
            .subject(sample_subject())
            .build();

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("issuanceDate"));
    }

    #[test]
    fn requires_issuer() {
        let result = CredentialBuilder::v1()
            .subject(sample_subject())
            .issuance_date("2024-01-01T00:00:00Z")
            .build();

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("issuer"));
    }

    #[test]
    fn requires_subject() {
        let result = CredentialBuilder::v1()
            .issuer_uri("did:example:issuer")
            .issuance_date("2024-01-01T00:00:00Z")
            .build();

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("credentialSubject")
        );
    }

    #[test]
    fn serialize_v1_roundtrip() {
        let vc = CredentialBuilder::v1()
            .id("urn:uuid:12345")
            .add_type("ExampleCredential")
            .issuer_uri("did:example:issuer")
            .subject(sample_subject())
            .issuance_date("2024-01-01T00:00:00Z")
            .build()
            .unwrap();

        let json = serde_json::to_string(&vc).unwrap();
        let parsed: VerifiableCredential = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, vc.id);
        assert_eq!(parsed.issuer.id(), vc.issuer.id());
    }

    #[test]
    fn serialize_v2_roundtrip() {
        let vc = CredentialBuilder::v2()
            .add_type("ExampleCredential")
            .issuer_uri("did:example:issuer")
            .subject(sample_subject())
            .valid_from("2024-01-01T00:00:00Z")
            .valid_until("2025-01-01T00:00:00Z")
            .build()
            .unwrap();

        let json = serde_json::to_string(&vc).unwrap();
        let parsed: VerifiableCredential = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.valid_from, vc.valid_from);
        assert_eq!(parsed.valid_until, vc.valid_until);
    }

    #[test]
    fn check_validity_current() {
        let vc = CredentialBuilder::v2()
            .issuer_uri("did:example:issuer")
            .subject(sample_subject())
            .valid_from("2020-01-01T00:00:00Z")
            .valid_until("2030-01-01T00:00:00Z")
            .build()
            .unwrap();

        assert!(vc.check_validity(&Utc::now()).is_ok());
    }

    #[test]
    fn check_validity_expired() {
        let vc = CredentialBuilder::v2()
            .issuer_uri("did:example:issuer")
            .subject(sample_subject())
            .valid_from("2020-01-01T00:00:00Z")
            .valid_until("2021-01-01T00:00:00Z")
            .build()
            .unwrap();

        assert!(matches!(
            vc.check_validity(&Utc::now()),
            Err(VcError::Expired)
        ));
    }

    #[test]
    fn check_validity_not_yet_valid() {
        let vc = CredentialBuilder::v2()
            .issuer_uri("did:example:issuer")
            .subject(sample_subject())
            .valid_from("2099-01-01T00:00:00Z")
            .build()
            .unwrap();

        assert!(matches!(
            vc.check_validity(&Utc::now()),
            Err(VcError::NotYetValid)
        ));
    }

    #[test]
    fn deserialize_v1_from_json() {
        let json = json!({
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiableCredential", "ExampleCredential"],
            "issuer": "did:example:issuer",
            "issuanceDate": "2024-01-01T00:00:00Z",
            "credentialSubject": {
                "id": "did:example:subject",
                "name": "Alice"
            }
        });

        let vc: VerifiableCredential = serde_json::from_value(json).unwrap();
        assert_eq!(vc.version(), Some(1));
        assert_eq!(vc.issuer.id(), "did:example:issuer");
    }

    #[test]
    fn deserialize_v2_from_json() {
        let json = json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential", "ExampleCredential"],
            "issuer": {"id": "did:example:issuer", "name": "Example Corp"},
            "validFrom": "2024-01-01T00:00:00Z",
            "credentialSubject": {
                "id": "did:example:subject",
                "degree": {
                    "type": "BachelorDegree",
                    "name": "Computer Science"
                }
            }
        });

        let vc: VerifiableCredential = serde_json::from_value(json).unwrap();
        assert_eq!(vc.version(), Some(2));
        match &vc.issuer {
            IssuerValue::Object { id, properties } => {
                assert_eq!(id, "did:example:issuer");
                assert_eq!(properties["name"], "Example Corp");
            }
            _ => panic!("expected object issuer"),
        }
    }

    #[test]
    fn credential_with_status() {
        let status = CredentialStatus {
            id: Some("https://example.com/status/1#42".into()),
            status_type: "BitstringStatusListEntry".into(),
            status_purpose: Some("revocation".into()),
            status_list_index: Some("42".into()),
            status_list_credential: Some("https://example.com/status/1".into()),
            additional: serde_json::Map::new(),
        };

        let vc = CredentialBuilder::v2()
            .issuer_uri("did:example:issuer")
            .subject(sample_subject())
            .credential_status(status)
            .build()
            .unwrap();

        assert!(vc.credential_status.is_some());
        let s = vc.credential_status.unwrap();
        assert_eq!(s.status_type, "BitstringStatusListEntry");
        assert_eq!(s.status_purpose.as_deref(), Some("revocation"));
    }

    #[test]
    fn issuer_id_works_for_both_formats() {
        let uri_issuer = IssuerValue::Uri("did:example:1".into());
        assert_eq!(uri_issuer.id(), "did:example:1");

        let obj_issuer = IssuerValue::Object {
            id: "did:example:2".into(),
            properties: serde_json::Map::new(),
        };
        assert_eq!(obj_issuer.id(), "did:example:2");
    }
}
