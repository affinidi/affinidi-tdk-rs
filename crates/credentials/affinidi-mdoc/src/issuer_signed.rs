/*!
 * IssuerSigned and Document structures per ISO 18013-5.
 *
 * ```text
 * IssuerSigned = {
 *   "nameSpaces": IssuerNameSpaces,    ; Map<namespace, [Tag24<IssuerSignedItem>]>
 *   "issuerAuth": COSE_Sign1           ; COSE_Sign1(Tag24<MSO>)
 * }
 *
 * Document = {
 *   "docType": tstr,
 *   "issuerSigned": IssuerSigned,
 *   ? "deviceSigned": DeviceSigned,
 *   ? "errors": Errors
 * }
 * ```
 */

use std::collections::BTreeMap;

use coset::CoseSign1;

use crate::cose::{CoseSigner, CoseVerifier, sign_mso, verify_issuer_auth};
use crate::error::Result;
use crate::issuer_signed_item::{IssuerSignedItem, json_to_cbor};
use crate::mso::{MobileSecurityObject, ValidityInfo};
use crate::tag24::Tag24;

/// An mdoc credential as created by the issuer.
///
/// Contains the issuer's signed data (namespaces with Tag24-wrapped items)
/// and the COSE_Sign1 signature over the MSO.
#[derive(Debug, Clone)]
pub struct IssuerSigned {
    /// The Mobile Security Object containing digests.
    pub mso: MobileSecurityObject,
    /// Tag24-wrapped IssuerSignedItems organized by namespace.
    pub namespaces: BTreeMap<String, Vec<Tag24<IssuerSignedItem>>>,
    /// The COSE_Sign1 signature over the MSO (issuerAuth).
    pub issuer_auth: CoseSign1,
    /// Document type.
    pub doc_type: String,
}

/// Builder for constructing an IssuerSigned mdoc.
pub struct MdocBuilder {
    doc_type: String,
    digest_algorithm: String,
    namespaces: BTreeMap<String, Vec<IssuerSignedItem>>,
    device_key: ciborium::Value,
    validity: ValidityInfo,
    decoys_per_namespace: usize,
}

impl MdocBuilder {
    /// Create a new builder for the given document type.
    pub fn new(doc_type: impl Into<String>) -> Self {
        Self {
            doc_type: doc_type.into(),
            digest_algorithm: "SHA-256".to_string(),
            namespaces: BTreeMap::new(),
            device_key: ciborium::Value::Map(vec![]),
            validity: ValidityInfo {
                signed: "2024-01-01T00:00:00Z".to_string(),
                valid_from: "2024-01-01T00:00:00Z".to_string(),
                valid_until: "2025-01-01T00:00:00Z".to_string(),
            },
            decoys_per_namespace: 0,
        }
    }

    /// Set the digest algorithm (default: "SHA-256").
    pub fn digest_algorithm(mut self, alg: impl Into<String>) -> Self {
        self.digest_algorithm = alg.into();
        self
    }

    /// Set the device (holder) public key as a COSE_Key.
    pub fn device_key(mut self, key: ciborium::Value) -> Self {
        self.device_key = key;
        self
    }

    /// Set the validity information.
    pub fn validity(mut self, validity: ValidityInfo) -> Self {
        self.validity = validity;
        self
    }

    /// Set the number of decoy digests per namespace.
    pub fn decoys(mut self, count: usize) -> Self {
        self.decoys_per_namespace = count;
        self
    }

    /// Add an attribute to a namespace using a CBOR value.
    pub fn add_attribute(
        mut self,
        namespace: &str,
        identifier: &str,
        value: ciborium::Value,
    ) -> Self {
        let items = self.namespaces.entry(namespace.to_string()).or_default();
        let digest_id = items.len() as u32;
        items.push(IssuerSignedItem::new(digest_id, identifier, value));
        self
    }

    /// Add an attribute to a namespace using a JSON value (auto-converted to CBOR).
    pub fn add_json_attribute(
        self,
        namespace: &str,
        identifier: &str,
        value: &serde_json::Value,
    ) -> Self {
        self.add_attribute(namespace, identifier, json_to_cbor(value))
    }

    /// Build and sign the mdoc, producing an IssuerSigned.
    pub fn build(self, signer: &dyn CoseSigner) -> Result<IssuerSigned> {
        let mso = MobileSecurityObject::create(
            &self.doc_type,
            &self.digest_algorithm,
            &self.namespaces,
            self.device_key,
            self.validity,
            self.decoys_per_namespace,
        )?;

        let issuer_auth = sign_mso(&mso, signer)?;

        // Wrap items in Tag24
        let mut tagged_namespaces = BTreeMap::new();
        for (ns, items) in &self.namespaces {
            let tagged_items: Vec<Tag24<IssuerSignedItem>> = items
                .iter()
                .map(|item| item.to_tagged())
                .collect::<Result<_>>()?;
            tagged_namespaces.insert(ns.clone(), tagged_items);
        }

        Ok(IssuerSigned {
            mso,
            namespaces: tagged_namespaces,
            issuer_auth,
            doc_type: self.doc_type,
        })
    }
}

impl IssuerSigned {
    /// Get all attribute identifiers in a namespace.
    pub fn attribute_names(&self, namespace: &str) -> Vec<&str> {
        self.namespaces
            .get(namespace)
            .map(|items| {
                items
                    .iter()
                    .map(|t| t.inner.element_identifier.as_str())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get a specific attribute by namespace and identifier.
    pub fn get_attribute(
        &self,
        namespace: &str,
        identifier: &str,
    ) -> Option<&Tag24<IssuerSignedItem>> {
        self.namespaces.get(namespace).and_then(|items| {
            items
                .iter()
                .find(|t| t.inner.element_identifier == identifier)
        })
    }

    /// Verify all digests in the MSO match the Tag24-wrapped items.
    pub fn verify_digests(&self) -> Result<bool> {
        for (ns, items) in &self.namespaces {
            for tagged_item in items {
                if !self.mso.verify_item_digest(ns, &tagged_item.inner)? {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    /// Verify the issuerAuth COSE_Sign1 signature and return the decoded MSO.
    pub fn verify_issuer_auth(&self, verifier: &dyn CoseVerifier) -> Result<MobileSecurityObject> {
        verify_issuer_auth(&self.issuer_auth, verifier)
    }
}

/// A device response for presenting selected attributes to a verifier.
///
/// The holder selects which namespaces and attributes to reveal.
/// Only the selected Tag24-wrapped IssuerSignedItems are included.
#[derive(Debug, Clone)]
pub struct DeviceResponse {
    /// Protocol version (always "1.0").
    pub version: String,
    /// The document type.
    pub doc_type: String,
    /// Selected Tag24-wrapped items by namespace.
    pub disclosed: BTreeMap<String, Vec<Tag24<IssuerSignedItem>>>,
    /// The original MSO (for digest verification by the verifier).
    pub mso: MobileSecurityObject,
    /// The original issuerAuth (for signature verification by the verifier).
    pub issuer_auth: CoseSign1,
    /// Response status (0 = OK).
    pub status: u32,
}

impl DeviceResponse {
    /// Create a device response by selecting attributes to disclose.
    ///
    /// # Arguments
    ///
    /// * `issuer_signed` — The full issuer-signed credential
    /// * `requested` — Map of namespace to list of attribute identifiers to disclose
    pub fn create(
        issuer_signed: &IssuerSigned,
        requested: &BTreeMap<String, Vec<String>>,
    ) -> Result<Self> {
        let mut disclosed = BTreeMap::new();

        for (ns, attr_names) in requested {
            if let Some(items) = issuer_signed.namespaces.get(ns) {
                let selected: Vec<Tag24<IssuerSignedItem>> = items
                    .iter()
                    .filter(|t| attr_names.contains(&t.inner.element_identifier))
                    .cloned()
                    .collect();

                if !selected.is_empty() {
                    disclosed.insert(ns.clone(), selected);
                }
            }
        }

        Ok(DeviceResponse {
            version: "1.0".to_string(),
            doc_type: issuer_signed.doc_type.clone(),
            disclosed,
            mso: issuer_signed.mso.clone(),
            issuer_auth: issuer_signed.issuer_auth.clone(),
            status: 0,
        })
    }

    /// Verify that all disclosed items have valid digests in the MSO.
    pub fn verify_digests(&self) -> Result<bool> {
        for (ns, items) in &self.disclosed {
            for tagged_item in items {
                if !self.mso.verify_item_digest(ns, &tagged_item.inner)? {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    /// Verify the issuerAuth signature.
    pub fn verify_issuer_auth(&self, verifier: &dyn CoseVerifier) -> Result<MobileSecurityObject> {
        verify_issuer_auth(&self.issuer_auth, verifier)
    }

    /// Get the disclosed attribute names for a namespace.
    pub fn disclosed_names(&self, namespace: &str) -> Vec<&str> {
        self.disclosed
            .get(namespace)
            .map(|items| {
                items
                    .iter()
                    .map(|t| t.inner.element_identifier.as_str())
                    .collect()
            })
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cose::test_utils::{TestSigner, TestVerifier};
    use crate::issuer_signed_item::cbor_to_json;

    fn test_key() -> &'static [u8] {
        b"test-signing-key-for-mdoc-tests!"
    }

    fn pid_namespace() -> &'static str {
        "eu.europa.ec.eudi.pid.1"
    }

    fn build_test_mdoc(signer: &TestSigner) -> IssuerSigned {
        MdocBuilder::new("eu.europa.ec.eudi.pid.1")
            .validity(ValidityInfo {
                signed: "2024-01-01T00:00:00Z".to_string(),
                valid_from: "2024-01-01T00:00:00Z".to_string(),
                valid_until: "2025-01-01T00:00:00Z".to_string(),
            })
            .add_attribute(
                pid_namespace(),
                "family_name",
                ciborium::Value::Text("Doe".into()),
            )
            .add_attribute(
                pid_namespace(),
                "given_name",
                ciborium::Value::Text("John".into()),
            )
            .add_attribute(
                pid_namespace(),
                "birth_date",
                ciborium::Value::Text("1990-01-01".into()),
            )
            .add_attribute(pid_namespace(), "age_over_18", ciborium::Value::Bool(true))
            .add_attribute(
                pid_namespace(),
                "nationality",
                ciborium::Value::Text("DE".into()),
            )
            .build(signer)
            .unwrap()
    }

    #[test]
    fn build_and_verify_mdoc() {
        let signer = TestSigner::new(test_key());
        let verifier = TestVerifier::new(test_key());

        let mdoc = build_test_mdoc(&signer);

        assert_eq!(mdoc.doc_type, "eu.europa.ec.eudi.pid.1");
        assert_eq!(mdoc.attribute_names(pid_namespace()).len(), 5);

        // Verify digests
        assert!(mdoc.verify_digests().unwrap());

        // Verify issuer auth
        let decoded_mso = mdoc.verify_issuer_auth(&verifier).unwrap();
        assert_eq!(decoded_mso.doc_type, "eu.europa.ec.eudi.pid.1");
    }

    #[test]
    fn get_attribute() {
        let signer = TestSigner::new(test_key());
        let mdoc = build_test_mdoc(&signer);

        let attr = mdoc.get_attribute(pid_namespace(), "family_name").unwrap();
        assert_eq!(
            attr.inner.element_value,
            ciborium::Value::Text("Doe".into())
        );

        assert!(mdoc.get_attribute(pid_namespace(), "nonexistent").is_none());
    }

    #[test]
    fn selective_disclosure() {
        let signer = TestSigner::new(test_key());
        let verifier = TestVerifier::new(test_key());

        let mdoc = build_test_mdoc(&signer);

        // Request only age_over_18 and nationality
        let mut requested = BTreeMap::new();
        requested.insert(
            pid_namespace().to_string(),
            vec!["age_over_18".to_string(), "nationality".to_string()],
        );

        let response = DeviceResponse::create(&mdoc, &requested).unwrap();

        // Only 2 attributes disclosed
        let names = response.disclosed_names(pid_namespace());
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"age_over_18"));
        assert!(names.contains(&"nationality"));
        assert!(!names.contains(&"family_name"));

        // Digests still verify
        assert!(response.verify_digests().unwrap());

        // IssuerAuth still verifies
        let decoded = response.verify_issuer_auth(&verifier).unwrap();
        assert_eq!(decoded.doc_type, "eu.europa.ec.eudi.pid.1");
    }

    #[test]
    fn empty_request_returns_empty() {
        let signer = TestSigner::new(test_key());
        let mdoc = build_test_mdoc(&signer);

        let requested = BTreeMap::new();
        let response = DeviceResponse::create(&mdoc, &requested).unwrap();
        assert!(response.disclosed.is_empty());
    }

    #[test]
    fn unknown_namespace_ignored() {
        let signer = TestSigner::new(test_key());
        let mdoc = build_test_mdoc(&signer);

        let mut requested = BTreeMap::new();
        requested.insert("unknown".to_string(), vec!["x".to_string()]);
        let response = DeviceResponse::create(&mdoc, &requested).unwrap();
        assert!(response.disclosed.is_empty());
    }

    #[test]
    fn wrong_key_fails_auth() {
        let signer = TestSigner::new(test_key());
        let wrong_verifier = TestVerifier::new(b"wrong-key-should-fail-verify!!!");

        let mdoc = build_test_mdoc(&signer);
        assert!(mdoc.verify_issuer_auth(&wrong_verifier).is_err());
    }

    #[test]
    fn json_attribute_convenience() {
        let signer = TestSigner::new(test_key());

        let mdoc = MdocBuilder::new("test")
            .add_json_attribute("ns", "name", &serde_json::json!("Alice"))
            .add_json_attribute("ns", "age", &serde_json::json!(30))
            .add_json_attribute("ns", "verified", &serde_json::json!(true))
            .build(&signer)
            .unwrap();

        let attr = mdoc.get_attribute("ns", "name").unwrap();
        let json_val = cbor_to_json(&attr.inner.element_value);
        assert_eq!(json_val, "Alice");
    }

    #[test]
    fn builder_with_decoys() {
        let signer = TestSigner::new(test_key());

        let mdoc = MdocBuilder::new("test")
            .decoys(5)
            .add_attribute("ns", "x", ciborium::Value::Integer(1.into()))
            .build(&signer)
            .unwrap();

        // MSO should have 1 real + 5 decoy digests
        assert_eq!(mdoc.mso.value_digests["ns"].len(), 6);
        // But only 1 actual item in namespaces
        assert_eq!(mdoc.namespaces["ns"].len(), 1);
    }

    #[test]
    fn device_response_version_and_status() {
        let signer = TestSigner::new(test_key());
        let mdoc = build_test_mdoc(&signer);

        let mut requested = BTreeMap::new();
        requested.insert(pid_namespace().to_string(), vec!["given_name".to_string()]);

        let response = DeviceResponse::create(&mdoc, &requested).unwrap();
        assert_eq!(response.version, "1.0");
        assert_eq!(response.status, 0);
    }
}
