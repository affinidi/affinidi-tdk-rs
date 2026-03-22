/*!
 * Mobile Security Object (MSO) — the issuer-signed digest structure.
 *
 * The MSO contains:
 * - `digestAlgorithm`: Hash algorithm used (e.g., "SHA-256")
 * - `valueDigests`: Map of namespace → (digest_id → digest_value)
 * - `deviceKeyInfo`: Holder's device public key
 * - `docType`: Document type identifier
 * - `validityInfo`: Temporal validity (signed, validFrom, validUntil)
 *
 * The MSO is signed by the issuer using COSE_Sign1 and included in
 * `IssuerSigned.issuerAuth`.
 */

use std::collections::BTreeMap;

use rand::Rng;
use sha2::{Digest, Sha256};

use crate::error::{MdocError, Result};

/// A single data element with its random salt and value.
#[derive(Debug, Clone)]
pub struct DataElement {
    /// The attribute identifier (e.g., "family_name").
    pub identifier: String,
    /// The attribute value as a CBOR-compatible JSON value.
    pub value: serde_json::Value,
    /// Random salt for digest computation.
    pub random: Vec<u8>,
    /// The digest ID assigned to this element.
    pub digest_id: u32,
}

/// Digest computation for a data element.
///
/// Per ISO 18013-5, the digest is computed as:
/// `SHA-256(CBOR(DataElementValue))` where DataElementValue includes
/// the random salt, element identifier, and element value.
impl DataElement {
    /// Create a new data element with a random salt.
    pub fn new(identifier: impl Into<String>, value: serde_json::Value) -> Self {
        let mut rng = rand::rng();
        let mut random = vec![0u8; 32];
        rng.fill(&mut random[..]);

        Self {
            identifier: identifier.into(),
            value,
            random,
            digest_id: 0, // Set during MSO creation
        }
    }

    /// Create a data element with a specific salt (for test vectors).
    pub fn with_random(
        identifier: impl Into<String>,
        value: serde_json::Value,
        random: Vec<u8>,
    ) -> Self {
        Self {
            identifier: identifier.into(),
            value,
            random,
            digest_id: 0,
        }
    }

    /// Compute the digest of this data element.
    ///
    /// The input to the hash function is the CBOR encoding of a tagged
    /// structure containing: digestID, random, elementIdentifier, elementValue.
    pub fn compute_digest(&self) -> Vec<u8> {
        // Simplified: hash(random || identifier || CBOR(value))
        // Full ISO 18013-5 uses CBOR Tag 24 wrapping
        let mut hasher = Sha256::new();
        hasher.update(&self.random);
        hasher.update(self.identifier.as_bytes());

        // Encode value as CBOR bytes
        let mut cbor_buf = Vec::new();
        ciborium::into_writer(&self.value, &mut cbor_buf)
            .expect("CBOR encoding should not fail for JSON values");
        hasher.update(&cbor_buf);

        hasher.finalize().to_vec()
    }
}

/// The Mobile Security Object — contains digests of all data elements.
#[derive(Debug, Clone)]
pub struct MobileSecurityObject {
    /// Document type (e.g., "eu.europa.ec.eudi.pid.1").
    pub doc_type: String,

    /// Hash algorithm name (e.g., "SHA-256").
    pub digest_algorithm: String,

    /// Digests organized by namespace.
    /// namespace → (digest_id → digest_bytes)
    pub value_digests: BTreeMap<String, BTreeMap<u32, Vec<u8>>>,

    /// Validity information.
    pub validity: ValidityInfo,
}

/// Temporal validity of an MSO.
#[derive(Debug, Clone)]
pub struct ValidityInfo {
    /// When the MSO was signed (ISO 8601).
    pub signed: String,
    /// Valid from (ISO 8601).
    pub valid_from: String,
    /// Valid until (ISO 8601).
    pub valid_until: String,
}

impl MobileSecurityObject {
    /// Create an MSO from data elements organized by namespace.
    ///
    /// Assigns sequential digest IDs and computes all digests.
    pub fn create(
        doc_type: impl Into<String>,
        namespaces: &mut BTreeMap<String, Vec<DataElement>>,
        validity: ValidityInfo,
    ) -> Result<Self> {
        let mut value_digests = BTreeMap::new();

        for (ns, elements) in namespaces.iter_mut() {
            let mut ns_digests = BTreeMap::new();

            for (i, element) in elements.iter_mut().enumerate() {
                let digest_id = i as u32;
                element.digest_id = digest_id;
                let digest = element.compute_digest();
                ns_digests.insert(digest_id, digest);
            }

            value_digests.insert(ns.clone(), ns_digests);
        }

        Ok(MobileSecurityObject {
            doc_type: doc_type.into(),
            digest_algorithm: "SHA-256".to_string(),
            value_digests,
            validity,
        })
    }

    /// Verify a data element's digest against the stored digest.
    pub fn verify_digest(&self, namespace: &str, element: &DataElement) -> Result<bool> {
        let ns_digests = self.value_digests.get(namespace).ok_or_else(|| {
            MdocError::InvalidNamespace(format!("namespace not found: {namespace}"))
        })?;

        let stored = ns_digests.get(&element.digest_id).ok_or_else(|| {
            MdocError::DigestMismatch(format!("digest_id {} not found", element.digest_id))
        })?;

        let computed = element.compute_digest();
        Ok(computed == *stored)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn test_validity() -> ValidityInfo {
        ValidityInfo {
            signed: "2024-01-01T00:00:00Z".to_string(),
            valid_from: "2024-01-01T00:00:00Z".to_string(),
            valid_until: "2025-01-01T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn data_element_digest_deterministic() {
        let random = vec![1u8; 32];
        let e1 = DataElement::with_random("name", json!("Alice"), random.clone());
        let e2 = DataElement::with_random("name", json!("Alice"), random);

        assert_eq!(e1.compute_digest(), e2.compute_digest());
    }

    #[test]
    fn data_element_different_random_different_digest() {
        let e1 = DataElement::with_random("name", json!("Alice"), vec![1u8; 32]);
        let e2 = DataElement::with_random("name", json!("Alice"), vec![2u8; 32]);

        assert_ne!(e1.compute_digest(), e2.compute_digest());
    }

    #[test]
    fn data_element_different_value_different_digest() {
        let random = vec![1u8; 32];
        let e1 = DataElement::with_random("name", json!("Alice"), random.clone());
        let e2 = DataElement::with_random("name", json!("Bob"), random);

        assert_ne!(e1.compute_digest(), e2.compute_digest());
    }

    #[test]
    fn create_mso_and_verify() {
        let mut namespaces = BTreeMap::new();
        namespaces.insert(
            "eu.europa.ec.eudi.pid.1".to_string(),
            vec![
                DataElement::new("family_name", json!("Doe")),
                DataElement::new("given_name", json!("John")),
                DataElement::new("birth_date", json!("1990-01-01")),
            ],
        );

        let mso = MobileSecurityObject::create(
            "eu.europa.ec.eudi.pid.1",
            &mut namespaces,
            test_validity(),
        )
        .unwrap();

        assert_eq!(mso.doc_type, "eu.europa.ec.eudi.pid.1");
        assert_eq!(mso.digest_algorithm, "SHA-256");

        let ns_digests = &mso.value_digests["eu.europa.ec.eudi.pid.1"];
        assert_eq!(ns_digests.len(), 3);

        // Verify each element's digest
        for element in &namespaces["eu.europa.ec.eudi.pid.1"] {
            assert!(
                mso.verify_digest("eu.europa.ec.eudi.pid.1", element)
                    .unwrap()
            );
        }
    }

    #[test]
    fn verify_digest_tampered_value_fails() {
        let mut namespaces = BTreeMap::new();
        let mut elements = vec![DataElement::new("name", json!("Alice"))];
        namespaces.insert("test".to_string(), elements.clone());

        let mso = MobileSecurityObject::create("test", &mut namespaces, test_validity()).unwrap();

        // Tamper with the value
        elements[0].value = json!("Bob");
        elements[0].digest_id = 0;

        assert!(!mso.verify_digest("test", &elements[0]).unwrap());
    }

    #[test]
    fn verify_unknown_namespace_fails() {
        let mut namespaces = BTreeMap::new();
        namespaces.insert("test".to_string(), vec![DataElement::new("x", json!(1))]);

        let mso = MobileSecurityObject::create("test", &mut namespaces, test_validity()).unwrap();

        let element = DataElement::new("x", json!(1));
        assert!(mso.verify_digest("unknown", &element).is_err());
    }

    #[test]
    fn mso_has_sequential_digest_ids() {
        let mut namespaces = BTreeMap::new();
        namespaces.insert(
            "ns".to_string(),
            vec![
                DataElement::new("a", json!(1)),
                DataElement::new("b", json!(2)),
                DataElement::new("c", json!(3)),
            ],
        );

        let mso = MobileSecurityObject::create("test", &mut namespaces, test_validity()).unwrap();

        let ids: Vec<u32> = mso.value_digests["ns"].keys().copied().collect();
        assert_eq!(ids, vec![0, 1, 2]);
    }

    #[test]
    fn digest_is_32_bytes_sha256() {
        let e = DataElement::new("test", json!("value"));
        assert_eq!(e.compute_digest().len(), 32);
    }
}
