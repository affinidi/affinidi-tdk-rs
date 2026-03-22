/*!
 * IssuerSigned structure — the issuer-provided portion of an mdoc.
 *
 * Contains:
 * - `nameSpaces`: Map of namespace → vec of IssuerSignedItems
 * - `issuerAuth`: COSE_Sign1 signature over the MSO
 */

use std::collections::BTreeMap;

use crate::error::Result;
use crate::mso::{DataElement, MobileSecurityObject, ValidityInfo};

/// An mdoc credential as created by the issuer.
#[derive(Debug, Clone)]
pub struct IssuerSigned {
    /// The Mobile Security Object containing digests.
    pub mso: MobileSecurityObject,
    /// Data elements organized by namespace.
    pub namespaces: BTreeMap<String, Vec<DataElement>>,
    /// Document type (e.g., "eu.europa.ec.eudi.pid.1").
    pub doc_type: String,
}

impl IssuerSigned {
    /// Create an IssuerSigned structure from data elements.
    pub fn create(
        doc_type: impl Into<String>,
        mut namespaces: BTreeMap<String, Vec<DataElement>>,
        validity: ValidityInfo,
    ) -> Result<Self> {
        let doc_type = doc_type.into();
        let mso = MobileSecurityObject::create(&doc_type, &mut namespaces, validity)?;

        Ok(IssuerSigned {
            mso,
            namespaces,
            doc_type,
        })
    }

    /// Get all attribute names in a given namespace.
    pub fn attribute_names(&self, namespace: &str) -> Vec<&str> {
        self.namespaces
            .get(namespace)
            .map(|elements| elements.iter().map(|e| e.identifier.as_str()).collect())
            .unwrap_or_default()
    }

    /// Get a specific data element by namespace and identifier.
    pub fn get_element(&self, namespace: &str, identifier: &str) -> Option<&DataElement> {
        self.namespaces
            .get(namespace)
            .and_then(|elements| elements.iter().find(|e| e.identifier == identifier))
    }

    /// Verify all digests in the MSO match the data elements.
    pub fn verify_digests(&self) -> Result<bool> {
        for (ns, elements) in &self.namespaces {
            for element in elements {
                if !self.mso.verify_digest(ns, element)? {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }
}

/// A device response for presenting selected attributes to a verifier.
///
/// The holder selects which namespaces and attributes to reveal.
#[derive(Debug, Clone)]
pub struct DeviceResponse {
    /// The document type.
    pub doc_type: String,
    /// Selected data elements by namespace (subset of issuer-signed elements).
    pub disclosed: BTreeMap<String, Vec<DataElement>>,
    /// The original MSO (needed for digest verification).
    pub mso: MobileSecurityObject,
}

impl DeviceResponse {
    /// Create a device response by selecting attributes to disclose.
    ///
    /// # Arguments
    ///
    /// * `issuer_signed` — The full issuer-signed credential
    /// * `requested` — Map of namespace → list of attribute identifiers to disclose
    pub fn create(
        issuer_signed: &IssuerSigned,
        requested: &BTreeMap<String, Vec<String>>,
    ) -> Result<Self> {
        let mut disclosed = BTreeMap::new();

        for (ns, attr_names) in requested {
            if let Some(elements) = issuer_signed.namespaces.get(ns) {
                let selected: Vec<DataElement> = elements
                    .iter()
                    .filter(|e| attr_names.contains(&e.identifier))
                    .cloned()
                    .collect();

                if !selected.is_empty() {
                    disclosed.insert(ns.clone(), selected);
                }
            }
        }

        Ok(DeviceResponse {
            doc_type: issuer_signed.doc_type.clone(),
            disclosed,
            mso: issuer_signed.mso.clone(),
        })
    }

    /// Verify that all disclosed elements have valid digests.
    pub fn verify_digests(&self) -> Result<bool> {
        for (ns, elements) in &self.disclosed {
            for element in elements {
                if !self.mso.verify_digest(ns, element)? {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mso::DataElement;
    use serde_json::json;

    fn sample_validity() -> ValidityInfo {
        ValidityInfo {
            signed: "2024-01-01T00:00:00Z".to_string(),
            valid_from: "2024-01-01T00:00:00Z".to_string(),
            valid_until: "2025-01-01T00:00:00Z".to_string(),
        }
    }

    fn sample_namespaces() -> BTreeMap<String, Vec<DataElement>> {
        let mut ns = BTreeMap::new();
        ns.insert(
            "eu.europa.ec.eudi.pid.1".to_string(),
            vec![
                DataElement::new("family_name", json!("Doe")),
                DataElement::new("given_name", json!("John")),
                DataElement::new("birth_date", json!("1990-01-01")),
                DataElement::new("age_over_18", json!(true)),
                DataElement::new("nationality", json!("DE")),
            ],
        );
        ns
    }

    #[test]
    fn create_issuer_signed() {
        let issuer_signed = IssuerSigned::create(
            "eu.europa.ec.eudi.pid.1",
            sample_namespaces(),
            sample_validity(),
        )
        .unwrap();

        assert_eq!(issuer_signed.doc_type, "eu.europa.ec.eudi.pid.1");

        let names = issuer_signed.attribute_names("eu.europa.ec.eudi.pid.1");
        assert_eq!(names.len(), 5);
        assert!(names.contains(&"family_name"));
        assert!(names.contains(&"given_name"));
    }

    #[test]
    fn get_element() {
        let issuer_signed = IssuerSigned::create(
            "eu.europa.ec.eudi.pid.1",
            sample_namespaces(),
            sample_validity(),
        )
        .unwrap();

        let element = issuer_signed
            .get_element("eu.europa.ec.eudi.pid.1", "family_name")
            .unwrap();
        assert_eq!(element.value, json!("Doe"));

        assert!(
            issuer_signed
                .get_element("eu.europa.ec.eudi.pid.1", "nonexistent")
                .is_none()
        );
    }

    #[test]
    fn verify_all_digests() {
        let issuer_signed = IssuerSigned::create(
            "eu.europa.ec.eudi.pid.1",
            sample_namespaces(),
            sample_validity(),
        )
        .unwrap();

        assert!(issuer_signed.verify_digests().unwrap());
    }

    #[test]
    fn selective_disclosure_via_device_response() {
        let issuer_signed = IssuerSigned::create(
            "eu.europa.ec.eudi.pid.1",
            sample_namespaces(),
            sample_validity(),
        )
        .unwrap();

        // Verifier only requests age_over_18 and nationality
        let mut requested = BTreeMap::new();
        requested.insert(
            "eu.europa.ec.eudi.pid.1".to_string(),
            vec!["age_over_18".to_string(), "nationality".to_string()],
        );

        let response = DeviceResponse::create(&issuer_signed, &requested).unwrap();

        // Only 2 attributes disclosed
        let disclosed = &response.disclosed["eu.europa.ec.eudi.pid.1"];
        assert_eq!(disclosed.len(), 2);

        let names: Vec<&str> = disclosed.iter().map(|e| e.identifier.as_str()).collect();
        assert!(names.contains(&"age_over_18"));
        assert!(names.contains(&"nationality"));
        assert!(!names.contains(&"family_name"));

        // Digests still verify
        assert!(response.verify_digests().unwrap());
    }

    #[test]
    fn device_response_empty_request() {
        let issuer_signed = IssuerSigned::create(
            "eu.europa.ec.eudi.pid.1",
            sample_namespaces(),
            sample_validity(),
        )
        .unwrap();

        let requested = BTreeMap::new();
        let response = DeviceResponse::create(&issuer_signed, &requested).unwrap();

        assert!(response.disclosed.is_empty());
    }

    #[test]
    fn device_response_unknown_namespace() {
        let issuer_signed = IssuerSigned::create(
            "eu.europa.ec.eudi.pid.1",
            sample_namespaces(),
            sample_validity(),
        )
        .unwrap();

        let mut requested = BTreeMap::new();
        requested.insert(
            "unknown.namespace".to_string(),
            vec!["some_attr".to_string()],
        );

        let response = DeviceResponse::create(&issuer_signed, &requested).unwrap();
        assert!(response.disclosed.is_empty());
    }
}
