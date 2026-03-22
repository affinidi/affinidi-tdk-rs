/*!
 * Mobile Security Object (MSO) — the issuer-signed digest structure.
 *
 * Per ISO 18013-5 §9.1.2.4, the MSO contains:
 *
 * ```text
 * MobileSecurityObject = {
 *   "version": tstr,                    ; "1.0"
 *   "digestAlgorithm": tstr,            ; "SHA-256" | "SHA-384" | "SHA-512"
 *   "valueDigests": ValueDigests,       ; namespace → (digestID → digest)
 *   "deviceKeyInfo": DeviceKeyInfo,     ; holder's device public key
 *   "docType": tstr,                    ; e.g. "org.iso.18013.5.1.mDL"
 *   "validityInfo": ValidityInfo        ; temporal validity
 * }
 * ```
 *
 * The MSO is CBOR-encoded, wrapped in Tag24, and signed with COSE_Sign1
 * to produce `issuerAuth`.
 */

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::{MdocError, Result};
use crate::issuer_signed_item::{IssuerSignedItem, generate_decoy_digest};
use crate::tag24::Tag24;

/// The Mobile Security Object per ISO 18013-5.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MobileSecurityObject {
    /// Version string (always "1.0").
    pub version: String,

    /// Hash algorithm name: "SHA-256", "SHA-384", or "SHA-512".
    #[serde(rename = "digestAlgorithm")]
    pub digest_algorithm: String,

    /// Digests organized by namespace.
    /// `Map<namespace, Map<digestID, digest_bytes>>`
    #[serde(rename = "valueDigests")]
    pub value_digests: BTreeMap<String, BTreeMap<u32, serde_bytes::ByteBuf>>,

    /// Holder's device public key information.
    #[serde(rename = "deviceKeyInfo")]
    pub device_key_info: DeviceKeyInfo,

    /// Document type (e.g., "org.iso.18013.5.1.mDL", "eu.europa.ec.eudi.pid.1").
    #[serde(rename = "docType")]
    pub doc_type: String,

    /// Temporal validity information.
    #[serde(rename = "validityInfo")]
    pub validity_info: ValidityInfo,
}

/// Device key information embedded in the MSO.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceKeyInfo {
    /// The device's public key (COSE_Key).
    #[serde(rename = "deviceKey")]
    pub device_key: ciborium::Value,
}

/// Temporal validity of an MSO per ISO 18013-5.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidityInfo {
    /// When the MSO was signed (CBOR Tag 0, RFC 3339 tstr).
    pub signed: String,

    /// Valid from date (CBOR Tag 0, RFC 3339 tstr).
    #[serde(rename = "validFrom")]
    pub valid_from: String,

    /// Valid until date (CBOR Tag 0, RFC 3339 tstr).
    #[serde(rename = "validUntil")]
    pub valid_until: String,
}

impl MobileSecurityObject {
    /// Create an MSO from IssuerSignedItems organized by namespace.
    ///
    /// Computes the digest of each Tag24-wrapped IssuerSignedItem and stores
    /// them in `valueDigests`. Optionally adds decoy digests per namespace.
    pub fn create(
        doc_type: impl Into<String>,
        digest_algorithm: &str,
        namespaces: &BTreeMap<String, Vec<IssuerSignedItem>>,
        device_key: ciborium::Value,
        validity: ValidityInfo,
        decoys_per_namespace: usize,
    ) -> Result<Self> {
        let mut value_digests = BTreeMap::new();

        for (ns, items) in namespaces {
            let mut ns_digests = BTreeMap::new();

            for item in items {
                let digest = item.compute_digest(digest_algorithm)?;
                ns_digests.insert(item.digest_id, serde_bytes::ByteBuf::from(digest));
            }

            // Add decoy digests
            let max_id = items.iter().map(|i| i.digest_id).max().unwrap_or(0);
            for i in 0..decoys_per_namespace {
                let decoy_id = max_id + 1 + i as u32;
                let decoy = generate_decoy_digest(digest_algorithm)?;
                ns_digests.insert(decoy_id, serde_bytes::ByteBuf::from(decoy));
            }

            value_digests.insert(ns.clone(), ns_digests);
        }

        Ok(MobileSecurityObject {
            version: "1.0".to_string(),
            digest_algorithm: digest_algorithm.to_string(),
            value_digests,
            device_key_info: DeviceKeyInfo { device_key },
            doc_type: doc_type.into(),
            validity_info: validity,
        })
    }

    /// Wrap the MSO in Tag24 for inclusion in COSE_Sign1 payload.
    pub fn to_tagged(&self) -> Result<Tag24<MobileSecurityObject>> {
        Tag24::new(self.clone())
    }

    /// Verify a single IssuerSignedItem's digest against the stored digest.
    pub fn verify_item_digest(&self, namespace: &str, item: &IssuerSignedItem) -> Result<bool> {
        let ns_digests = self.value_digests.get(namespace).ok_or_else(|| {
            MdocError::InvalidNamespace(format!("namespace not found: {namespace}"))
        })?;

        let stored = ns_digests.get(&item.digest_id).ok_or_else(|| {
            MdocError::DigestMismatch(format!("digest_id {} not found", item.digest_id))
        })?;

        let computed = item.compute_digest(&self.digest_algorithm)?;
        Ok(computed == stored.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_validity() -> ValidityInfo {
        ValidityInfo {
            signed: "2024-01-01T00:00:00Z".to_string(),
            valid_from: "2024-01-01T00:00:00Z".to_string(),
            valid_until: "2025-01-01T00:00:00Z".to_string(),
        }
    }

    fn test_device_key() -> ciborium::Value {
        // Minimal COSE_Key placeholder
        ciborium::Value::Map(vec![
            (
                ciborium::Value::Integer(1.into()), // kty
                ciborium::Value::Integer(2.into()), // EC2
            ),
            (
                ciborium::Value::Integer((-1).into()), // crv
                ciborium::Value::Integer(1.into()),    // P-256
            ),
        ])
    }

    #[test]
    fn create_mso_and_verify() {
        let mut namespaces = BTreeMap::new();
        namespaces.insert(
            "eu.europa.ec.eudi.pid.1".to_string(),
            vec![
                IssuerSignedItem::new(0, "family_name", ciborium::Value::Text("Doe".into())),
                IssuerSignedItem::new(1, "given_name", ciborium::Value::Text("John".into())),
                IssuerSignedItem::new(2, "birth_date", ciborium::Value::Text("1990-01-01".into())),
            ],
        );

        let mso = MobileSecurityObject::create(
            "eu.europa.ec.eudi.pid.1",
            "SHA-256",
            &namespaces,
            test_device_key(),
            test_validity(),
            0,
        )
        .unwrap();

        assert_eq!(mso.version, "1.0");
        assert_eq!(mso.digest_algorithm, "SHA-256");
        assert_eq!(mso.doc_type, "eu.europa.ec.eudi.pid.1");

        let ns_digests = &mso.value_digests["eu.europa.ec.eudi.pid.1"];
        assert_eq!(ns_digests.len(), 3);

        // Verify each item
        for item in &namespaces["eu.europa.ec.eudi.pid.1"] {
            assert!(
                mso.verify_item_digest("eu.europa.ec.eudi.pid.1", item)
                    .unwrap()
            );
        }
    }

    #[test]
    fn tampered_value_fails_verification() {
        let item = IssuerSignedItem::new(0, "name", ciborium::Value::Text("Alice".into()));

        let mut namespaces = BTreeMap::new();
        namespaces.insert("test".to_string(), vec![item]);

        let mso = MobileSecurityObject::create(
            "test",
            "SHA-256",
            &namespaces,
            test_device_key(),
            test_validity(),
            0,
        )
        .unwrap();

        // Tamper: different value
        let tampered = IssuerSignedItem::with_random(
            0,
            "name",
            ciborium::Value::Text("Bob".into()),
            namespaces["test"][0].random.clone(),
        )
        .unwrap();

        assert!(!mso.verify_item_digest("test", &tampered).unwrap());
    }

    #[test]
    fn decoy_digests_added() {
        let mut namespaces = BTreeMap::new();
        namespaces.insert(
            "test".to_string(),
            vec![IssuerSignedItem::new(
                0,
                "attr",
                ciborium::Value::Bool(true),
            )],
        );

        let mso = MobileSecurityObject::create(
            "test",
            "SHA-256",
            &namespaces,
            test_device_key(),
            test_validity(),
            5, // 5 decoy digests
        )
        .unwrap();

        // 1 real + 5 decoy
        assert_eq!(mso.value_digests["test"].len(), 6);
    }

    #[test]
    fn mso_cbor_roundtrip() {
        let mut namespaces = BTreeMap::new();
        namespaces.insert(
            "test".to_string(),
            vec![IssuerSignedItem::new(
                0,
                "name",
                ciborium::Value::Text("Alice".into()),
            )],
        );

        let mso = MobileSecurityObject::create(
            "test",
            "SHA-256",
            &namespaces,
            test_device_key(),
            test_validity(),
            0,
        )
        .unwrap();

        // Encode to CBOR
        let mut buf = Vec::new();
        ciborium::into_writer(&mso, &mut buf).unwrap();

        // Decode back
        let decoded: MobileSecurityObject = ciborium::from_reader(&buf[..]).unwrap();
        assert_eq!(decoded.doc_type, "test");
        assert_eq!(decoded.version, "1.0");
        assert_eq!(decoded.digest_algorithm, "SHA-256");
        assert_eq!(decoded.value_digests["test"].len(), 1);
    }

    #[test]
    fn mso_tag24_wrapping() {
        let mut namespaces = BTreeMap::new();
        namespaces.insert(
            "test".to_string(),
            vec![IssuerSignedItem::new(
                0,
                "x",
                ciborium::Value::Integer(1.into()),
            )],
        );

        let mso = MobileSecurityObject::create(
            "test",
            "SHA-256",
            &namespaces,
            test_device_key(),
            test_validity(),
            0,
        )
        .unwrap();

        let tagged = mso.to_tagged().unwrap();
        let tagged_bytes = tagged.to_tagged_bytes().unwrap();

        // Tag24 marker
        assert_eq!(tagged_bytes[0], 0xd8);
        assert_eq!(tagged_bytes[1], 24);
    }

    #[test]
    fn unknown_namespace_fails() {
        let mut namespaces = BTreeMap::new();
        namespaces.insert(
            "test".to_string(),
            vec![IssuerSignedItem::new(
                0,
                "x",
                ciborium::Value::Integer(1.into()),
            )],
        );

        let mso = MobileSecurityObject::create(
            "test",
            "SHA-256",
            &namespaces,
            test_device_key(),
            test_validity(),
            0,
        )
        .unwrap();

        let item = IssuerSignedItem::new(0, "x", ciborium::Value::Integer(1.into()));
        assert!(mso.verify_item_digest("unknown", &item).is_err());
    }
}
