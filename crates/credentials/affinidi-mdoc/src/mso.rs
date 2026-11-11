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

use serde::{Deserialize, Serialize, Serializer};

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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ValidityInfo {
    /// When the MSO was signed (CBOR Tag 0, RFC 3339 tstr).
    #[serde(serialize_with = "serialize_with_cbor_0_tag")]
    pub signed: String,

    /// Valid from date (CBOR Tag 0, RFC 3339 tstr).
    #[serde(rename = "validFrom", serialize_with = "serialize_with_cbor_0_tag")]
    pub valid_from: String,

    /// Valid until date (CBOR Tag 0, RFC 3339 tstr).
    #[serde(rename = "validUntil", serialize_with = "serialize_with_cbor_0_tag")]
    pub valid_until: String,
}

/// Encode a `tdate` as ISO 18013-5 requires: CBOR Tag 0 around the RFC 3339
/// tstr. Decoding stays lenient (ciborium skips tags), so MSOs issued before
/// 0.3.3 with bare tstr dates still parse.
fn serialize_with_cbor_0_tag<S>(value: &str, serializer: S) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    ciborium::tag::Required::<&str, 0>(value).serialize(serializer)
}

impl ValidityInfo {
    /// Check that `now` falls within `[validFrom, validUntil]`.
    ///
    /// ISO/IEC 18013-5 §9.3.1 requires the mdoc reader to verify the
    /// `ValidityInfo` structure before accepting any disclosed elements.
    /// Verifiers MUST call this (typically on the MSO returned from
    /// [`crate::IssuerSigned::verify_issuer_auth`]) — signature and digest
    /// checks alone do not establish that the credential is currently valid.
    ///
    /// Returns [`MdocError::Expired`] if `now` is outside the window, or
    /// [`MdocError::InvalidMso`] if `signed`, `validFrom` or `validUntil` does
    /// not parse as RFC 3339, `signed` lies in the future, or `validFrom` is earlier
    /// than `signed`.
    pub fn check(&self, now: time::OffsetDateTime) -> Result<()> {
        self.check_with_leeway(now, time::Duration::ZERO)
    }

    /// [`ValidityInfo::check`] with a clock-skew allowance: `now` may be up to
    /// `leeway` before `validFrom` or after `validUntil`.
    ///
    /// `signed` must also parse as RFC 3339, must not lie more than `leeway`
    /// in the future, and must not be later than `validFrom` (ISO 18013-5
    /// §9.1.2.4). A negative `leeway` is treated as zero.
    pub fn check_with_leeway(
        &self,
        now: time::OffsetDateTime,
        leeway: time::Duration,
    ) -> Result<()> {
        use time::format_description::well_known::Rfc3339;

        let leeway = leeway.max(time::Duration::ZERO);
        let signed = time::OffsetDateTime::parse(&self.signed, &Rfc3339)
            .map_err(|e| MdocError::InvalidMso(format!("signed not RFC 3339: {e}")))?;
        let valid_from = time::OffsetDateTime::parse(&self.valid_from, &Rfc3339)
            .map_err(|e| MdocError::InvalidMso(format!("validFrom not RFC 3339: {e}")))?;
        let valid_until = time::OffsetDateTime::parse(&self.valid_until, &Rfc3339)
            .map_err(|e| MdocError::InvalidMso(format!("validUntil not RFC 3339: {e}")))?;

        // Out-of-range arithmetic means the window edge is beyond any
        // representable date, so the comparison against it cannot fail.
        let latest = now.checked_add(leeway);
        let earliest = now.checked_sub(leeway);

        if latest.is_some_and(|latest| latest < valid_from) {
            return Err(MdocError::Expired(format!(
                "not yet valid (validFrom = {})",
                self.valid_from
            )));
        }
        if earliest.is_some_and(|earliest| earliest > valid_until) {
            return Err(MdocError::Expired(format!(
                "expired (validUntil = {})",
                self.valid_until
            )));
        }
        if latest.is_some_and(|latest| signed > latest) {
            return Err(MdocError::InvalidMso(format!(
                "signed lies in the future (signed = {})",
                self.signed
            )));
        }
        if valid_from < signed {
            return Err(MdocError::InvalidMso(format!(
                "validFrom {} is earlier than signed {}",
                self.valid_from, self.signed
            )));
        }
        Ok(())
    }

    /// Convenience wrapper for [`ValidityInfo::check`] using the current
    /// system time.
    pub fn check_now(&self) -> Result<()> {
        self.check(time::OffsetDateTime::now_utc())
    }
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

    /// Verify a received item against the stored digest.
    ///
    /// The digest is taken over the item's bytes as received
    /// ([`Tag24::digest`]), never over a re-encoding of the decoded item. This
    /// is the check a verifier wants.
    pub fn verify_tagged_item_digest(
        &self,
        namespace: &str,
        item: &Tag24<IssuerSignedItem>,
    ) -> Result<bool> {
        let stored = self.stored_digest(namespace, item.inner.digest_id)?;
        let computed = item.digest(&self.digest_algorithm)?;
        Ok(computed == stored)
    }

    fn stored_digest(&self, namespace: &str, digest_id: u32) -> Result<&[u8]> {
        let ns_digests = self.value_digests.get(namespace).ok_or_else(|| {
            MdocError::InvalidNamespace(format!("namespace not found: {namespace}"))
        })?;
        ns_digests
            .get(&digest_id)
            .map(|digest| digest.as_ref())
            .ok_or_else(|| MdocError::DigestMismatch(format!("digest_id {digest_id} not found")))
    }

    /// Verify an item built in memory against the stored digest.
    ///
    /// This re-encodes `item` with this crate's encoder, so it only matches
    /// items this crate encoded. For an item decoded from the wire use
    /// [`Self::verify_tagged_item_digest`], which hashes the received bytes.
    pub fn verify_item_digest(&self, namespace: &str, item: &IssuerSignedItem) -> Result<bool> {
        let stored = self.stored_digest(namespace, item.digest_id)?;
        let computed = item.compute_digest(&self.digest_algorithm)?;
        Ok(computed == stored)
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

        let validity = test_validity();

        let mso = MobileSecurityObject::create(
            "test",
            "SHA-256",
            &namespaces,
            test_device_key(),
            validity.clone(),
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
        assert_eq!(decoded.validity_info, validity);
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

    #[test]
    fn validity_info_check_within_window() {
        let v = test_validity();
        let mid = time::OffsetDateTime::parse(
            "2024-06-01T00:00:00Z",
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap();
        v.check(mid).expect("mid-window must be valid");
    }

    #[test]
    fn validity_info_check_expired() {
        let v = test_validity();
        let after = time::OffsetDateTime::parse(
            "2025-06-01T00:00:00Z",
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap();
        assert!(matches!(v.check(after), Err(MdocError::Expired(_))));
    }

    #[test]
    fn validity_info_check_not_yet_valid() {
        let v = test_validity();
        let before = time::OffsetDateTime::parse(
            "2023-06-01T00:00:00Z",
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap();
        assert!(matches!(v.check(before), Err(MdocError::Expired(_))));
    }

    #[test]
    fn validity_info_check_malformed() {
        let v = ValidityInfo {
            signed: "2024-01-01T00:00:00Z".into(),
            valid_from: "not-a-date".into(),
            valid_until: "2025-01-01T00:00:00Z".into(),
        };
        assert!(matches!(
            v.check(time::OffsetDateTime::now_utc()),
            Err(MdocError::InvalidMso(_))
        ));
    }

    fn validity_map(v: &ValidityInfo) -> Vec<(ciborium::Value, ciborium::Value)> {
        let mut buf = Vec::new();
        ciborium::into_writer(v, &mut buf).unwrap();
        match ciborium::from_reader(&buf[..]).unwrap() {
            ciborium::Value::Map(m) => m,
            other => panic!("ValidityInfo must encode as a map, got {other:?}"),
        }
    }

    #[test]
    fn validity_info_dates_encode_as_tdate() {
        // tdate = #6.0(tstr) (RFC 8610 Appendix D). A round-trip can't see
        // this — ciborium drops tags on decode — so inspect the encoded form.
        let v = test_validity();
        let map = validity_map(&v);
        assert_eq!(map.len(), 3);
        for (key, value) in map {
            match value {
                ciborium::Value::Tag(0, inner) => {
                    assert!(
                        matches!(*inner, ciborium::Value::Text(_)),
                        "{key:?}: {inner:?}"
                    )
                }
                other => panic!("{key:?} must be CBOR Tag 0, got {other:?}"),
            }
        }
    }

    #[test]
    fn validity_info_decodes_untagged_dates() {
        // MSOs issued before 0.3.3 carry bare tstr dates; they must still parse.
        let legacy = ciborium::Value::Map(vec![
            ("signed".into(), "2024-01-01T00:00:00Z".into()),
            ("validFrom".into(), "2024-01-01T00:00:00Z".into()),
            ("validUntil".into(), "2025-01-01T00:00:00Z".into()),
        ]);
        let mut buf = Vec::new();
        ciborium::into_writer(&legacy, &mut buf).unwrap();
        let decoded: ValidityInfo = ciborium::from_reader(&buf[..]).unwrap();
        assert_eq!(decoded, test_validity());
    }

    #[test]
    fn a_signed_date_in_the_future_is_rejected_beyond_leeway() {
        let validity = ValidityInfo {
            signed: "2024-06-01T00:10:00Z".into(),
            valid_from: "2024-06-01T00:10:00Z".into(),
            valid_until: "2025-01-01T00:00:00Z".into(),
        };
        let now = time::OffsetDateTime::parse(
            "2024-06-01T00:00:00Z",
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap();
        assert!(validity.check(now).is_err());
        validity
            .check_with_leeway(now, time::Duration::minutes(15))
            .expect("within leeway");
    }

    #[test]
    fn valid_from_earlier_than_signed_is_rejected() {
        let validity = ValidityInfo {
            signed: "2024-06-01T00:00:00Z".into(),
            valid_from: "2024-01-01T00:00:00Z".into(),
            valid_until: "2025-01-01T00:00:00Z".into(),
        };
        let now = time::OffsetDateTime::parse(
            "2024-07-01T00:00:00Z",
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap();
        assert!(matches!(validity.check(now), Err(MdocError::InvalidMso(_))));
    }

    #[test]
    fn an_extreme_leeway_does_not_overflow() {
        let validity = test_validity();
        let now = time::OffsetDateTime::parse(
            "2024-06-01T00:00:00Z",
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap();
        validity
            .check_with_leeway(now, time::Duration::MAX)
            .expect("an unbounded leeway accepts any time");
        validity
            .check_with_leeway(time::OffsetDateTime::now_utc(), time::Duration::ZERO)
            .expect_err("the fixture window is in the past");
    }

    #[test]
    fn a_tagged_item_digest_is_taken_over_the_received_bytes() {
        let item = IssuerSignedItem::new(0, "x", ciborium::Value::Integer(1.into()));
        let mut namespaces = BTreeMap::new();
        namespaces.insert("ns".to_string(), vec![item.clone()]);
        let mso = MobileSecurityObject::create(
            "doc",
            "SHA-256",
            &namespaces,
            test_device_key(),
            test_validity(),
            0,
        )
        .unwrap();
        let mut tagged = item.to_tagged().unwrap();
        assert!(mso.verify_tagged_item_digest("ns", &tagged).unwrap());
        tagged.inner_bytes.push(0x00);
        assert!(!mso.verify_tagged_item_digest("ns", &tagged).unwrap());
    }
}
