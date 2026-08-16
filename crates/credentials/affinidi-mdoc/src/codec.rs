/*!
 * CBOR wire codec for [`IssuerSigned`] — ISO/IEC 18013-5 §8.3.2.1.2.2.
 *
 * The rest of this crate models an mdoc in memory and does the cryptography
 * over it. This module is the boundary: it turns an [`IssuerSigned`] into the
 * bytes an issuer actually hands out, and back.
 *
 * # Why this is not a `derive`
 *
 * [`IssuerSigned`] carries `mso` and `doc_type` as fields for ergonomics, but
 * neither is a wire member. The ISO CDDL is:
 *
 * ```text
 * IssuerSigned = {
 *   ? "nameSpaces" : IssuerNameSpaces,
 *   "issuerAuth"   : IssuerAuth          ; COSE_Sign1
 * }
 *
 * IssuerNameSpaces      = { + NameSpace => [ + IssuerSignedItemBytes ] }
 * IssuerSignedItemBytes = #6.24(bstr .cbor IssuerSignedItem)
 * IssuerAuth            = COSE_Sign1     ; payload is #6.24(bstr .cbor MSO)
 * ```
 *
 * The MSO — and therefore `docType` — lives inside the `issuerAuth` payload.
 * A `#[derive(Serialize)]` would emit both twice and let a decoder trust a
 * `docType` that the issuer never signed. Decoding reads them out of the
 * signed payload instead, so there is only ever one source for them.
 *
 * # Parsing is not verifying
 *
 * [`IssuerSigned::from_cbor_bytes`] checks structure, not signatures. It will
 * happily decode a credential whose `issuerAuth` signature is forged or whose
 * digests do not match. Callers **must** follow it with
 * [`IssuerSigned::verify_issuer_auth`] (signature, against a trusted issuer
 * key) and [`IssuerSigned::verify_digests`] (items against the MSO) before
 * trusting any claim. The two are separate because the issuer key normally has
 * to be resolved *from* the decoded credential's `x5chain`.
 *
 * # Digest fidelity
 *
 * Digests are computed over the Tag24-wrapped item bytes exactly as received,
 * never over a re-encode. [`Tag24`]'s `Deserialize` preserves `inner_bytes`,
 * so a decode → [`verify_digests`](IssuerSigned::verify_digests) round trip
 * holds even against an encoder whose map ordering or integer widths differ
 * from ours. The round-trip tests below pin that.
 */

use std::collections::BTreeMap;

use ciborium::Value;
use coset::{AsCborValue, CoseSign1};

use crate::error::{MdocError, Result};
use crate::issuer_signed::IssuerSigned;
use crate::issuer_signed_item::IssuerSignedItem;
use crate::mso::MobileSecurityObject;
use crate::tag24::Tag24;

/// Wire member names, spelled once.
const KEY_NAME_SPACES: &str = "nameSpaces";
const KEY_ISSUER_AUTH: &str = "issuerAuth";

/// Look up a text key in a CBOR map.
fn map_get<'a>(entries: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    entries
        .iter()
        .find(|(k, _)| k.as_text() == Some(key))
        .map(|(_, v)| v)
}

impl IssuerSigned {
    /// Encode to the ISO 18013-5 `IssuerSigned` CBOR wire form.
    ///
    /// `mso` and `doc_type` are deliberately **not** emitted — they are read
    /// back out of the signed `issuerAuth` payload on decode. Emitting them
    /// would create a second, unsigned copy that a decoder could be tricked
    /// into preferring.
    ///
    /// The `COSE_Sign1` is written untagged, which is what ISO 18013-5
    /// specifies for `IssuerAuth`. (`from_cbor_bytes` accepts a tagged one
    /// anyway — see there for why.)
    pub fn to_cbor_bytes(&self) -> Result<Vec<u8>> {
        let mut namespaces: Vec<(Value, Value)> = Vec::with_capacity(self.namespaces.len());
        for (ns, items) in &self.namespaces {
            let encoded: std::result::Result<Vec<Value>, _> =
                items.iter().map(Value::serialized).collect();
            let encoded =
                encoded.map_err(|e| MdocError::Cbor(format!("encoding items for `{ns}`: {e}")))?;
            namespaces.push((Value::Text(ns.clone()), Value::Array(encoded)));
        }

        let issuer_auth = self
            .issuer_auth
            .clone()
            .to_cbor_value()
            .map_err(|e| MdocError::Cose(format!("encoding issuerAuth: {e}")))?;

        let doc = Value::Map(vec![
            (Value::Text(KEY_NAME_SPACES.into()), Value::Map(namespaces)),
            (Value::Text(KEY_ISSUER_AUTH.into()), issuer_auth),
        ]);

        let mut buf = Vec::new();
        ciborium::into_writer(&doc, &mut buf)
            .map_err(|e| MdocError::Cbor(format!("encoding IssuerSigned: {e}")))?;
        Ok(buf)
    }

    /// Decode from the ISO 18013-5 `IssuerSigned` CBOR wire form.
    ///
    /// **This performs no cryptographic verification** — see the module docs.
    /// Follow with [`Self::verify_issuer_auth`] and [`Self::verify_digests`].
    ///
    /// `mso` and `doc_type` come from the `issuerAuth` payload, so the values
    /// on the returned struct are always the ones the issuer signed.
    pub fn from_cbor_bytes(bytes: &[u8]) -> Result<Self> {
        let value: Value = ciborium::from_reader(bytes)
            .map_err(|e| MdocError::Cbor(format!("decoding IssuerSigned: {e}")))?;

        let entries = match &value {
            Value::Map(entries) => entries,
            other => {
                return Err(MdocError::Cbor(format!(
                    "IssuerSigned must be a CBOR map, got {other:?}"
                )));
            }
        };

        // ── issuerAuth ────────────────────────────────────────────────
        let issuer_auth_value = map_get(entries, KEY_ISSUER_AUTH)
            .ok_or_else(|| MdocError::Cbor("IssuerSigned is missing `issuerAuth`".into()))?;

        // ISO specifies an untagged COSE_Sign1 here, but tag 18 is common in
        // the wild (it is what a generic COSE encoder emits). Unwrapping it is
        // free and refusing it would reject otherwise-valid credentials over a
        // difference that carries no meaning at this position.
        let issuer_auth_value = match issuer_auth_value {
            Value::Tag(18, inner) => inner.as_ref().clone(),
            other => other.clone(),
        };

        let issuer_auth = CoseSign1::from_cbor_value(issuer_auth_value)
            .map_err(|e| MdocError::Cose(format!("decoding issuerAuth: {e}")))?;

        // ── MSO, out of the signed payload ────────────────────────────
        let payload = issuer_auth
            .payload
            .as_ref()
            .ok_or_else(|| MdocError::Cose("issuerAuth has no payload (detached MSO)".into()))?;
        let tagged: Tag24<MobileSecurityObject> = ciborium::from_reader(&payload[..])
            .map_err(|e| MdocError::Cbor(format!("decoding MSO from issuerAuth: {e}")))?;
        let mso = tagged.inner;
        let doc_type = mso.doc_type.clone();

        // ── nameSpaces ────────────────────────────────────────────────
        // Absent is legal per the CDDL (`?`) and means "no disclosed items",
        // not an error.
        let mut namespaces: BTreeMap<String, Vec<Tag24<IssuerSignedItem>>> = BTreeMap::new();
        if let Some(ns_value) = map_get(entries, KEY_NAME_SPACES) {
            let ns_entries = match ns_value {
                Value::Map(entries) => entries,
                other => {
                    return Err(MdocError::Cbor(format!(
                        "`nameSpaces` must be a CBOR map, got {other:?}"
                    )));
                }
            };

            for (ns_key, items_value) in ns_entries {
                let ns = ns_key
                    .as_text()
                    .ok_or_else(|| MdocError::Cbor("namespace keys must be text strings".into()))?;
                let items = match items_value {
                    Value::Array(items) => items,
                    other => {
                        return Err(MdocError::Cbor(format!(
                            "namespace `{ns}` must hold an array, got {other:?}"
                        )));
                    }
                };

                let mut decoded = Vec::with_capacity(items.len());
                for item in items {
                    let tag: Tag24<IssuerSignedItem> = item
                        .deserialized()
                        .map_err(|e| MdocError::Cbor(format!("decoding an item in `{ns}`: {e}")))?;
                    decoded.push(tag);
                }
                namespaces.insert(ns.to_string(), decoded);
            }
        }

        Ok(IssuerSigned {
            mso,
            namespaces,
            issuer_auth,
            doc_type,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::issuer_signed::MdocBuilder;
    use crate::mso::ValidityInfo;
    use crate::namespace::EIDAS_PID_NAMESPACE;

    #[cfg(feature = "es256")]
    use crate::es256_cose::{Es256CoseSigner, Es256CoseVerifier};

    fn validity() -> ValidityInfo {
        ValidityInfo {
            signed: "2026-01-01T00:00:00Z".into(),
            valid_from: "2026-01-01T00:00:00Z".into(),
            valid_until: "2036-01-01T00:00:00Z".into(),
        }
    }

    #[cfg(feature = "es256")]
    fn sample() -> (IssuerSigned, Es256CoseVerifier) {
        let signer = Es256CoseSigner::generate();
        let verifier = Es256CoseVerifier::from_bytes(&signer.public_key_bytes()).unwrap();
        let issued = MdocBuilder::new("eu.europa.ec.eudi.pid.1")
            .validity(validity())
            .add_json_attribute(
                EIDAS_PID_NAMESPACE,
                "family_name",
                &serde_json::json!("Gore"),
            )
            .add_json_attribute(EIDAS_PID_NAMESPACE, "age_over_18", &serde_json::json!(true))
            .build(&signer)
            .unwrap();
        (issued, verifier)
    }

    /// The property everything else depends on: bytes out, bytes in, and the
    /// credential still verifies against the issuer key and its own digests.
    #[cfg(feature = "es256")]
    #[test]
    fn round_trip_preserves_signature_and_digests() {
        let (issued, verifier) = sample();

        let bytes = issued.to_cbor_bytes().expect("encode");
        let decoded = IssuerSigned::from_cbor_bytes(&bytes).expect("decode");

        assert_eq!(decoded.doc_type, issued.doc_type);
        assert_eq!(decoded.mso.doc_type, issued.mso.doc_type);
        assert!(
            decoded.verify_digests().expect("digest check"),
            "digests must survive a decode — Tag24 must preserve inner bytes"
        );
        decoded
            .verify_issuer_auth(&verifier)
            .expect("issuerAuth must still verify after a round trip");
    }

    /// Attribute values must survive intact, not merely the container.
    #[cfg(feature = "es256")]
    #[test]
    fn round_trip_preserves_attribute_values() {
        let (issued, _) = sample();
        let decoded = IssuerSigned::from_cbor_bytes(&issued.to_cbor_bytes().unwrap()).unwrap();

        let mut names = decoded.attribute_names(EIDAS_PID_NAMESPACE);
        names.sort_unstable();
        assert_eq!(names, vec!["age_over_18", "family_name"]);

        let item = decoded
            .get_attribute(EIDAS_PID_NAMESPACE, "family_name")
            .expect("family_name present");
        assert_eq!(
            crate::issuer_signed_item::cbor_to_json(&item.inner.element_value),
            serde_json::json!("Gore")
        );
    }

    /// `docType` is never read from the wire map — only from the signed MSO —
    /// so an attacker cannot bolt an unsigned `docType` onto a credential and
    /// have a verifier believe it.
    #[cfg(feature = "es256")]
    #[test]
    fn doc_type_comes_from_the_signed_mso_not_the_outer_map() {
        let (issued, _) = sample();
        let bytes = issued.to_cbor_bytes().unwrap();

        // Splice a bogus `docType` into the outer map.
        let mut value: Value = ciborium::from_reader(&bytes[..]).unwrap();
        if let Value::Map(entries) = &mut value {
            entries.push((
                Value::Text("docType".into()),
                Value::Text("org.iso.18013.5.1.mDL".into()),
            ));
        }
        let mut tampered = Vec::new();
        ciborium::into_writer(&value, &mut tampered).unwrap();

        let decoded = IssuerSigned::from_cbor_bytes(&tampered).expect("decode");
        assert_eq!(
            decoded.doc_type, "eu.europa.ec.eudi.pid.1",
            "docType must track the signed MSO, not an injected outer member"
        );
    }

    /// A tagged COSE_Sign1 (tag 18) is accepted — generic COSE encoders emit
    /// it and the tag carries no meaning at this position.
    #[cfg(feature = "es256")]
    #[test]
    fn a_tagged_cose_sign1_is_accepted() {
        let (issued, verifier) = sample();
        let bytes = issued.to_cbor_bytes().unwrap();

        let mut value: Value = ciborium::from_reader(&bytes[..]).unwrap();
        if let Value::Map(entries) = &mut value {
            for (k, v) in entries.iter_mut() {
                if k.as_text() == Some(KEY_ISSUER_AUTH) {
                    *v = Value::Tag(18, Box::new(v.clone()));
                }
            }
        }
        let mut tagged = Vec::new();
        ciborium::into_writer(&value, &mut tagged).unwrap();

        let decoded = IssuerSigned::from_cbor_bytes(&tagged).expect("tagged issuerAuth decodes");
        decoded
            .verify_issuer_auth(&verifier)
            .expect("still verifies");
    }

    /// A credential with no disclosed items is structurally legal (`?` in the
    /// CDDL) and must not be rejected as malformed.
    #[cfg(feature = "es256")]
    #[test]
    fn absent_namespaces_decodes_to_an_empty_map() {
        let (issued, _) = sample();
        let bytes = issued.to_cbor_bytes().unwrap();

        let mut value: Value = ciborium::from_reader(&bytes[..]).unwrap();
        if let Value::Map(entries) = &mut value {
            entries.retain(|(k, _)| k.as_text() != Some(KEY_NAME_SPACES));
        }
        let mut stripped = Vec::new();
        ciborium::into_writer(&value, &mut stripped).unwrap();

        let decoded = IssuerSigned::from_cbor_bytes(&stripped).expect("decode");
        assert!(decoded.namespaces.is_empty());
        assert_eq!(decoded.doc_type, "eu.europa.ec.eudi.pid.1");
    }

    #[test]
    fn a_non_map_is_rejected() {
        let mut buf = Vec::new();
        ciborium::into_writer(&Value::Text("not a credential".into()), &mut buf).unwrap();
        assert!(IssuerSigned::from_cbor_bytes(&buf).is_err());
    }

    #[test]
    fn a_missing_issuer_auth_is_rejected() {
        let mut buf = Vec::new();
        ciborium::into_writer(&Value::Map(vec![]), &mut buf).unwrap();
        let err = IssuerSigned::from_cbor_bytes(&buf).unwrap_err();
        assert!(
            format!("{err}").contains("issuerAuth"),
            "error should name the missing member, got: {err}"
        );
    }

    #[test]
    fn trailing_garbage_is_not_silently_accepted() {
        assert!(IssuerSigned::from_cbor_bytes(&[0xff, 0xff, 0xff]).is_err());
    }
}
