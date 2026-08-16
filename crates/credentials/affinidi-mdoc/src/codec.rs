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

use crate::device_auth::{CoseMac0Tag, DeviceAuth, DeviceSigned};
use crate::error::{MdocError, Result};
use crate::issuer_signed::{DeviceResponse, IssuerSigned};
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

/// Build the `IssuerSigned` CBOR map. Shared by [`IssuerSigned::to_cbor_bytes`]
/// and the `Document` entries of a [`DeviceResponse`], which embed exactly this
/// structure — a `DeviceResponse` discloses a subset of items but the container
/// is identical, so the two must not drift.
fn issuer_signed_to_value(
    namespaces: &BTreeMap<String, Vec<Tag24<IssuerSignedItem>>>,
    issuer_auth: &CoseSign1,
) -> Result<Value> {
    let mut encoded_ns: Vec<(Value, Value)> = Vec::with_capacity(namespaces.len());
    for (ns, items) in namespaces {
        let encoded: std::result::Result<Vec<Value>, _> =
            items.iter().map(Value::serialized).collect();
        let encoded =
            encoded.map_err(|e| MdocError::Cbor(format!("encoding items for `{ns}`: {e}")))?;
        encoded_ns.push((Value::Text(ns.clone()), Value::Array(encoded)));
    }

    let issuer_auth = issuer_auth
        .clone()
        .to_cbor_value()
        .map_err(|e| MdocError::Cose(format!("encoding issuerAuth: {e}")))?;

    Ok(Value::Map(vec![
        (Value::Text(KEY_NAME_SPACES.into()), Value::Map(encoded_ns)),
        (Value::Text(KEY_ISSUER_AUTH.into()), issuer_auth),
    ]))
}

/// Decode an `IssuerSigned` CBOR map into its parts. Shared with the
/// `DeviceResponse` path for the same reason as [`issuer_signed_to_value`].
///
/// The MSO is read out of the `issuerAuth` payload, never from the outer map.
#[allow(clippy::type_complexity)]
fn issuer_signed_from_value(
    value: &Value,
) -> Result<(
    BTreeMap<String, Vec<Tag24<IssuerSignedItem>>>,
    CoseSign1,
    MobileSecurityObject,
)> {
    let entries = match value {
        Value::Map(entries) => entries,
        other => {
            return Err(MdocError::Cbor(format!(
                "IssuerSigned must be a CBOR map, got {other:?}"
            )));
        }
    };

    let issuer_auth_value = map_get(entries, KEY_ISSUER_AUTH)
        .ok_or_else(|| MdocError::Cbor("IssuerSigned is missing `issuerAuth`".into()))?;

    // ISO specifies an untagged COSE_Sign1 here, but tag 18 is common in the
    // wild (it is what a generic COSE encoder emits). Unwrapping it is free and
    // refusing it would reject otherwise-valid credentials over a difference
    // that carries no meaning at this position.
    let issuer_auth_value = match issuer_auth_value {
        Value::Tag(18, inner) => inner.as_ref().clone(),
        other => other.clone(),
    };

    let issuer_auth = CoseSign1::from_cbor_value(issuer_auth_value)
        .map_err(|e| MdocError::Cose(format!("decoding issuerAuth: {e}")))?;

    let payload = issuer_auth
        .payload
        .as_ref()
        .ok_or_else(|| MdocError::Cose("issuerAuth has no payload (detached MSO)".into()))?;
    let tagged: Tag24<MobileSecurityObject> = ciborium::from_reader(&payload[..])
        .map_err(|e| MdocError::Cbor(format!("decoding MSO from issuerAuth: {e}")))?;
    let mso = tagged.inner;

    // Absent is legal per the CDDL (`?`) and means "no items", not an error.
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

    Ok((namespaces, issuer_auth, mso))
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
        let doc = issuer_signed_to_value(&self.namespaces, &self.issuer_auth)?;
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
        let (namespaces, issuer_auth, mso) = issuer_signed_from_value(&value)?;
        let doc_type = mso.doc_type.clone();
        Ok(IssuerSigned {
            mso,
            namespaces,
            issuer_auth,
            doc_type,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────
// DeviceResponse
// ─────────────────────────────────────────────────────────────────────────

const KEY_VERSION: &str = "version";
const KEY_DOCUMENTS: &str = "documents";
const KEY_STATUS: &str = "status";
const KEY_DOC_TYPE: &str = "docType";
const KEY_ISSUER_SIGNED: &str = "issuerSigned";
const KEY_DEVICE_SIGNED: &str = "deviceSigned";
const KEY_DEVICE_AUTH: &str = "deviceAuth";
const KEY_DEVICE_SIGNATURE: &str = "deviceSignature";
const KEY_DEVICE_MAC: &str = "deviceMac";

/// Encode a [`DeviceSigned`] to its ISO wire map.
///
/// `nameSpaces` is Tag24-wrapped here even though [`DeviceSigned::namespaces_bytes`]
/// holds the *untagged* inner CBOR: the struct keeps the inner form because that
/// is what `DeviceAuthentication` embeds before signing, and the tag belongs to
/// the wire. Getting this backwards produces a response whose device signature
/// cannot be reproduced by any verifier.
fn device_signed_to_value(ds: &DeviceSigned) -> Result<Value> {
    let auth = match &ds.device_auth {
        DeviceAuth::Signature(sign1) => {
            let v = sign1
                .as_ref()
                .clone()
                .to_cbor_value()
                .map_err(|e| MdocError::Cose(format!("encoding deviceSignature: {e}")))?;
            Value::Map(vec![(Value::Text(KEY_DEVICE_SIGNATURE.into()), v)])
        }
        DeviceAuth::Mac(mac) => {
            // COSE_Mac0 = [protected, unprotected, payload, tag], payload
            // detached (null) per ISO 18013-5 §9.1.3.
            let protected: Value = ciborium::from_reader(&mac.protected[..]).map_err(|e| {
                MdocError::Cbor(format!("decoding deviceMac protected header: {e}"))
            })?;
            let mac0 = Value::Array(vec![
                protected,
                Value::Map(vec![]),
                Value::Null,
                Value::Bytes(mac.tag.clone()),
            ]);
            Value::Map(vec![(Value::Text(KEY_DEVICE_MAC.into()), mac0)])
        }
    };

    Ok(Value::Map(vec![
        (
            Value::Text(KEY_NAME_SPACES.into()),
            Value::Tag(24, Box::new(Value::Bytes(ds.namespaces_bytes.clone()))),
        ),
        (Value::Text(KEY_DEVICE_AUTH.into()), auth),
    ]))
}

/// Decode a [`DeviceSigned`] from its ISO wire map.
fn device_signed_from_value(value: &Value) -> Result<DeviceSigned> {
    let entries = match value {
        Value::Map(entries) => entries,
        other => {
            return Err(MdocError::Cbor(format!(
                "`deviceSigned` must be a CBOR map, got {other:?}"
            )));
        }
    };

    // Unwrap Tag24 back to the inner bytes the struct holds. A bare bstr is
    // accepted for the same reason `Tag24`'s own Deserialize accepts one.
    let namespaces_bytes = match map_get(entries, KEY_NAME_SPACES) {
        Some(Value::Tag(24, inner)) => match inner.as_ref() {
            Value::Bytes(b) => b.clone(),
            other => {
                return Err(MdocError::Cbor(format!(
                    "`deviceSigned.nameSpaces` tag must wrap bytes, got {other:?}"
                )));
            }
        },
        Some(Value::Bytes(b)) => b.clone(),
        Some(other) => {
            return Err(MdocError::Cbor(format!(
                "`deviceSigned.nameSpaces` must be Tag(24, bstr), got {other:?}"
            )));
        }
        None => {
            return Err(MdocError::Cbor(
                "`deviceSigned` is missing `nameSpaces`".into(),
            ));
        }
    };

    let auth_entries = match map_get(entries, KEY_DEVICE_AUTH) {
        Some(Value::Map(entries)) => entries,
        Some(other) => {
            return Err(MdocError::Cbor(format!(
                "`deviceAuth` must be a CBOR map, got {other:?}"
            )));
        }
        None => {
            return Err(MdocError::Cbor(
                "`deviceSigned` is missing `deviceAuth`".into(),
            ));
        }
    };

    let device_auth = if let Some(sig) = map_get(auth_entries, KEY_DEVICE_SIGNATURE) {
        let sig = match sig {
            Value::Tag(18, inner) => inner.as_ref().clone(),
            other => other.clone(),
        };
        let sign1 = CoseSign1::from_cbor_value(sig)
            .map_err(|e| MdocError::Cose(format!("decoding deviceSignature: {e}")))?;
        DeviceAuth::Signature(Box::new(sign1))
    } else if let Some(Value::Array(mac0)) = map_get(auth_entries, KEY_DEVICE_MAC) {
        if mac0.len() != 4 {
            return Err(MdocError::Cbor(format!(
                "COSE_Mac0 must have 4 elements, got {}",
                mac0.len()
            )));
        }
        let mut protected = Vec::new();
        ciborium::into_writer(&mac0[0], &mut protected)
            .map_err(|e| MdocError::Cbor(format!("re-encoding deviceMac protected: {e}")))?;
        let tag = match &mac0[3] {
            Value::Bytes(b) => b.clone(),
            other => {
                return Err(MdocError::Cbor(format!(
                    "COSE_Mac0 tag must be bytes, got {other:?}"
                )));
            }
        };
        DeviceAuth::Mac(CoseMac0Tag { protected, tag })
    } else {
        return Err(MdocError::Cbor(
            "`deviceAuth` must carry exactly one of `deviceSignature` or `deviceMac`".into(),
        ));
    };

    Ok(DeviceSigned {
        namespaces_bytes,
        device_auth,
    })
}

impl DeviceResponse {
    /// Encode to the ISO 18013-5 `DeviceResponse` CBOR wire form — the bytes a
    /// holder returns to a reader, and (base64url-encoded) the content of an
    /// OpenID4VP `vp_token` entry for an `mso_mdoc` credential.
    ///
    /// # Single document
    ///
    /// This type models **one** document; the wire form carries a `documents`
    /// array. Encoding therefore always emits exactly one entry. That covers
    /// every OID4VP presentation of a single credential, which is what the
    /// `vp_token` shape wants, but a multi-document response has to be
    /// assembled by the caller.
    pub fn to_cbor_bytes(&self) -> Result<Vec<u8>> {
        let issuer_signed = issuer_signed_to_value(&self.disclosed, &self.issuer_auth)?;

        let mut document = vec![
            (
                Value::Text(KEY_DOC_TYPE.into()),
                Value::Text(self.doc_type.clone()),
            ),
            (Value::Text(KEY_ISSUER_SIGNED.into()), issuer_signed),
        ];
        if let Some(ds) = &self.device_signed {
            document.push((
                Value::Text(KEY_DEVICE_SIGNED.into()),
                device_signed_to_value(ds)?,
            ));
        }

        let response = Value::Map(vec![
            (
                Value::Text(KEY_VERSION.into()),
                Value::Text(self.version.clone()),
            ),
            (
                Value::Text(KEY_DOCUMENTS.into()),
                Value::Array(vec![Value::Map(document)]),
            ),
            (
                Value::Text(KEY_STATUS.into()),
                Value::Integer(self.status.into()),
            ),
        ]);

        let mut buf = Vec::new();
        ciborium::into_writer(&response, &mut buf)
            .map_err(|e| MdocError::Cbor(format!("encoding DeviceResponse: {e}")))?;
        Ok(buf)
    }

    /// Decode from the ISO 18013-5 `DeviceResponse` CBOR wire form.
    ///
    /// **This performs no cryptographic verification** — see the module docs.
    /// Follow with [`Self::verify_issuer_auth`], [`Self::verify_digests`] and,
    /// when holder binding matters, [`Self::verify_device_auth`].
    ///
    /// Rejects a response that does not carry exactly one document: zero means
    /// there is nothing to present, and this type cannot represent more than
    /// one. Failing loudly beats silently dropping documents a reader asked for.
    pub fn from_cbor_bytes(bytes: &[u8]) -> Result<Self> {
        let value: Value = ciborium::from_reader(bytes)
            .map_err(|e| MdocError::Cbor(format!("decoding DeviceResponse: {e}")))?;

        let entries = match &value {
            Value::Map(entries) => entries,
            other => {
                return Err(MdocError::Cbor(format!(
                    "DeviceResponse must be a CBOR map, got {other:?}"
                )));
            }
        };

        let version = map_get(entries, KEY_VERSION)
            .and_then(Value::as_text)
            .ok_or_else(|| MdocError::Cbor("DeviceResponse is missing `version`".into()))?
            .to_string();

        let status = map_get(entries, KEY_STATUS)
            .and_then(Value::as_integer)
            .and_then(|i| u32::try_from(i).ok())
            .ok_or_else(|| MdocError::Cbor("DeviceResponse is missing a valid `status`".into()))?;

        let documents = match map_get(entries, KEY_DOCUMENTS) {
            Some(Value::Array(docs)) => docs,
            Some(other) => {
                return Err(MdocError::Cbor(format!(
                    "`documents` must be an array, got {other:?}"
                )));
            }
            None => {
                return Err(MdocError::Cbor(
                    "DeviceResponse carries no `documents` — nothing to present".into(),
                ));
            }
        };

        if documents.len() != 1 {
            return Err(MdocError::Cbor(format!(
                "DeviceResponse must carry exactly one document, got {} \
                 (this type models a single document)",
                documents.len()
            )));
        }

        let doc_entries = match &documents[0] {
            Value::Map(entries) => entries,
            other => {
                return Err(MdocError::Cbor(format!(
                    "a document must be a CBOR map, got {other:?}"
                )));
            }
        };

        let issuer_signed_value = map_get(doc_entries, KEY_ISSUER_SIGNED)
            .ok_or_else(|| MdocError::Cbor("document is missing `issuerSigned`".into()))?;
        let (disclosed, issuer_auth, mso) = issuer_signed_from_value(issuer_signed_value)?;

        // As with `IssuerSigned`, docType tracks the signed MSO rather than the
        // document's own unsigned member.
        let doc_type = mso.doc_type.clone();

        let device_signed = match map_get(doc_entries, KEY_DEVICE_SIGNED) {
            Some(v) => Some(device_signed_from_value(v)?),
            None => None,
        };

        Ok(DeviceResponse {
            version,
            doc_type,
            disclosed,
            mso,
            issuer_auth,
            device_signed,
            status,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::issuer_signed::MdocBuilder;
    use crate::mso::ValidityInfo;
    use crate::namespace::EIDAS_PID_NAMESPACE;
    use crate::session_transcript::SessionTranscript;

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
    // ── DeviceResponse ────────────────────────────────────────────────

    #[cfg(feature = "es256")]
    fn requested_all() -> std::collections::BTreeMap<String, Vec<String>> {
        let mut m = std::collections::BTreeMap::new();
        m.insert(
            EIDAS_PID_NAMESPACE.to_string(),
            vec!["family_name".to_string(), "age_over_18".to_string()],
        );
        m
    }

    /// The presentation counterpart of the credential round trip: a response
    /// must survive encode → decode with both the issuer signature and the
    /// selective-disclosure digests intact.
    #[cfg(feature = "es256")]
    #[test]
    fn device_response_round_trip_preserves_issuer_proof() {
        let (issued, verifier) = sample();
        let response = DeviceResponse::create(&issued, &requested_all()).expect("create");

        let bytes = response.to_cbor_bytes().expect("encode");
        let decoded = DeviceResponse::from_cbor_bytes(&bytes).expect("decode");

        assert_eq!(decoded.version, "1.0");
        assert_eq!(decoded.status, 0);
        assert_eq!(decoded.doc_type, issued.doc_type);
        assert!(decoded.verify_digests().expect("digests"));
        decoded.verify_issuer_auth(&verifier).expect("issuerAuth");
    }

    /// Only the disclosed subset crosses the wire — the whole point of the
    /// format. A round trip must not resurrect withheld attributes.
    #[cfg(feature = "es256")]
    #[test]
    fn device_response_round_trip_carries_only_disclosed_items() {
        let (issued, _) = sample();
        let mut requested = std::collections::BTreeMap::new();
        requested.insert(
            EIDAS_PID_NAMESPACE.to_string(),
            vec!["age_over_18".to_string()],
        );

        let response = DeviceResponse::create(&issued, &requested).expect("create");
        let decoded =
            DeviceResponse::from_cbor_bytes(&response.to_cbor_bytes().unwrap()).expect("decode");

        let names = decoded.disclosed_names(EIDAS_PID_NAMESPACE);
        assert_eq!(names, vec!["age_over_18"]);
        assert!(
            !names.contains(&"family_name"),
            "a withheld attribute must not survive the round trip"
        );
        assert!(decoded.verify_digests().expect("digests"));
    }

    /// The one that pins the Tag24 decision on `deviceSigned.nameSpaces`: the
    /// device signature is detached over `Tag24(DeviceAuthentication)`, so if
    /// the wire wrapping is wrong the signature stops verifying after a trip
    /// through the codec even though every byte looks plausible.
    #[cfg(feature = "es256")]
    #[test]
    fn device_response_round_trip_preserves_device_auth() {
        let (issued, _) = sample();
        let device_signer = Es256CoseSigner::generate();
        let device_verifier =
            Es256CoseVerifier::from_bytes(&device_signer.public_key_bytes()).unwrap();
        let transcript = SessionTranscript::new_oid4vp(
            "client-id",
            "https://verifier.example/response",
            "nonce-abc",
            "mdoc-nonce-xyz",
        );

        let response = DeviceResponse::create_with_device_auth(
            &issued,
            &requested_all(),
            &transcript,
            &device_signer,
            None,
        )
        .expect("create with device auth");

        let decoded =
            DeviceResponse::from_cbor_bytes(&response.to_cbor_bytes().unwrap()).expect("decode");

        assert!(decoded.device_signed.is_some(), "deviceSigned must survive");
        assert!(
            decoded
                .verify_device_auth(&transcript, &device_verifier)
                .expect("device auth check"),
            "device signature must still verify after a round trip"
        );
    }

    /// A response with no holder binding is legal — `deviceSigned` is optional
    /// in this type — and must not be invented on decode.
    #[cfg(feature = "es256")]
    #[test]
    fn device_response_without_device_signed_round_trips() {
        let (issued, _) = sample();
        let response = DeviceResponse::create(&issued, &requested_all()).unwrap();
        let decoded = DeviceResponse::from_cbor_bytes(&response.to_cbor_bytes().unwrap()).unwrap();
        assert!(decoded.device_signed.is_none());
    }

    /// Zero or many documents are refused rather than silently truncated —
    /// this type models exactly one.
    #[cfg(feature = "es256")]
    #[test]
    fn a_response_without_exactly_one_document_is_refused() {
        let (issued, _) = sample();
        let response = DeviceResponse::create(&issued, &requested_all()).unwrap();
        let bytes = response.to_cbor_bytes().unwrap();

        for count in [0usize, 2usize] {
            let mut value: Value = ciborium::from_reader(&bytes[..]).unwrap();
            if let Value::Map(entries) = &mut value {
                for (k, v) in entries.iter_mut() {
                    if k.as_text() == Some("documents")
                        && let Value::Array(docs) = v
                    {
                        let one = docs[0].clone();
                        *docs = std::iter::repeat_n(one, count).collect();
                    }
                }
            }
            let mut mangled = Vec::new();
            ciborium::into_writer(&value, &mut mangled).unwrap();

            let err = DeviceResponse::from_cbor_bytes(&mangled).unwrap_err();
            assert!(
                format!("{err}").contains("exactly one document"),
                "count {count} should be refused with a clear error, got: {err}"
            );
        }
    }

    #[test]
    fn a_device_response_missing_documents_is_rejected() {
        let mut buf = Vec::new();
        ciborium::into_writer(
            &Value::Map(vec![
                (Value::Text("version".into()), Value::Text("1.0".into())),
                (Value::Text("status".into()), Value::Integer(0.into())),
            ]),
            &mut buf,
        )
        .unwrap();
        let err = DeviceResponse::from_cbor_bytes(&buf).unwrap_err();
        assert!(format!("{err}").contains("documents"), "got: {err}");
    }
    /// Asserts the **encoded wire shape**, not a round trip.
    ///
    /// `deviceSigned.nameSpaces` is `DeviceNameSpacesBytes = #6.24(bstr)` in the
    /// CDDL. Our decoder deliberately also accepts a bare `bstr` (as `Tag24`'s
    /// own `Deserialize` does, for encoders that omit the tag) — which means a
    /// round-trip test passes just as happily if the encoder forgets the tag.
    /// It is self-consistent and wrong, and only a peer implementation would
    /// ever notice. So look at the bytes.
    #[cfg(feature = "es256")]
    #[test]
    fn encoded_device_namespaces_are_tag24_wrapped_on_the_wire() {
        let (issued, _) = sample();
        let device_signer = Es256CoseSigner::generate();
        let transcript = SessionTranscript::new_oid4vp("c", "https://v.example/r", "n", "m");
        let response = DeviceResponse::create_with_device_auth(
            &issued,
            &requested_all(),
            &transcript,
            &device_signer,
            None,
        )
        .unwrap();

        let bytes = response.to_cbor_bytes().unwrap();
        let value: Value = ciborium::from_reader(&bytes[..]).unwrap();

        let Value::Map(top) = &value else {
            panic!("top level must be a map")
        };
        let Some(Value::Array(docs)) = map_get(top, "documents") else {
            panic!("documents must be an array")
        };
        let Value::Map(doc) = &docs[0] else {
            panic!("document must be a map")
        };
        let Some(Value::Map(ds)) = map_get(doc, "deviceSigned") else {
            panic!("deviceSigned must be a map")
        };

        match map_get(ds, "nameSpaces") {
            Some(Value::Tag(24, inner)) => {
                assert!(
                    matches!(inner.as_ref(), Value::Bytes(_)),
                    "tag 24 must wrap a byte string"
                );
            }
            other => panic!("deviceSigned.nameSpaces must be Tag(24, bstr), got {other:?}"),
        }
    }

    /// Same reasoning one level up: `issuerAuth` must go out as an **untagged**
    /// COSE_Sign1 array, per ISO. The decoder tolerates tag 18, so a round trip
    /// cannot tell the two apart.
    #[cfg(feature = "es256")]
    #[test]
    fn encoded_issuer_auth_is_an_untagged_cose_sign1() {
        let (issued, _) = sample();
        let bytes = issued.to_cbor_bytes().unwrap();
        let value: Value = ciborium::from_reader(&bytes[..]).unwrap();

        let Value::Map(top) = &value else {
            panic!("top level must be a map")
        };
        match map_get(top, KEY_ISSUER_AUTH) {
            Some(Value::Array(parts)) => assert_eq!(
                parts.len(),
                4,
                "COSE_Sign1 is a 4-element array [protected, unprotected, payload, signature]"
            ),
            other => panic!("issuerAuth must be an untagged COSE_Sign1 array, got {other:?}"),
        }
    }
}
