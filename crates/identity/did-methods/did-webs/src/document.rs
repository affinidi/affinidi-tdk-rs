//! Building a DID document from verified KERI state.
//!
//! The published `did.json` is a cache. What a resolver returns must be
//! *derived* from the key event log it verified, so this module takes verified
//! key state, designated aliases and authorised services, and produces the
//! document they imply — and nothing else.
//!
//! The document is built as JSON in the form the specification defines
//! (§ DID documents): relative verification method ids (`#<key qb64>`), the
//! subject as `controller`, and no `@context` ("pure JSON"). That form is what
//! `did.json` publishes, after [`to_did_web`]. [`into_document`] turns it into
//! an [`affinidi_did_common::Document`], whose ids are absolute URLs, by
//! resolving every relative reference against the subject — the same
//! identifiers, in the form a consumer looks keys up by.

use affinidi_cesr::Matter;
use affinidi_did_common::Document;
use affinidi_keri_core::threshold::Threshold;
use serde_json::{Map, Value, json};

use crate::errors::DidWebsError;
use crate::identifier::DidWebs;

/// The verification relationships a `did:webs` document may carry.
///
/// `authentication` and `assertionMethod` are derived from the key state; the
/// others are permitted ("MAY also include other verification relationship
/// properties") and are compared like the rest when present.
pub(crate) const RELATIONSHIPS: [&str; 5] = [
    "authentication",
    "assertionMethod",
    "keyAgreement",
    "capabilityInvocation",
    "capabilityDelegation",
];

/// Build the `did:webs` form of the document implied by verified state.
///
/// * `keys` and `threshold` are the current key state's `k` and `kt`;
/// * `aliases` are the identifiers to list in `alsoKnownAs`, already verified
///   as designated and with the subject itself removed;
/// * `services` are rendered service entries, each already authorised.
///
/// # Errors
/// Returns [`DidWebsError::Kel`] if the key state has no keys, a key is not a
/// CESR public key this implementation can express as a JWK, or the threshold
/// cannot be expressed as a `ConditionalProof2022`.
pub fn derive_document(
    did: &DidWebs,
    keys: &[String],
    threshold: &Threshold,
    aliases: &[String],
    services: &[Value],
) -> Result<Value, DidWebsError> {
    if keys.is_empty() {
        return Err(DidWebsError::Kel(
            "verified key state has no signing keys".into(),
        ));
    }
    let subject = did.did();

    let mut methods = Vec::with_capacity(keys.len() + 1);
    for key in keys {
        methods.push(json!({
            "id": format!("#{key}"),
            "type": "JsonWebKey",
            "controller": subject,
            "publicKeyJwk": jwk_from_cesr_key(key)?,
        }));
    }

    // § Verification Relationships: with `kt` == 1 each key authenticates and
    // asserts on its own. With a higher or weighted threshold no single key
    // does — only the threshold condition over them, which is what the
    // `ConditionalProof2022` method expresses.
    let referenced: Vec<Value> = match threshold_condition(did, keys, threshold)? {
        None => keys.iter().map(|k| json!(format!("#{k}"))).collect(),
        Some(condition) => {
            let id = condition["id"].clone();
            // Appended after the keys, as the reference implementation does.
            methods.push(condition);
            vec![id]
        }
    };

    let mut doc = Map::new();
    doc.insert("id".into(), json!(subject));
    doc.insert("controller".into(), json!(subject));
    doc.insert("verificationMethod".into(), Value::Array(methods));
    doc.insert("authentication".into(), Value::Array(referenced.clone()));
    doc.insert("assertionMethod".into(), Value::Array(referenced));
    doc.insert("service".into(), Value::Array(services.to_vec()));
    doc.insert("alsoKnownAs".into(), json!(aliases));
    Ok(Value::Object(doc))
}

/// The `ConditionalProof2022` method for a threshold above one key, or `None`
/// when `kt` is 1.
///
/// § Thresholds: a numeric `kt` > 1 becomes `threshold` with every key in
/// `conditionThreshold`; a weighted `kt` becomes `threshold` = the lowest
/// common denominator of its fractions, each key carrying its numerator over
/// that denominator in `conditionWeightedThreshold`.
fn threshold_condition(
    did: &DidWebs,
    keys: &[String],
    threshold: &Threshold,
) -> Result<Option<Value>, DidWebsError> {
    let base = |extra: Value| -> Value {
        let mut condition = json!({
            "id": format!("#{}", did.aid()),
            "type": "ConditionalProof2022",
            "controller": did.did(),
        });
        if let (Some(obj), Value::Object(extra)) = (condition.as_object_mut(), extra) {
            obj.extend(extra);
        }
        condition
    };

    match threshold {
        Threshold::Simple(n) if *n <= 1 => Ok(None),
        Threshold::Simple(n) => Ok(Some(base(json!({
            "threshold": n,
            "conditionThreshold": keys.iter().map(|k| format!("#{k}")).collect::<Vec<_>>(),
        })))),
        Threshold::Weighted(clauses) => {
            // KERI ANDs several weighted clauses together. The specification
            // defines the rendering of one; rendering only the first would
            // publish a condition weaker than the controller's.
            let [clause] = clauses.as_slice() else {
                return Err(DidWebsError::Kel(format!(
                    "a weighted threshold with {} clauses cannot be expressed as one \
                     ConditionalProof2022",
                    clauses.len()
                )));
            };
            if clause.len() != keys.len() {
                return Err(DidWebsError::Kel(format!(
                    "weighted threshold has {} weights for {} keys",
                    clause.len(),
                    keys.len()
                )));
            }
            let lcd = clause
                .iter()
                .try_fold(1u64, |acc, w| lcm(acc, u64::from(w.den)))
                .ok_or_else(|| DidWebsError::Kel("weighted threshold overflows".into()))?;
            let conditions = keys
                .iter()
                .zip(clause)
                .map(|(key, w)| {
                    let weight = u64::from(w.num) * (lcd / u64::from(w.den));
                    json!({ "condition": format!("#{key}"), "weight": weight })
                })
                .collect::<Vec<_>>();
            Ok(Some(base(json!({
                "threshold": lcd,
                "conditionWeightedThreshold": conditions,
            }))))
        }
    }
}

fn gcd(a: u64, b: u64) -> u64 {
    if b == 0 { a } else { gcd(b, a % b) }
}

fn lcm(a: u64, b: u64) -> Option<u64> {
    if a == 0 || b == 0 {
        return None;
    }
    (a / gcd(a, b)).checked_mul(b)
}

/// Transform the `did:webs` form of a document into the `did:web` form that
/// `did.json` publishes (§ Transformation to `did:web` DID document).
///
/// The subject-identifying DIDs are rewritten — top-level `id` and
/// `controller`, every verification method `controller` equal to the subject,
/// and the reciprocal `alsoKnownAs` entry — and nothing else is touched.
///
/// The caller must only publish the result when the `did:web` twin is
/// designated; [`crate::create`] always designates it.
pub fn to_did_web(doc: &Value, did: &DidWebs) -> Value {
    swap_subject(doc, did.did(), &did.did_web_twin())
}

/// Transform a published `did:web` document back into the `did:webs` form
/// (§ Transformation to `did:webs` DID document). A document already in the
/// `did:webs` form is returned as it is.
///
/// `twin_designated` is the specification's precondition: an arbitrary
/// `did:web` document is not a `did:webs` one merely because its identifier
/// ends in an AID.
///
/// # Errors
/// Returns [`DidWebsError::DocumentMismatch`] if the document is for neither
/// this DID nor its `did:web` twin, or is the twin's when the twin is not
/// designated.
pub fn from_did_web(
    doc: &Value,
    did: &DidWebs,
    twin_designated: bool,
) -> Result<Value, DidWebsError> {
    let id = doc
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| DidWebsError::DocumentMismatch("did.json has no `id`".into()))?;

    let twin = did.did_web_twin();
    if same_did(id, did.did()) {
        Ok(doc.clone())
    } else if same_did(id, &twin) {
        if !twin_designated {
            return Err(DidWebsError::DocumentMismatch(format!(
                "did.json is the did:web document {id:?}, but no designated-aliases \
                 attestation authorises that identifier"
            )));
        }
        Ok(swap_subject(doc, id, did.did()))
    } else {
        Err(DidWebsError::DocumentMismatch(format!(
            "did.json is for {id:?}, which is neither {:?} nor its did:web twin {twin:?}",
            did.did(),
        )))
    }
}

/// Rewrite the subject-identifying DIDs of a document from `from` to `to`.
fn swap_subject(doc: &Value, from: &str, to: &str) -> Value {
    let mut out = doc.clone();
    let Some(obj) = out.as_object_mut() else {
        return out;
    };

    for field in ["id", "controller"] {
        if obj.get(field).and_then(Value::as_str).is_some() {
            obj.insert(field.into(), json!(to));
        }
    }

    if let Some(Value::Array(methods)) = obj.get_mut("verificationMethod") {
        for method in methods {
            if let Some(controller) = method.get("controller").and_then(Value::as_str)
                && same_did(controller, from)
            {
                method["controller"] = json!(to);
            }
        }
    }

    // The reciprocal alias: the document for one form names the other.
    if let Some(Value::Array(aliases)) = obj.get_mut("alsoKnownAs") {
        for alias in aliases {
            if let Some(a) = alias.as_str()
                && same_did(a, to)
            {
                *alias = json!(from);
            }
        }
    }
    out
}

/// Turn the `did:webs` form of a document into a [`Document`], resolving every
/// relative reference against the subject.
///
/// A reference that is not a URL on its own — a `DelegatorOOBI` service is
/// identified by a bare SAID — is given as a fragment of the subject, since
/// [`Document`] holds service ids as URLs.
///
/// # Errors
/// Returns [`DidWebsError::Json`] if the result is not a valid [`Document`].
pub fn into_document(doc: &Value, did: &DidWebs) -> Result<Document, DidWebsError> {
    let subject = did.did();
    let mut out = doc.clone();

    if let Some(obj) = out.as_object_mut() {
        if let Some(Value::Array(methods)) = obj.get_mut("verificationMethod") {
            for method in methods {
                absolutize_field(method, "id", subject);
                for list in ["conditionThreshold"] {
                    if let Some(Value::Array(refs)) = method.get_mut(list) {
                        for r in refs {
                            absolutize(r, subject);
                        }
                    }
                }
                if let Some(Value::Array(weighted)) = method.get_mut("conditionWeightedThreshold") {
                    for entry in weighted {
                        absolutize_field(entry, "condition", subject);
                    }
                }
            }
        }
        for relationship in RELATIONSHIPS {
            if let Some(Value::Array(refs)) = obj.get_mut(relationship) {
                for r in refs {
                    absolutize(r, subject);
                }
            }
        }
        if let Some(Value::Array(services)) = obj.get_mut("service") {
            for service in services {
                absolutize_field(service, "id", subject);
            }
        }
    }

    Ok(serde_json::from_value(out)?)
}

fn absolutize_field(value: &mut Value, field: &str, subject: &str) {
    if let Some(v) = value.get_mut(field) {
        absolutize(v, subject);
    }
}

fn absolutize(value: &mut Value, subject: &str) {
    let Some(s) = value.as_str() else { return };
    if s.starts_with('#') {
        *value = json!(format!("{subject}{s}"));
    } else if !s.contains(':') {
        *value = json!(format!("{subject}#{s}"));
    }
}

/// Whether two DIDs are the same, with percent-encoding case normalised.
///
/// RFC 3986 makes `%3a` and `%3A` equivalent, and real artifacts write the port
/// separator lowercase while the specification writes it uppercase.
pub(crate) fn same_did(a: &str, b: &str) -> bool {
    normalize_percent_encoding(a) == normalize_percent_encoding(b)
}

/// Uppercase the hex digits of every percent-encoded triplet (RFC 3986
/// §6.2.2.1).
pub(crate) fn normalize_percent_encoding(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && bytes[i + 1].is_ascii_hexdigit()
            && bytes[i + 2].is_ascii_hexdigit()
        {
            out.push('%');
            out.push(bytes[i + 1].to_ascii_uppercase() as char);
            out.push(bytes[i + 2].to_ascii_uppercase() as char);
            i += 3;
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}

/// Turn a CESR-encoded public key into a JWK.
///
/// `did:webs` documents carry `JsonWebKey` verification methods with the CESR
/// key as the `kid`, so a published document can be compared field for field
/// against a derived one.
///
/// The conversion goes through `affinidi_crypto`, which validates that an EC
/// point is actually on its curve while decompressing it. That check matters:
/// a compressed point is 33 bytes of attacker-supplied data, and a key that is
/// not on the curve must be refused rather than published in a document.
fn jwk_from_cesr_key(key_qb64: &str) -> Result<Value, DidWebsError> {
    let matter = Matter::from_qb64(key_qb64)
        .map_err(|e| DidWebsError::Kel(format!("key {key_qb64:?} is not a CESR primitive: {e}")))?;

    let raw = matter.raw();
    let jwk = match matter.code() {
        // Ed25519 verification key, non-transferable ("B") and transferable ("D").
        "B" | "D" => affinidi_crypto::ed25519::public_jwk(raw),
        // secp256k1, non-transferable and transferable.
        "1AAA" | "1AAB" => affinidi_crypto::secp256k1::public_jwk(raw),
        // NIST P-256, non-transferable and transferable.
        "1AAI" | "1AAJ" => affinidi_crypto::p256::public_jwk(raw),
        other => {
            return Err(DidWebsError::Kel(format!(
                "key {key_qb64:?} uses CESR code {other:?}, which this implementation \
                 cannot express as a JWK"
            )));
        }
    }
    .map_err(|e| DidWebsError::Kel(format!("key {key_qb64:?} is not a valid public key: {e}")))?;

    let mut value = serde_json::to_value(&jwk)?;
    if let Some(obj) = value.as_object_mut() {
        // A public JWK serializes its absent private part as `"d": null`. That
        // member does not belong in a published key, and a document carrying
        // it differs from every other implementation's.
        obj.retain(|_, v| !v.is_null());
        // The CESR form is the key's identity in a did:webs document, and it
        // is what the verification method id references.
        obj.insert("kid".to_string(), json!(key_qb64));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_keri_core::threshold::Weight;

    const ED25519_KEY: &str = "DHr0-I-mMN7h6cLMOTRJkkfPuMd0vgQPrOk4Y3edaHjr";
    const AID: &str = "ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe";

    fn did() -> DidWebs {
        DidWebs::parse(&format!("did:webs:example.com:{AID}")).expect("valid did")
    }

    fn one_key() -> Value {
        derive_document(
            &did(),
            &[ED25519_KEY.to_string()],
            &Threshold::Simple(1),
            &[],
            &[],
        )
        .expect("builds")
    }

    #[test]
    fn builds_a_document_for_an_ed25519_key() {
        let doc = one_key();
        assert_eq!(doc["id"], format!("did:webs:example.com:{AID}"));
        assert_eq!(doc["controller"], doc["id"]);

        let vm = &doc["verificationMethod"][0];
        assert_eq!(vm["type"], "JsonWebKey");
        // § Verification Methods: a relative DID URL with the key as fragment.
        assert_eq!(vm["id"], format!("#{ED25519_KEY}"));
        assert_eq!(vm["controller"], doc["id"]);

        let jwk = &vm["publicKeyJwk"];
        assert_eq!(jwk["kty"], "OKP");
        assert_eq!(jwk["crv"], "Ed25519");
        assert_eq!(jwk["kid"], ED25519_KEY);
        // The published artifact for this AID carries exactly this `x`.
        assert_eq!(jwk["x"], "evT4j6Yw3uHpwsw5NEmSR8-4x3S-BA-s6Thjd51oeOs");
        // A public key has no private member, not even a null one.
        assert!(jwk.get("d").is_none(), "{jwk}");
    }

    #[test]
    fn a_single_key_authenticates_and_asserts_on_its_own() {
        let doc = one_key();
        let reference = json!([format!("#{ED25519_KEY}")]);
        assert_eq!(doc["authentication"], reference);
        assert_eq!(doc["assertionMethod"], reference);
    }

    #[test]
    fn no_alias_is_added_that_was_not_designated() {
        // § Also Known As: every alias, the did:web twin included, must be in a
        // designated-aliases attestation. The caller passes only those.
        assert_eq!(one_key()["alsoKnownAs"], json!([]));
    }

    const K2: &str = "DA-vW9ynSkvOWv5e7idtikLANdS6pGO2IHJy7v0rypvE";
    const K3: &str = "DLWJrsKIHrrn1Q1jy2oEi8Bmv6aEcwuyIqgngVf2nNwu";

    fn three_keys() -> Vec<String> {
        vec![ED25519_KEY.to_string(), K2.to_string(), K3.to_string()]
    }

    #[test]
    fn a_numeric_threshold_is_a_conditional_proof_and_no_key_acts_alone() {
        let doc = derive_document(&did(), &three_keys(), &Threshold::Simple(2), &[], &[])
            .expect("builds");

        let methods = doc["verificationMethod"].as_array().expect("array");
        assert_eq!(methods.len(), 4);
        let condition = &methods[3];
        assert_eq!(condition["type"], "ConditionalProof2022");
        assert_eq!(condition["id"], format!("#{AID}"));
        assert_eq!(condition["threshold"], 2);
        assert_eq!(
            condition["conditionThreshold"],
            json!([
                format!("#{ED25519_KEY}"),
                format!("#{K2}"),
                format!("#{K3}")
            ]),
        );

        // One key of a 2-of-3 identifier is not the controller.
        assert_eq!(doc["authentication"], json!([format!("#{AID}")]));
        assert_eq!(doc["assertionMethod"], json!([format!("#{AID}")]));
    }

    #[test]
    fn a_weighted_threshold_is_expanded_over_the_lowest_common_denominator() {
        // The specification's own example: 1/2, 1/3, 1/4 over 12.
        let weights = vec![
            Weight::new(1, 2).expect("weight"),
            Weight::new(1, 3).expect("weight"),
            Weight::new(1, 4).expect("weight"),
        ];
        let doc = derive_document(
            &did(),
            &three_keys(),
            &Threshold::Weighted(vec![weights]),
            &[],
            &[],
        )
        .expect("builds");

        let condition = &doc["verificationMethod"][3];
        assert_eq!(condition["threshold"], 12);
        assert_eq!(
            condition["conditionWeightedThreshold"],
            json!([
                {"condition": format!("#{ED25519_KEY}"), "weight": 6},
                {"condition": format!("#{K2}"), "weight": 4},
                {"condition": format!("#{K3}"), "weight": 3},
            ]),
        );
    }

    #[test]
    fn a_multi_clause_weighted_threshold_is_refused_rather_than_weakened() {
        let clause = || vec![Weight::new(1, 2).expect("w"), Weight::new(1, 2).expect("w")];
        let keys = vec![ED25519_KEY.to_string(), K2.to_string()];
        let err = derive_document(
            &did(),
            &keys,
            &Threshold::Weighted(vec![clause(), clause()]),
            &[],
            &[],
        )
        .expect_err("two clauses cannot be one condition");
        assert!(err.to_string().contains("2 clauses"), "{err}");
    }

    #[test]
    fn the_did_web_form_swaps_the_subject_and_the_reciprocal_alias() {
        let d = did();
        let doc = derive_document(
            &d,
            &[ED25519_KEY.to_string()],
            &Threshold::Simple(1),
            &[d.did_web_twin(), d.did_keri()],
            &[],
        )
        .expect("builds");

        let web = to_did_web(&doc, &d);
        assert_eq!(web["id"], d.did_web_twin());
        assert_eq!(web["controller"], d.did_web_twin());
        assert_eq!(web["verificationMethod"][0]["controller"], d.did_web_twin());
        assert_eq!(web["alsoKnownAs"], json!([d.did(), d.did_keri()]));
        // Nothing else changes.
        assert_eq!(web["authentication"], doc["authentication"]);

        assert_eq!(from_did_web(&web, &d, true).expect("transforms back"), doc);
    }

    #[test]
    fn an_undesignated_did_web_document_is_not_a_did_webs_one() {
        let d = did();
        let web = to_did_web(&one_key(), &d);
        assert!(from_did_web(&web, &d, false).is_err());
    }

    #[test]
    fn the_document_resolves_relative_references_against_the_subject() {
        let document = into_document(&one_key(), &did()).expect("a valid document");
        let expected = format!("did:webs:example.com:{AID}#{ED25519_KEY}");
        assert_eq!(document.verification_method[0].id.as_str(), expected);
        assert_eq!(document.authentication.len(), 1);
    }

    #[test]
    fn rejects_an_empty_key_state() {
        assert!(derive_document(&did(), &[], &Threshold::Simple(1), &[], &[]).is_err());
    }

    #[test]
    fn rejects_a_key_that_is_not_a_cesr_primitive() {
        assert!(
            derive_document(
                &did(),
                &["not-a-key".to_string()],
                &Threshold::Simple(1),
                &[],
                &[]
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_a_non_key_cesr_primitive() {
        // A digest is a valid CESR primitive but not a public key.
        assert!(
            derive_document(&did(), &[AID.to_string()], &Threshold::Simple(1), &[], &[]).is_err()
        );
    }

    #[test]
    fn percent_encoding_case_is_normalised() {
        assert_eq!(
            normalize_percent_encoding("did:web:host%3a7676:E123"),
            "did:web:host%3A7676:E123",
        );
        assert_eq!(normalize_percent_encoding("100%"), "100%");
        assert_eq!(normalize_percent_encoding("a%zz"), "a%zz");
    }
}
