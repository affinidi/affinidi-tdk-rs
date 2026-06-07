/*!
 * BBS-2023 Data Integrity Cryptosuite.
 *
 * Implements the [W3C VC Data Integrity BBS Cryptosuites](https://www.w3.org/TR/vc-di-bbs/)
 * specification for zero-knowledge selective disclosure of Verifiable Credentials.
 *
 * # Overview
 *
 * The bbs-2023 cryptosuite uses BBS signatures over BLS12-381 to enable:
 * - **Base proof creation** (issuer): Sign a VC with selective disclosure capabilities
 * - **Derived proof creation** (holder): Create a ZK proof revealing only chosen claims
 * - **Proof verification** (verifier): Verify the ZK proof without seeing hidden claims
 *
 * # Flow
 *
 * ```text
 * Issuer: sign_base(document, mandatory_pointers, sk, pk) → base_proof
 * Holder: derive_proof(base_document, selective_pointers, ph) → derived_proof
 * Verifier: verify_proof(derived_document, pk) → bool
 * ```
 *
 * # eIDAS 2.0
 *
 * Addresses ARF ZKP requirements ZKP_01 through ZKP_06 for unlinkable
 * selective disclosure of PID and QEAA attributes.
 *
 * # ⚠️ Deprecated — not interoperable
 *
 * This module's statement encoding (an affinidi-internal `pointer`/JCS scheme)
 * is **not** interoperable with other vc-di-bbs implementations: it does not use
 * RDF Dataset Canonicalization, so its `proofValue`s do not match the W3C
 * vectors and cannot be verified by a conforming verifier (or vice versa).
 *
 * Use [`crate::bbs_2023_transform`] instead — the standards-track,
 * RDF-canonical `bbs-2023` implementation, pinned byte-for-byte to the official
 * `w3c/vc-di-bbs` test vectors (issuer / holder / verifier, plus per-verifier
 * pseudonym / holder binding). No BBS credentials using this legacy encoding
 * were issued in production.
 */

// This module is itself deprecated; allow its internal cross-calls and tests to
// use the deprecated functions without warnings. External callers still get the
// per-function deprecation warnings.
#![allow(deprecated)]

use affinidi_bbs::{self as bbs, PublicKey, SecretKey, Signature};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::DataIntegrityError;

/// Sign a document's claims with BBS, creating a base proof.
///
/// The base proof contains the BBS signature and metadata needed
/// for the holder to later create derived (selective disclosure) proofs.
///
/// # Arguments
///
/// * `claims` - The credential claims as key-value pairs
/// * `mandatory_pointers` - JSON pointers to claims that MUST always be disclosed
/// * `header` - Application-specific header (typically SHA-256 of proof options)
/// * `sk` - The issuer's BBS secret key
/// * `pk` - The issuer's BBS public key
///
/// # Returns
///
/// A tuple of (BBS signature, message bytes used for signing).
#[deprecated(
    since = "0.7.3",
    note = "the affinidi-internal bbs_2023 statement encoding is NOT interoperable with other vc-di-bbs implementations; use the standards-track `bbs_2023_transform` (W3C vc-di-bbs, RDF-canonical) instead"
)]
pub fn sign_base(
    claims: &[(&str, &[u8])],
    header: &[u8],
    sk: &SecretKey,
    pk: &PublicKey,
) -> Result<(Signature, Vec<Vec<u8>>), DataIntegrityError> {
    // Convert claims to message bytes
    let messages: Vec<Vec<u8>> = claims
        .iter()
        .map(|(key, value)| {
            let mut msg = key.as_bytes().to_vec();
            msg.push(b':');
            msg.extend_from_slice(value);
            msg
        })
        .collect();

    let msg_refs: Vec<&[u8]> = messages.iter().map(|m| m.as_slice()).collect();

    let signature = bbs::sign(sk, pk, header, &msg_refs).map_err(DataIntegrityError::signing)?;

    Ok((signature, messages))
}

/// Create a derived proof by selectively disclosing claims.
///
/// # Arguments
///
/// * `pk` - The issuer's BBS public key
/// * `signature` - The BBS signature from the base proof
/// * `header` - The same header used during signing
/// * `presentation_header` - Session-specific header (nonce from verifier)
/// * `messages` - All message bytes (from sign_base)
/// * `disclosed_indexes` - Which claim indexes to reveal
///
/// # Returns
///
/// The BBS zero-knowledge proof bytes.
#[deprecated(
    since = "0.7.3",
    note = "the affinidi-internal bbs_2023 statement encoding is NOT interoperable with other vc-di-bbs implementations; use the standards-track `bbs_2023_transform` (W3C vc-di-bbs, RDF-canonical) instead"
)]
pub fn derive_proof(
    pk: &PublicKey,
    signature: &Signature,
    header: &[u8],
    presentation_header: &[u8],
    messages: &[Vec<u8>],
    disclosed_indexes: &[usize],
) -> Result<bbs::Proof, DataIntegrityError> {
    let msg_refs: Vec<&[u8]> = messages.iter().map(|m| m.as_slice()).collect();

    bbs::proof_gen(
        pk,
        signature,
        header,
        presentation_header,
        &msg_refs,
        disclosed_indexes,
    )
    .map_err(DataIntegrityError::signing)
}

/// Verify a derived proof.
///
/// # Arguments
///
/// * `pk` - The issuer's BBS public key
/// * `proof` - The BBS proof to verify
/// * `header` - The same header used during signing
/// * `presentation_header` - The same session-specific header
/// * `disclosed_messages` - The messages that were disclosed
/// * `disclosed_indexes` - The indexes of disclosed messages
///
/// # Returns
///
/// `true` if the proof is valid.
#[deprecated(
    since = "0.7.3",
    note = "the affinidi-internal bbs_2023 statement encoding is NOT interoperable with other vc-di-bbs implementations; use the standards-track `bbs_2023_transform` (W3C vc-di-bbs, RDF-canonical) instead"
)]
pub fn verify_proof(
    pk: &PublicKey,
    proof: &bbs::Proof,
    header: &[u8],
    presentation_header: &[u8],
    disclosed_messages: &[&[u8]],
    disclosed_indexes: &[usize],
) -> Result<bool, DataIntegrityError> {
    bbs::proof_verify(
        pk,
        proof,
        header,
        presentation_header,
        disclosed_messages,
        disclosed_indexes,
    )
    .map_err(|e| {
        tracing::debug!("BBS proof verification failed: {e}");
        DataIntegrityError::InvalidSignature {
            suite: crate::crypto_suites::CryptoSuite::Bbs2023,
            reason: crate::error::SignatureFailure::Invalid,
        }
    })
}

/// Compute a BBS header from proof options and mandatory claims.
///
/// Per W3C vc-di-bbs: `header = SHA-256(proof_options) || SHA-256(mandatory_statements)`
///
/// Each mandatory statement is length-prefixed (8-byte big-endian) before hashing
/// to prevent ambiguity (e.g., `["ab","cd"]` vs `["abc","d"]`).
#[deprecated(
    since = "0.7.3",
    note = "the affinidi-internal bbs_2023 statement encoding is NOT interoperable with other vc-di-bbs implementations; use the standards-track `bbs_2023_transform` (W3C vc-di-bbs, RDF-canonical) instead"
)]
pub fn compute_bbs_header(proof_options: &[u8], mandatory_statements: &[&[u8]]) -> Vec<u8> {
    let mut header = Vec::with_capacity(64);

    // SHA-256 of proof options
    let options_hash = Sha256::digest(proof_options);
    header.extend_from_slice(&options_hash);

    // SHA-256 of length-prefixed mandatory statements
    let mut mandatory_hasher = Sha256::new();
    for statement in mandatory_statements {
        // Length prefix prevents concatenation ambiguity
        mandatory_hasher.update((statement.len() as u64).to_be_bytes());
        mandatory_hasher.update(statement);
    }
    let mandatory_hash = mandatory_hasher.finalize();
    header.extend_from_slice(&mandatory_hash);

    header
}

// ===========================================================================
// Document-level bbs-2023 (W3C Verifiable Credential API)
//
// The functions above operate on message arrays; the ones below wrap them in
// the W3C VC document model, so callers sign / derive / verify a VC JSON
// document directly. The claim <-> message mapping is defined here:
//
//   * The document (minus its `proof`) is flattened into per-leaf *statements*
//     `(json_pointer, jcs_value)`, ordered by pointer (deterministic).
//   * Objects are recursed; **scalars and arrays are leaves** — selective
//     disclosure is at object-field granularity (an array is disclosed whole),
//     which keeps every disclosed statement's pointer stable when hidden
//     siblings are removed (object keys don't shift, unlike array indices).
//   * `mandatory_pointers` select statements ALWAYS disclosed; they are folded
//     into the BBS *header* (not signed as individual messages). The remaining
//     (non-mandatory) statements are the BBS *messages* — the selectively
//     disclosable claims.
//
// NOTE: this uses affinidi-bbs' simple statement encoding (not RDF dataset
// canonicalization), so it interoperates within the affinidi stack rather than
// with arbitrary W3C vc-di-bbs implementations.
// ===========================================================================

const PROOF_TYPE: &str = "DataIntegrityProof";
const PROOF_CRYPTOSUITE: &str = "bbs-2023";

/// A `(rfc6901_pointer, canonical_value_bytes)` statement.
type Statement = (String, Vec<u8>);

/// The base-proof `proofValue` payload: the holder needs the issuer signature
/// and the mandatory-pointer set to derive a presentation.
#[derive(Serialize, Deserialize)]
struct BaseProofValue {
    /// multibase(base64url) of the 80-byte BBS signature.
    signature: String,
    mandatory_pointers: Vec<String>,
}

/// The derived-proof `proofValue` payload.
#[derive(Serialize, Deserialize)]
struct DerivedProofValue {
    /// multibase(base64url) of the BBS proof bytes.
    proof: String,
    /// Original indexes (into the non-mandatory message list) of the disclosed
    /// statements, ascending.
    disclosed_indexes: Vec<usize>,
    mandatory_pointers: Vec<String>,
}

/// Sign a VC document with a BBS **base proof** (issuer side).
///
/// `mandatory_pointers` are RFC-6901 pointers to claims that must always be
/// disclosed (typically `/@context`, `/type`, `/issuer`,
/// `/credentialSubject/id`, validity dates). The returned document carries a
/// `proof` with `cryptosuite: bbs-2023`.
#[deprecated(
    since = "0.7.3",
    note = "the affinidi-internal bbs_2023 statement encoding is NOT interoperable with other vc-di-bbs implementations; use the standards-track `bbs_2023_transform` (W3C vc-di-bbs, RDF-canonical) instead"
)]
pub fn sign_vc_base(
    document: &Value,
    mandatory_pointers: &[&str],
    verification_method: &str,
    sk: &SecretKey,
    pk: &PublicKey,
) -> Result<Value, DataIntegrityError> {
    let mut doc = document.clone();
    doc.as_object_mut()
        .ok_or_else(|| DataIntegrityError::Conformance("document must be a JSON object".into()))?
        .remove("proof");

    let statements = flatten_statements(&doc)?;
    let mandatory: Vec<String> = mandatory_pointers.iter().map(|s| s.to_string()).collect();

    let proof_config = serde_json::json!({
        "type": PROOF_TYPE,
        "cryptosuite": PROOF_CRYPTOSUITE,
        "proofPurpose": "assertionMethod",
        "verificationMethod": verification_method,
    });
    let proof_options = jcs_bytes(&proof_config)?;

    let mut mandatory_msgs = Vec::new();
    let mut non_mandatory_msgs = Vec::new();
    for stmt in &statements {
        let msg = statement_message(stmt);
        if pointer_matches(&stmt.0, &mandatory) {
            mandatory_msgs.push(msg);
        } else {
            non_mandatory_msgs.push(msg);
        }
    }
    let header = compute_bbs_header(&proof_options, &as_refs(&mandatory_msgs));

    let signature = bbs::sign(sk, pk, &header, &as_refs(&non_mandatory_msgs))
        .map_err(DataIntegrityError::signing)?;

    let base_value = BaseProofValue {
        signature: mb_encode(&signature.to_bytes()),
        mandatory_pointers: mandatory,
    };
    let mut proof = proof_config;
    proof["proofValue"] = Value::String(encode_proof_value(&base_value)?);
    doc.as_object_mut().unwrap().insert("proof".into(), proof);
    Ok(doc)
}

/// Create a **derived proof** from a base-proof document (holder side),
/// disclosing only the claims under `selective_pointers` (plus the mandatory
/// ones). `presentation_header` is the verifier's nonce/challenge. `pk` is the
/// issuer's BBS public key.
#[deprecated(
    since = "0.7.3",
    note = "the affinidi-internal bbs_2023 statement encoding is NOT interoperable with other vc-di-bbs implementations; use the standards-track `bbs_2023_transform` (W3C vc-di-bbs, RDF-canonical) instead"
)]
pub fn derive_vc(
    base_document: &Value,
    selective_pointers: &[&str],
    presentation_header: &[u8],
    pk: &PublicKey,
) -> Result<Value, DataIntegrityError> {
    let proof = base_document
        .get("proof")
        .ok_or_else(|| DataIntegrityError::MalformedProof("base document has no proof".into()))?;
    let base_value: BaseProofValue = decode_proof_value(proof)?;
    let signature = Signature::from_bytes(&mb_decode(&base_value.signature)?)
        .map_err(|e| DataIntegrityError::MalformedProof(format!("decode signature: {e}")))?;

    let mut doc = base_document.clone();
    doc.as_object_mut()
        .ok_or_else(|| DataIntegrityError::Conformance("document must be a JSON object".into()))?
        .remove("proof");
    let statements = flatten_statements(&doc)?;
    let proof_config = proof_config_without_value(proof);
    let proof_options = jcs_bytes(&proof_config)?;
    let selective: Vec<String> = selective_pointers.iter().map(|s| s.to_string()).collect();

    // Non-mandatory statements in order; record the indexes of the disclosed ones.
    let mut mandatory_msgs = Vec::new();
    let mut non_mandatory_msgs = Vec::new();
    let mut disclosed_indexes = Vec::new();
    for stmt in &statements {
        if pointer_matches(&stmt.0, &base_value.mandatory_pointers) {
            mandatory_msgs.push(statement_message(stmt));
            continue;
        }
        if pointer_matches(&stmt.0, &selective) {
            disclosed_indexes.push(non_mandatory_msgs.len());
        }
        non_mandatory_msgs.push(statement_message(stmt));
    }
    let header = compute_bbs_header(&proof_options, &as_refs(&mandatory_msgs));

    let bbs_proof = bbs::proof_gen(
        pk,
        &signature,
        &header,
        presentation_header,
        &as_refs(&non_mandatory_msgs),
        &disclosed_indexes,
    )
    .map_err(DataIntegrityError::signing)?;

    // Build the derived document: keep mandatory + selectively-disclosed leaves,
    // prune everything else.
    let kept: Vec<String> = base_value
        .mandatory_pointers
        .iter()
        .cloned()
        .chain(selective.iter().cloned())
        .collect();
    let mut derived =
        retain_disclosed(&doc, "", &kept).unwrap_or_else(|| Value::Object(serde_json::Map::new()));

    let derived_value = DerivedProofValue {
        proof: mb_encode(bbs_proof.to_bytes()),
        disclosed_indexes,
        mandatory_pointers: base_value.mandatory_pointers,
    };
    let mut proof_obj = proof_config;
    proof_obj["proofValue"] = Value::String(encode_proof_value(&derived_value)?);
    derived
        .as_object_mut()
        .ok_or_else(|| DataIntegrityError::Conformance("derived document is not an object".into()))?
        .insert("proof".into(), proof_obj);
    Ok(derived)
}

/// Verify a **derived proof** document (verifier side). `presentation_header`
/// must match the one the holder derived with; `pk` is the issuer's BBS public
/// key. Returns `Ok(true)` iff the proof is valid for the disclosed claims.
#[deprecated(
    since = "0.7.3",
    note = "the affinidi-internal bbs_2023 statement encoding is NOT interoperable with other vc-di-bbs implementations; use the standards-track `bbs_2023_transform` (W3C vc-di-bbs, RDF-canonical) instead"
)]
pub fn verify_vc_derived(
    derived_document: &Value,
    presentation_header: &[u8],
    pk: &PublicKey,
) -> Result<bool, DataIntegrityError> {
    let proof = derived_document
        .get("proof")
        .ok_or_else(|| DataIntegrityError::MalformedProof("document has no proof".into()))?;
    let derived_value: DerivedProofValue = decode_proof_value(proof)?;
    let bbs_proof = bbs::Proof::from_bytes(&mb_decode(&derived_value.proof)?);

    let mut doc = derived_document.clone();
    doc.as_object_mut()
        .ok_or_else(|| DataIntegrityError::Conformance("document must be a JSON object".into()))?
        .remove("proof");
    let statements = flatten_statements(&doc)?;
    let proof_config = proof_config_without_value(proof);
    let proof_options = jcs_bytes(&proof_config)?;

    let mut mandatory_msgs = Vec::new();
    let mut disclosed_msgs = Vec::new();
    for stmt in &statements {
        if pointer_matches(&stmt.0, &derived_value.mandatory_pointers) {
            mandatory_msgs.push(statement_message(stmt));
        } else {
            disclosed_msgs.push(statement_message(stmt));
        }
    }
    let header = compute_bbs_header(&proof_options, &as_refs(&mandatory_msgs));

    verify_proof(
        pk,
        &bbs_proof,
        &header,
        presentation_header,
        &as_refs(&disclosed_msgs),
        &derived_value.disclosed_indexes,
    )
}

// --- document-level helpers ------------------------------------------------

/// Flatten a JSON document into per-leaf statements, sorted by pointer.
/// Objects are recursed; scalars and arrays are leaves (see module note).
fn flatten_statements(doc: &Value) -> Result<Vec<Statement>, DataIntegrityError> {
    let mut leaves: Vec<(String, Value)> = Vec::new();
    collect_leaves("", doc, &mut leaves);
    leaves.sort_by(|a, b| a.0.cmp(&b.0));
    leaves
        .into_iter()
        .map(|(ptr, val)| Ok((ptr, jcs_bytes(&val)?)))
        .collect()
}

fn collect_leaves(prefix: &str, v: &Value, out: &mut Vec<(String, Value)>) {
    match v {
        Value::Object(map) => {
            for (k, val) in map {
                let p = format!("{prefix}/{}", escape_token(k));
                collect_leaves(&p, val, out);
            }
        }
        // Scalars and arrays are leaves: an array is disclosed atomically.
        leaf => out.push((prefix.to_string(), leaf.clone())),
    }
}

/// Rebuild a document keeping only leaves whose pointer is disclosed, pruning
/// objects with no kept descendants. Returns `None` when nothing is kept.
fn retain_disclosed(v: &Value, prefix: &str, disclosed: &[String]) -> Option<Value> {
    match v {
        Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for (k, val) in map {
                let p = format!("{prefix}/{}", escape_token(k));
                if let Some(kept) = retain_disclosed(val, &p, disclosed) {
                    out.insert(k.clone(), kept);
                }
            }
            if out.is_empty() {
                None
            } else {
                Some(Value::Object(out))
            }
        }
        leaf => pointer_matches(prefix, disclosed).then(|| leaf.clone()),
    }
}

/// RFC 6901 token escaping (`~` -> `~0`, `/` -> `~1`).
fn escape_token(token: &str) -> String {
    token.replace('~', "~0").replace('/', "~1")
}

/// `pointer` is disclosed iff some entry of `pointers` equals it or is a parent
/// of it at a path-segment boundary.
fn pointer_matches(pointer: &str, pointers: &[String]) -> bool {
    pointers
        .iter()
        .any(|p| pointer == p || pointer.starts_with(&format!("{p}/")))
}

/// Encode one statement as a BBS message: `pointer \0 jcs_value`.
fn statement_message((ptr, val): &Statement) -> Vec<u8> {
    let mut m = Vec::with_capacity(ptr.len() + 1 + val.len());
    m.extend_from_slice(ptr.as_bytes());
    m.push(0);
    m.extend_from_slice(val);
    m
}

fn as_refs(msgs: &[Vec<u8>]) -> Vec<&[u8]> {
    msgs.iter().map(|m| m.as_slice()).collect()
}

fn proof_config_without_value(proof: &Value) -> Value {
    let mut c = proof.clone();
    if let Some(obj) = c.as_object_mut() {
        obj.remove("proofValue");
    }
    c
}

fn jcs_bytes(v: &Value) -> Result<Vec<u8>, DataIntegrityError> {
    serde_json_canonicalizer::to_string(v)
        .map(String::into_bytes)
        .map_err(|e| DataIntegrityError::Canonicalization(format!("jcs: {e}")))
}

fn mb_encode(bytes: &[u8]) -> String {
    multibase::encode(multibase::Base::Base64Url, bytes)
}

fn mb_decode(s: &str) -> Result<Vec<u8>, DataIntegrityError> {
    multibase::decode(s)
        .map(|(_, b)| b)
        .map_err(|e| DataIntegrityError::MalformedProof(format!("multibase decode: {e}")))
}

fn encode_proof_value<T: Serialize>(value: &T) -> Result<String, DataIntegrityError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|e| DataIntegrityError::MalformedProof(format!("encode proofValue: {e}")))?;
    Ok(mb_encode(&bytes))
}

fn decode_proof_value<T: for<'de> Deserialize<'de>>(
    proof: &Value,
) -> Result<T, DataIntegrityError> {
    let s = proof
        .get("proofValue")
        .and_then(Value::as_str)
        .ok_or_else(|| DataIntegrityError::MalformedProof("proof has no proofValue".into()))?;
    serde_json::from_slice(&mb_decode(s)?)
        .map_err(|e| DataIntegrityError::MalformedProof(format!("decode proofValue: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_keypair() -> (SecretKey, PublicKey) {
        let sk = bbs::keygen(b"test-key-material-for-bbs-2023!!", b"").unwrap();
        let pk = bbs::sk_to_pk(&sk);
        (sk, pk)
    }

    #[test]
    fn sign_base_and_verify() {
        let (sk, pk) = test_keypair();

        let claims = vec![
            ("given_name", b"John".as_ref()),
            ("family_name", b"Doe"),
            ("age_over_18", b"true"),
        ];

        let header = compute_bbs_header(b"proof-options", &[b"mandatory-1"]);

        let (signature, messages) = sign_base(&claims, &header, &sk, &pk).unwrap();

        // Verify the full signature
        let msg_refs: Vec<&[u8]> = messages.iter().map(|m| m.as_slice()).collect();
        let valid = bbs::verify(&pk, &signature, &header, &msg_refs).unwrap();
        assert!(valid);
    }

    #[test]
    fn derive_and_verify_selective_proof() {
        let (sk, pk) = test_keypair();

        let claims = vec![
            ("given_name", b"John".as_ref()),
            ("family_name", b"Doe"),
            ("age_over_18", b"true"),
            ("nationality", b"DE"),
        ];

        let header = compute_bbs_header(b"proof-options", &[]);

        let (signature, messages) = sign_base(&claims, &header, &sk, &pk).unwrap();

        // Holder: disclose only age_over_18 (index 2)
        let proof = derive_proof(
            &pk,
            &signature,
            &header,
            b"verifier-session-nonce",
            &messages,
            &[2],
        )
        .unwrap();

        // Verifier: verify with only the disclosed message
        let disclosed_msg = messages[2].as_slice();
        let valid = verify_proof(
            &pk,
            &proof,
            &header,
            b"verifier-session-nonce",
            &[disclosed_msg],
            &[2],
        )
        .unwrap();

        assert!(valid);
    }

    #[test]
    fn derive_proof_wrong_message_fails() {
        let (sk, pk) = test_keypair();

        let claims = vec![("name", b"Alice".as_ref())];
        let header = compute_bbs_header(b"opts", &[]);

        let (signature, messages) = sign_base(&claims, &header, &sk, &pk).unwrap();

        let proof = derive_proof(&pk, &signature, &header, b"ph", &messages, &[0]).unwrap();

        // Verify with wrong message
        let valid = verify_proof(
            &pk,
            &proof,
            &header,
            b"ph",
            &[b"name:Bob"], // Wrong!
            &[0],
        )
        .unwrap();

        assert!(!valid);
    }

    #[test]
    fn proofs_are_unlinkable() {
        let (sk, pk) = test_keypair();

        let claims = vec![("attr", b"value".as_ref())];
        let header = compute_bbs_header(b"opts", &[]);

        let (signature, messages) = sign_base(&claims, &header, &sk, &pk).unwrap();

        let proof1 = derive_proof(&pk, &signature, &header, b"session1", &messages, &[0]).unwrap();
        let proof2 = derive_proof(&pk, &signature, &header, b"session2", &messages, &[0]).unwrap();

        assert_ne!(proof1.to_bytes(), proof2.to_bytes());

        // Both verify
        let msg = messages[0].as_slice();
        assert!(verify_proof(&pk, &proof1, &header, b"session1", &[msg], &[0]).unwrap());
        assert!(verify_proof(&pk, &proof2, &header, b"session2", &[msg], &[0]).unwrap());
    }

    #[test]
    fn zero_knowledge_existence_proof() {
        let (sk, pk) = test_keypair();

        let claims = vec![("secret1", b"hidden".as_ref()), ("secret2", b"also_hidden")];
        let header = compute_bbs_header(b"opts", &[]);

        let (signature, messages) = sign_base(&claims, &header, &sk, &pk).unwrap();

        // Disclose nothing
        let proof = derive_proof(&pk, &signature, &header, b"ph", &messages, &[]).unwrap();

        let valid = verify_proof(&pk, &proof, &header, b"ph", &[], &[]).unwrap();
        assert!(valid);
    }

    #[test]
    fn compute_header_deterministic() {
        let h1 = compute_bbs_header(b"opts", &[b"stmt1", b"stmt2"]);
        let h2 = compute_bbs_header(b"opts", &[b"stmt1", b"stmt2"]);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // Two SHA-256 hashes
    }

    #[test]
    fn compute_header_different_inputs() {
        let h1 = compute_bbs_header(b"opts1", &[b"stmt"]);
        let h2 = compute_bbs_header(b"opts2", &[b"stmt"]);
        assert_ne!(h1, h2);
    }

    // --- document-level (W3C VC) round-trip -------------------------------

    fn sample_vc() -> Value {
        serde_json::json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential", "MembershipCredential"],
            "issuer": "did:webvh:issuer.example",
            "validFrom": "2020-01-01T00:00:00Z",
            "credentialSubject": {
                "id": "did:key:zHolder",
                "givenName": "Alice",
                "familyName": "Smith",
                "memberLevel": "gold"
            }
        })
    }

    const MANDATORY: &[&str] = &["/@context", "/type", "/issuer", "/credentialSubject/id"];
    const VM: &str = "did:webvh:issuer.example#bbs-key-0";

    fn assert_invalid(r: Result<bool, DataIntegrityError>) {
        assert!(!matches!(r, Ok(true)), "expected invalid, got {r:?}");
    }

    #[test]
    fn vc_base_derive_verify_round_trip() {
        let (sk, pk) = test_keypair();
        let base = sign_vc_base(&sample_vc(), MANDATORY, VM, &sk, &pk).unwrap();
        assert_eq!(base["proof"]["cryptosuite"], "bbs-2023");

        // Disclose only givenName (+ the mandatory claims).
        let derived = derive_vc(&base, &["/credentialSubject/givenName"], b"nonce-1", &pk).unwrap();

        // Disclosed + mandatory claims are present; hidden ones are gone.
        let cs = &derived["credentialSubject"];
        assert_eq!(cs["givenName"], "Alice");
        assert_eq!(cs["id"], "did:key:zHolder");
        assert_eq!(derived["issuer"], "did:webvh:issuer.example");
        assert!(cs.get("familyName").is_none(), "familyName must be hidden");
        assert!(
            cs.get("memberLevel").is_none(),
            "memberLevel must be hidden"
        );

        assert!(verify_vc_derived(&derived, b"nonce-1", &pk).unwrap());
    }

    #[test]
    fn verify_fails_on_wrong_presentation_header() {
        let (sk, pk) = test_keypair();
        let base = sign_vc_base(&sample_vc(), MANDATORY, VM, &sk, &pk).unwrap();
        let derived = derive_vc(&base, &["/credentialSubject/givenName"], b"nonce-1", &pk).unwrap();
        assert_invalid(verify_vc_derived(&derived, b"different-nonce", &pk));
    }

    #[test]
    fn verify_fails_on_wrong_public_key() {
        let (sk, pk) = test_keypair();
        let other = bbs::sk_to_pk(&bbs::keygen(b"another-bbs-key-material-32bytes", b"").unwrap());
        let base = sign_vc_base(&sample_vc(), MANDATORY, VM, &sk, &pk).unwrap();
        let derived = derive_vc(&base, &["/credentialSubject/givenName"], b"nonce-1", &pk).unwrap();
        assert_invalid(verify_vc_derived(&derived, b"nonce-1", &other));
    }

    #[test]
    fn verify_fails_on_tampered_disclosed_claim() {
        let (sk, pk) = test_keypair();
        let base = sign_vc_base(&sample_vc(), MANDATORY, VM, &sk, &pk).unwrap();
        let mut derived =
            derive_vc(&base, &["/credentialSubject/givenName"], b"nonce-1", &pk).unwrap();
        derived["credentialSubject"]["givenName"] = Value::String("Mallory".into());
        assert_invalid(verify_vc_derived(&derived, b"nonce-1", &pk));
    }

    #[test]
    fn verify_fails_on_tampered_mandatory_claim() {
        let (sk, pk) = test_keypair();
        let base = sign_vc_base(&sample_vc(), MANDATORY, VM, &sk, &pk).unwrap();
        let mut derived =
            derive_vc(&base, &["/credentialSubject/givenName"], b"nonce-1", &pk).unwrap();
        // Mandatory claims are bound via the header — tampering must fail too.
        derived["issuer"] = Value::String("did:webvh:attacker.example".into());
        assert_invalid(verify_vc_derived(&derived, b"nonce-1", &pk));
    }

    #[test]
    fn disclosing_nothing_still_verifies_mandatory() {
        let (sk, pk) = test_keypair();
        let base = sign_vc_base(&sample_vc(), MANDATORY, VM, &sk, &pk).unwrap();
        let derived = derive_vc(&base, &[], b"nonce-1", &pk).unwrap();
        // No selective claims disclosed, but the mandatory set is bound + present.
        assert!(derived["credentialSubject"].get("givenName").is_none());
        assert_eq!(derived["credentialSubject"]["id"], "did:key:zHolder");
        assert!(verify_vc_derived(&derived, b"nonce-1", &pk).unwrap());
    }
}
