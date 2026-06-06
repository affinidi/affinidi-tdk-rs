/*!
 * W3C `bbs-2023` transformation primitives (RDF-canonical, interoperable).
 *
 * This is the standards-track replacement for the affinidi-internal statement
 * encoding in [`crate::bbs_2023`]. It implements the
 * [W3C vc-di-bbs](https://www.w3.org/TR/vc-di-bbs/) `bbs-2023` cryptosuite over
 * the conformant RDFC-1.0 canonicalizer in `affinidi-rdf-encoding`.
 *
 * Every step is pinned byte-for-byte against the official `w3c/vc-di-bbs`
 * `TestVectors/` (see the KATs at the bottom). All three roles are implemented
 * and interoperate with the reference implementation end-to-end:
 *
 * - [`create_base_proof_value`] (issuer) — `proofHash`, the HMAC blank-node
 *   label map ([`hmac_canonicalize`]), mandatory/non-mandatory grouping
 *   ([`canonicalize_and_group`]), BBS sign, and the CBOR base `proofValue`
 *   (`0xd95d02`). Matches the W3C base proof exactly.
 * - [`create_derived_proof`] (holder) — selective disclosure: combined
 *   grouping, BBS `proof_gen`, the reveal label map, and the CBOR derived
 *   `proofValue` (`0xd95d03`).
 * - [`verify_derived_proof`] (verifier) — relabel + recompute hashes + BBS
 *   `proof_verify`; accepts the reference derived proof byte-for-byte.
 *
 * Grouping uses the vc-di-ecdsa `selectJsonLd` / `parsePointer` / skolemize
 * algorithms; skolem labels are self-consistent (grouping matches by statement
 * content), so they never leak into the output.
 */

use std::collections::{BTreeMap, BTreeSet};

use affinidi_bbs as bbs;
use affinidi_rdf_encoding::{jsonld, nquads, rdfc1};
use hmac::{Hmac, Mac};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::DataIntegrityError;

type HmacSha256 = Hmac<Sha256>;

/// Skolemization URN prefix (vc-di-ecdsa).
const URN_BNID: &str = "urn:bnid:";

/// CBOR prefix bytes for a `bbs-2023` **base** proof value.
const CBOR_PREFIX_BASE: [u8; 3] = [0xd9, 0x5d, 0x02];

/// Produce a `bbs-2023` **base proof** value (issuer side), per W3C vc-di-bbs.
///
/// Computes `proofHash`, groups statements by `mandatory_pointers`, signs the
/// non-mandatory statements with BBS (header = `proofHash || mandatoryHash`),
/// and serializes the multibase CBOR `proofValue`.
pub fn create_base_proof_value(
    document: &Value,
    proof_config: &Value,
    mandatory_pointers: &[&str],
    sk: &bbs::SecretKey,
    pk: &bbs::PublicKey,
    hmac_key: &[u8],
) -> Result<String, DataIntegrityError> {
    let proof_hash = proof_hash(proof_config)?;
    let grouped = canonicalize_and_group(document, mandatory_pointers, hmac_key)?;

    let mut bbs_header = proof_hash.to_vec();
    bbs_header.extend_from_slice(&grouped.mandatory_hash);

    let non_mandatory = grouped.non_mandatory();
    let messages: Vec<&[u8]> = non_mandatory.iter().map(|s| s.as_bytes()).collect();
    let signature =
        bbs::sign(sk, pk, &bbs_header, &messages).map_err(DataIntegrityError::signing)?;

    serialize_base_proof_value(
        &signature.to_bytes(),
        &bbs_header,
        &pk.to_bytes(),
        hmac_key,
        mandatory_pointers,
    )
}

/// Sign a VC document with a `bbs-2023` **base proof** (issuer side, document
/// API). Builds the proof configuration, signs, and returns the document with a
/// `proof` (cryptosuite `bbs-2023`). `created` is an ISO-8601 timestamp.
///
/// `hmac_key` is a per-credential secret (32 random bytes) that the holder needs
/// to derive presentations; it is carried inside the base `proofValue`.
#[allow(clippy::too_many_arguments)]
pub fn sign_base_document(
    document: &Value,
    mandatory_pointers: &[&str],
    verification_method: &str,
    created: &str,
    sk: &bbs::SecretKey,
    pk: &bbs::PublicKey,
    hmac_key: &[u8],
) -> Result<Value, DataIntegrityError> {
    let conformance = |m: &str| DataIntegrityError::Conformance(m.to_string());
    let context = document
        .get("@context")
        .cloned()
        .ok_or_else(|| conformance("document must have an @context"))?;

    // The proof config (for hashing) carries the document's @context; the proof
    // object attached to the document does NOT (it is re-added at verify time).
    let proof_config = serde_json::json!({
        "type": "DataIntegrityProof",
        "cryptosuite": "bbs-2023",
        "created": created,
        "verificationMethod": verification_method,
        "proofPurpose": "assertionMethod",
        "@context": context,
    });
    let proof_value = create_base_proof_value(
        document,
        &proof_config,
        mandatory_pointers,
        sk,
        pk,
        hmac_key,
    )?;

    let mut proof = proof_config;
    let obj = proof.as_object_mut().expect("proof config is an object");
    obj.remove("@context");
    obj.insert("proofValue".to_string(), Value::String(proof_value));

    let mut base = document.clone();
    base.as_object_mut()
        .ok_or_else(|| conformance("document must be an object"))?
        .insert("proof".to_string(), proof);
    Ok(base)
}

/// `serializeBaseProofValue`: `multibase-base64url-no-pad("u" + 0xd95d02 +
/// CBOR([bbsSignature, bbsHeader, publicKey, hmacKey, mandatoryPointers]))`.
pub fn serialize_base_proof_value(
    bbs_signature: &[u8],
    bbs_header: &[u8],
    public_key: &[u8],
    hmac_key: &[u8],
    mandatory_pointers: &[&str],
) -> Result<String, DataIntegrityError> {
    let components = ciborium::Value::Array(vec![
        ciborium::Value::Bytes(bbs_signature.to_vec()),
        ciborium::Value::Bytes(bbs_header.to_vec()),
        ciborium::Value::Bytes(public_key.to_vec()),
        ciborium::Value::Bytes(hmac_key.to_vec()),
        ciborium::Value::Array(
            mandatory_pointers
                .iter()
                .map(|p| ciborium::Value::Text((*p).to_string()))
                .collect(),
        ),
    ]);

    let mut buf = CBOR_PREFIX_BASE.to_vec();
    ciborium::into_writer(&components, &mut buf)
        .map_err(|e| DataIntegrityError::MalformedProof(format!("CBOR encode: {e}")))?;
    Ok(multibase::encode(multibase::Base::Base64Url, &buf))
}

/// CBOR prefix bytes for a `bbs-2023` **pseudonym base** proof value
/// (`featureOption: pseudonym`).
const CBOR_PREFIX_BASE_PSEUDONYM: [u8; 3] = [0xd9, 0x5d, 0x08];

/// Convert 32 entropy/secret bytes to a BBS scalar.
fn scalar_from_32(bytes: &[u8], what: &str) -> Result<bbs::Scalar, DataIntegrityError> {
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| DataIntegrityError::Conformance(format!("{what} must be 32 bytes")))?;
    bbs::hash::scalar_from_bytes(&arr)
        .ok_or_else(|| DataIntegrityError::Conformance(format!("{what} is not a valid scalar")))
}

/// Produce a `bbs-2023` **pseudonym base proof** value (issuer side), per
/// vc-di-bbs `featureOption: pseudonym`.
///
/// Identical to [`create_base_proof_value`] except the non-mandatory statements
/// are **blind-signed** over the holder's `commitment_with_proof` (from
/// `affinidi_bbs::nym_commit`, committing the holder's `prover_nym`) with the
/// issuer's `signer_nym_entropy` mixed in, and the serialized `proofValue`
/// carries `signer_nym_entropy` under the `0xd95d08` prefix.
#[allow(clippy::too_many_arguments)]
pub fn create_pseudonym_base_proof_value(
    document: &Value,
    proof_config: &Value,
    mandatory_pointers: &[&str],
    sk: &bbs::SecretKey,
    pk: &bbs::PublicKey,
    hmac_key: &[u8],
    commitment_with_proof: &[u8],
    signer_nym_entropy: &[u8],
) -> Result<String, DataIntegrityError> {
    let proof_hash = proof_hash(proof_config)?;
    let grouped = canonicalize_and_group(document, mandatory_pointers, hmac_key)?;

    let mut bbs_header = proof_hash.to_vec();
    bbs_header.extend_from_slice(&grouped.mandatory_hash);

    let non_mandatory = grouped.non_mandatory();
    let messages: Vec<&[u8]> = non_mandatory.iter().map(|s| s.as_bytes()).collect();

    let entropy = scalar_from_32(signer_nym_entropy, "signer_nym_entropy")?;
    let signature = bbs::blind_sign_with_nym(
        sk,
        pk,
        commitment_with_proof,
        entropy,
        &bbs_header,
        &messages,
        bbs::Ciphersuite::default(),
    )
    .map_err(DataIntegrityError::signing)?;

    serialize_pseudonym_base_proof_value(
        &signature.to_bytes(),
        &bbs_header,
        &pk.to_bytes(),
        hmac_key,
        mandatory_pointers,
        signer_nym_entropy,
    )
}

/// `serializeBaseProofValue` (pseudonym): `multibase("u" + 0xd95d08 +
/// CBOR([bbsSignature, bbsHeader, publicKey, hmacKey, mandatoryPointers,
/// signerNymEntropy]))`. `featureOption` is implied by the prefix.
pub fn serialize_pseudonym_base_proof_value(
    bbs_signature: &[u8],
    bbs_header: &[u8],
    public_key: &[u8],
    hmac_key: &[u8],
    mandatory_pointers: &[&str],
    signer_nym_entropy: &[u8],
) -> Result<String, DataIntegrityError> {
    let components = ciborium::Value::Array(vec![
        ciborium::Value::Bytes(bbs_signature.to_vec()),
        ciborium::Value::Bytes(bbs_header.to_vec()),
        ciborium::Value::Bytes(public_key.to_vec()),
        ciborium::Value::Bytes(hmac_key.to_vec()),
        ciborium::Value::Array(
            mandatory_pointers
                .iter()
                .map(|p| ciborium::Value::Text((*p).to_string()))
                .collect(),
        ),
        // signer_nym_entropy is a scalar → CBOR tag 2 (positive bignum).
        ciborium::Value::Tag(
            2,
            Box::new(ciborium::Value::Bytes(signer_nym_entropy.to_vec())),
        ),
    ]);

    let mut buf = CBOR_PREFIX_BASE_PSEUDONYM.to_vec();
    ciborium::into_writer(&components, &mut buf)
        .map_err(|e| DataIntegrityError::MalformedProof(format!("CBOR encode: {e}")))?;
    Ok(multibase::encode(multibase::Base::Base64Url, &buf))
}

/// CBOR prefix bytes for a `bbs-2023` **derived** proof value.
const CBOR_PREFIX_DERIVED: [u8; 3] = [0xd9, 0x5d, 0x03];

/// A parsed derived (`0xd95d03`) proof value.
struct DerivedProofValue {
    bbs_proof: Vec<u8>,
    /// `c14nN → bM` label map (decompressed from the integer→integer CBOR map).
    label_map: BTreeMap<String, String>,
    mandatory_indexes: Vec<usize>,
    selective_indexes: Vec<usize>,
    presentation_header: Vec<u8>,
}

/// `parseDisclosureProofValue`: decode the multibase CBOR derived proof value.
fn parse_derived_proof_value(proof_value: &str) -> Result<DerivedProofValue, DataIntegrityError> {
    let malformed = |m: &str| DataIntegrityError::MalformedProof(m.to_string());
    if !proof_value.starts_with('u') {
        return Err(malformed("proofValue must be multibase base64url ('u')"));
    }
    let (_base, bytes) =
        multibase::decode(proof_value).map_err(|e| malformed(&format!("multibase: {e}")))?;
    if bytes.len() < 3 || bytes[..3] != CBOR_PREFIX_DERIVED {
        return Err(malformed("proofValue is not a bbs-2023 derived proof"));
    }
    let value: ciborium::Value =
        ciborium::from_reader(&bytes[3..]).map_err(|e| malformed(&format!("CBOR: {e}")))?;
    let arr = value
        .as_array()
        .ok_or_else(|| malformed("derived proofValue must be a CBOR array"))?;
    if arr.len() != 5 {
        return Err(malformed("derived proofValue must have 5 elements"));
    }

    let bbs_proof = arr[0]
        .as_bytes()
        .ok_or_else(|| malformed("bbsProof must be bytes"))?
        .clone();

    // compressedLabelMap: CBOR map of integer → integer → c14nN → bM.
    let mut label_map = BTreeMap::new();
    for (k, v) in arr[1]
        .as_map()
        .ok_or_else(|| malformed("labelMap must be a CBOR map"))?
    {
        let n = cbor_int(k).ok_or_else(|| malformed("labelMap key"))?;
        let m = cbor_int(v).ok_or_else(|| malformed("labelMap value"))?;
        label_map.insert(format!("c14n{n}"), format!("b{m}"));
    }

    let mandatory_indexes =
        cbor_index_array(&arr[2]).ok_or_else(|| malformed("mandatoryIndexes"))?;
    let selective_indexes =
        cbor_index_array(&arr[3]).ok_or_else(|| malformed("selectiveIndexes"))?;
    let presentation_header = arr[4]
        .as_bytes()
        .ok_or_else(|| malformed("presentationHeader must be bytes"))?
        .clone();

    Ok(DerivedProofValue {
        bbs_proof,
        label_map,
        mandatory_indexes,
        selective_indexes,
        presentation_header,
    })
}

fn cbor_int(v: &ciborium::Value) -> Option<usize> {
    let i: i128 = v.as_integer()?.into();
    usize::try_from(i).ok()
}

fn cbor_index_array(v: &ciborium::Value) -> Option<Vec<usize>> {
    v.as_array()?.iter().map(cbor_int).collect()
}

/// Verify a `bbs-2023` **derived proof** (verifier side), per W3C vc-di-bbs.
///
/// Reconstructs the verify data from the disclosed `reveal_document` and its
/// derived `proofValue`, then BBS-`proof_verify`s. `pk` is the issuer's BBS
/// public key (resolved from the proof's verification method by the caller).
pub fn verify_derived_proof(
    reveal_document: &Value,
    pk: &bbs::PublicKey,
) -> Result<bool, DataIntegrityError> {
    let malformed = |m: &str| DataIntegrityError::MalformedProof(m.to_string());
    let proof = reveal_document
        .get("proof")
        .ok_or_else(|| malformed("reveal document has no proof"))?;
    let proof_value = proof
        .get("proofValue")
        .and_then(Value::as_str)
        .ok_or_else(|| malformed("proof has no proofValue"))?;
    let parsed = parse_derived_proof_value(proof_value)?;

    // proofHash = SHA-256(RDFC(proofConfig)); proofConfig = proof - proofValue,
    // carrying the document's @context.
    let mut proof_config = proof.clone();
    let cfg = proof_config
        .as_object_mut()
        .ok_or_else(|| malformed("proof must be an object"))?;
    cfg.remove("proofValue");
    if let Some(ctx) = reveal_document.get("@context") {
        cfg.insert("@context".to_string(), ctx.clone());
    }
    let proof_hash = proof_hash(&proof_config)?;

    // Canonicalize the reveal document (minus proof), relabel via the label map.
    let mut doc = reveal_document.clone();
    doc.as_object_mut()
        .ok_or_else(|| malformed("document must be an object"))?
        .remove("proof");
    let dataset = jsonld::expand_and_to_rdf(&doc).map_err(canon_err)?;
    let (canonical_c14n, _) = rdfc1::canonicalize_with_label_map(&dataset).map_err(canon_err)?;
    let labeled = lines_with_newline(&relabel_and_sort(&canonical_c14n, &parsed.label_map));

    // Split mandatory vs disclosed non-mandatory by index.
    let mandatory_set: BTreeSet<usize> = parsed.mandatory_indexes.iter().copied().collect();
    let mut mandatory = Vec::new();
    let mut non_mandatory = Vec::new();
    for (i, nq) in labeled.iter().enumerate() {
        if mandatory_set.contains(&i) {
            mandatory.push(nq.clone());
        } else {
            non_mandatory.push(nq.clone());
        }
    }

    let mut hasher = Sha256::new();
    for m in &mandatory {
        hasher.update(m.as_bytes());
    }
    let mandatory_hash: [u8; 32] = hasher.finalize().into();

    let mut bbs_header = proof_hash.to_vec();
    bbs_header.extend_from_slice(&mandatory_hash);

    let disclosed: Vec<&[u8]> = non_mandatory.iter().map(|s| s.as_bytes()).collect();
    let bbs_proof = bbs::Proof::from_bytes(&parsed.bbs_proof);
    bbs::proof_verify(
        pk,
        &bbs_proof,
        &bbs_header,
        &parsed.presentation_header,
        &disclosed,
        &parsed.selective_indexes,
    )
    .map_err(|e| {
        tracing::debug!("bbs-2023 derived proof verification failed: {e}");
        DataIntegrityError::InvalidSignature {
            suite: crate::crypto_suites::CryptoSuite::Bbs2023,
            reason: crate::error::SignatureFailure::Invalid,
        }
    })
}

/// The result of grouping canonical statements by mandatory pointers.
#[derive(Debug)]
pub struct GroupedStatements {
    /// All HMAC-canonical statements (sorted), one per line including `\n`.
    pub canonical: Vec<String>,
    /// Indices (into `canonical`) of the mandatory statements, ascending.
    pub mandatory_indexes: Vec<usize>,
    /// Indices of the non-mandatory statements, ascending.
    pub non_mandatory_indexes: Vec<usize>,
    /// `mandatoryHash = SHA-256(concat(mandatory statements in index order))`.
    pub mandatory_hash: [u8; 32],
}

impl GroupedStatements {
    /// The mandatory statements (in `mandatory_indexes` order).
    pub fn mandatory(&self) -> Vec<&str> {
        self.mandatory_indexes
            .iter()
            .map(|&i| self.canonical[i].as_str())
            .collect()
    }

    /// The non-mandatory statements — the BBS messages — in index order.
    pub fn non_mandatory(&self) -> Vec<&str> {
        self.non_mandatory_indexes
            .iter()
            .map(|&i| self.canonical[i].as_str())
            .collect()
    }
}

/// A document canonicalized with the HMAC label map, plus everything needed to
/// group its statements by JSON-pointer selection.
struct CanonicalizedHmac {
    /// The document with `urn:bnid:` skolem ids on its node objects.
    skolemized: Value,
    /// Sorted, `bK`-labeled canonical statements (each with trailing `\n`).
    canonical: Vec<String>,
    /// Skolem blank-node id → `bK` label.
    input_to_b: BTreeMap<String, String>,
}

/// `labelReplacementCanonicalizeJsonLd` with the HMAC label map factory.
fn canonicalize_hmac(
    document: &Value,
    hmac_key: &[u8],
) -> Result<CanonicalizedHmac, DataIntegrityError> {
    let skolemized = skolemize_compact(document);
    let deskolemized = to_deskolemized_nquads(&skolemized)?;
    let joined: String = deskolemized.iter().cloned().collect();
    let dataset = nquads::parse(&joined).map_err(canon_err)?;
    let (canonical_c14n, input_to_c14n) =
        rdfc1::canonicalize_with_label_map(&dataset).map_err(canon_err)?;

    let c14n_to_b = hmac_label_map(&canonical_c14n, hmac_key)?;
    let input_to_b: BTreeMap<String, String> = input_to_c14n
        .iter()
        .filter_map(|(input, c14n)| c14n_to_b.get(c14n).map(|b| (input.clone(), b.clone())))
        .collect();
    let canonical = lines_with_newline(&relabel_and_sort(&canonical_c14n, &c14n_to_b));

    Ok(CanonicalizedHmac {
        skolemized,
        canonical,
        input_to_b,
    })
}

/// Indices (into `c.canonical`) of the statements selected by `pointers`.
fn select_indices(
    c: &CanonicalizedHmac,
    pointers: &[&str],
) -> Result<Vec<usize>, DataIntegrityError> {
    if pointers.is_empty() {
        return Ok(Vec::new());
    }
    let selection =
        select_json_ld(&c.skolemized, pointers).ok_or_else(|| canon_err("empty selection"))?;
    let sel_nquads = to_deskolemized_nquads(&selection)?;
    let mut idx = BTreeSet::new();
    for line in &sel_nquads {
        let relabeled = relabel_blank_line(line, &c.input_to_b);
        let pos = c
            .canonical
            .iter()
            .position(|x| *x == relabeled)
            .ok_or_else(|| canon_err(format!("selected statement not found: {relabeled:?}")))?;
        idx.insert(pos);
    }
    Ok(idx.into_iter().collect())
}

/// `canonicalizeAndGroup` for the base proof: split `document`'s HMAC-canonical
/// statements into mandatory (selected by `mandatory_pointers`) and
/// non-mandatory, and compute `mandatoryHash`.
pub fn canonicalize_and_group(
    document: &Value,
    mandatory_pointers: &[&str],
    hmac_key: &[u8],
) -> Result<GroupedStatements, DataIntegrityError> {
    let c = canonicalize_hmac(document, hmac_key)?;
    let mandatory_indexes = select_indices(&c, mandatory_pointers)?;

    let mandatory_set: BTreeSet<usize> = mandatory_indexes.iter().copied().collect();
    let non_mandatory_indexes: Vec<usize> = (0..c.canonical.len())
        .filter(|i| !mandatory_set.contains(i))
        .collect();

    let mut hasher = Sha256::new();
    for &i in &mandatory_indexes {
        hasher.update(c.canonical[i].as_bytes());
    }
    let mandatory_hash: [u8; 32] = hasher.finalize().into();

    Ok(GroupedStatements {
        canonical: c.canonical,
        mandatory_indexes,
        non_mandatory_indexes,
        mandatory_hash,
    })
}

fn canon_err(e: impl std::fmt::Display) -> DataIntegrityError {
    DataIntegrityError::Canonicalization(e.to_string())
}

/// A parsed base (`0xd95d02`) proof value.
struct BaseProofValue {
    bbs_signature: Vec<u8>,
    bbs_header: Vec<u8>,
    hmac_key: Vec<u8>,
    mandatory_pointers: Vec<String>,
}

/// `parseBaseProofValue`: decode the multibase CBOR base proof value.
fn parse_base_proof_value(proof_value: &str) -> Result<BaseProofValue, DataIntegrityError> {
    let malformed = |m: &str| DataIntegrityError::MalformedProof(m.to_string());
    if !proof_value.starts_with('u') {
        return Err(malformed("proofValue must be multibase base64url ('u')"));
    }
    let (_base, bytes) =
        multibase::decode(proof_value).map_err(|e| malformed(&format!("multibase: {e}")))?;
    if bytes.len() < 3 || bytes[..3] != CBOR_PREFIX_BASE {
        return Err(malformed("proofValue is not a bbs-2023 base proof"));
    }
    let value: ciborium::Value =
        ciborium::from_reader(&bytes[3..]).map_err(|e| malformed(&format!("CBOR: {e}")))?;
    let arr = value
        .as_array()
        .ok_or_else(|| malformed("base proofValue must be a CBOR array"))?;
    if arr.len() != 5 {
        return Err(malformed("base proofValue must have 5 elements"));
    }
    let bytes_at = |i: usize, what: &str| {
        arr[i]
            .as_bytes()
            .cloned()
            .ok_or_else(|| malformed(&format!("{what} must be bytes")))
    };
    let mandatory_pointers = arr[4]
        .as_array()
        .ok_or_else(|| malformed("mandatoryPointers must be an array"))?
        .iter()
        .map(|p| {
            p.as_text()
                .map(str::to_string)
                .ok_or_else(|| malformed("mandatory pointer must be text"))
        })
        .collect::<Result<_, _>>()?;
    Ok(BaseProofValue {
        bbs_signature: bytes_at(0, "bbsSignature")?,
        bbs_header: bytes_at(1, "bbsHeader")?,
        hmac_key: bytes_at(3, "hmacKey")?,
        mandatory_pointers,
    })
}

/// Create a `bbs-2023` **derived proof** (holder side), selectively disclosing
/// the claims under `selective_pointers` (plus the issuer's mandatory ones).
///
/// `base_document` is the issuer's base-proof VC; `pk` is the issuer's BBS
/// public key; `presentation_header` is the verifier's nonce. Returns the
/// disclosed reveal document with a derived `proof`.
pub fn create_derived_proof(
    base_document: &Value,
    selective_pointers: &[&str],
    presentation_header: &[u8],
    pk: &bbs::PublicKey,
) -> Result<Value, DataIntegrityError> {
    let malformed = |m: &str| DataIntegrityError::MalformedProof(m.to_string());
    let proof = base_document
        .get("proof")
        .ok_or_else(|| malformed("base document has no proof"))?;
    let base = parse_base_proof_value(
        proof
            .get("proofValue")
            .and_then(Value::as_str)
            .ok_or_else(|| malformed("proof has no proofValue"))?,
    )?;

    let mut document = base_document.clone();
    document
        .as_object_mut()
        .ok_or_else(|| malformed("document must be an object"))?
        .remove("proof");

    let mandatory_ptrs: Vec<&str> = base.mandatory_pointers.iter().map(String::as_str).collect();
    let combined_ptrs: Vec<&str> = mandatory_ptrs
        .iter()
        .copied()
        .chain(selective_pointers.iter().copied())
        .collect();

    // Group the full document and compute the index sets.
    let c = canonicalize_hmac(&document, &base.hmac_key)?;
    let mandatory_indexes = select_indices(&c, &mandatory_ptrs)?;
    let selective_indexes = select_indices(&c, selective_pointers)?;
    let combined_indexes = select_indices(&c, &combined_ptrs)?;

    let mandatory_set: BTreeSet<usize> = mandatory_indexes.iter().copied().collect();
    let selective_set: BTreeSet<usize> = selective_indexes.iter().copied().collect();
    let non_mandatory_indexes: Vec<usize> = (0..c.canonical.len())
        .filter(|i| !mandatory_set.contains(i))
        .collect();

    // Mandatory indices relative to the revealed (combined) statement set.
    let adj_mandatory: Vec<usize> = mandatory_indexes
        .iter()
        .map(|m| {
            combined_indexes
                .iter()
                .position(|x| x == m)
                .expect("mandatory ⊆ combined")
        })
        .collect();
    // Selectively-disclosed indices relative to the non-mandatory message list
    // (these are the BBS proof's disclosed indexes).
    let adj_selective: Vec<usize> = non_mandatory_indexes
        .iter()
        .enumerate()
        .filter(|(_, nm)| selective_set.contains(nm))
        .map(|(pos, _)| pos)
        .collect();

    // BBS proof over the non-mandatory messages, disclosing the selective ones.
    let non_mandatory: Vec<&str> = non_mandatory_indexes
        .iter()
        .map(|&i| c.canonical[i].as_str())
        .collect();
    let messages: Vec<&[u8]> = non_mandatory.iter().map(|s| s.as_bytes()).collect();
    let signature = bbs::Signature::from_bytes(&base.bbs_signature)
        .map_err(|e| malformed(&format!("decode bbsSignature: {e}")))?;
    let bbs_proof = bbs::proof_gen(
        pk,
        &signature,
        &base.bbs_header,
        presentation_header,
        &messages,
        &adj_selective,
    )
    .map_err(DataIntegrityError::signing)?;

    // Derived label map: reveal-document c14n labels → original bK labels.
    let label_map = build_derived_label_map(&c, &combined_ptrs)?;

    let proof_value = serialize_derived_proof_value(
        bbs_proof.to_bytes(),
        &label_map,
        &adj_mandatory,
        &adj_selective,
        presentation_header,
    )?;

    // Reveal document = the disclosed sub-document + the derived proof.
    let mut reveal = select_json_ld(&document, &combined_ptrs)
        .ok_or_else(|| malformed("empty reveal selection"))?;
    let mut proof_obj = proof.clone();
    proof_obj
        .as_object_mut()
        .ok_or_else(|| malformed("proof must be an object"))?
        .insert("proofValue".to_string(), Value::String(proof_value));
    reveal
        .as_object_mut()
        .ok_or_else(|| malformed("reveal must be an object"))?
        .insert("proof".to_string(), proof_obj);
    Ok(reveal)
}

/// Build the derived proof's label map (`reveal c14nN → original bM`) by
/// canonicalizing the skolemized reveal selection and composing through the
/// full document's `input → bM` map.
fn build_derived_label_map(
    c: &CanonicalizedHmac,
    combined_ptrs: &[&str],
) -> Result<BTreeMap<String, String>, DataIntegrityError> {
    let selection =
        select_json_ld(&c.skolemized, combined_ptrs).ok_or_else(|| canon_err("empty selection"))?;
    let sel_nquads = to_deskolemized_nquads(&selection)?;
    let joined: String = sel_nquads.concat();
    let dataset = nquads::parse(&joined).map_err(canon_err)?;
    let (_canonical, reveal_input_to_c14n) =
        rdfc1::canonicalize_with_label_map(&dataset).map_err(canon_err)?;

    let mut label_map = BTreeMap::new();
    for (reveal_input, reveal_c14n) in &reveal_input_to_c14n {
        if let Some(b) = c.input_to_b.get(reveal_input) {
            label_map.insert(reveal_c14n.clone(), b.clone());
        }
    }
    Ok(label_map)
}

/// `serializeDisclosureProofValue`: `multibase("u" + 0xd95d03 + CBOR([bbsProof,
/// compressedLabelMap, mandatoryIndexes, selectiveIndexes, presentationHeader]))`.
fn serialize_derived_proof_value(
    bbs_proof: &[u8],
    label_map: &BTreeMap<String, String>,
    mandatory_indexes: &[usize],
    selective_indexes: &[usize],
    presentation_header: &[u8],
) -> Result<String, DataIntegrityError> {
    let malformed = |m: &str| DataIntegrityError::MalformedProof(m.to_string());
    // Compress `c14nN → bM` to a CBOR integer→integer map.
    let mut compressed = Vec::with_capacity(label_map.len());
    for (k, v) in label_map {
        let n: i64 = k
            .strip_prefix("c14n")
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| malformed("label map key"))?;
        let m: i64 = v
            .strip_prefix('b')
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| malformed("label map value"))?;
        compressed.push((
            ciborium::Value::Integer(n.into()),
            ciborium::Value::Integer(m.into()),
        ));
    }
    let index_array = |idx: &[usize]| {
        ciborium::Value::Array(
            idx.iter()
                .map(|&i| ciborium::Value::Integer((i as i64).into()))
                .collect(),
        )
    };
    let payload = ciborium::Value::Array(vec![
        ciborium::Value::Bytes(bbs_proof.to_vec()),
        ciborium::Value::Map(compressed),
        index_array(mandatory_indexes),
        index_array(selective_indexes),
        ciborium::Value::Bytes(presentation_header.to_vec()),
    ]);
    let mut buf = CBOR_PREFIX_DERIVED.to_vec();
    ciborium::into_writer(&payload, &mut buf)
        .map_err(|e| malformed(&format!("CBOR encode: {e}")))?;
    Ok(multibase::encode(multibase::Base::Base64Url, &buf))
}

/// `proofHash = SHA-256(RDFC-1.0(proofConfig))`.
///
/// `proof_config` is the proof options as a JSON-LD object (its `@context` must
/// match the secured document's). Returns the 32-byte hash.
pub fn proof_hash(proof_config: &Value) -> Result<[u8; 32], DataIntegrityError> {
    let dataset = jsonld::expand_and_to_rdf(proof_config).map_err(canon_err)?;
    let canonical = rdfc1::canonicalize(&dataset).map_err(canon_err)?;
    Ok(Sha256::digest(canonical.as_bytes()).into())
}

/// Apply the `bbs-2023` HMAC blank-node label map to a JSON-LD document and
/// return the relabeled, re-sorted canonical N-Quads.
///
/// Algorithm (vc-di-bbs / vc-di-ecdsa `createShuffledIdLabelMapFunction`):
/// 1. RDFC-1.0 canonicalize → `c14n0, c14n1, …` labels.
/// 2. For each canonical label (the bare `c14nN` string), compute
///    `HMAC-SHA-256(hmac_key, label)`.
/// 3. Sort the labels by the multibase-base64url-no-pad encoding of the digest
///    (`u…`), then assign `b0, b1, …` in that order.
/// 4. Relabel the canonical N-Quads and re-sort the lines.
pub fn hmac_canonicalize(document: &Value, hmac_key: &[u8]) -> Result<String, DataIntegrityError> {
    let dataset = jsonld::expand_and_to_rdf(document).map_err(canon_err)?;
    let canonical = rdfc1::canonicalize(&dataset).map_err(canon_err)?;
    let label_map = hmac_label_map(&canonical, hmac_key)?;
    Ok(relabel_and_sort(&canonical, &label_map))
}

/// Build the `c14nN → bM` label map by HMAC-and-sort.
fn hmac_label_map(
    canonical: &str,
    hmac_key: &[u8],
) -> Result<BTreeMap<String, String>, DataIntegrityError> {
    // Distinct canonical labels (`c14n0`, `c14n1`, …) in lexicographic order.
    let labels = distinct_c14n_labels(canonical);

    // HMAC each label; the sort key is the multibase-base64url-no-pad digest.
    let mut keyed: Vec<(String, String)> = labels
        .into_iter()
        .map(|label| {
            let mut mac = HmacSha256::new_from_slice(hmac_key)
                .map_err(|e| canon_err(format!("HMAC key: {e}")))?;
            mac.update(label.as_bytes());
            let digest = mac.finalize().into_bytes();
            let sort_key = multibase::encode(multibase::Base::Base64Url, digest);
            Ok((sort_key, label))
        })
        .collect::<Result<_, DataIntegrityError>>()?;
    keyed.sort();

    Ok(keyed
        .into_iter()
        .enumerate()
        .map(|(i, (_, label))| (label, format!("b{i}")))
        .collect())
}

/// Distinct `c14nN` blank-node labels appearing in canonical N-Quads.
fn distinct_c14n_labels(canonical: &str) -> Vec<String> {
    let mut set = std::collections::BTreeSet::new();
    for line in canonical.lines() {
        let mut rest = line;
        while let Some(pos) = rest.find("_:c14n") {
            let after = &rest[pos + 2..]; // skip "_:"
            let end = after
                .char_indices()
                .find(|(_, c)| !(c.is_ascii_alphanumeric()))
                .map(|(i, _)| i)
                .unwrap_or(after.len());
            set.insert(after[..end].to_string());
            rest = &after[end..];
        }
    }
    set.into_iter().collect()
}

/// Replace each `_:c14nN` with `_:bM` per `label_map`, then re-sort the lines.
fn relabel_and_sort(canonical: &str, label_map: &BTreeMap<String, String>) -> String {
    let mut lines: Vec<String> = canonical
        .lines()
        .map(|line| {
            let mut out = String::with_capacity(line.len() + 1);
            let mut rest = line;
            while let Some(pos) = rest.find("_:c14n") {
                out.push_str(&rest[..pos]);
                let after = &rest[pos + 2..]; // after "_:"
                let end = after
                    .char_indices()
                    .find(|(_, c)| !c.is_ascii_alphanumeric())
                    .map(|(i, _)| i)
                    .unwrap_or(after.len());
                let label = &after[..end];
                out.push_str("_:");
                out.push_str(label_map.get(label).map(String::as_str).unwrap_or(label));
                rest = &after[end..];
            }
            out.push_str(rest);
            out.push('\n');
            out
        })
        .collect();
    lines.sort();
    lines.concat()
}

// --- skolemization, selection, grouping helpers ----------------------------

/// Split a joined N-Quads string into lines, each terminated with `\n`.
fn lines_with_newline(joined: &str) -> Vec<String> {
    joined
        .lines()
        .map(|l| {
            let mut s = l.to_string();
            s.push('\n');
            s
        })
        .collect()
}

/// Skolemize a compact JSON-LD document: give every node object that lacks an
/// id a stable `urn:bnid:` `@id`. Self-consistent labeling is sufficient —
/// grouping matches statements by content against the canonical set, so the
/// exact skolem ids never leak into the output.
fn skolemize_compact(document: &Value) -> Value {
    let mut counter = 0u64;
    let mut out = document.clone();
    skolemize_value(&mut out, &mut counter);
    out
}

fn skolemize_value(v: &mut Value, counter: &mut u64) {
    match v {
        Value::Object(map) => {
            // Value objects are literals, not nodes.
            if map.contains_key("@value") {
                return;
            }
            for (k, val) in map.iter_mut() {
                // Skip JSON-LD keywords except @list, whose members are nodes.
                if k.starts_with('@') && k != "@list" {
                    continue;
                }
                skolemize_value(val, counter);
            }
            if !map.contains_key("@id") && !map.contains_key("id") {
                let id = format!("{URN_BNID}_skolem_{counter}");
                *counter += 1;
                map.insert("@id".to_string(), Value::String(id));
            }
        }
        Value::Array(arr) => {
            for item in arr.iter_mut() {
                skolemize_value(item, counter);
            }
        }
        _ => {}
    }
}

/// Convert a (skolemized) JSON-LD document to deskolemized N-Quads: expand →
/// RDF → serialize, then map `<urn:bnid:X>` back to blank nodes `_:X`. Each
/// returned line is newline-terminated.
fn to_deskolemized_nquads(document: &Value) -> Result<Vec<String>, DataIntegrityError> {
    let dataset = jsonld::expand_and_to_rdf(document).map_err(canon_err)?;
    let mut lines: Vec<String> = dataset
        .quads()
        .iter()
        .map(|q| {
            let mut line = deskolemize_line(&nquads::serialize_quad(q));
            line.push('\n');
            line
        })
        .collect();
    lines.sort();
    Ok(lines)
}

/// Replace every `<urn:bnid:X>` IRI in an N-Quad line with the blank node `_:X`.
fn deskolemize_line(line: &str) -> String {
    let needle = format!("<{URN_BNID}");
    let mut out = String::with_capacity(line.len());
    let mut rest = line;
    while let Some(pos) = rest.find(&needle) {
        out.push_str(&rest[..pos]);
        let after = &rest[pos + needle.len()..];
        let end = after.find('>').unwrap_or(after.len());
        out.push_str("_:");
        out.push_str(&after[..end]);
        rest = if end < after.len() {
            &after[end + 1..]
        } else {
            ""
        };
    }
    out.push_str(rest);
    out
}

/// Relabel blank nodes `_:X` in an N-Quad line per `label_map` (`X → bK`).
fn relabel_blank_line(line: &str, label_map: &BTreeMap<String, String>) -> String {
    let mut out = String::with_capacity(line.len());
    let mut rest = line;
    while let Some(pos) = rest.find("_:") {
        out.push_str(&rest[..pos]);
        let after = &rest[pos + 2..];
        // A blank-node label runs until whitespace.
        let end = after
            .find(|c: char| c.is_whitespace())
            .unwrap_or(after.len());
        let label = &after[..end];
        out.push_str("_:");
        out.push_str(label_map.get(label).map(String::as_str).unwrap_or(label));
        rest = &after[end..];
    }
    out.push_str(rest);
    out
}

/// Parse an RFC-6901 JSON pointer into path segments (with `~0`/`~1` unescaped).
fn parse_pointer(pointer: &str) -> Vec<String> {
    pointer
        .split('/')
        .skip(1)
        .map(|p| p.replace("~1", "/").replace("~0", "~"))
        .collect()
}

/// `selectJsonLd` (vc-di-ecdsa): build a sub-document containing only the values
/// at `pointers`, always carrying `@context`, non-blank ids, and `type`.
fn select_json_ld(document: &Value, pointers: &[&str]) -> Option<Value> {
    if pointers.is_empty() {
        return None;
    }
    let mut selection = Map::new();
    if let Some(ctx) = document.get("@context") {
        selection.insert("@context".to_string(), ctx.clone());
    }
    init_selection(&mut selection, document);

    let mut selection = Value::Object(selection);
    for pointer in pointers {
        let paths = parse_pointer(pointer);
        if paths.is_empty() {
            return Some(document.clone());
        }
        select_path(document, &paths, &mut selection);
    }
    compact_arrays(&mut selection);
    Some(selection)
}

/// Remove the null placeholders introduced when selecting sparse array indices.
fn compact_arrays(v: &mut Value) {
    match v {
        Value::Array(arr) => {
            arr.retain(|x| !x.is_null());
            arr.iter_mut().for_each(compact_arrays);
        }
        Value::Object(map) => map.values_mut().for_each(compact_arrays),
        _ => {}
    }
}

/// Carry over `@id`/`id` (when not a blank node) and `type`/`@type`.
fn init_selection(selection: &mut Map<String, Value>, source: &Value) {
    for id_key in ["@id", "id"] {
        if let Some(id) = source.get(id_key).and_then(Value::as_str)
            && !id.starts_with("_:")
        {
            selection.insert(id_key.to_string(), Value::String(id.to_string()));
        }
    }
    for type_key in ["@type", "type"] {
        if let Some(t) = source.get(type_key) {
            selection.insert(type_key.to_string(), t.clone());
        }
    }
}

/// Walk one pointer's path (recursively), materializing intermediate node/array
/// selections and copying the targeted leaf value.
fn select_path(source: &Value, paths: &[String], selection: &mut Value) {
    let path = &paths[0];
    let child_source = match index_value(source, path) {
        Some(v) => v,
        None => return, // pointer does not match; skip
    };

    if paths.len() == 1 {
        let new_value = match child_source {
            Value::Object(obj) => {
                // Merge already-selected fields (e.g. id/type) with the value.
                let mut merged = index_value(selection, path)
                    .and_then(Value::as_object)
                    .cloned()
                    .unwrap_or_default();
                for (k, v) in obj {
                    merged.insert(k.clone(), v.clone());
                }
                Value::Object(merged)
            }
            other => other.clone(),
        };
        set_index(selection, path, new_value);
    } else {
        ensure_intermediate(selection, path, child_source);
        let child_sel = index_value_mut(selection, path).expect("intermediate exists");
        select_path(child_source, &paths[1..], child_sel);
    }
}

/// Index a JSON value by an object key or array index path segment.
fn index_value<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    match value {
        Value::Object(map) => map.get(path),
        Value::Array(arr) => path.parse::<usize>().ok().and_then(|i| arr.get(i)),
        _ => None,
    }
}

fn index_value_mut<'a>(value: &'a mut Value, path: &str) -> Option<&'a mut Value> {
    match value {
        Value::Object(map) => map.get_mut(path),
        Value::Array(arr) => path.parse::<usize>().ok().and_then(|i| arr.get_mut(i)),
        _ => None,
    }
}

/// Set `selected[path] = new_value`, growing arrays with nulls as needed.
fn set_index(selected: &mut Value, path: &str, new_value: Value) {
    match selected {
        Value::Object(map) => {
            map.insert(path.to_string(), new_value);
        }
        Value::Array(arr) => {
            if let Ok(i) = path.parse::<usize>() {
                while arr.len() <= i {
                    arr.push(Value::Null);
                }
                arr[i] = new_value;
            }
        }
        _ => {}
    }
}

/// Ensure `selected[path]` is an initialized container matching `source` (an
/// array placeholder or a node-selection object carrying id/type).
fn ensure_intermediate(selected: &mut Value, path: &str, source: &Value) {
    if index_value(selected, path).is_some() {
        return;
    }
    let init = if source.is_array() {
        Value::Array(Vec::new())
    } else {
        let mut node = Map::new();
        init_selection(&mut node, source);
        Value::Object(node)
    };
    set_index(selected, path, init);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> String {
        std::fs::read_to_string(format!(
            "{}/tests/fixtures/vc-di-bbs/{}",
            env!("CARGO_MANIFEST_DIR"),
            name
        ))
        .unwrap()
    }

    fn json(name: &str) -> Value {
        serde_json::from_str(&fixture(name)).unwrap()
    }

    #[test]
    fn proof_hash_matches_w3c_vector() {
        let got = proof_hash(&json("addProofConfig.json")).unwrap();
        let expected = json("addHashData.json")["proofHash"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(hex_lower(&got), expected);
    }

    #[test]
    fn hmac_canonicalize_matches_w3c_vector() {
        let key_hex = json("BBSKeyMaterial.json")["hmacKeyString"]
            .as_str()
            .unwrap()
            .to_string();
        let key = hex_decode(&key_hex);
        let got = hmac_canonicalize(&json("windDoc.json"), &key).unwrap();
        let expected: String =
            serde_json::from_str::<Vec<String>>(&fixture("addBaseDocHMACCanon.json"))
                .unwrap()
                .concat();
        assert_eq!(
            got, expected,
            "HMAC canonicalization diverges from the W3C vc-di-bbs vector"
        );
    }

    #[test]
    fn canonicalize_and_group_matches_w3c_vector() {
        let key = hex_decode(
            json("BBSKeyMaterial.json")["hmacKeyString"]
                .as_str()
                .unwrap(),
        );
        let transform = json("addBaseTransform.json");
        let pointers: Vec<String> = transform["mandatoryPointers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p.as_str().unwrap().to_string())
            .collect();
        let refs: Vec<&str> = pointers.iter().map(String::as_str).collect();

        let grouped = canonicalize_and_group(&json("windDoc.json"), &refs, &key).unwrap();

        let idxs = |v: &Value| -> Vec<usize> {
            v["value"]
                .as_array()
                .unwrap()
                .iter()
                .map(|e| e[0].as_u64().unwrap() as usize)
                .collect()
        };
        assert_eq!(
            grouped.mandatory_indexes,
            idxs(&transform["mandatory"]),
            "mandatory indices"
        );
        assert_eq!(
            grouped.non_mandatory_indexes,
            idxs(&transform["nonMandatory"]),
            "non-mandatory indices"
        );
        assert_eq!(
            hex_lower(&grouped.mandatory_hash),
            json("addHashData.json")["mandatoryHash"].as_str().unwrap(),
            "mandatoryHash"
        );
    }

    #[test]
    fn create_base_proof_value_matches_w3c_vector() {
        let km = json("BBSKeyMaterial.json");
        let sk_bytes: [u8; 32] = hex_decode(km["privateKeyHex"].as_str().unwrap())
            .try_into()
            .unwrap();
        let pk_bytes: [u8; 96] = hex_decode(km["publicKeyHex"].as_str().unwrap())
            .try_into()
            .unwrap();
        let sk = bbs::SecretKey::from_bytes(&sk_bytes).unwrap();
        let pk = bbs::PublicKey::from_bytes(&pk_bytes).unwrap();
        let hmac_key = hex_decode(km["hmacKeyString"].as_str().unwrap());

        let pointers: Vec<String> = json("addBaseTransform.json")["mandatoryPointers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p.as_str().unwrap().to_string())
            .collect();
        let refs: Vec<&str> = pointers.iter().map(String::as_str).collect();

        let proof_value = create_base_proof_value(
            &json("windDoc.json"),
            &json("addProofConfig.json"),
            &refs,
            &sk,
            &pk,
            &hmac_key,
        )
        .unwrap();

        let expected = json("addSignedSDBase.json")["proof"]["proofValue"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(
            proof_value, expected,
            "base proofValue diverges from the W3C vc-di-bbs vector"
        );
    }

    #[test]
    fn serialize_pseudonym_base_proof_value_matches_w3c_vector() {
        // Gate the 0xd95d08 framing byte-exact from the published base signature
        // components (independent of the AAMVA-document canonicalization).
        let raw = json("pseudonym/addRawBaseSignatureInfo.json");
        let h = |k: &str| hex_decode(raw[k].as_str().unwrap());
        let pointers: Vec<String> = raw["mandatoryPointers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p.as_str().unwrap().to_string())
            .collect();
        let refs: Vec<&str> = pointers.iter().map(String::as_str).collect();

        let proof_value = serialize_pseudonym_base_proof_value(
            &h("bbsSignature"),
            &h("bbsHeader"),
            &h("publicKey"),
            &h("hmacKey"),
            &refs,
            &h("signerNymEntropyHex"),
        )
        .unwrap();

        let expected = json("pseudonym/addSignedSDBase.json")["proof"]["proofValue"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(
            proof_value, expected,
            "pseudonym base 0xd95d08 framing diverges from the W3C vc-di-bbs vector"
        );
    }

    #[test]
    fn verify_derived_proof_accepts_w3c_reference_proof() {
        let pk_bytes: [u8; 96] = hex_decode(
            json("BBSKeyMaterial.json")["publicKeyHex"]
                .as_str()
                .unwrap(),
        )
        .try_into()
        .unwrap();
        let pk = bbs::PublicKey::from_bytes(&pk_bytes).unwrap();

        let reveal = json("derivedRevealDocument.json");
        let ok = verify_derived_proof(&reveal, &pk).unwrap();
        assert!(ok, "must verify the reference-generated derived proof");
    }

    #[test]
    fn verify_derived_proof_rejects_tampered_claim() {
        let pk_bytes: [u8; 96] = hex_decode(
            json("BBSKeyMaterial.json")["publicKeyHex"]
                .as_str()
                .unwrap(),
        )
        .try_into()
        .unwrap();
        let pk = bbs::PublicKey::from_bytes(&pk_bytes).unwrap();

        let mut reveal = json("derivedRevealDocument.json");
        reveal["credentialSubject"]["sailNumber"] = Value::String("Tampered".into());
        let r = verify_derived_proof(&reveal, &pk);
        assert!(
            !matches!(r, Ok(true)),
            "tampered claim must not verify: {r:?}"
        );
    }

    #[test]
    fn create_derived_proof_matches_w3c_structure_and_round_trips() {
        let pk_bytes: [u8; 96] = hex_decode(
            json("BBSKeyMaterial.json")["publicKeyHex"]
                .as_str()
                .unwrap(),
        )
        .try_into()
        .unwrap();
        let pk = bbs::PublicKey::from_bytes(&pk_bytes).unwrap();
        let ph = hex_decode(
            json("BBSDeriveMaterial.json")["presentationHeaderHex"]
                .as_str()
                .unwrap(),
        );
        let selective: Vec<String> = serde_json::from_value(json("windSelective.json")).unwrap();
        let refs: Vec<&str> = selective.iter().map(String::as_str).collect();

        // Derive from the reference base-proof document.
        let reveal = create_derived_proof(&json("addSignedSDBase.json"), &refs, &ph, &pk).unwrap();

        // Round-trip: our own verifier accepts our derived proof.
        assert!(
            verify_derived_proof(&reveal, &pk).unwrap(),
            "round-trip derive→verify must hold"
        );

        // Structural match against the W3C disclosure-data vector (the BBS proof
        // bytes themselves are randomized, so we check the deterministic parts).
        let parsed =
            parse_derived_proof_value(reveal["proof"]["proofValue"].as_str().unwrap()).unwrap();
        let dd = json("derivedDisclosureData.json");

        let exp_label: BTreeMap<String, String> = dd["labelMap"]["value"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| {
                (
                    e[0].as_str().unwrap().to_string(),
                    e[1].as_str().unwrap().to_string(),
                )
            })
            .collect();
        assert_eq!(parsed.label_map, exp_label, "derived label map");

        let usizes = |v: &Value| -> Vec<usize> {
            v.as_array()
                .unwrap()
                .iter()
                .map(|x| x.as_u64().unwrap() as usize)
                .collect()
        };
        assert_eq!(
            parsed.mandatory_indexes,
            usizes(&dd["mandatoryIndexes"]),
            "adjusted mandatory indexes"
        );
        assert_eq!(
            parsed.selective_indexes,
            usizes(&dd["adjSelectiveIndexes"]),
            "adjusted selective indexes"
        );
        assert_eq!(parsed.presentation_header, ph, "presentation header");
    }

    #[test]
    fn end_to_end_sign_derive_verify_round_trip() {
        // Full document-level vc-di-bbs round trip with a fresh HMAC key and
        // arbitrary mandatory/selective pointers (not the vector's), exercising
        // issuer → holder → verifier entirely through our own code.
        let km = json("BBSKeyMaterial.json");
        let sk = bbs::SecretKey::from_bytes(
            &hex_decode(km["privateKeyHex"].as_str().unwrap())
                .try_into()
                .unwrap(),
        )
        .unwrap();
        let pk = bbs::PublicKey::from_bytes(
            &hex_decode(km["publicKeyHex"].as_str().unwrap())
                .try_into()
                .unwrap(),
        )
        .unwrap();
        let hmac_key = [0x42u8; 32];

        let doc = json("windDoc.json");
        let mandatory = ["/issuer", "/credentialSubject/sailNumber"];
        let base = sign_base_document(
            &doc,
            &mandatory,
            "did:key:zHolder#bbs",
            "2024-01-01T00:00:00Z",
            &sk,
            &pk,
            &hmac_key,
        )
        .unwrap();
        assert_eq!(base["proof"]["cryptosuite"], "bbs-2023");

        // Holder discloses one board selectively.
        let reveal =
            create_derived_proof(&base, &["/credentialSubject/boards/0"], b"nonce-xyz", &pk)
                .unwrap();

        // Verifier accepts; mandatory + disclosed present, others hidden.
        assert!(verify_derived_proof(&reveal, &pk).unwrap());
        let cs = &reveal["credentialSubject"];
        assert_eq!(cs["sailNumber"], "Earth101"); // mandatory
        assert!(
            cs["boards"].as_array().unwrap()[0]
                .get("boardName")
                .is_some()
        ); // disclosed
        assert!(
            cs.get("sails").is_none(),
            "undisclosed sails must be absent"
        );

        // Tampering with a disclosed claim fails.
        let mut bad = reveal.clone();
        bad["credentialSubject"]["sailNumber"] = Value::String("Mallory".into());
        assert!(!matches!(verify_derived_proof(&bad, &pk), Ok(true)));
    }

    fn hex_lower(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
