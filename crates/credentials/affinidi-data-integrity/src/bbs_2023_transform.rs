/*!
 * W3C `bbs-2023` transformation primitives (RDF-canonical, interoperable).
 *
 * This is the standards-track replacement for the affinidi-internal statement
 * encoding in [`crate::bbs_2023`]. It implements the
 * [W3C vc-di-bbs](https://www.w3.org/TR/vc-di-bbs/) `bbs-2023` cryptosuite over
 * the conformant RDFC-1.0 canonicalizer in `affinidi-rdf-encoding`.
 *
 * Each step here is pinned byte-for-byte against the official `w3c/vc-di-bbs`
 * `TestVectors/` (see the KATs at the bottom). Implemented so far:
 *
 * - [`proof_hash`] — `proofHash = SHA-256(RDFC(proofConfig))`.
 * - [`hmac_canonicalize`] — the HMAC blank-node label map: canonicalize, HMAC
 *   each `c14n` label, sort by the multibase-base64url digest, relabel
 *   `b0, b1, …`, re-sort.
 *
 * Still to come (tracked): mandatory/selective grouping (`canonicalizeAndGroup`
 * / `selectJsonLd` / skolemize, per vc-di-ecdsa), `mandatoryHash`, BBS signing,
 * and the CBOR `proofValue` (base `0xd95d02` / derived `0xd95d03`).
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

/// `canonicalizeAndGroup` for the base proof: canonicalize `document` with the
/// HMAC label map, then split its statements into mandatory (selected by
/// `mandatory_pointers`) and non-mandatory, and compute `mandatoryHash`.
pub fn canonicalize_and_group(
    document: &Value,
    mandatory_pointers: &[&str],
    hmac_key: &[u8],
) -> Result<GroupedStatements, DataIntegrityError> {
    // 1. Skolemize, deskolemize to N-Quads, canonicalize with the HMAC label map.
    let skolemized = skolemize_compact(document);
    let deskolemized = to_deskolemized_nquads(&skolemized)?;

    let joined: String = deskolemized.iter().cloned().collect();
    let dataset = nquads::parse(&joined).map_err(canon_err)?;
    let (canonical_c14n, input_to_c14n) =
        rdfc1::canonicalize_with_label_map(&dataset).map_err(canon_err)?;

    // c14n -> bK (HMAC shuffle), then compose input -> bK.
    let c14n_to_b = hmac_label_map(&canonical_c14n, hmac_key)?;
    let input_to_b: BTreeMap<String, String> = input_to_c14n
        .iter()
        .filter_map(|(input, c14n)| c14n_to_b.get(c14n).map(|b| (input.clone(), b.clone())))
        .collect();

    let canonical: Vec<String> = lines_with_newline(&relabel_and_sort(&canonical_c14n, &c14n_to_b));

    // 2. Select the mandatory sub-document and find its statements' indices.
    let mut mandatory_indexes: Vec<usize> = Vec::new();
    if !mandatory_pointers.is_empty() {
        let selection = select_json_ld(&skolemized, mandatory_pointers)
            .ok_or_else(|| canon_err("empty mandatory selection"))?;
        let sel_nquads = to_deskolemized_nquads(&selection)?;
        let mut idx = BTreeSet::new();
        for line in &sel_nquads {
            let relabeled = relabel_blank_line(line, &input_to_b);
            match canonical.iter().position(|c| *c == relabeled) {
                Some(pos) => {
                    idx.insert(pos);
                }
                None => {
                    return Err(canon_err(format!(
                        "selected statement not found among canonical statements: {relabeled:?}"
                    )));
                }
            }
        }
        mandatory_indexes = idx.into_iter().collect();
    }

    let mandatory_set: BTreeSet<usize> = mandatory_indexes.iter().copied().collect();
    let non_mandatory_indexes: Vec<usize> = (0..canonical.len())
        .filter(|i| !mandatory_set.contains(i))
        .collect();

    let mut hasher = Sha256::new();
    for &i in &mandatory_indexes {
        hasher.update(canonical[i].as_bytes());
    }
    let mandatory_hash: [u8; 32] = hasher.finalize().into();

    Ok(GroupedStatements {
        canonical,
        mandatory_indexes,
        non_mandatory_indexes,
        mandatory_hash,
    })
}

fn canon_err(e: impl std::fmt::Display) -> DataIntegrityError {
    DataIntegrityError::Canonicalization(e.to_string())
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
