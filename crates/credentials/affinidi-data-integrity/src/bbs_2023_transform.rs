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

use std::collections::BTreeMap;

use affinidi_rdf_encoding::{jsonld, rdfc1};
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::DataIntegrityError;

type HmacSha256 = Hmac<Sha256>;

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
