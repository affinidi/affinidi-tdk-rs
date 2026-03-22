use std::collections::{BTreeMap, HashMap};

use sha2::{Digest, Sha256};

use crate::error::{RdfError, Result};
use crate::model::{GraphLabel, Object, Quad, Subject};

use super::hash_first_degree::hex_encode;
use super::hash_related::{Position, hash_related_blank_node};
use super::identifier_issuer::IdentifierIssuer;

/// Maximum number of permutations to explore before aborting (DoS protection).
const MAX_PERMUTATIONS: usize = 10_000;

/// Hash N-Degree Quads algorithm.
///
/// For blank nodes whose first-degree hashes are non-unique, this recursive algorithm
/// explores the relationships between blank nodes to produce a unique hash.
///
/// Returns `(hash, issuer)` where issuer contains the canonical mappings found.
pub fn hash_ndegree_quads(
    blank_node_id: &str,
    blank_node_to_quads: &HashMap<String, Vec<&Quad>>,
    canonical_issuer: &IdentifierIssuer,
    issuer: &IdentifierIssuer,
    blank_node_to_hash: &HashMap<String, String>,
) -> Result<(String, IdentifierIssuer)> {
    // Create a hash-to-related-blank-nodes map
    let mut hash_to_related: BTreeMap<String, Vec<String>> = BTreeMap::new();

    // Get quads for this blank node
    let quads = blank_node_to_quads
        .get(blank_node_id)
        .map(|v| v.as_slice())
        .unwrap_or_default();

    for quad in quads {
        // Check each position for related blank nodes
        for (related_id, position, predicate) in related_blank_nodes(quad, blank_node_id) {
            let hash = hash_related_blank_node(
                &related_id,
                position,
                predicate,
                canonical_issuer,
                issuer,
                blank_node_to_hash,
            );
            hash_to_related.entry(hash).or_default().push(related_id);
        }
    }

    // Process hash groups in sorted order
    let mut data_to_hash = String::new();
    let mut chosen_issuer = issuer.clone();
    let mut permutation_count: usize = 0;

    for (hash, blank_node_list) in &hash_to_related {
        data_to_hash.push_str(hash);

        // Find the permutation that produces the smallest hash path
        let mut chosen_path = String::new();
        let mut chosen_perm_issuer: Option<IdentifierIssuer> = None;

        // Generate permutations
        let mut perm_indices: Vec<usize> = (0..blank_node_list.len()).collect();
        let mut first = true;

        loop {
            permutation_count += 1;
            if permutation_count > MAX_PERMUTATIONS {
                return Err(RdfError::canonicalization(format!(
                    "exceeded maximum permutations ({MAX_PERMUTATIONS}) — possible DoS"
                )));
            }

            let mut path = String::new();
            let mut path_issuer = chosen_issuer.clone();
            let mut skip = false;

            for &idx in &perm_indices {
                let related = &blank_node_list[idx];

                if canonical_issuer.is_issued(related) {
                    path.push_str(canonical_issuer.get(related).unwrap());
                } else if path_issuer.is_issued(related) {
                    path.push_str(path_issuer.get(related).unwrap());
                } else {
                    // Recursively hash this related blank node
                    let (result_hash, result_issuer) = hash_ndegree_quads(
                        related,
                        blank_node_to_quads,
                        canonical_issuer,
                        &path_issuer,
                        blank_node_to_hash,
                    )?;
                    path_issuer = result_issuer;
                    path.push_str(path_issuer.get(related).unwrap_or(""));
                    path.push('<');
                    path.push_str(&result_hash);
                    path.push('>');
                }

                // Early termination: if path is already larger than chosen, skip
                if !chosen_path.is_empty() && !first && path > chosen_path {
                    skip = true;
                    break;
                }
            }

            if !skip && (chosen_path.is_empty() || path < chosen_path) {
                chosen_path = path;
                chosen_perm_issuer = Some(path_issuer);
            }

            first = false;

            // Generate next permutation (lexicographic order)
            if !next_permutation(&mut perm_indices) {
                break;
            }
        }

        data_to_hash.push_str(&chosen_path);
        if let Some(perm_issuer) = chosen_perm_issuer {
            chosen_issuer = perm_issuer;
        }
    }

    // Issue identifier for this blank node
    chosen_issuer.issue(blank_node_id);

    let hash = Sha256::digest(data_to_hash.as_bytes());
    Ok((hex_encode(hash), chosen_issuer))
}

/// Extract related blank nodes from a quad (blank nodes other than the target).
fn related_blank_nodes<'a>(quad: &'a Quad, target_id: &str) -> Vec<(String, Position, &'a str)> {
    let mut related = Vec::new();

    if let Subject::Blank(b) = &quad.subject
        && b.id != target_id
    {
        related.push((b.id.clone(), Position::Subject, quad.predicate.iri.as_str()));
    }

    if let Object::Blank(b) = &quad.object
        && b.id != target_id
    {
        related.push((b.id.clone(), Position::Object, quad.predicate.iri.as_str()));
    }

    if let GraphLabel::Blank(b) = &quad.graph
        && b.id != target_id
    {
        related.push((b.id.clone(), Position::Graph, ""));
    }

    related
}

/// Generate the next lexicographic permutation in-place. Returns false if no more permutations.
fn next_permutation(arr: &mut [usize]) -> bool {
    let n = arr.len();
    if n <= 1 {
        return false;
    }

    // Find largest i such that arr[i] < arr[i+1]
    let mut i = n - 1;
    while i > 0 && arr[i - 1] >= arr[i] {
        i -= 1;
    }
    if i == 0 {
        return false;
    }
    let i = i - 1;

    // Find largest j such that arr[i] < arr[j]
    let mut j = n - 1;
    while arr[j] <= arr[i] {
        j -= 1;
    }

    arr.swap(i, j);
    arr[i + 1..].reverse();
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permutation_generation() {
        let mut arr = vec![0, 1, 2];
        let mut perms = vec![arr.clone()];
        while next_permutation(&mut arr) {
            perms.push(arr.clone());
        }
        assert_eq!(perms.len(), 6); // 3! = 6
        assert_eq!(
            perms,
            vec![
                vec![0, 1, 2],
                vec![0, 2, 1],
                vec![1, 0, 2],
                vec![1, 2, 0],
                vec![2, 0, 1],
                vec![2, 1, 0],
            ]
        );
    }

    #[test]
    fn permutation_single() {
        let mut arr = vec![0];
        assert!(!next_permutation(&mut arr));
    }
}
