pub mod hash_first_degree;
pub mod hash_ndegree;
pub mod hash_related;
pub mod identifier_issuer;

use std::collections::{BTreeMap, HashMap};

use sha2::{Digest, Sha256};

use crate::error::Result;
use crate::model::{
    BlankNode, Dataset, GraphLabel, Object, Quad, Subject,
};
use crate::nquads;

use hash_first_degree::{hash_first_degree_quads, hex_encode};
use identifier_issuer::IdentifierIssuer;

/// Canonicalize an RDF dataset using RDFC-1.0 and return the canonical N-Quads string.
///
/// Implements the W3C RDF Dataset Canonicalization algorithm (RDFC-1.0).
pub fn canonicalize(dataset: &Dataset) -> Result<String> {
    let quads = dataset.quads();

    // Step 1: Build blank_node_to_quads map
    let mut blank_node_to_quads: HashMap<String, Vec<&Quad>> = HashMap::new();
    for quad in quads {
        for bn_id in quad_blank_node_ids(quad) {
            blank_node_to_quads
                .entry(bn_id)
                .or_default()
                .push(quad);
        }
    }

    // If no blank nodes, just serialize and sort
    if blank_node_to_quads.is_empty() {
        return Ok(serialize_sorted(quads));
    }

    // Step 2: Compute first-degree hashes
    // Map: hash -> list of blank node IDs with that hash
    let mut hash_to_blank_nodes: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (bn_id, bn_quads) in &blank_node_to_quads {
        let hash = hash_first_degree_quads(bn_id, bn_quads);
        hash_to_blank_nodes
            .entry(hash)
            .or_default()
            .push(bn_id.clone());
    }

    // Step 3: Issue canonical IDs for unique first-degree hashes
    let mut canonical_issuer = IdentifierIssuer::new("c14n");
    // Process in sorted hash order (BTreeMap gives us this)
    for (hash, bn_ids) in &hash_to_blank_nodes {
        if bn_ids.len() == 1 {
            tracing::debug!(
                hash = %hash,
                blank_node = %bn_ids[0],
                "unique first-degree hash"
            );
            canonical_issuer.issue(&bn_ids[0]);
        }
    }

    // Step 4: Run N-degree algorithm for non-unique hashes
    for bn_ids in hash_to_blank_nodes.values() {
        if bn_ids.len() <= 1 {
            continue;
        }

        let mut hash_path_list: Vec<(String, IdentifierIssuer)> = Vec::new();

        for bn_id in bn_ids {
            if canonical_issuer.is_issued(bn_id) {
                continue;
            }

            let temp_issuer = IdentifierIssuer::new("b");
            let mut temp_issuer = temp_issuer;
            temp_issuer.issue(bn_id);

            let (hash, result_issuer) = hash_ndegree::hash_ndegree_quads(
                bn_id,
                &blank_node_to_quads,
                &canonical_issuer,
                &temp_issuer,
                &hash_to_blank_nodes,
            )?;
            hash_path_list.push((hash, result_issuer));
        }

        // Sort by hash
        hash_path_list.sort_by(|a, b| a.0.cmp(&b.0));

        // Issue canonical identifiers in order
        for (_hash, result_issuer) in hash_path_list {
            for existing in result_issuer.issued_order() {
                canonical_issuer.issue(existing);
            }
        }
    }

    // Step 5: Relabel all blank nodes
    let relabeled: Vec<Quad> = quads
        .iter()
        .map(|q| relabel_quad(q, &canonical_issuer))
        .collect();

    // Step 6: Serialize and sort
    Ok(serialize_sorted(&relabeled))
}

/// Canonicalize and return the SHA-256 hash of the canonical N-Quads.
pub fn canonicalize_and_hash(dataset: &Dataset) -> Result<[u8; 32]> {
    let canonical = canonicalize(dataset)?;
    let hash = Sha256::digest(canonical.as_bytes());
    Ok(hash.into())
}

/// Canonicalize and return the SHA-256 hash as a hex string.
pub fn canonicalize_and_hash_hex(dataset: &Dataset) -> Result<String> {
    let hash = canonicalize_and_hash(dataset)?;
    Ok(hex_encode(hash))
}

/// Serialize quads to N-Quads, sort lines, and join.
fn serialize_sorted(quads: &[Quad]) -> String {
    let mut lines: Vec<String> = quads
        .iter()
        .map(|q| {
            let mut line = nquads::serialize_quad(q);
            line.push('\n');
            line
        })
        .collect();
    lines.sort();
    lines.join("")
}

/// Collect all blank node IDs referenced by a quad.
fn quad_blank_node_ids(quad: &Quad) -> Vec<String> {
    let mut ids = Vec::new();
    if let Subject::Blank(b) = &quad.subject {
        ids.push(b.id.clone());
    }
    if let Object::Blank(b) = &quad.object {
        ids.push(b.id.clone());
    }
    if let GraphLabel::Blank(b) = &quad.graph {
        ids.push(b.id.clone());
    }
    ids
}

/// Relabel blank nodes in a quad using the canonical issuer.
fn relabel_quad(quad: &Quad, issuer: &IdentifierIssuer) -> Quad {
    let subject = match &quad.subject {
        Subject::Blank(b) => {
            Subject::Blank(BlankNode::new(
                issuer.get(&b.id).unwrap_or(&b.id),
            ))
        }
        other => other.clone(),
    };

    let object = match &quad.object {
        Object::Blank(b) => {
            Object::Blank(BlankNode::new(
                issuer.get(&b.id).unwrap_or(&b.id),
            ))
        }
        other => other.clone(),
    };

    let graph = match &quad.graph {
        GraphLabel::Blank(b) => {
            GraphLabel::Blank(BlankNode::new(
                issuer.get(&b.id).unwrap_or(&b.id),
            ))
        }
        other => other.clone(),
    };

    Quad {
        subject,
        predicate: quad.predicate.clone(),
        object,
        graph,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::*;

    #[test]
    fn canonicalize_no_blank_nodes() {
        let mut ds = Dataset::new();
        ds.add(Quad::new(
            NamedNode::new("http://example.org/s2"),
            NamedNode::new("http://example.org/p"),
            NamedNode::new("http://example.org/o2"),
            GraphLabel::Default,
        ));
        ds.add(Quad::new(
            NamedNode::new("http://example.org/s1"),
            NamedNode::new("http://example.org/p"),
            NamedNode::new("http://example.org/o1"),
            GraphLabel::Default,
        ));

        let result = canonicalize(&ds).unwrap();
        // Lines should be sorted
        let lines: Vec<&str> = result.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0] < lines[1]);
    }

    #[test]
    fn canonicalize_single_blank_node() {
        let mut ds = Dataset::new();
        ds.add(Quad::new(
            BlankNode::new("b0"),
            NamedNode::new("http://example.org/p"),
            Literal::new("value"),
            GraphLabel::Default,
        ));

        let result = canonicalize(&ds).unwrap();
        assert!(result.contains("_:c14n0"));
        assert!(!result.contains("_:b0"));
    }

    #[test]
    fn canonicalize_deterministic() {
        // Same dataset with different blank node labels should produce same result
        let mut ds1 = Dataset::new();
        ds1.add(Quad::new(
            BlankNode::new("x"),
            NamedNode::new("http://example.org/p"),
            Literal::new("value"),
            GraphLabel::Default,
        ));

        let mut ds2 = Dataset::new();
        ds2.add(Quad::new(
            BlankNode::new("y"),
            NamedNode::new("http://example.org/p"),
            Literal::new("value"),
            GraphLabel::Default,
        ));

        let result1 = canonicalize(&ds1).unwrap();
        let result2 = canonicalize(&ds2).unwrap();
        assert_eq!(result1, result2);
    }

    #[test]
    fn canonicalize_multiple_blank_nodes() {
        let mut ds = Dataset::new();
        ds.add(Quad::new(
            BlankNode::new("b0"),
            NamedNode::new("http://example.org/name"),
            Literal::new("Alice"),
            GraphLabel::Default,
        ));
        ds.add(Quad::new(
            BlankNode::new("b1"),
            NamedNode::new("http://example.org/name"),
            Literal::new("Bob"),
            GraphLabel::Default,
        ));
        ds.add(Quad::new(
            BlankNode::new("b0"),
            NamedNode::new("http://example.org/knows"),
            BlankNode::new("b1"),
            GraphLabel::Default,
        ));

        let result = canonicalize(&ds).unwrap();
        // Should have c14n0 and c14n1
        assert!(result.contains("_:c14n0"));
        assert!(result.contains("_:c14n1"));
        assert!(!result.contains("_:b0"));
        assert!(!result.contains("_:b1"));
    }
}
