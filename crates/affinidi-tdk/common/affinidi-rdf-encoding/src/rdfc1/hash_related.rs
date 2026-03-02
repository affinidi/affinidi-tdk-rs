use sha2::{Digest, Sha256};

use super::hash_first_degree::hex_encode;
use super::identifier_issuer::IdentifierIssuer;

/// Hash Related Blank Node algorithm.
///
/// Builds an input string from:
/// 1. The position of the related node in the quad (s, o, g)
/// 2. The predicate IRI (for s and o positions)
/// 3. The identifier of the related node (canonical, temporary, or first-degree hash)
///
/// Returns the SHA-256 hex hash.
pub fn hash_related_blank_node(
    related_id: &str,
    position: Position,
    predicate_iri: &str,
    canonical_issuer: &IdentifierIssuer,
    temp_issuer: &IdentifierIssuer,
    first_degree_hashes: &std::collections::BTreeMap<String, Vec<String>>,
) -> String {
    // Build the identifier to use for the related node
    let identifier = if let Some(canonical) = canonical_issuer.get(related_id) {
        canonical.to_string()
    } else if let Some(temp) = temp_issuer.get(related_id) {
        temp.to_string()
    } else {
        // Use the first-degree hash
        find_hash_for_blank_node(related_id, first_degree_hashes)
    };

    let mut input = String::new();
    input.push_str(position.as_str());
    if position != Position::Graph {
        input.push('<');
        input.push_str(predicate_iri);
        input.push('>');
    }
    input.push_str("_:");
    input.push_str(&identifier);

    let hash = Sha256::digest(input.as_bytes());
    hex_encode(hash)
}

/// Find the first-degree hash for a blank node by scanning the hash-to-nodes map.
fn find_hash_for_blank_node(
    node_id: &str,
    first_degree_hashes: &std::collections::BTreeMap<String, Vec<String>>,
) -> String {
    for (hash, nodes) in first_degree_hashes {
        if nodes.contains(&node_id.to_string()) {
            return hash.clone();
        }
    }
    // Shouldn't happen if the algorithm is correct
    String::new()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Position {
    Subject,
    Object,
    Graph,
}

impl Position {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Subject => "s",
            Self::Object => "o",
            Self::Graph => "g",
        }
    }
}
