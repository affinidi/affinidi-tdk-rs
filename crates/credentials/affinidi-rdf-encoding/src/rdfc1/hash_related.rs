use std::collections::HashMap;

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
    blank_node_to_hash: &HashMap<String, String>,
) -> String {
    // Build the identifier to use for the related node. Per RDFC-1.0, an
    // *issued* id (canonical or temporary) is used in blank-node form (`_:id`),
    // but when neither issuer has issued one, the related node's first-degree
    // HASH is appended raw — with NO `_:` prefix. Prefixing it changes the hash
    // and silently flips the canonical ordering of symmetric blank nodes.
    let identifier = if let Some(canonical) = canonical_issuer.get(related_id) {
        format!("_:{canonical}")
    } else if let Some(temp) = temp_issuer.get(related_id) {
        format!("_:{temp}")
    } else {
        // First-degree hash via O(1) reverse lookup — appended raw.
        blank_node_to_hash
            .get(related_id)
            .cloned()
            .unwrap_or_default()
    };

    let mut input = String::new();
    input.push_str(position.as_str());
    if position != Position::Graph {
        input.push('<');
        input.push_str(predicate_iri);
        input.push('>');
    }
    input.push_str(&identifier);

    let hash = Sha256::digest(input.as_bytes());
    hex_encode(hash)
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
