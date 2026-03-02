use sha2::{Digest, Sha256};

use crate::model::{GraphLabel, Object, Quad, Subject};
use crate::nquads;

/// Compute the first-degree hash for a blank node.
///
/// For each quad referencing this blank node:
/// - Replace the blank node itself with `_:a`
/// - Replace all other blank nodes with `_:z`
///
/// Then sort the resulting N-Quads lines, join, and SHA-256 hash.
pub fn hash_first_degree_quads(blank_node_id: &str, quads: &[&Quad]) -> String {
    let mut nquad_lines: Vec<String> = Vec::with_capacity(quads.len());

    for quad in quads {
        let substituted = substitute_blank_nodes(quad, blank_node_id);
        let line = nquads::serialize_quad(&substituted);
        nquad_lines.push(line);
    }

    nquad_lines.sort();

    let mut hasher = Sha256::new();
    for line in &nquad_lines {
        hasher.update(line.as_bytes());
        hasher.update(b"\n");
    }

    hex::encode(hasher.finalize())
}

/// Substitute blank nodes in a quad:
/// - The target blank node becomes `_:a`
/// - All other blank nodes become `_:z`
fn substitute_blank_nodes(quad: &Quad, target_id: &str) -> Quad {
    let subject = match &quad.subject {
        Subject::Blank(b) => {
            if b.id == target_id {
                Subject::Blank(crate::model::BlankNode::new("a"))
            } else {
                Subject::Blank(crate::model::BlankNode::new("z"))
            }
        }
        other => other.clone(),
    };

    let object = match &quad.object {
        Object::Blank(b) => {
            if b.id == target_id {
                Object::Blank(crate::model::BlankNode::new("a"))
            } else {
                Object::Blank(crate::model::BlankNode::new("z"))
            }
        }
        other => other.clone(),
    };

    let graph = match &quad.graph {
        GraphLabel::Blank(b) => {
            if b.id == target_id {
                GraphLabel::Blank(crate::model::BlankNode::new("a"))
            } else {
                GraphLabel::Blank(crate::model::BlankNode::new("z"))
            }
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

/// Encode bytes as lowercase hex string.
mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        let bytes = bytes.as_ref();
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }
}

pub(crate) use hex::encode as hex_encode;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::*;

    #[test]
    fn single_quad_hash() {
        let quad = Quad::new(
            BlankNode::new("b0"),
            NamedNode::new("http://example.org/p"),
            NamedNode::new("http://example.org/o"),
            GraphLabel::Default,
        );
        let hash = hash_first_degree_quads("b0", &[&quad]);
        // Should be deterministic
        assert_eq!(hash.len(), 64); // SHA-256 hex
        let hash2 = hash_first_degree_quads("b0", &[&quad]);
        assert_eq!(hash, hash2);
    }

    #[test]
    fn substitution_target_vs_other() {
        let quad = Quad::new(
            BlankNode::new("b0"),
            NamedNode::new("http://example.org/p"),
            BlankNode::new("b1"),
            GraphLabel::Default,
        );
        let substituted = substitute_blank_nodes(&quad, "b0");
        assert_eq!(substituted.subject, Subject::Blank(BlankNode::new("a")));
        assert_eq!(substituted.object, Object::Blank(BlankNode::new("z")));
    }
}
