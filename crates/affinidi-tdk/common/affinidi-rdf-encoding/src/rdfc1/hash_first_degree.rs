use sha2::{Digest, Sha256};

use crate::model::Quad;
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
        let line = nquads::serialize_quad_substituted(quad, blank_node_id);
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

/// Encode bytes as lowercase hex string using a compile-time lookup table.
mod hex {
    const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        let bytes = bytes.as_ref();
        let mut s = String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            s.push(HEX_DIGITS[(b >> 4) as usize] as char);
            s.push(HEX_DIGITS[(b & 0x0f) as usize] as char);
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
        let serialized = nquads::serialize_quad_substituted(&quad, "b0");
        // Target blank node "b0" in subject becomes "_:a", other "b1" in object becomes "_:z"
        assert_eq!(serialized, "_:a <http://example.org/p> _:z .");
    }
}
