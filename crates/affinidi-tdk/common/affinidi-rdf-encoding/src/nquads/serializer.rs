use super::escape::escape_nquads;
use crate::model::{GraphLabel, Object, Quad, Subject, xsd};

/// Serialize a single quad to an N-Quads line (without trailing newline).
pub fn serialize_quad(quad: &Quad) -> String {
    let mut out = String::with_capacity(128);

    // Subject
    match &quad.subject {
        Subject::Named(n) => {
            out.push('<');
            out.push_str(&n.iri);
            out.push('>');
        }
        Subject::Blank(b) => {
            out.push_str("_:");
            out.push_str(&b.id);
        }
    }

    out.push(' ');

    // Predicate
    out.push('<');
    out.push_str(&quad.predicate.iri);
    out.push('>');

    out.push(' ');

    // Object
    match &quad.object {
        Object::Named(n) => {
            out.push('<');
            out.push_str(&n.iri);
            out.push('>');
        }
        Object::Blank(b) => {
            out.push_str("_:");
            out.push_str(&b.id);
        }
        Object::Literal(lit) => {
            out.push('"');
            out.push_str(&escape_nquads(&lit.value));
            out.push('"');
            if let Some(ref lang) = lit.language {
                out.push('@');
                out.push_str(lang);
            } else if lit.datatype.iri != xsd::STRING {
                out.push_str("^^<");
                out.push_str(&lit.datatype.iri);
                out.push('>');
            }
        }
    }

    out.push(' ');

    // Graph (optional)
    match &quad.graph {
        GraphLabel::Named(n) => {
            out.push('<');
            out.push_str(&n.iri);
            out.push_str("> ");
        }
        GraphLabel::Blank(b) => {
            out.push_str("_:");
            out.push_str(&b.id);
            out.push(' ');
        }
        GraphLabel::Default => {}
    }

    out.push('.');
    out
}

/// Serialize a dataset to N-Quads format (one line per quad, newline-terminated).
pub fn serialize_dataset(quads: &[Quad]) -> String {
    let mut out = String::new();
    for q in quads {
        out.push_str(&serialize_quad(q));
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::*;

    #[test]
    fn serialize_named_nodes() {
        let q = Quad::new(
            NamedNode::new("http://example.org/s"),
            NamedNode::new("http://example.org/p"),
            NamedNode::new("http://example.org/o"),
            GraphLabel::Default,
        );
        assert_eq!(
            serialize_quad(&q),
            "<http://example.org/s> <http://example.org/p> <http://example.org/o> ."
        );
    }

    #[test]
    fn serialize_blank_node_subject() {
        let q = Quad::new(
            BlankNode::new("b0"),
            NamedNode::new("http://example.org/p"),
            NamedNode::new("http://example.org/o"),
            GraphLabel::Default,
        );
        assert_eq!(
            serialize_quad(&q),
            "_:b0 <http://example.org/p> <http://example.org/o> ."
        );
    }

    #[test]
    fn serialize_plain_literal() {
        let q = Quad::new(
            NamedNode::new("http://example.org/s"),
            NamedNode::new("http://example.org/p"),
            Literal::new("hello world"),
            GraphLabel::Default,
        );
        assert_eq!(
            serialize_quad(&q),
            "<http://example.org/s> <http://example.org/p> \"hello world\" ."
        );
    }

    #[test]
    fn serialize_typed_literal() {
        let q = Quad::new(
            NamedNode::new("http://example.org/s"),
            NamedNode::new("http://example.org/p"),
            Literal::typed("42", NamedNode::new(xsd::INTEGER)),
            GraphLabel::Default,
        );
        assert_eq!(
            serialize_quad(&q),
            "<http://example.org/s> <http://example.org/p> \"42\"^^<http://www.w3.org/2001/XMLSchema#integer> ."
        );
    }

    #[test]
    fn serialize_lang_literal() {
        let q = Quad::new(
            NamedNode::new("http://example.org/s"),
            NamedNode::new("http://example.org/p"),
            Literal::lang("bonjour", "fr"),
            GraphLabel::Default,
        );
        assert_eq!(
            serialize_quad(&q),
            "<http://example.org/s> <http://example.org/p> \"bonjour\"@fr ."
        );
    }

    #[test]
    fn serialize_with_named_graph() {
        let q = Quad::new(
            NamedNode::new("http://example.org/s"),
            NamedNode::new("http://example.org/p"),
            NamedNode::new("http://example.org/o"),
            GraphLabel::Named(NamedNode::new("http://example.org/g")),
        );
        assert_eq!(
            serialize_quad(&q),
            "<http://example.org/s> <http://example.org/p> <http://example.org/o> <http://example.org/g> ."
        );
    }

    #[test]
    fn serialize_escaped_literal() {
        let q = Quad::new(
            NamedNode::new("http://example.org/s"),
            NamedNode::new("http://example.org/p"),
            Literal::new("line1\nline2\t\"quoted\""),
            GraphLabel::Default,
        );
        assert_eq!(
            serialize_quad(&q),
            "<http://example.org/s> <http://example.org/p> \"line1\\nline2\\t\\\"quoted\\\"\" ."
        );
    }
}
