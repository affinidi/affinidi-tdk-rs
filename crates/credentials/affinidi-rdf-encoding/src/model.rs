use std::collections::HashSet;
use std::fmt;

/// An IRI-identified RDF node.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct NamedNode {
    pub iri: String,
}

impl NamedNode {
    pub fn new(iri: impl Into<String>) -> Self {
        Self { iri: iri.into() }
    }
}

impl fmt::Display for NamedNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<{}>", self.iri)
    }
}

/// A blank (anonymous) RDF node. The `id` field stores the label without the `_:` prefix.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BlankNode {
    pub id: String,
}

impl BlankNode {
    pub fn new(id: impl Into<String>) -> Self {
        Self { id: id.into() }
    }
}

impl fmt::Display for BlankNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "_:{}", self.id)
    }
}

/// An RDF literal value with datatype and optional language tag.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Literal {
    pub value: String,
    pub datatype: NamedNode,
    pub language: Option<String>,
}

impl Literal {
    /// Create a plain string literal (xsd:string).
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            datatype: NamedNode::new(xsd::STRING),
            language: None,
        }
    }

    /// Create a typed literal.
    pub fn typed(value: impl Into<String>, datatype: NamedNode) -> Self {
        Self {
            value: value.into(),
            datatype,
            language: None,
        }
    }

    /// Create a language-tagged literal (rdf:langString).
    pub fn lang(value: impl Into<String>, language: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            datatype: NamedNode::new(rdf::LANG_STRING),
            language: Some(language.into()),
        }
    }
}

impl fmt::Display for Literal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\"{}\"", self.value)?;
        if let Some(ref lang) = self.language {
            write!(f, "@{lang}")
        } else if self.datatype.iri != xsd::STRING {
            write!(f, "^^{}", self.datatype)
        } else {
            Ok(())
        }
    }
}

/// The subject of an RDF quad.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Subject {
    Named(NamedNode),
    Blank(BlankNode),
}

impl fmt::Display for Subject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Named(n) => n.fmt(f),
            Self::Blank(b) => b.fmt(f),
        }
    }
}

impl From<NamedNode> for Subject {
    fn from(n: NamedNode) -> Self {
        Self::Named(n)
    }
}

impl From<BlankNode> for Subject {
    fn from(b: BlankNode) -> Self {
        Self::Blank(b)
    }
}

/// The object of an RDF quad.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Object {
    Named(NamedNode),
    Blank(BlankNode),
    Literal(Literal),
}

impl fmt::Display for Object {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Named(n) => n.fmt(f),
            Self::Blank(b) => b.fmt(f),
            Self::Literal(l) => l.fmt(f),
        }
    }
}

impl From<NamedNode> for Object {
    fn from(n: NamedNode) -> Self {
        Self::Named(n)
    }
}

impl From<BlankNode> for Object {
    fn from(b: BlankNode) -> Self {
        Self::Blank(b)
    }
}

impl From<Literal> for Object {
    fn from(l: Literal) -> Self {
        Self::Literal(l)
    }
}

/// The graph label of an RDF quad.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum GraphLabel {
    Named(NamedNode),
    Blank(BlankNode),
    Default,
}

impl fmt::Display for GraphLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Named(n) => n.fmt(f),
            Self::Blank(b) => b.fmt(f),
            Self::Default => Ok(()),
        }
    }
}

/// An RDF quad (subject, predicate, object, graph).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Quad {
    pub subject: Subject,
    pub predicate: NamedNode,
    pub object: Object,
    pub graph: GraphLabel,
}

impl Quad {
    pub fn new(
        subject: impl Into<Subject>,
        predicate: NamedNode,
        object: impl Into<Object>,
        graph: GraphLabel,
    ) -> Self {
        Self {
            subject: subject.into(),
            predicate,
            object: object.into(),
            graph,
        }
    }

    /// Returns true if this quad references the given blank node ID in subject, object, or graph.
    pub fn references_blank_node(&self, id: &str) -> bool {
        match &self.subject {
            Subject::Blank(b) if b.id == id => return true,
            _ => {}
        }
        match &self.object {
            Object::Blank(b) if b.id == id => return true,
            _ => {}
        }
        match &self.graph {
            GraphLabel::Blank(b) if b.id == id => return true,
            _ => {}
        }
        false
    }
}

/// A collection of RDF quads.
#[derive(Clone, Debug, Default)]
pub struct Dataset {
    pub quads: Vec<Quad>,
}

impl Dataset {
    pub fn new() -> Self {
        Self { quads: Vec::new() }
    }

    pub fn add(&mut self, quad: Quad) {
        self.quads.push(quad);
    }

    pub fn quads(&self) -> &[Quad] {
        &self.quads
    }

    /// Returns the set of all blank node IDs in this dataset.
    pub fn blank_nodes(&self) -> HashSet<String> {
        let mut ids = HashSet::new();
        for q in &self.quads {
            if let Subject::Blank(b) = &q.subject {
                ids.insert(b.id.clone());
            }
            if let Object::Blank(b) = &q.object {
                ids.insert(b.id.clone());
            }
            if let GraphLabel::Blank(b) = &q.graph {
                ids.insert(b.id.clone());
            }
        }
        ids
    }

    /// Returns all quads that reference the given blank node ID.
    pub fn quads_for_blank_node(&self, id: &str) -> Vec<&Quad> {
        self.quads
            .iter()
            .filter(|q| q.references_blank_node(id))
            .collect()
    }
}

/// XSD namespace constants.
pub mod xsd {
    pub const STRING: &str = "http://www.w3.org/2001/XMLSchema#string";
    pub const BOOLEAN: &str = "http://www.w3.org/2001/XMLSchema#boolean";
    pub const INTEGER: &str = "http://www.w3.org/2001/XMLSchema#integer";
    pub const DOUBLE: &str = "http://www.w3.org/2001/XMLSchema#double";
    pub const DATE_TIME: &str = "http://www.w3.org/2001/XMLSchema#dateTime";
    pub const DATE: &str = "http://www.w3.org/2001/XMLSchema#date";
    pub const ANY_URI: &str = "http://www.w3.org/2001/XMLSchema#anyURI";
}

/// RDF namespace constants.
pub mod rdf {
    pub const TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
    pub const FIRST: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#first";
    pub const REST: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#rest";
    pub const NIL: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#nil";
    pub const LANG_STRING: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#langString";
    pub const JSON: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#JSON";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn named_node_display() {
        let n = NamedNode::new("http://example.org/foo");
        assert_eq!(n.to_string(), "<http://example.org/foo>");
    }

    #[test]
    fn blank_node_display() {
        let b = BlankNode::new("b0");
        assert_eq!(b.to_string(), "_:b0");
    }

    #[test]
    fn literal_plain_display() {
        let l = Literal::new("hello");
        assert_eq!(l.to_string(), "\"hello\"");
    }

    #[test]
    fn literal_typed_display() {
        let l = Literal::typed("42", NamedNode::new(xsd::INTEGER));
        assert_eq!(
            l.to_string(),
            "\"42\"^^<http://www.w3.org/2001/XMLSchema#integer>"
        );
    }

    #[test]
    fn literal_lang_display() {
        let l = Literal::lang("bonjour", "fr");
        assert_eq!(l.to_string(), "\"bonjour\"@fr");
    }

    #[test]
    fn dataset_blank_nodes() {
        let mut ds = Dataset::new();
        ds.add(Quad::new(
            BlankNode::new("b0"),
            NamedNode::new("http://example.org/p"),
            NamedNode::new("http://example.org/o"),
            GraphLabel::Default,
        ));
        ds.add(Quad::new(
            NamedNode::new("http://example.org/s"),
            NamedNode::new("http://example.org/p"),
            BlankNode::new("b1"),
            GraphLabel::Default,
        ));

        let bns = ds.blank_nodes();
        assert_eq!(bns.len(), 2);
        assert!(bns.contains("b0"));
        assert!(bns.contains("b1"));
    }

    #[test]
    fn dataset_quads_for_blank_node() {
        let mut ds = Dataset::new();
        ds.add(Quad::new(
            BlankNode::new("b0"),
            NamedNode::new("http://example.org/p"),
            NamedNode::new("http://example.org/o"),
            GraphLabel::Default,
        ));
        ds.add(Quad::new(
            NamedNode::new("http://example.org/s"),
            NamedNode::new("http://example.org/p"),
            BlankNode::new("b0"),
            GraphLabel::Default,
        ));
        ds.add(Quad::new(
            NamedNode::new("http://example.org/s"),
            NamedNode::new("http://example.org/p"),
            NamedNode::new("http://example.org/o2"),
            GraphLabel::Default,
        ));

        let quads = ds.quads_for_blank_node("b0");
        assert_eq!(quads.len(), 2);
    }
}
