pub mod error;
pub mod jsonld;
pub mod model;
pub mod nquads;
pub mod rdfc1;

pub use error::{RdfError, Result};
pub use model::{
    BlankNode, Dataset, GraphLabel, Literal, NamedNode, Object, Quad, Subject, rdf, xsd,
};

/// Convenience: expand a JSON-LD document to RDF, canonicalize via RDFC-1.0,
/// and return the SHA-256 hash of the canonical N-Quads output.
pub fn expand_canonicalize_and_hash(document: &serde_json::Value) -> Result<[u8; 32]> {
    let dataset = jsonld::expand_and_to_rdf(document)?;
    rdfc1::canonicalize_and_hash(&dataset)
}
