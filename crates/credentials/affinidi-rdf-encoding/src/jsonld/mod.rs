pub mod bundled;
pub mod context;
pub mod expand;
pub mod to_rdf;

use serde_json::Value;

use crate::error::Result;
use crate::model::Dataset;

/// Expand a JSON-LD document and convert it to an RDF Dataset.
///
/// This is the main entry point for the JSON-LD module. It:
/// 1. Processes the `@context` and expands all terms to full IRIs
/// 2. Converts the expanded JSON-LD to RDF quads
///
/// The implementation handles the W3C Verifiable Credentials subset of JSON-LD,
/// with bundled contexts for `credentials/v2`, `credentials/examples/v2`,
/// and `data-integrity/v2`.
pub fn expand_and_to_rdf(document: &Value) -> Result<Dataset> {
    let expanded = expand::expand_document(document)?;
    tracing::debug!(expanded = %expanded, "JSON-LD expanded form");
    to_rdf::to_rdf(&expanded)
}

/// Expand a JSON-LD document in **safe mode** and convert it to an RDF Dataset.
///
/// Identical to [`expand_and_to_rdf`] except that any term not defined by the
/// active `@context` — which lenient expansion would silently drop — raises an
/// error. Use this for Data Integrity canonicalization so that undefined claims
/// cannot ride along in the JSON envelope without being part of the signed RDF
/// dataset (issue #381).
pub fn expand_and_to_rdf_safe(document: &Value) -> Result<Dataset> {
    let expanded = expand::expand_document_safe(document)?;
    tracing::debug!(expanded = %expanded, "JSON-LD expanded form (safe mode)");
    to_rdf::to_rdf(&expanded)
}
