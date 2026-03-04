use std::fmt;

/// Errors that can occur during RDF processing.
#[derive(Debug, thiserror::Error)]
pub enum RdfError {
    #[error("N-Quads parse error: {0}")]
    NQuadsParseError(String),

    #[error("Canonicalization error: {0}")]
    CanonicalizationError(String),

    #[error("JSON-LD expansion error: {0}")]
    JsonLdExpansionError(String),

    #[error("Context error: {0}")]
    ContextError(String),

    #[error("To-RDF conversion error: {0}")]
    ToRdfError(String),

    #[error("Invalid IRI: {0}")]
    InvalidIri(String),
}

/// Result type alias for RDF operations.
pub type Result<T> = std::result::Result<T, RdfError>;

impl RdfError {
    pub fn parse(msg: impl fmt::Display) -> Self {
        Self::NQuadsParseError(msg.to_string())
    }

    pub fn canonicalization(msg: impl fmt::Display) -> Self {
        Self::CanonicalizationError(msg.to_string())
    }

    pub fn expansion(msg: impl fmt::Display) -> Self {
        Self::JsonLdExpansionError(msg.to_string())
    }

    pub fn context(msg: impl fmt::Display) -> Self {
        Self::ContextError(msg.to_string())
    }

    pub fn to_rdf(msg: impl fmt::Display) -> Self {
        Self::ToRdfError(msg.to_string())
    }
}
