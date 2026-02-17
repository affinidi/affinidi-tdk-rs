//! Error types for DID resolution.

use affinidi_did_common::DIDError;

/// Error type for resolver failures.
///
/// Distinct from [`DIDError`] which covers parsing and type-level errors.
/// `ResolverError` covers failures during the resolution process itself:
/// network errors, invalid documents, unsupported methods, etc.
#[derive(Debug, thiserror::Error)]
pub enum ResolverError {
    /// The DID method is not supported by this resolver.
    #[error("Unsupported DID method: {0}")]
    UnsupportedMethod(String),

    /// Resolution failed due to a DID-level error (parsing, validation).
    #[error("DID error: {0}")]
    DIDError(#[from] DIDError),

    /// Resolution failed due to a network or IO error.
    #[error("Resolution failed: {0}")]
    ResolutionFailed(String),

    /// The resolved document was malformed or invalid.
    #[error("Invalid document: {0}")]
    InvalidDocument(String),

    /// Wraps an arbitrary error source.
    #[error("{message}")]
    Other {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },
}

impl ResolverError {
    /// Create an `Other` error from any error type.
    pub fn other(err: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::Other {
            message: err.to_string(),
            source: Some(Box::new(err)),
        }
    }
}
