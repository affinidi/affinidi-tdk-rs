//! Error types for DID resolution.

use affinidi_did_common::{DIDError, DocumentError};

/// Error type for resolver failures.
///
/// Distinct from [`DIDError`] which covers parsing and type-level errors.
/// `ResolverError` covers failures during the resolution process itself:
/// network errors, invalid documents, unsupported methods, etc.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ResolverError {
    /// The DID method is not supported by this resolver.
    #[error("Unsupported DID method: {0}")]
    UnsupportedMethod(String),

    /// Resolution failed due to a DID-level error (parsing, validation).
    #[error("DID error: {0}")]
    DIDError(#[from] DIDError),

    /// Resolution failed due to a document-level error (key expansion, encoding).
    #[error("Document error: {0}")]
    DocumentError(#[from] DocumentError),

    /// Resolution failed due to a network or IO error.
    #[error("Resolution failed: {0}")]
    ResolutionFailed(String),

    /// Fetching the DID's material over the network failed.
    ///
    /// Carries the HTTP status when the host answered, so a caller can tell a
    /// host that rate-limited or refused the request apart from a DID that is
    /// invalid. See [`NetworkFetchError`].
    #[error("{0}")]
    NetworkFetch(#[from] NetworkFetchError),

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

/// A resolution that failed while fetching over the network.
///
/// `status` is the HTTP status of an unsuccessful response. It is `None` when
/// no response arrived (DNS, connect, TLS, timeout) and when the failure came
/// after a successful status line (reading or decoding the body).
///
/// `#[non_exhaustive]` so that fields can be added without a breaking release —
/// notably the host's `Retry-After`, which the method crates do not surface
/// yet. Build one with [`NetworkFetchError::new`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NetworkFetchError {
    /// The URL that was being fetched, when known.
    pub url: Option<String>,
    /// The HTTP status of the unsuccessful response, when the host answered.
    pub status: Option<u16>,
    /// What went wrong, as reported by the method implementation.
    pub message: String,
}

impl NetworkFetchError {
    /// HTTP 429 Too Many Requests.
    pub const TOO_MANY_REQUESTS: u16 = 429;

    /// A fetch failure with no URL or status recorded.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            url: None,
            status: None,
            message: message.into(),
        }
    }

    /// Record the URL that was being fetched.
    pub fn with_url(mut self, url: impl Into<String>) -> Self {
        self.url = Some(url.into());
        self
    }

    /// Record the HTTP status of the unsuccessful response.
    pub fn with_status(mut self, status: u16) -> Self {
        self.status = Some(status);
        self
    }

    /// The host rate-limited the request (HTTP 429). This says nothing about
    /// the DID itself; the same resolution may succeed later.
    pub fn is_rate_limited(&self) -> bool {
        self.status == Some(Self::TOO_MANY_REQUESTS)
    }
}

impl std::fmt::Display for NetworkFetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (self.status, &self.url) {
            (Some(Self::TOO_MANY_REQUESTS), Some(url)) => {
                write!(f, "DID host {url} rate-limited resolution (HTTP 429)")
            }
            (Some(Self::TOO_MANY_REQUESTS), None) => {
                write!(f, "DID host rate-limited resolution (HTTP 429)")
            }
            (Some(status), Some(url)) => write!(f, "DID host {url} answered HTTP {status}"),
            (Some(status), None) => write!(f, "DID host answered HTTP {status}"),
            (None, Some(url)) => write!(f, "fetching {url} failed: {}", self.message),
            (None, None) => write!(f, "network fetch failed: {}", self.message),
        }
    }
}

impl std::error::Error for NetworkFetchError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limited_display_names_the_host() {
        let err = NetworkFetchError::new("HTTP 429")
            .with_url("https://example.com/did.jsonl")
            .with_status(429);
        assert!(err.is_rate_limited());
        assert_eq!(
            ResolverError::from(err).to_string(),
            "DID host https://example.com/did.jsonl rate-limited resolution (HTTP 429)"
        );
    }

    #[test]
    fn other_status_is_not_rate_limited() {
        let err = NetworkFetchError::new("HTTP 404")
            .with_url("https://example.com/did.jsonl")
            .with_status(404);
        assert!(!err.is_rate_limited());
        assert_eq!(
            err.to_string(),
            "DID host https://example.com/did.jsonl answered HTTP 404"
        );
    }

    #[test]
    fn transport_failure_keeps_the_message() {
        let err = NetworkFetchError::new("connection refused");
        assert_eq!(err.status, None);
        assert!(!err.is_rate_limited());
        assert_eq!(err.to_string(), "network fetch failed: connection refused");
    }
}
