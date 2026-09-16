use thiserror::Error;

use crate::HttpStatusError;

/// Errors from the unified messaging layer.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum MessagingError {
    #[error("pack error: {0}")]
    Pack(String),

    #[error("unpack error: {0}")]
    Unpack(String),

    #[error("identity resolution error: {0}")]
    Resolution(String),

    #[error("relationship error: {0}")]
    Relationship(String),

    #[error("transport error: {0}")]
    Transport(String),

    /// A transport's HTTP call — a send, or the authentication in front of it —
    /// was answered with a non-success status. The status, and for a `429` who
    /// refused and how long to wait, are data rather than text; see
    /// [`HttpStatusError`]. Every other transport failure is still
    /// [`MessagingError::Transport`]. Boxed so the variant does not grow every
    /// `Result<_, MessagingError>`.
    #[error("transport error: {0}")]
    HttpStatus(Box<HttpStatusError>),

    #[error("no endpoint available for {0}")]
    NoEndpoint(String),

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("not supported by this protocol: {0}")]
    NotSupported(String),
}

impl MessagingError {
    /// The HTTP status error, when this failure is one.
    pub fn http_status(&self) -> Option<&HttpStatusError> {
        match self {
            MessagingError::HttpStatus(err) => Some(err),
            _ => None,
        }
    }

    /// A rate limiter refused the request (HTTP 429). Which one, and when to
    /// retry, are on [`Self::http_status`].
    pub fn is_rate_limited(&self) -> bool {
        self.http_status()
            .is_some_and(HttpStatusError::is_rate_limited)
    }
}

impl From<HttpStatusError> for MessagingError {
    fn from(err: HttpStatusError) -> Self {
        MessagingError::HttpStatus(Box::new(err))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_status_is_typed() {
        let err = MessagingError::from(HttpStatusError::from_parts(
            "didcomm forward+send",
            429,
            Some("mediator"),
            Some("3"),
            "",
        ));
        assert!(err.is_rate_limited());
        assert_eq!(err.http_status().unwrap().retry_after_secs, Some(3));
        assert!(
            err.to_string()
                .starts_with("transport error: didcomm forward+send: rate-limited by mediator"),
            "{err}"
        );
        assert!(!MessagingError::Transport("down".into()).is_rate_limited());
        assert!(
            MessagingError::Transport("down".into())
                .http_status()
                .is_none()
        );
    }
}
