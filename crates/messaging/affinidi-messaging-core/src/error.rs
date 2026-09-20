use thiserror::Error;

use crate::http_status::{HttpStatusError, QueueFullGate};

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

    /// A queue-depth gate at the mediator refused the send, and which one.
    ///
    /// Distinct from every other transport failure because the remedy is
    /// different: the message is fine, the wire is fine, and retrying *this
    /// message* changes nothing until the destination's queue drains. A sender
    /// that treats it as an ordinary failure retries once per queued message,
    /// which is the worst possible response to a queue that is already full.
    pub fn queue_full(&self) -> Option<QueueFullGate> {
        self.http_status().and_then(HttpStatusError::queue_full)
    }

    /// How long the server asked the caller to wait, when it said.
    ///
    /// Carried by a `429` from a rate limiter and by a queue-full `503`. It is
    /// a pacing hint rather than a promise — for a queue-full refusal the
    /// mediator cannot know when the recipient will next collect — so a caller
    /// should treat it as a floor, not a schedule.
    pub fn retry_after(&self) -> Option<std::time::Duration> {
        self.http_status().and_then(HttpStatusError::retry_after)
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
