//! A network fetch that failed, in a shape every DID method crate shares.
//!
//! A method that fetches its DID's material over HTTP (did:web, did:webs,
//! did:ebsi, did:scid, ...) reports a failed fetch as a [`NetworkError`], so a
//! caller can tell a host that rate-limited or refused the request apart from
//! a DID that is invalid, and see how long the host asked it to wait.
//! `affinidi-did-resolver-traits` converts one into its `NetworkFetchError`.

use std::fmt;
use std::time::Duration;

/// A fetch of a DID's material that failed.
///
/// `status` is the HTTP status of an unsuccessful response. It is `None` when
/// no response arrived (DNS, connect, TLS, timeout) and when the failure came
/// after a successful status line (reading or decoding the body).
/// `retry_after` is the host's `Retry-After`, when it sent one in seconds.
///
/// `#[non_exhaustive]`: build one with [`NetworkError::new`] and the `with_*`
/// methods.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NetworkError {
    /// The URL that was being fetched, when known.
    pub url: Option<String>,
    /// The HTTP status of the unsuccessful response, when the host answered.
    pub status: Option<u16>,
    /// How long the host asked the caller to wait before trying again.
    pub retry_after: Option<Duration>,
    /// What went wrong, as the method implementation reports it.
    pub message: String,
}

impl NetworkError {
    /// HTTP 429 Too Many Requests.
    pub const TOO_MANY_REQUESTS: u16 = 429;

    /// A fetch failure with no URL, status or `Retry-After` recorded.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            url: None,
            status: None,
            retry_after: None,
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

    /// Record how long the host asked the caller to wait.
    pub fn with_retry_after(mut self, retry_after: Duration) -> Self {
        self.retry_after = Some(retry_after);
        self
    }

    /// Record a `Retry-After` header value, when it is one this reads (see
    /// [`parse_retry_after`]); otherwise leave `retry_after` unset.
    pub fn with_retry_after_header(mut self, value: Option<&str>) -> Self {
        if let Some(retry_after) = value.and_then(parse_retry_after) {
            self.retry_after = Some(retry_after);
        }
        self
    }

    /// The host rate-limited the request (HTTP 429). This says nothing about
    /// the DID itself; the same resolution may succeed later.
    pub fn is_rate_limited(&self) -> bool {
        self.status == Some(Self::TOO_MANY_REQUESTS)
    }
}

/// Read a `Retry-After` header value given in seconds (`"120"`).
///
/// The HTTP-date form is not read and gives `None`, as does anything else
/// that is not a whole number of seconds.
pub fn parse_retry_after(value: &str) -> Option<Duration> {
    value.trim().parse::<u64>().ok().map(Duration::from_secs)
}

impl fmt::Display for NetworkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.status, &self.url) {
            (Some(Self::TOO_MANY_REQUESTS), Some(url)) => {
                write!(f, "DID host {url} rate-limited resolution (HTTP 429)")?
            }
            (Some(Self::TOO_MANY_REQUESTS), None) => {
                write!(f, "DID host rate-limited resolution (HTTP 429)")?
            }
            (Some(status), Some(url)) => write!(f, "DID host {url} answered HTTP {status}")?,
            (Some(status), None) => write!(f, "DID host answered HTTP {status}")?,
            (None, Some(url)) => write!(f, "fetching {url} failed: {}", self.message)?,
            (None, None) => write!(f, "network fetch failed: {}", self.message)?,
        }
        if let Some(retry_after) = self.retry_after {
            write!(f, "; retry after {}s", retry_after.as_secs())?;
        }
        Ok(())
    }
}

impl std::error::Error for NetworkError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limited_with_retry_after() {
        let err = NetworkError::new("HTTP 429")
            .with_url("https://example.com/did.json")
            .with_status(429)
            .with_retry_after_header(Some(" 30 "));
        assert!(err.is_rate_limited());
        assert_eq!(err.retry_after, Some(Duration::from_secs(30)));
        assert_eq!(
            err.to_string(),
            "DID host https://example.com/did.json rate-limited resolution (HTTP 429); retry after 30s"
        );
    }

    #[test]
    fn an_http_date_retry_after_is_not_read() {
        let err = NetworkError::new("HTTP 503")
            .with_status(503)
            .with_retry_after_header(Some("Wed, 21 Oct 2015 07:28:00 GMT"));
        assert_eq!(err.retry_after, None);
        assert_eq!(err.to_string(), "DID host answered HTTP 503");
    }

    #[test]
    fn transport_failure_keeps_the_message() {
        let err = NetworkError::new("connection refused").with_url("https://example.com/");
        assert_eq!(err.status, None);
        assert_eq!(
            err.to_string(),
            "fetching https://example.com/ failed: connection refused"
        );
    }
}
