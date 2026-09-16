//! [`HttpStatusError`] — an HTTP endpoint answered with a non-success status.
//!
//! This lives here, in the dependency-light core, rather than in
//! `affinidi-messaging-sdk` (where it first appeared) so that every layer that
//! makes or relays an HTTP call can carry the **same** type:
//! `affinidi-did-authentication` (the mediator's `/authenticate*` endpoints),
//! the SDK's transports (which re-export it as
//! `affinidi_messaging_sdk::errors::HttpStatusError`) and [`MessagingError`]
//! (which a `MessageTransport` returns through `MessagingService`). The SDK
//! depends on the other two, so neither of them could depend on the SDK.
//!
//! [`MessagingError`]: crate::MessagingError

use std::time::{Duration, SystemTime};

/// An HTTP request was answered with a non-success status.
///
/// For a `429` the refusing service is named by the
/// [`RATE_LIMIT_SOURCE_HEADER`](Self::RATE_LIMIT_SOURCE_HEADER) response header
/// (`mediator`, `vta`, `vtc`, `did-host`) and the wait by `Retry-After`. A `429`
/// without the header is **unattributed**: a proxy or load balancer in front of
/// the service, or a service too old to label its limits. `rate_limit_source`
/// is then `None`, and nothing here guesses.
///
/// `#[non_exhaustive]` so fields can be added without a breaking release. Build
/// one with [`HttpStatusError::new`] or [`HttpStatusError::from_parts`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct HttpStatusError {
    /// What the caller was doing, e.g. `"send DIDComm message"`.
    pub context: String,
    /// The URL that was requested, when known.
    pub url: Option<String>,
    /// The HTTP status of the response.
    pub status: u16,
    /// The service whose limiter refused the request, from the
    /// `x-rate-limit-source` header (or, failing that, the `limiter` field of a
    /// `rate_limited` JSON body).
    pub rate_limit_source: Option<String>,
    /// Seconds to wait before retrying, from the `Retry-After` header — either
    /// form, delta-seconds or an HTTP-date (a date already past reads as `0`)
    /// — or, failing that, `retryAfterSecs` in a `rate_limited` JSON body.
    pub retry_after_secs: Option<u64>,
    /// The response body, as received.
    pub body: String,
}

impl HttpStatusError {
    /// HTTP 429 Too Many Requests.
    pub const TOO_MANY_REQUESTS: u16 = 429;
    /// Response header naming the service whose rate limiter refused a request.
    pub const RATE_LIMIT_SOURCE_HEADER: &'static str = "x-rate-limit-source";

    /// A status error with nothing else recorded.
    pub fn new(context: impl Into<String>, status: u16) -> Self {
        Self {
            context: context.into(),
            url: None,
            status,
            rate_limit_source: None,
            retry_after_secs: None,
            body: String::new(),
        }
    }

    /// Build from what an HTTP response carried: its status, the raw
    /// `x-rate-limit-source` and `Retry-After` header values, and its body.
    ///
    /// Headers win. The body's `limiter` and `retryAfterSecs` are read only
    /// when the body is the rate-limit contract's JSON (`"error":
    /// "rate_limited"`), so an intermediary that strips headers but passes the
    /// body through still attributes the refusal, and an arbitrary JSON body
    /// cannot.
    pub fn from_parts(
        context: impl Into<String>,
        status: u16,
        rate_limit_source: Option<&str>,
        retry_after: Option<&str>,
        body: impl Into<String>,
    ) -> Self {
        let body = body.into();
        let contract = serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .filter(|value| value.get("error").and_then(|e| e.as_str()) == Some("rate_limited"));

        let rate_limit_source = rate_limit_source
            .map(str::trim)
            .filter(|source| !source.is_empty())
            .map(str::to_owned)
            .or_else(|| {
                contract
                    .as_ref()
                    .and_then(|c| c.get("limiter")?.as_str().map(str::to_owned))
            });
        let retry_after_secs = retry_after
            .and_then(|value| parse_retry_after(value, SystemTime::now()))
            .or_else(|| {
                contract
                    .as_ref()
                    .and_then(|c| c.get("retryAfterSecs")?.as_u64())
            });

        Self {
            context: context.into(),
            url: None,
            status,
            rate_limit_source,
            retry_after_secs,
            body,
        }
    }

    /// Record the URL that was requested.
    pub fn with_url(mut self, url: impl Into<String>) -> Self {
        self.url = Some(url.into());
        self
    }

    /// Replace the context, e.g. to prefix what the caller was doing.
    pub fn with_context(mut self, context: impl Into<String>) -> Self {
        self.context = context.into();
        self
    }

    /// A rate limiter refused the request (HTTP 429). Retrying after
    /// [`Self::retry_after_secs`] may succeed; nothing about the request itself
    /// was wrong.
    pub fn is_rate_limited(&self) -> bool {
        self.status == Self::TOO_MANY_REQUESTS
    }

    /// `Retry-After` as a [`Duration`], when one was given.
    pub fn retry_after(&self) -> Option<Duration> {
        self.retry_after_secs.map(Duration::from_secs)
    }
}

/// Parse a `Retry-After` header value (RFC 9110 §10.2.3): delta-seconds, or an
/// HTTP-date, which is turned into seconds from `now` (rounded up, `0` when the
/// date has passed). Anything else is `None`.
fn parse_retry_after(value: &str, now: SystemTime) -> Option<u64> {
    let value = value.trim();
    if let Ok(secs) = value.parse::<u64>() {
        return Some(secs);
    }
    let at = httpdate::parse_http_date(value).ok()?;
    Some(match at.duration_since(now) {
        Ok(wait) => wait.as_secs() + u64::from(wait.subsec_nanos() > 0),
        Err(_) => 0,
    })
}

impl std::fmt::Display for HttpStatusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: ", self.context)?;
        if self.is_rate_limited() {
            match &self.rate_limit_source {
                Some(source) => write!(f, "rate-limited by {source} (HTTP 429")?,
                None => write!(
                    f,
                    "rate-limited by an unattributed limiter, no {} header (HTTP 429",
                    Self::RATE_LIMIT_SOURCE_HEADER
                )?,
            }
            if let Some(secs) = self.retry_after_secs {
                write!(f, ", retry after {secs}s")?;
            }
            write!(f, ")")?;
        } else {
            write!(f, "status({})", self.status)?;
        }
        if let Some(url) = &self.url {
            write!(f, ", url({url})")?;
        }
        write!(f, ", body({})", self.body)
    }
}

impl std::error::Error for HttpStatusError {}

#[cfg(test)]
mod tests {
    use super::*;

    const CONTRACT_BODY: &str = r#"{"error":"rate_limited","limiter":"mediator","message":"Rate limit exceeded. Please try again later.","retryAfterSecs":4}"#;

    #[test]
    fn delta_seconds_retry_after() {
        let err = HttpStatusError::from_parts("fetch", 429, Some("vta"), Some(" 9 "), "");
        assert_eq!(err.rate_limit_source.as_deref(), Some("vta"));
        assert_eq!(err.retry_after_secs, Some(9));
        assert_eq!(err.retry_after(), Some(Duration::from_secs(9)));
    }

    #[test]
    fn http_date_retry_after_is_seconds_from_now() {
        let now = httpdate::parse_http_date("Wed, 21 Oct 2015 07:28:00 GMT").unwrap();
        assert_eq!(
            parse_retry_after("Wed, 21 Oct 2015 07:28:30 GMT", now),
            Some(30)
        );
        // A date already past means "now", not "never".
        assert_eq!(
            parse_retry_after("Wed, 21 Oct 2015 07:27:00 GMT", now),
            Some(0)
        );
        assert_eq!(parse_retry_after("soon", now), None);
        assert_eq!(parse_retry_after("-5", now), None);
    }

    #[test]
    fn a_future_http_date_is_parsed_from_the_header() {
        let at = SystemTime::now() + Duration::from_secs(120);
        let header = httpdate::fmt_http_date(at);
        let err = HttpStatusError::from_parts("fetch", 429, None, Some(&header), "");
        let secs = err.retry_after_secs.expect("HTTP-date parsed");
        assert!((118..=121).contains(&secs), "{secs}");
    }

    #[test]
    fn contract_body_attributes_when_headers_are_missing() {
        let err = HttpStatusError::from_parts("fetch", 429, None, None, CONTRACT_BODY);
        assert_eq!(err.rate_limit_source.as_deref(), Some("mediator"));
        assert_eq!(err.retry_after_secs, Some(4));
    }

    #[test]
    fn an_unparseable_header_falls_back_to_the_contract_body() {
        let err = HttpStatusError::from_parts("fetch", 429, None, Some("later"), CONTRACT_BODY);
        assert_eq!(err.retry_after_secs, Some(4));
    }

    #[test]
    fn other_json_bodies_do_not_attribute() {
        let err = HttpStatusError::from_parts(
            "fetch",
            429,
            None,
            None,
            r#"{"error":"other","limiter":"mediator","retryAfterSecs":4}"#,
        );
        assert_eq!(err.rate_limit_source, None);
        assert_eq!(err.retry_after_secs, None);
        assert!(err.to_string().contains("unattributed"), "{err}");
    }

    #[test]
    fn display() {
        let err = HttpStatusError::from_parts("send", 429, Some("mediator"), Some("4"), "slow")
            .with_url("https://m.example/inbound");
        assert_eq!(
            err.to_string(),
            "send: rate-limited by mediator (HTTP 429, retry after 4s), \
             url(https://m.example/inbound), body(slow)"
        );
        let err = HttpStatusError::from_parts("send", 503, None, None, "busy");
        assert!(!err.is_rate_limited());
        assert_eq!(err.to_string(), "send: status(503), body(busy)");
    }
}
