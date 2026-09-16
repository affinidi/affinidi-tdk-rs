use affinidi_did_authentication::errors::DIDAuthError;
use affinidi_messaging_didcomm::message::Message;
use affinidi_messaging_mediator_common::types::acls::ACLError;
use affinidi_tdk_common::errors::TDKError;
use thiserror::Error;

use crate::messages::{known::MessageType, problem_report::ProblemReport};

/// ATMError
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum ATMError {
    #[error("DID error: {0}")]
    DIDError(String),
    #[error("Secrets error: {0}")]
    SecretsError(String),
    #[error("SSL error: {0}")]
    SSLError(String),
    #[error("Transport (HTTP(S)) error: {0}")]
    TransportError(String),
    /// An HTTP endpoint — the mediator, normally — answered with a non-success
    /// status. The status, and for a `429` who refused and how long to wait,
    /// are data rather than text. See [`HttpStatusError`]. Boxed so the
    /// variant does not grow every `Result<_, ATMError>`.
    #[error("Transport (HTTP(S)) error: {0}")]
    HttpStatus(Box<HttpStatusError>),
    #[error("Message sending error: {0}")]
    MsgSendError(String),
    #[error("Message receive error: {0}")]
    MsgReceiveError(String),
    #[error("WebSocket disconnected: {0}")]
    Disconnected(String),
    #[error("Config error: {0}")]
    ConfigError(String),
    #[error("Authentication error: {0}")]
    AuthenticationError(String),
    /// Authenticating to the mediator failed. The [`DIDAuthError`] is kept
    /// whole — an HTTP status (a `429` and who sent it) is reachable through
    /// [`ATMError::http_status`] / [`ATMError::is_rate_limited`], through the
    /// retry loop's [`DIDAuthError::RetriesExhausted`] too. Every
    /// `DIDAuthError` converts to this variant; boxed so it does not grow every
    /// `Result<_, ATMError>`.
    #[error("Authentication error: {0}")]
    DIDAuth(Box<DIDAuthError>),
    #[error("ACL Denied error: {0}")]
    ACLDenied(String),
    #[error("ACL config error: {0}")]
    ACLConfigError(String),
    #[error("DIDComm message error: {0}. Reason: {1}")]
    DidcommError(String, String),
    #[error("Unexpected envelope: {0}")]
    UnexpectedEnvelope(String),
    #[error("Addressing consistency error: {0}")]
    AddressingMismatch(String),
    #[error("Verification failed: {0}")]
    VerificationFailed(String),
    #[error("SDK Error: {0}")]
    SDKError(String),
    #[error("TDK Error: {0}")]
    TDKError(String),
    #[error("DIDComm Problem Report: code: ({0}), comment: ({1}), escalate?: ({2})")]
    ProblemReport(String, String, String),
    #[error("DIDComm Mediator error: code({0}), message: ({1})")]
    MediatorError(String, String),
    #[error("ATM DID Profile error: {0}")]
    ProfileError(String),
}

impl ATMError {
    /// The HTTP status error, when this failure is one — including an
    /// authentication that failed on one ([`ATMError::DIDAuth`]).
    pub fn http_status(&self) -> Option<&HttpStatusError> {
        match self {
            ATMError::HttpStatus(err) => Some(err),
            ATMError::DIDAuth(err) => err.http_status(),
            _ => None,
        }
    }

    /// A rate limiter refused the request (HTTP 429). Which one, and when to
    /// retry, are on [`Self::http_status`].
    pub fn is_rate_limited(&self) -> bool {
        self.http_status()
            .is_some_and(HttpStatusError::is_rate_limited)
    }

    /// Creates an ATM Error from a DIDComm Problem Report Error Message
    pub fn from_problem_report(message: &Message) -> Self {
        if let Ok(MessageType::ProblemReport) = message.typ.parse::<MessageType>() {
            let body: ProblemReport = match serde_json::from_value(message.body.clone()) {
                Ok(body) => body,
                Err(err) => {
                    return ATMError::SDKError(format!(
                        "Internal error handling error. Could not parse Problem Report message. Reason: {err}"
                    ));
                }
            };

            let comment = body.interpolation();

            ATMError::ProblemReport(
                body.code,
                comment,
                body.escalate_to.unwrap_or("NONE".into()),
            )
        } else {
            // Handling for non-Problem Report messages
            ATMError::SDKError(format!(
                "Internal error handling error. Expecting a DIDComm Problem Report message. Received instead ({})",
                message.typ
            ))
        }
    }
}

/// An HTTP request the SDK made was answered with a non-success status.
///
/// Defined in `affinidi-messaging-core` so that `affinidi-did-authentication`
/// ([`DIDAuthError::HttpStatus`]) and `MessagingError::HttpStatus` carry the
/// same type; re-exported here, at the path it was introduced under.
pub use affinidi_messaging_core::HttpStatusError;

/// Read an HTTP response the SDK received: its body on success, an
/// [`ATMError::HttpStatus`] otherwise.
pub(crate) async fn check_response(
    context: &str,
    response: reqwest::Response,
) -> Result<String, ATMError> {
    let status = response.status();
    let url = response.url().to_string();
    let header = |name: &str| {
        response
            .headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
    };
    let source = header(HttpStatusError::RATE_LIMIT_SOURCE_HEADER);
    let retry_after = header(reqwest::header::RETRY_AFTER.as_str());
    let body = response.text().await.map_err(|e| {
        ATMError::TransportError(format!("{context}: couldn't read response body: {e:?}"))
    })?;
    if status.is_success() {
        return Ok(body);
    }
    Err(ATMError::from(
        HttpStatusError::from_parts(
            context,
            status.as_u16(),
            source.as_deref(),
            retry_after.as_deref(),
            body,
        )
        .with_url(url),
    ))
}

impl From<HttpStatusError> for ATMError {
    fn from(err: HttpStatusError) -> Self {
        ATMError::HttpStatus(Box::new(err))
    }
}

impl From<ATMError> for TDKError {
    fn from(err: ATMError) -> Self {
        TDKError::ATM(err.to_string())
    }
}

impl From<TDKError> for ATMError {
    fn from(err: TDKError) -> Self {
        ATMError::TDKError(err.to_string())
    }
}

impl From<DIDAuthError> for ATMError {
    fn from(err: DIDAuthError) -> Self {
        ATMError::DIDAuth(Box::new(err))
    }
}

impl From<ACLError> for ATMError {
    fn from(err: ACLError) -> Self {
        match err {
            ACLError::Config(msg) => ATMError::ACLConfigError(msg),
            ACLError::Denied(msg) => ATMError::ACLDenied(msg),
            // ACLError is `#[non_exhaustive]` from mediator-common 0.15;
            // surface any future variant as a generic ACL error so the
            // SDK keeps compiling against unmodified consumers when
            // mediator-common lands new ACL failure modes.
            other => ATMError::ACLConfigError(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_problem_report_works() {
        let message = Message::build(
            "example-1".to_string(),
            "https://didcomm.org/report-problem/2.0/problem-report".to_string(),
            serde_json::json!({
                "code": "test-code",
                "comment": "Test one {1} two {2} three {3}",
                "escalate_to": "test-escalate",
                "args": ["1", "2", "3"]
            }),
        )
        .finalize();

        let error = ATMError::from_problem_report(&message);

        match error {
            ATMError::ProblemReport(code, comment, escalate) => {
                assert_eq!(code, "test-code");
                assert_eq!(comment, "Test one 1 two 2 three 3");
                assert_eq!(escalate, "test-escalate");
            }
            _ => panic!("Expected ProblemReport error"),
        }
    }

    #[test]
    fn test_from_problem_report_wrong_type() {
        let message = Message::build(
            "example-1".to_string(),
            "https://didcomm.org/NOT-A-PROBLEM/2.0/problem-report".to_string(),
            serde_json::json!({
                "code": "test-code",
                "comment": "Test one {1} two {2} three {3}",
                "escalate_to": "test-escalate",
                "args": ["1", "2", "3"]
            }),
        )
        .finalize();

        let error = ATMError::from_problem_report(&message);

        match error {
            ATMError::SDKError(_) => {}
            _ => panic!("Expected SDKError error"),
        }
    }

    const CONTRACT_BODY: &str = r#"{"error":"rate_limited","limiter":"mediator","message":"Rate limit exceeded. Please try again later.","retryAfterSecs":4}"#;

    #[test]
    fn attributed_429_is_typed() {
        let err = HttpStatusError::from_parts(
            "send DIDComm message",
            429,
            Some("mediator"),
            Some("4"),
            CONTRACT_BODY,
        )
        .with_url("https://mediator.example/inbound");
        assert!(err.is_rate_limited());
        assert_eq!(err.rate_limit_source.as_deref(), Some("mediator"));
        assert_eq!(err.retry_after_secs, Some(4));
        assert_eq!(err.retry_after(), Some(std::time::Duration::from_secs(4)));

        let err = ATMError::from(err);
        assert!(err.is_rate_limited());
        assert!(
            err.to_string().starts_with(
                "Transport (HTTP(S)) error: send DIDComm message: rate-limited by mediator \
                 (HTTP 429, retry after 4s), url(https://mediator.example/inbound)"
            ),
            "{err}"
        );
    }

    /// Headers are authoritative; the body is only a fallback.
    #[test]
    fn headers_win_over_the_body() {
        let err = HttpStatusError::from_parts("fetch", 429, Some("vta"), Some("9"), CONTRACT_BODY);
        assert_eq!(err.rate_limit_source.as_deref(), Some("vta"));
        assert_eq!(err.retry_after_secs, Some(9));
    }

    /// An intermediary that strips the headers but passes the contract body
    /// through still leaves the refusal attributed.
    #[test]
    fn contract_body_attributes_when_headers_are_missing() {
        let err = HttpStatusError::from_parts("fetch", 429, None, None, CONTRACT_BODY);
        assert_eq!(err.rate_limit_source.as_deref(), Some("mediator"));
        assert_eq!(err.retry_after_secs, Some(4));
    }

    /// A `429` with no source header — a proxy, or a mediator too old to label
    /// its limits — is unattributed, and says so rather than guessing.
    #[test]
    fn unlabelled_429_is_unattributed() {
        let err = HttpStatusError::from_parts(
            "fetch",
            429,
            None,
            Some("Wed, 21 Oct 2015 07:28:00 GMT"),
            "Rate limit exceeded. Please try again later.",
        );
        assert!(err.is_rate_limited());
        assert_eq!(err.rate_limit_source, None);
        // An HTTP-date `Retry-After` is parsed; this one is long past, so "now".
        assert_eq!(err.retry_after_secs, Some(0));
        assert!(err.to_string().contains("unattributed"), "{err}");
    }

    /// A JSON body that is not the rate-limit contract cannot attribute.
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
    }

    #[test]
    fn other_statuses_are_not_rate_limited() {
        let err = ATMError::from(HttpStatusError::from_parts(
            "fetch",
            503,
            None,
            Some("30"),
            "busy",
        ));
        assert!(!err.is_rate_limited());
        assert_eq!(err.http_status().unwrap().status, 503);
        assert_eq!(err.http_status().unwrap().retry_after_secs, Some(30));
        assert_eq!(
            err.to_string(),
            "Transport (HTTP(S)) error: fetch: status(503), body(busy)"
        );
        assert!(!ATMError::TransportError("x".into()).is_rate_limited());
    }

    /// Serve one canned HTTP response on a loopback port and return its URL.
    async fn serve_once(response: &'static str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/inbound", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 4096];
            let _ = socket.read(&mut request).await;
            socket.write_all(response.as_bytes()).await.unwrap();
            socket.shutdown().await.unwrap();
        });
        url
    }

    /// The headers are read off a real response, not just handed in.
    #[tokio::test]
    async fn check_response_reads_the_rate_limit_headers() {
        let url = serve_once(
            "HTTP/1.1 429 Too Many Requests\r\n\
             x-rate-limit-source: mediator\r\n\
             retry-after: 7\r\n\
             content-type: text/plain\r\n\
             content-length: 4\r\n\
             connection: close\r\n\r\n\
             slow",
        )
        .await;
        let response = reqwest::Client::new().post(&url).send().await.unwrap();
        let err = check_response("send DIDComm message", response)
            .await
            .unwrap_err();
        assert!(err.is_rate_limited());
        let status = err.http_status().unwrap();
        assert_eq!(status.rate_limit_source.as_deref(), Some("mediator"));
        assert_eq!(status.retry_after_secs, Some(7));
        assert_eq!(status.url.as_deref(), Some(url.as_str()));
        assert_eq!(status.body, "slow");
    }

    #[tokio::test]
    async fn check_response_returns_the_body_on_success() {
        let url =
            serve_once("HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok").await;
        let response = reqwest::Client::new().post(&url).send().await.unwrap();
        assert_eq!(check_response("fetch", response).await.unwrap(), "ok");
    }

    #[test]
    fn test_from_problem_report_wrong_body() {
        let message = Message::build(
            "example-1".to_string(),
            "https://didcomm.org/NOT-A-PROBLEM/2.0/problem-report".to_string(),
            serde_json::json!({}),
        )
        .finalize();

        let error = ATMError::from_problem_report(&message);

        match error {
            ATMError::SDKError(_) => {}
            _ => panic!("Expected SDKError error"),
        }
    }
}
