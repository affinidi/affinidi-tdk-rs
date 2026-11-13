use affinidi_did_authentication::errors::DIDAuthError;
use affinidi_messaging_didcomm::message::Message;
use affinidi_messaging_mediator_types::acls::ACLError;
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
    /// The mediator refused a Trust Task with a `trust-task-error` document
    /// (Trust Tasks SPEC §8), the framework's own error response. A mediator
    /// sends one instead of a DIDComm problem report when the request asks
    /// for it, which every Trust Task this SDK sends does (see
    /// [`ERROR_FORMAT_MEMBER`](crate::protocols::trust_tasks::ERROR_FORMAT_MEMBER));
    /// an older mediator still answers with [`ATMError::ProblemReport`].
    ///
    /// To act on a refusal whichever form it arrived in, use
    /// [`ATMError::refusal_code`], [`ATMError::mediator_code`] and
    /// [`ATMError::current_epoch`] rather than matching either variant.
    /// Boxed so the variant does not grow every `Result<_, ATMError>`.
    #[error("Trust Task refused: {0}")]
    TrustTaskError(Box<TrustTaskRefusal>),
}

/// The `details` member a mediator adds to a `trust-task-error` whose code it
/// translated from its own vocabulary into a standard one: the code the same
/// refusal carries in a problem report.
pub const MEDIATOR_CODE_DETAIL: &str = "mediatorCode";

/// A `trust-task-error` document's payload (Trust Tasks SPEC §8.2), with the
/// identifiers of the error document itself.
///
/// `code` is kept as the string on the wire: a standard code
/// (`permissionDenied`, `unsupportedType`, …) or one an individual
/// specification declares (`messaging/mux/revoke-all:epochMismatch`).
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub struct TrustTaskRefusal {
    /// The error code.
    pub code: String,
    /// Whether the same request may be sent again.
    pub retryable: bool,
    /// Human-readable explanation, for logs and operators.
    pub message: Option<String>,
    /// RFC 3339 instant before which a retry should not be sent.
    pub retry_after: Option<String>,
    /// The document the error reports on.
    pub in_response_to: Option<RefusedDocument>,
    /// Structured data whose shape the code's specification declares, e.g.
    /// `{"currentEpoch": 3}` for an `…:epochMismatch`.
    pub details: Option<serde_json::Value>,
    /// The error document's own `id`.
    pub id: String,
    /// The error document's `threadId`: the request's.
    pub thread_id: Option<String>,
}

/// `inResponseTo` of a `trust-task-error`: which document was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct RefusedDocument {
    /// The refused document's `type`.
    pub type_uri: String,
    /// The refused document's `id` (omitted under `identityMismatch`).
    pub id: Option<String>,
}

impl TrustTaskRefusal {
    /// Read a `trust-task-error` document. `None` when `doc` is not one (its
    /// `type` is not a `trust-task-error` Type URI), and when it is one
    /// without the `code` and `retryable` the specification requires.
    pub fn from_document(doc: &serde_json::Value) -> Option<Self> {
        if !is_trust_task_error(doc) {
            return None;
        }
        let payload = doc.get("payload")?;
        let text =
            |v: &serde_json::Value, k: &str| v.get(k).and_then(|s| s.as_str()).map(str::to_string);
        Some(Self {
            code: text(payload, "code")?,
            retryable: payload.get("retryable")?.as_bool()?,
            message: text(payload, "message"),
            retry_after: text(payload, "retryAfter"),
            in_response_to: payload.get("inResponseTo").and_then(|r| {
                Some(RefusedDocument {
                    type_uri: text(r, "typeUri")?,
                    id: text(r, "id"),
                })
            }),
            details: payload.get("details").filter(|d| d.is_object()).cloned(),
            id: text(doc, "id").unwrap_or_default(),
            thread_id: text(doc, "threadId"),
        })
    }

    /// The code the mediator gives the same refusal in a problem report,
    /// when it translated it into a standard code here (`details.mediatorCode`);
    /// otherwise the code itself, which is then the same in both forms.
    pub fn mediator_code(&self) -> &str {
        self.details
            .as_ref()
            .and_then(|d| d.get(MEDIATOR_CODE_DETAIL))
            .and_then(|c| c.as_str())
            .unwrap_or(&self.code)
    }

    /// For an `…:epochMismatch`: the member DID's epoch in force
    /// (`details.currentEpoch`).
    pub fn current_epoch(&self) -> Option<u64> {
        if !self.code.ends_with(":epochMismatch") {
            return None;
        }
        self.details.as_ref()?.get("currentEpoch")?.as_u64()
    }
}

impl std::fmt::Display for TrustTaskRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "code: ({})", self.code)?;
        if let Some(m) = &self.message {
            write!(f, ", message: ({m})")?;
        }
        write!(f, ", retryable: {}", self.retryable)
    }
}

/// Whether `doc` is a `trust-task-error` document, by its `type`.
pub(crate) fn is_trust_task_error(doc: &serde_json::Value) -> bool {
    doc.get("type")
        .and_then(|t| t.as_str())
        .is_some_and(|t| t.starts_with("https://trusttasks.org/spec/trust-task-error/"))
}

/// A problem report's code without its sorter and scope (`e.p.`), which is
/// the descriptor the mediator chose: `messaging/mux/revoke-all:epochMismatch`
/// from `e.p.messaging/mux/revoke-all:epochMismatch`.
fn problem_descriptor(code: &str) -> &str {
    let mut parts = code.splitn(3, '.');
    match (parts.next(), parts.next(), parts.next()) {
        (Some("e" | "w"), Some(_), Some(descriptor)) => descriptor,
        _ => code,
    }
}

/// The number after "current epoch is" in an `epochMismatch` comment, which
/// is where a mediator that answers with problem reports puts it.
fn epoch_in_comment(comment: &str) -> Option<u64> {
    let (_, rest) = comment.split_once("current epoch is ")?;
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

impl ATMError {
    /// The `trust-task-error` the mediator refused a Trust Task with, when
    /// this failure is one.
    pub fn trust_task_refusal(&self) -> Option<&TrustTaskRefusal> {
        match self {
            ATMError::TrustTaskError(r) => Some(r),
            _ => None,
        }
    }

    /// The code a refusal by the mediator carries, whichever form it came
    /// in: a `trust-task-error`'s `code`, or a problem report's code without
    /// its `e.p.` prefix. `None` for any other failure.
    ///
    /// A code a Trust Task specification declares
    /// (`messaging/mux/revoke-all:epochMismatch`) is the same in both forms.
    /// A refusal outside the specifications' vocabulary is a standard code
    /// in a `trust-task-error` (`permissionDenied`) and the mediator's own in
    /// a problem report (`authorization.admin_required`); to keep matching
    /// the latter, use [`mediator_code`](Self::mediator_code).
    pub fn refusal_code(&self) -> Option<&str> {
        match self {
            ATMError::TrustTaskError(r) => Some(&r.code),
            ATMError::ProblemReport(code, ..) => Some(problem_descriptor(code)),
            _ => None,
        }
    }

    /// The mediator's own code for a refusal, whichever form it came in: a
    /// problem report's code without its `e.p.` prefix, or what a
    /// `trust-task-error` names in `details.mediatorCode` when the mediator
    /// translated it into a standard code (else its `code`). Code that
    /// matched problem-report codes keeps working on this once the mediator
    /// answers with `trust-task-error` documents.
    pub fn mediator_code(&self) -> Option<&str> {
        match self {
            ATMError::TrustTaskError(r) => Some(r.mediator_code()),
            ATMError::ProblemReport(code, ..) => Some(problem_descriptor(code)),
            _ => None,
        }
    }

    /// For an `…:epochMismatch` refusal (`messaging/mux/revoke-all`,
    /// `messaging/mux/admin-revoke-all`): the member DID's epoch in force,
    /// to send instead. Read from `details.currentEpoch` of a
    /// `trust-task-error`; from an older mediator's problem report, from its
    /// comment.
    pub fn current_epoch(&self) -> Option<u64> {
        match self {
            ATMError::TrustTaskError(r) => r.current_epoch(),
            ATMError::ProblemReport(code, comment, _) if code.ends_with(":epochMismatch") => {
                epoch_in_comment(comment)
            }
            _ => None,
        }
    }

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

    /// Is this unpack failure worth retrying, or is the inbound frame poison?
    ///
    /// The one classifier both inbound paths share — the TSP adapter
    /// (`transport_adapter`) and the DIDComm live stream (the websocket
    /// transport) — so the two halves of one socket agree on what "transient"
    /// means:
    ///
    /// - [`ATMError::DIDError`] — resolving the sender's DID (or our own)
    ///   failed. The overwhelmingly common transient case.
    /// - [`ATMError::TransportError`] / [`ATMError::HttpStatus`] /
    ///   [`ATMError::Disconnected`] / [`ATMError::TDKError`] — network or
    ///   resolver-cache trouble underneath.
    /// - Everything else — envelope parse, wrong recipient, decrypt/verify
    ///   failure, a policy rejection — is a deterministic property of the
    ///   bytes (or of local configuration). Retrying identical input cannot
    ///   change it.
    pub(crate) fn is_transient_unpack_failure(&self) -> bool {
        matches!(
            self,
            ATMError::DIDError(_)
                | ATMError::TransportError(_)
                | ATMError::HttpStatus(_)
                | ATMError::Disconnected(_)
                | ATMError::TDKError(_)
        )
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

/// Read `response`'s body chunk by chunk, refusing it once it passes
/// `max_bytes`, whether or not it declared its length.
async fn read_body_capped(
    context: &str,
    response: &mut reqwest::Response,
    max_bytes: usize,
) -> Result<String, ATMError> {
    let too_large = || {
        ATMError::TransportError(format!(
            "{context}: response body is larger than {max_bytes} bytes"
        ))
    };
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes as u64)
    {
        return Err(too_large());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|e| {
        ATMError::TransportError(format!("{context}: couldn't read response body: {e:?}"))
    })? {
        if body.len() + chunk.len() > max_bytes {
            return Err(too_large());
        }
        body.extend_from_slice(&chunk);
    }
    String::from_utf8(body).map_err(|e| {
        ATMError::TransportError(format!("{context}: response body is not UTF-8: {e}"))
    })
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
    check_response_within(context, response, None).await
}

/// [`check_response`] reading at most `max_bytes` of the body, for a response
/// from an endpoint the SDK does not otherwise know (a URL handed to it), so
/// an oversized body is refused rather than read into memory whole.
pub(crate) async fn check_response_capped(
    context: &str,
    response: reqwest::Response,
    max_bytes: usize,
) -> Result<String, ATMError> {
    check_response_within(context, response, Some(max_bytes)).await
}

async fn check_response_within(
    context: &str,
    mut response: reqwest::Response,
    max_bytes: Option<usize>,
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
    let body = match max_bytes {
        None => response.text().await.map_err(|e| {
            ATMError::TransportError(format!("{context}: couldn't read response body: {e:?}"))
        })?,
        Some(max_bytes) => match read_body_capped(context, &mut response, max_bytes).await {
            Ok(body) => body,
            // An error status is reported as itself, whatever its body.
            Err(e) if !status.is_success() => format!("({e})"),
            Err(e) => return Err(e),
        },
    };
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

    fn problem(code: &str, comment: &str) -> ATMError {
        ATMError::ProblemReport(code.into(), comment.into(), "NONE".into())
    }

    fn refusal(code: &str, details: Option<serde_json::Value>) -> ATMError {
        let mut payload = serde_json::json!({ "code": code, "retryable": false });
        if let Some(d) = details {
            payload["details"] = d;
        }
        ATMError::TrustTaskError(Box::new(
            TrustTaskRefusal::from_document(&serde_json::json!({
                "id": "e1",
                "type": "https://trusttasks.org/spec/trust-task-error/0.6",
                "payload": payload,
            }))
            .expect("a trust-task-error"),
        ))
    }

    #[test]
    fn the_refusal_code_is_read_from_either_form() {
        let code = "messaging/mux/admin-revoke-all:epochMismatch";
        assert_eq!(
            problem(&format!("e.p.{code}"), "").refusal_code(),
            Some(code)
        );
        assert_eq!(refusal(code, None).refusal_code(), Some(code));
        assert_eq!(ATMError::SDKError("x".into()).refusal_code(), None);
    }

    #[test]
    fn the_mediator_code_survives_translation_to_a_standard_code() {
        let legacy = problem("e.p.authorization.admin_required", "admin only");
        let translated = refusal(
            "permissionDenied",
            Some(serde_json::json!({ "mediatorCode": "authorization.admin_required" })),
        );
        assert_eq!(legacy.mediator_code(), Some("authorization.admin_required"));
        assert_eq!(
            translated.mediator_code(),
            Some("authorization.admin_required")
        );
        assert_eq!(translated.refusal_code(), Some("permissionDenied"));
        // Untranslated: the code itself.
        assert_eq!(
            refusal("messaging/mux:notMuxConnection", None).mediator_code(),
            Some("messaging/mux:notMuxConnection")
        );
    }

    #[test]
    fn the_current_epoch_comes_from_details_or_an_older_comment() {
        let code = "messaging/mux/revoke-all:epochMismatch";
        assert_eq!(
            refusal(code, Some(serde_json::json!({ "currentEpoch": 7 }))).current_epoch(),
            Some(7)
        );
        assert_eq!(
            problem(
                &format!("e.p.{code}"),
                "statement voids epoch 9, the DID's current epoch is 7"
            )
            .current_epoch(),
            Some(7)
        );
        // Only an epochMismatch carries one.
        assert_eq!(
            refusal(
                "messaging/mux/revoke-all:contended",
                Some(serde_json::json!({ "currentEpoch": 7 }))
            )
            .current_epoch(),
            None
        );
        assert_eq!(refusal(code, None).current_epoch(), None);
    }

    #[test]
    fn a_problem_code_without_a_sorter_is_kept_whole() {
        assert_eq!(problem_descriptor("plain.code"), "plain.code");
        assert_eq!(problem_descriptor("w.m.x.y"), "x.y");
    }

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

    /// An error status with a body over the cap is reported as that status,
    /// not as an oversized body.
    #[tokio::test]
    async fn an_oversized_error_response_keeps_its_status() {
        let url = serve_once(
            "HTTP/1.1 404 Not Found\r\ncontent-length: 64\r\nconnection: close\r\n\r\n\
             0123456789012345678901234567890123456789012345678901234567890123",
        )
        .await;
        let response = reqwest::Client::new().post(&url).send().await.unwrap();
        let err = check_response_capped("retrieve OOB invitation", response, 8)
            .await
            .unwrap_err();
        assert_eq!(err.http_status().map(|s| s.status), Some(404), "{err:?}");
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
