/*!
 * DID Authentication Errors
 */

use affinidi_did_resolver_cache_sdk::errors::DIDCacheError;
pub use affinidi_messaging_core::HttpStatusError;
use affinidi_messaging_didcomm::error::DIDCommError;
use affinidi_secrets_resolver::errors::SecretsResolverError;
use thiserror::Error;

/// DID Authentication Errors
///
/// This type is `#[non_exhaustive]`: callers must include a wildcard arm when
/// matching, so future additions do not constitute breaking changes.
///
/// [`DIDAuthError::is_retryable`] says whether trying again can help;
/// [`DIDAuthentication::authenticate`](crate::DIDAuthentication::authenticate)
/// retries only those errors.
///
/// `Clone` so that one failed authentication can be handed to every caller
/// waiting on it.
#[derive(Error, Debug, Clone)]
#[non_exhaustive]
pub enum DIDAuthError {
    /// The authentication request could not be made or its answer could not
    /// be read: a transport failure that may pass. Can be retried.
    ///
    /// An answer that arrived but cannot be used is
    /// [`DIDAuthError::InvalidResponse`] (since 0.4.0).
    #[error("Authentication failed: {0}")]
    Authentication(String),

    /// The authentication service answered successfully, but with something
    /// this client cannot use: a body that does not deserialize, or tokens
    /// whose expiry is not a valid RFC 3339 timestamp or is before the Unix
    /// epoch. The same request would get the same answer, so it cannot be
    /// retried.
    #[error("Invalid authentication response: {0}")]
    InvalidResponse(String),

    /// There are no tokens to refresh, or the refresh token has expired too:
    /// a refresh cannot succeed, and a full
    /// [`DIDAuthentication::authenticate`](crate::DIDAuthentication::authenticate)
    /// is needed. Cannot be retried as a refresh.
    #[error("Authentication tokens unavailable: {0}")]
    NoTokens(String),

    /// Authentication error, cannot be retried
    #[error("Authentication Aborted: {0}")]
    AuthenticationAbort(String),

    /// Access Control Denied
    #[error("ACL Denied: {0}")]
    ACLDenied(String),

    /// DIDComm related Error
    #[error("DIDComm error: {0}")]
    DIDComm(String),

    /// Resolving a DID failed in a way that may pass: the resolver or its
    /// network. Can be retried.
    #[error("DID Resolver error: {0}")]
    DIDResolver(String),

    /// A DID cannot be resolved as given: it is malformed, or its method is
    /// not supported. Cannot be retried.
    #[error("DID Resolver error: {0}")]
    UnresolvableDID(String),

    #[error("Secrets Error: {0}")]
    Secrets(String),

    /// The authentication service answered with a non-success HTTP status
    /// (other than `401`, which is [`DIDAuthError::ACLDenied`]). For a `429`,
    /// [`HttpStatusError::rate_limit_source`] names the refusing service and
    /// [`HttpStatusError::retry_after_secs`] the wait. Can be retried. Boxed so
    /// the variant does not grow every `Result<_, DIDAuthError>`.
    #[error("Authentication failed: {0}")]
    HttpStatus(Box<HttpStatusError>),

    /// [`DIDAuthentication::authenticate`](crate::DIDAuthentication::authenticate)
    /// gave up: the retry limit was reached, or a rate limiter asked for a
    /// longer wait than the retry loop will spend. `last` is the failure of the
    /// final attempt, so the cause — a `429` and who sent it, say — is not
    /// lost. Cannot be retried by the same call.
    #[error(
        "Authentication Aborted: Maximum number of authentication retries reached \
         ({attempts} attempt(s)); last error: {last}"
    )]
    RetriesExhausted {
        /// Attempts made, including the first.
        attempts: u32,
        /// The error from the last attempt.
        #[source]
        last: Box<DIDAuthError>,
    },

    /// The authentication did not finish within the time the caller allowed.
    /// Can be retried.
    #[error("Authentication timed out: {0}")]
    Timeout(String),

    /// The background task that runs authentications is not running (it was
    /// terminated, or never started). Cannot be retried until it is.
    #[error("Authentication task unavailable: {0}")]
    TaskUnavailable(String),
}

pub type Result<T> = std::result::Result<T, DIDAuthError>;

impl DIDAuthError {
    /// Can trying again succeed?
    ///
    /// Retryable: transport failures ([`DIDAuthError::Authentication`],
    /// [`DIDAuthError::DIDResolver`]), timeouts, and HTTP 408, 429 and 5xx.
    /// Not retryable: everything that will fail the same way again — an abort,
    /// an ACL denial, a DIDComm or secrets problem (no usable key, say), a DID
    /// that cannot be resolved, an answer that cannot be used
    /// ([`DIDAuthError::InvalidResponse`]), no tokens to refresh
    /// ([`DIDAuthError::NoTokens`]), any other 4xx, and retries already
    /// exhausted.
    pub fn is_retryable(&self) -> bool {
        match self {
            DIDAuthError::Authentication(_)
            | DIDAuthError::DIDResolver(_)
            | DIDAuthError::Timeout(_) => true,
            DIDAuthError::HttpStatus(err) => {
                err.status == 408 || err.status == 429 || err.status >= 500
            }
            DIDAuthError::AuthenticationAbort(_)
            | DIDAuthError::InvalidResponse(_)
            | DIDAuthError::NoTokens(_)
            | DIDAuthError::ACLDenied(_)
            | DIDAuthError::DIDComm(_)
            | DIDAuthError::Secrets(_)
            | DIDAuthError::UnresolvableDID(_)
            | DIDAuthError::RetriesExhausted { .. }
            | DIDAuthError::TaskUnavailable(_) => false,
        }
    }

    /// The HTTP status error behind this failure, when there is one — looking
    /// through [`DIDAuthError::RetriesExhausted`] to the last attempt.
    pub fn http_status(&self) -> Option<&HttpStatusError> {
        match self {
            DIDAuthError::HttpStatus(err) => Some(err),
            DIDAuthError::RetriesExhausted { last, .. } => last.http_status(),
            _ => None,
        }
    }

    /// A rate limiter refused the authentication (HTTP 429). Which one, and
    /// when to retry, are on [`Self::http_status`].
    pub fn is_rate_limited(&self) -> bool {
        self.http_status()
            .is_some_and(HttpStatusError::is_rate_limited)
    }
}

impl From<HttpStatusError> for DIDAuthError {
    fn from(err: HttpStatusError) -> Self {
        DIDAuthError::HttpStatus(Box::new(err))
    }
}

impl From<DIDCommError> for DIDAuthError {
    fn from(error: DIDCommError) -> Self {
        DIDAuthError::DIDComm(error.to_string())
    }
}

impl From<DIDCacheError> for DIDAuthError {
    /// A malformed DID or an unsupported method is
    /// [`DIDAuthError::UnresolvableDID`]; anything else from the resolver is
    /// [`DIDAuthError::DIDResolver`].
    fn from(error: DIDCacheError) -> Self {
        match error {
            DIDCacheError::DIDError(_)
            | DIDCacheError::UnsupportedMethod(_)
            | DIDCacheError::ParsingError(_) => DIDAuthError::UnresolvableDID(error.to_string()),
            _ => DIDAuthError::DIDResolver(error.to_string()),
        }
    }
}

impl From<SecretsResolverError> for DIDAuthError {
    fn from(error: SecretsResolverError) -> Self {
        DIDAuthError::Secrets(error.to_string())
    }
}
