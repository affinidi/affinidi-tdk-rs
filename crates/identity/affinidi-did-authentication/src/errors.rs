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
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum DIDAuthError {
    /// Authentication error, can be retried
    #[error("Authentication failed: {0}")]
    Authentication(String),

    /// Authentication error, cannot be retried
    #[error("Authentication Aborted: {0}")]
    AuthenticationAbort(String),

    /// Access Control Denied
    #[error("ACL Denied: {0}")]
    ACLDenied(String),

    /// DIDComm related Error
    #[error("DIDComm error: {0}")]
    DIDComm(String),

    #[error("DID Resolver error: {0}")]
    DIDResolver(String),

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
}

pub type Result<T> = std::result::Result<T, DIDAuthError>;

impl DIDAuthError {
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
    fn from(error: DIDCacheError) -> Self {
        DIDAuthError::DIDResolver(error.to_string())
    }
}

impl From<SecretsResolverError> for DIDAuthError {
    fn from(error: SecretsResolverError) -> Self {
        DIDAuthError::Secrets(error.to_string())
    }
}
