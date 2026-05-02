/*!
 * Common TDK Errors and handling/conversion
 */

use affinidi_data_integrity::DataIntegrityError;
use affinidi_did_common::PeerError;
use affinidi_did_resolver_cache_sdk::errors::DIDCacheError;
use affinidi_secrets_resolver::errors::SecretsResolverError;
use thiserror::Error;

/// Affinidi Trust Development Kit Errors
///
/// Marked `#[non_exhaustive]` — consumers must include a wildcard arm when
/// matching, so new variants can be added without breaking downstream builds.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum TDKError {
    /// Authentication error, can be retried
    #[error("Authentication failed: {0}")]
    Authentication(String),

    /// Authentication error, cannot be retried
    #[error("Authentication Aborted: {0}")]
    AuthenticationAbort(String),

    /// Access Control Denied
    #[error("ACL Denied: {0}")]
    ACLDenied(String),

    #[error("Profile error: {0}")]
    Profile(String),

    #[error("DID Resolver error: {0}")]
    DIDResolver(String),

    #[error("Permission Denied: {0}")]
    PermissionDenied(String),

    #[error("DIDComm Error: {0}")]
    DIDComm(String),

    #[error("ATM Error: {0}")]
    ATM(String),

    #[error("Secrets Error: {0}")]
    Secrets(String),

    #[error("DID Method Error: {0}")]
    DIDMethod(String),

    #[error("Config Error: {0}")]
    Config(String),

    #[error("Data Integrity Error")]
    DataIntegrity(#[from] DataIntegrityError),

    /// Wraps any `std::io::Error` — file not found, permission denied,
    /// broken pipe, etc. Surfaced via `?` from internal IO sites that have
    /// no specific variant of their own.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Wraps any `serde_json` (de)serialisation failure.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, TDKError>;

impl From<DIDCacheError> for TDKError {
    fn from(error: DIDCacheError) -> Self {
        TDKError::DIDResolver(error.to_string())
    }
}

impl From<SecretsResolverError> for TDKError {
    fn from(error: SecretsResolverError) -> Self {
        TDKError::Secrets(error.to_string())
    }
}

impl From<PeerError> for TDKError {
    fn from(error: PeerError) -> Self {
        TDKError::DIDMethod(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn did_resolver_error_converts() {
        let inner = DIDCacheError::DIDError("bad did".into());
        let tdk: TDKError = inner.into();
        assert!(matches!(tdk, TDKError::DIDResolver(_)));
        assert!(tdk.to_string().contains("bad did"));
    }

    #[test]
    fn data_integrity_error_converts() {
        let inner = DataIntegrityError::signing(std::io::Error::other("bad sig"));
        let tdk: TDKError = inner.into();
        assert!(matches!(tdk, TDKError::DataIntegrity(_)));
    }

    #[test]
    fn display_format_preserves_payload() {
        let e = TDKError::Authentication("token expired".into());
        assert_eq!(e.to_string(), "Authentication failed: token expired");
    }

    #[test]
    fn io_error_converts_via_question_mark() {
        fn produce() -> Result<()> {
            let _file = std::fs::File::open("/nonexistent/should-not-exist")?;
            Ok(())
        }
        let err = produce().unwrap_err();
        assert!(matches!(err, TDKError::Io(_)));
    }

    #[test]
    fn json_error_converts_via_question_mark() {
        fn produce() -> Result<serde_json::Value> {
            let v = serde_json::from_str::<serde_json::Value>("not-json")?;
            Ok(v)
        }
        let err = produce().unwrap_err();
        assert!(matches!(err, TDKError::Json(_)));
    }
}
