//! Errors of the cache server itself (configuration and start-up).

use thiserror::Error;

type SessId = String;

/// CacheError the first String is always the session_id
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum CacheError {
    #[error("{1}")]
    InternalError(SessId, String),
    #[error("Configuration Error: {1}")]
    ConfigError(SessId, String),
}
