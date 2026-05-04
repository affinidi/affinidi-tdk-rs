//! Errors produced by the [`SecretStore`](crate::SecretStore) trait and its
//! backends.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, SecretStoreError>;

#[derive(Debug, Error)]
pub enum SecretStoreError {
    #[error("invalid backend URL '{url}': {reason}")]
    InvalidUrl { url: String, reason: String },

    #[error("backend '{backend}' is not available: {reason}")]
    BackendUnavailable {
        backend: &'static str,
        reason: String,
    },

    #[error("backend '{backend}' unreachable: {reason}")]
    Unreachable {
        backend: &'static str,
        reason: String,
    },

    #[error("secret '{key}' not found")]
    NotFound { key: String },

    #[error("permission denied on '{key}': {reason}")]
    PermissionDenied { key: String, reason: String },

    #[error("probe failed on backend '{backend}': {reason}")]
    ProbeFailed {
        backend: &'static str,
        reason: String,
    },

    #[error("stored envelope for '{key}' could not be decoded: {reason}")]
    EnvelopeDecode { key: String, reason: String },

    #[error("stored envelope for '{key}' has unexpected kind '{actual}' (wanted '{expected}')")]
    EnvelopeKindMismatch {
        key: String,
        expected: &'static str,
        actual: String,
    },

    #[error("stored envelope for '{key}' has unsupported version {version}")]
    EnvelopeUnsupportedVersion { key: String, version: u32 },

    #[error("stored secret '{key}' failed shape validation: {reason}")]
    InvalidShape { key: String, reason: String },

    #[error("I/O error on backend '{backend}': {source}")]
    Io {
        backend: &'static str,
        #[source]
        source: std::io::Error,
    },

    #[error("serialisation error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("{0}")]
    Other(String),
}

impl SecretStoreError {
    pub fn unreachable<S: Into<String>>(backend: &'static str, reason: S) -> Self {
        Self::Unreachable {
            backend,
            reason: reason.into(),
        }
    }

    pub fn other<S: Into<String>>(reason: S) -> Self {
        Self::Other(reason.into())
    }
}
