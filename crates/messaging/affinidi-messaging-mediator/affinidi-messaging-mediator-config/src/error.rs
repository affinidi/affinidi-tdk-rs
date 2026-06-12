//! Error type for config loading.
//!
//! The schema crate can't use the mediator's server-tier `MediatorError`, so
//! file-reading / parsing functions return this lean error instead. The
//! mediator maps it back to `MediatorError::ConfigError` at the call site.

/// Failure while reading or parsing a `mediator.toml`.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The config file could not be opened/read.
    #[error("could not open config file ({path}): {source}")]
    FileRead {
        path: String,
        source: std::io::Error,
    },
    /// The TOML did not deserialize into [`ConfigRaw`](crate::ConfigRaw).
    #[error("could not parse configuration settings: {0}")]
    Parse(String),
}
