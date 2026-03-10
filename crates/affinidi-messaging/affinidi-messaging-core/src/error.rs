use thiserror::Error;

/// Errors from the unified messaging layer.
#[derive(Debug, Error)]
pub enum MessagingError {
    #[error("pack error: {0}")]
    Pack(String),

    #[error("unpack error: {0}")]
    Unpack(String),

    #[error("identity resolution error: {0}")]
    Resolution(String),

    #[error("relationship error: {0}")]
    Relationship(String),

    #[error("transport error: {0}")]
    Transport(String),

    #[error("no endpoint available for {0}")]
    NoEndpoint(String),

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("not supported by this protocol: {0}")]
    NotSupported(String),
}
