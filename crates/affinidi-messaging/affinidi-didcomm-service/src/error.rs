use thiserror::Error;

#[derive(Debug, Error)]
pub enum DIDCommServiceError {
    #[error("ATM error: {0}")]
    ATM(#[from] affinidi_messaging_sdk::errors::ATMError),

    #[error("Mediator not configured for listener '{0}'")]
    MissingMediator(String),

    #[error("Timeout: {0}")]
    Timeout(#[from] tokio::time::error::Elapsed),

    #[error("TDK error: {0}")]
    TDK(#[from] affinidi_tdk_common::errors::TDKError),

    #[error("Missing ATM instance after TDK initialization")]
    MissingATM,

    #[error("Listener '{0}' already exists")]
    ListenerAlreadyExists(String),

    #[error("Listener '{0}' not found")]
    ListenerNotFound(String),

    #[error("Service startup failed: {0}")]
    StartupFailed(String),

    #[error("Handler error: {0}")]
    Handler(String),

    #[error("Transport error: {0}")]
    Transport(String),

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Internal error: {0}")]
    Internal(String),
}
