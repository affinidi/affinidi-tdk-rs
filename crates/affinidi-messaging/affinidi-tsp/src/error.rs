use thiserror::Error;

#[derive(Debug, Error)]
pub enum TspError {
    #[error("CESR encoding error: {0}")]
    Cesr(#[from] affinidi_cesr::CesrError),

    #[error("HPKE error: {0}")]
    Hpke(String),

    #[error("signing error: {0}")]
    Signing(String),

    #[error("verification failed: {0}")]
    Verification(String),

    #[error("invalid message: {0}")]
    InvalidMessage(String),

    #[error("VID error: {0}")]
    Vid(String),

    #[error("VID not found: {0}")]
    VidNotFound(String),

    #[error("relationship error: {0}")]
    Relationship(String),

    #[error("no encryption key available for VID: {0}")]
    NoEncryptionKey(String),

    #[error("no signing key available for VID: {0}")]
    NoSigningKey(String),

    #[error("store error: {0}")]
    Store(String),

    #[error("serialization error: {0}")]
    Serialization(String),
}
