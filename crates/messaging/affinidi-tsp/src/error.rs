use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
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

    /// The bytes are not a TSP message at all — no `-E` frame, or no `YTSP`
    /// genus code. Kept distinct from [`TspError::VersionMismatch`], which
    /// means "TSP, but a version this build cannot process" (Rev 3 §9.1).
    #[error("not a TSP message: {0}")]
    NotTsp(String),

    /// A well-formed TSP message whose MAJOR version this build cannot
    /// process. MINOR and PATCH differences are carried, not rejected.
    #[error("unsupported TSP major version {found} (this build speaks {supported})")]
    VersionMismatch { found: u16, supported: u16 },

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

    #[error("DID resolution error: {0}")]
    DidResolution(String),
}
