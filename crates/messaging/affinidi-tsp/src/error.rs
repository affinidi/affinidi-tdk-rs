use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TspError {
    #[error("CESR encoding error: {0}")]
    Cesr(#[from] affinidi_cesr::CesrError),

    #[error("HPKE error: {0}")]
    Hpke(String),

    /// A libsodium sealed box failed to seal or open (Rev 3 §8.3).
    ///
    /// Kept apart from [`TspError::Hpke`] because the two schemes fail for
    /// different reasons and an operator reading a log needs to know which one
    /// a peer was using — the ciphertext code says which, and this preserves it.
    #[error("sealed box error: {0}")]
    SealedBox(String),

    #[error("signing error: {0}")]
    Signing(String),

    #[error("verification failed: {0}")]
    Verification(String),

    #[error("invalid message: {0}")]
    InvalidMessage(String),

    /// The message was well-formed and authentic but is being discarded by a
    /// protocol rule — no relationship with the sender, a cancellation naming a
    /// relationship we do not hold, or a losing side of the invite race.
    ///
    /// Rev 3 §3.7 requires a receiver to discard silently and send nothing in
    /// response, so a caller must not turn this into a distinguishable answer:
    /// any response tells whoever sent it which check failed.
    #[error("message discarded: {0}")]
    Discarded(String),

    /// The bytes are not a TSP message at all — no `-E` frame, or no `YTSP`
    /// genus code. Kept distinct from [`TspError::VersionMismatch`], which
    /// means "TSP, but a version this build cannot process" (Rev 3 §9.1).
    #[error("not a TSP message: {0}")]
    NotTsp(String),

    /// A well-formed TSP message whose MAJOR version this build cannot
    /// process. MINOR and PATCH differences are carried, not rejected.
    #[error("unsupported TSP major version {found} (this build speaks {supported})")]
    VersionMismatch { found: u16, supported: u16 },

    /// A TSP message whose MAJOR version we accept but whose MINOR names a
    /// different revision, and which then failed to parse.
    ///
    /// §9.1 uses MINOR to track the CESR code table a revision pins, so a
    /// differing MINOR means the frame was built against a table this build does
    /// not have — which is very likely why the parse failed. It is not certain,
    /// so this is raised only once parsing has actually failed, and it carries
    /// the underlying error rather than replacing it.
    ///
    /// Worth the extra variant because of how the failure presents otherwise. A
    /// Rev 2 frame reaches a Rev 3 build with a version marker that passes, both
    /// VIDs parsing cleanly, and dies at the ciphertext selector — "missing F
    /// ciphertext field", which points an implementer at the crypto layer for a
    /// problem that is nothing of the sort.
    #[error(
        "TSP revision mismatch: message is {found_major}.{found_minor}, this build speaks {supported_major}.{supported_minor} ({source})"
    )]
    RevisionMismatch {
        found_major: u16,
        found_minor: u16,
        supported_major: u16,
        supported_minor: u16,
        source: Box<TspError>,
    },

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
