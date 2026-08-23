use didwebvh_rs::DIDWebVHError;
use thiserror::Error;

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum DIDSCIDError {
    /// A `did:webs` resolution failed.
    #[error("did:webs error: {0}")]
    WebsError(String),

    /// The DID names a `did:scid` format this implementation does not
    /// resolve. Distinct from [`Self::UnsupportedFormat`], which means the
    /// string is not a `did:scid` at all.
    #[error("unknown did:scid format: {0}")]
    UnknownFormat(String),

    /// The DID names a format version this implementation does not resolve.
    #[error("unsupported did:scid version: {0}")]
    UnsupportedVersion(String),

    #[error("Unsupported format")]
    UnsupportedFormat,
    #[error("DID URL Error: {0}")]
    DidUrlError(String),
    #[error("Invalid src parameter: {0}")]
    InvalidSrc(String),
    #[error("WebVH error")]
    WebVHError(#[from] DIDWebVHError),
    #[error("Cheqd error: {0}")]
    CheqdError(String),
    #[error("Is a peer SCID DID, but no peer source information provided")]
    MissingPeerSource,
    #[error("Serialization/Deserializaton error occurred")]
    SerdeError(#[from] serde_json::Error),
}
