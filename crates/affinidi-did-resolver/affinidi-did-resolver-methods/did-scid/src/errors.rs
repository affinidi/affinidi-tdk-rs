use didwebvh_rs::DIDWebVHError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DIDSCIDError {
    #[error("Unsupported format")]
    UnsupportedFormat,
    #[error("DID URL Error: {0}")]
    DidUrlError(String),
    #[error("WebVH error")]
    WebVHError(#[from] DIDWebVHError),
    #[error("Cheqd error: {0}")]
    CheqdError(String),
    #[error("Is a peer SCID DID, but no peer source information provided")]
    MissingPeerSource,
    #[error("Serialization/Deserializaton error occurred")]
    SerdeError(#[from] serde_json::Error),
}
