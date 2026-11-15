use affinidi_did_common::NetworkError;
use didwebvh_rs::DIDWebVHError;
use thiserror::Error;

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum DIDSCIDError {
    /// A `did:webs` resolution failed.
    #[error("did:webs error: {0}")]
    WebsError(String),

    /// The host of a `did:scid:ke` DID's did:webs artifacts answered with an
    /// unsuccessful HTTP status, kept as data (status, URL, `Retry-After`).
    /// A did:webvh fetch failure stays a [`DIDSCIDError::WebVHError`];
    /// [`DIDSCIDError::network_error`] reads both.
    #[error("did:webs error: {0}")]
    Network(NetworkError),

    /// The DID is deactivated, so it has no document whose keys may be used.
    #[error("{0} is deactivated")]
    Deactivated(String),

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

impl DIDSCIDError {
    /// The failed network fetch behind this error, as the [`NetworkError`]
    /// every DID method crate reports, whichever format failed:
    /// [`DIDSCIDError::Network`] as it is, and a did:webvh
    /// `DIDWebVHError::NetworkError` with its URL and status. A status in the
    /// 2xx range, which did:webvh reports when reading the body failed after
    /// a successful response, is not recorded as the failure's status.
    /// `None` for any other error.
    pub fn network_error(&self) -> Option<NetworkError> {
        match self {
            Self::Network(network) => Some(network.clone()),
            Self::WebVHError(DIDWebVHError::NetworkError {
                url,
                status_code,
                message,
            }) => {
                let mut network = NetworkError::new(message.clone());
                if !url.is_empty() {
                    network = network.with_url(url.clone());
                }
                if let Some(status) = status_code.filter(|status| !(200..300).contains(status)) {
                    network = network.with_status(status);
                }
                Some(network)
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_webvh_network_error_reads_as_a_network_error() {
        let err = DIDSCIDError::WebVHError(DIDWebVHError::NetworkError {
            url: "https://example.com/did.jsonl".to_string(),
            status_code: Some(429),
            message: "HTTP 429".to_string(),
        });
        let network = err.network_error().expect("a network error");
        assert!(network.is_rate_limited());
        assert_eq!(
            network.url.as_deref(),
            Some("https://example.com/did.jsonl")
        );

        let body = DIDSCIDError::WebVHError(DIDWebVHError::NetworkError {
            url: "https://example.com/did.jsonl".to_string(),
            status_code: Some(200),
            message: "body cut short".to_string(),
        });
        assert_eq!(body.network_error().and_then(|n| n.status), None);

        assert!(DIDSCIDError::MissingPeerSource.network_error().is_none());
    }
}
