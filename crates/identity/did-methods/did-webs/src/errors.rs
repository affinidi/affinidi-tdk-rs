//! Errors raised while resolving a `did:webs` identifier.

use affinidi_did_common::NetworkError;
use thiserror::Error;

/// Errors from `did:webs` parsing and resolution.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum DidWebsError {
    /// The identifier is not a syntactically valid `did:webs` DID.
    #[error("invalid did:webs identifier: {0}")]
    InvalidDid(String),

    /// An artifact could not be fetched: no response arrived (DNS, connect,
    /// TLS, timeout), or its body could not be read or was over the size
    /// cap. A host that answered with an unsuccessful status is
    /// [`DidWebsError::Network`].
    #[error("could not fetch {url}: {reason}")]
    Fetch {
        /// The URL that was requested.
        url: String,
        /// Why it failed.
        reason: String,
    },

    /// The host answered an artifact request with an unsuccessful HTTP
    /// status. The status, the URL and the host's `Retry-After` are kept as
    /// data, so a caller can tell a rate limit (HTTP 429) from an identifier
    /// that is not published (HTTP 404).
    #[error("{0}")]
    Network(NetworkError),

    /// The host the DID names is not one the resolver's
    /// [`HostPolicy`](crate::fetch::HostPolicy) lets it fetch from.
    #[error("did:webs host refused by host policy: {0}")]
    BlockedHost(String),

    /// The CESR stream could not be parsed, or carried something this
    /// implementation will not interpret.
    #[error("keri.cesr could not be read: {0}")]
    Stream(String),

    /// The key event log did not verify.
    #[error("key event log verification failed: {0}")]
    Kel(String),

    /// The published `did.json` disagrees with the document derived from the
    /// verified key state.
    #[error("did.json does not match the verified key state: {0}")]
    DocumentMismatch(String),

    /// No valid, unrevoked designated-aliases attestation in the stream
    /// authorises the DID being resolved, so the stream does not publish it
    /// (§ Read: a `did:webs` DID resolves only when its AID designated it).
    #[error("{0} is not designated by its AID")]
    NotDesignated(String),

    /// A designation's registry is broken, or the stream leaves out a
    /// registry event the identifier's key event log anchors — which would let
    /// a host withhold a revocation.
    #[error("designation registry: {0}")]
    Registry(String),

    /// The identifier stands behind a critical designation this
    /// implementation does not implement. A critical designation restricts the
    /// document, so serving it without the restriction would be wrong
    /// (`unsupportedDesignation`).
    #[error("unsupportedDesignation: schema {0} is critical and not implemented")]
    UnsupportedDesignation(String),

    /// The identifier is deactivated: its last rotation committed to no next
    /// keys (§ Deactivate). Returned where only a document is returned, so
    /// that its last keys are not taken for current ones;
    /// [`resolve_with_metadata`](crate::resolver::resolve_with_metadata)
    /// reports the deactivation in the metadata instead.
    #[error("{0} is deactivated")]
    Deactivated(String),

    /// A key is not one this implementation can publish for its purpose.
    #[error("invalid key: {0}")]
    InvalidKey(String),

    /// An identifier could not be created or continued.
    #[error("could not create: {0}")]
    Create(String),

    /// JSON deserialization failed.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

impl DidWebsError {
    /// The failed fetch behind this error, as the [`NetworkError`] every DID
    /// method crate reports: [`DidWebsError::Network`] as it is, and
    /// [`DidWebsError::Fetch`] with its URL and no status. `None` for any
    /// other error.
    pub fn network_error(&self) -> Option<NetworkError> {
        match self {
            Self::Network(network) => Some(network.clone()),
            Self::Fetch { url, reason } if !url.is_empty() => {
                Some(NetworkError::new(reason.clone()).with_url(url.clone()))
            }
            Self::Fetch { reason, .. } => Some(NetworkError::new(reason.clone())),
            _ => None,
        }
    }
}
