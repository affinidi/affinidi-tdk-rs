//! Errors raised while resolving a `did:webs` identifier.

use thiserror::Error;

/// Errors from `did:webs` parsing and resolution.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum DidWebsError {
    /// The identifier is not a syntactically valid `did:webs` DID.
    #[error("invalid did:webs identifier: {0}")]
    InvalidDid(String),

    /// An artifact could not be fetched.
    #[error("could not fetch {url}: {reason}")]
    Fetch {
        /// The URL that was requested.
        url: String,
        /// Why it failed.
        reason: String,
    },

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
