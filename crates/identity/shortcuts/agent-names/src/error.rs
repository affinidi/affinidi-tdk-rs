//! Errors produced while parsing, resolving or verifying an agent name.

use thiserror::Error;

/// Agent name errors.
///
/// This type is `#[non_exhaustive]`: callers must include a wildcard arm when
/// matching, so future additions do not constitute breaking changes.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AgentNameError {
    /// The string is not an agent name (no `/@` marker, empty local name,
    /// unparseable as a URL, …).
    #[error("Invalid agent name '{input}': {reason}")]
    InvalidName { input: String, reason: String },

    /// The name's scheme is not permitted (plain HTTP without opt-in).
    #[error("Refusing to resolve '{0}' over plain HTTP; agent names must use HTTPS")]
    InsecureScheme(String),

    /// The name resolved, but the DID Document does not claim the name back via
    /// `alsoKnownAs`. This is the mandatory Layer-1 anti-spoofing check.
    ///
    /// Anyone can publish a redirect pointing at someone else's DID; only the
    /// DID's own controller can add an `alsoKnownAs` entry to its Document.
    #[error(
        "Agent name '{name}' is not authorized by DID '{did}': its DID Document's alsoKnownAs does not contain the name"
    )]
    NotAuthorized { name: String, did: String },

    /// Transport failure reaching the agent name.
    #[error("HTTP error resolving agent name: {0}")]
    Http(#[from] reqwest::Error),

    /// The name did not redirect to anything.
    #[error("Agent name '{name}' did not redirect (HTTP {status}); expected a 3xx with a Location")]
    NoRedirect { name: String, status: u16 },

    /// A redirect was returned but its target is not a DID.
    #[error("Agent name '{name}' redirected to '{target}', which is not a DID")]
    NotADid { name: String, target: String },

    /// Too many redirect hops.
    #[error("Agent name '{name}' exceeded the redirect limit of {limit} hops")]
    TooManyRedirects { name: String, limit: u8 },

    /// A response exceeded the configured size cap.
    #[error("Response for agent name '{name}' exceeded the {limit} byte limit")]
    ResponseTooLarge { name: String, limit: usize },

    /// The name resolved to a non-public address (loopback, private, link-local…).
    ///
    /// Almost always an SSRF attempt rather than a real agent name.
    #[error(
        "Agent name '{name}' resolves to the non-public address {address}; refusing to fetch it"
    )]
    BlockedAddress { name: String, address: String },

    /// A cache server rejected or could not answer the lookup.
    #[error("Cache server returned HTTP {status} resolving '{name}': {message}")]
    CacheServer {
        name: String,
        status: u16,
        message: String,
    },

    /// No registered backend could resolve the name.
    #[error("No agent name resolver could resolve '{0}'")]
    Unresolvable(String),
}
