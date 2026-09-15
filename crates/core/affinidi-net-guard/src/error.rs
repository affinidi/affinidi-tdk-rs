//! [`EgressError`] and [`blocked_in_chain`].

use std::net::IpAddr;

use crate::IpClass;

/// Why an egress was refused, or failed.
///
/// [`EgressError::is_refusal`] separates a policy refusal from a malformed URL
/// or a transport failure. A refusal raised inside `reqwest` (by the resolver
/// or the redirect policy) arrives wrapped in a `reqwest::Error`; recover it
/// with [`blocked_in_chain`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EgressError {
    /// The input is not a valid URL, or has no host.
    #[error("invalid URL: {0}")]
    InvalidUrl(String),

    /// A policy was configured with a value it cannot use (a malformed CIDR
    /// or allow-list rule).
    #[error("invalid egress policy configuration: {0}")]
    InvalidConfig(String),

    /// The scheme is not admitted. Also raised for an https-to-http redirect
    /// downgrade.
    #[error("scheme not allowed: {0}")]
    SchemeNotAllowed(String),

    /// The URL carries a username or password.
    #[error("URLs carrying userinfo are not allowed")]
    UserinfoNotAllowed,

    /// The port is not admitted.
    #[error("port not allowed: {0}")]
    PortNotAllowed(u16),

    /// The host is not on the operator allow-list.
    #[error("host is not on the allow-list: {0}")]
    HostNotAllowed(String),

    /// A URL left the origin it was required to stay on.
    #[error("cross-origin URL not allowed: {0}")]
    CrossOrigin(String),

    /// The host is a special-use name (`localhost`, `*.local`, a single
    /// label, ...).
    #[error("special-use host name not allowed: {0}")]
    BlockedName(String),

    /// The host is, or resolves to, an address the policy refuses.
    #[error("blocked address {addr} ({class}) for host {host}")]
    BlockedAddress {
        /// The host as written, or the name that was resolved.
        host: String,
        /// The refused address.
        addr: IpAddr,
        /// Its classification.
        class: IpClass,
    },

    /// A name resolved to no addresses at all.
    #[error("{0} resolved to no addresses")]
    NoAddresses(String),

    /// A redirect hop was refused.
    #[error("redirect to {to} refused: {reason}")]
    RedirectBlocked {
        /// The `Location` the server redirected to.
        to: String,
        /// Why the hop was refused.
        #[source]
        reason: Box<EgressError>,
    },

    /// The redirect chain exceeded its hop cap.
    #[error("more than {max} redirects")]
    TooManyRedirects {
        /// The cap that was exceeded.
        max: u8,
    },

    /// The response body exceeded the client's cap.
    #[error("response body exceeded the {max}-byte cap")]
    BodyTooLarge {
        /// The cap that was exceeded.
        max: usize,
    },

    /// The HTTP client failed to build or the request failed in transport.
    /// A refusal may still be inside; see [`blocked_in_chain`].
    #[error("HTTP transport error: {0}")]
    Transport(#[from] reqwest::Error),
}

impl EgressError {
    /// `true` when the policy refused the egress, as opposed to the URL being
    /// malformed, a name not resolving, or the transport failing.
    pub fn is_refusal(&self) -> bool {
        matches!(
            self,
            Self::SchemeNotAllowed(_)
                | Self::UserinfoNotAllowed
                | Self::PortNotAllowed(_)
                | Self::HostNotAllowed(_)
                | Self::CrossOrigin(_)
                | Self::BlockedName(_)
                | Self::BlockedAddress { .. }
                | Self::RedirectBlocked { .. }
                | Self::TooManyRedirects { .. }
        )
    }
}

/// Find the outermost policy refusal anywhere in an error's source chain.
///
/// Use it on a `reqwest::Error` from a guarded client to tell "refused by the
/// guard" apart from "unreachable":
///
/// ```no_run
/// # async fn run(client: affinidi_net_guard::GuardedClient, url: affinidi_net_guard::VettedUrl) {
/// match client.get(&url).unwrap().send().await {
///     Err(e) if affinidi_net_guard::blocked_in_chain(&e).is_some() => { /* refused */ }
///     Err(_) => { /* transport failure */ }
///     Ok(_) => {}
/// }
/// # }
/// ```
pub fn blocked_in_chain<'a>(err: &'a (dyn std::error::Error + 'static)) -> Option<&'a EgressError> {
    let mut next = Some(err);
    while let Some(current) = next {
        if let Some(egress) = current.downcast_ref::<EgressError>()
            && egress.is_refusal()
        {
            return Some(egress);
        }
        next = current.source();
    }
    None
}
