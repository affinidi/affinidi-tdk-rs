//! Redirect handling: refuse by default, or re-vet every hop.

use reqwest::redirect::{Attempt, Policy};
use url::Url;

use crate::{EgressError, EgressPolicy};

/// How a guarded client treats an HTTP redirect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum RedirectMode {
    /// Do not follow. The 3xx response is returned to the caller. The default.
    #[default]
    None,
    /// Follow up to `max` redirects that keep the original request's scheme,
    /// host and port. Each hop is also re-vetted.
    SameOrigin {
        /// Most redirects followed.
        max: u8,
    },
    /// Follow up to `max` redirects, re-vetting every hop against the policy
    /// and refusing any `https`/`wss` to `http`/`ws` downgrade.
    ReVet {
        /// Most redirects followed.
        max: u8,
    },
}

/// A `reqwest` redirect policy that enforces `mode` under `policy`.
///
/// Only the URL half re-runs here. The DNS half re-applies by itself, because
/// the next hop's host goes through the same client's [`GuardedResolver`](crate::GuardedResolver);
/// install this on a client that has one.
pub fn redirect_policy(policy: EgressPolicy, mode: RedirectMode) -> Policy {
    match mode {
        RedirectMode::None => Policy::none(),
        RedirectMode::SameOrigin { .. } | RedirectMode::ReVet { .. } => {
            Policy::custom(move |attempt: Attempt| {
                match check_redirect(&policy, mode, attempt.url(), attempt.previous()) {
                    Ok(()) => attempt.follow(),
                    Err(refusal) => attempt.error(refusal),
                }
            })
        }
    }
}

/// `previous` is every URL already requested in the chain, starting with the
/// original request, as `reqwest` reports it.
pub(crate) fn check_redirect(
    policy: &EgressPolicy,
    mode: RedirectMode,
    next: &Url,
    previous: &[Url],
) -> Result<(), EgressError> {
    let (max, same_origin) = match mode {
        RedirectMode::None => return Err(EgressError::TooManyRedirects { max: 0 }),
        RedirectMode::SameOrigin { max } => (max, true),
        RedirectMode::ReVet { max } => (max, false),
    };
    // The first entry is the original request, not a redirect.
    if previous.len() > usize::from(max) {
        return Err(EgressError::TooManyRedirects { max });
    }
    let refuse = |reason: EgressError| EgressError::RedirectBlocked {
        to: next.to_string(),
        reason: Box::new(reason),
    };
    if let Some(last) = previous.last()
        && is_secure(last)
        && !is_secure(next)
    {
        return Err(refuse(EgressError::SchemeNotAllowed(format!(
            "{} to {} downgrade",
            last.scheme(),
            next.scheme()
        ))));
    }
    if same_origin
        && let Some(first) = previous.first()
        && first.origin() != next.origin()
    {
        return Err(refuse(EgressError::CrossOrigin(
            next.origin().ascii_serialization(),
        )));
    }
    policy.vet_url(next).map(drop).map_err(refuse)
}

fn is_secure(url: &Url) -> bool {
    matches!(url.scheme(), "https" | "wss")
}
