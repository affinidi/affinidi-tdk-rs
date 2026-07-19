//! Backends that turn an agent name into a DID.

use std::{future::Future, pin::Pin, time::Duration};

use tracing::debug;
use url::Url;

use crate::{error::AgentNameError, name::AgentName};

/// Default request timeout.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(20);

/// Default cap on redirect hops followed while chasing a name.
pub const DEFAULT_MAX_HOPS: u8 = 5;

/// The outcome of asking one backend to resolve a name.
///
/// Mirrors `affinidi_did_resolver_traits::Resolution`, so a chain of agent name
/// backends reads the same way as a chain of DID method resolvers:
///
/// - `None` — "not mine, try the next backend"
/// - `Some(Ok(did))` — resolved
/// - `Some(Err(e))` — recognised, but failed
pub type NameResolution = Option<Result<String, AgentNameError>>;

/// A backend that maps an agent name to a DID.
///
/// Implement this to resolve names from somewhere other than a live HTTP
/// redirect — a registry API, DNS, a cache server, or a fixed map in tests.
pub trait AgentNameResolver: Send + Sync {
    /// Short name for this backend, used for logging and de-duplication.
    fn name(&self) -> &str;

    /// Attempt to resolve `name` to a DID string.
    fn resolve<'a>(
        &'a self,
        name: &'a AgentName,
    ) -> Pin<Box<dyn Future<Output = NameResolution> + Send + 'a>>;
}

/// Resolves an agent name by following the web redirect it serves.
///
/// # The redirect contract is not pinned down by the specification
///
/// The agent name FAQ says only that resolution "typically works through a
/// simple web redirect". It does not state the status code, whether the DID
/// arrives as a bare `did:…` string or wrapped in a URI, or whether content
/// negotiation is involved. At the time of writing there is no reference
/// implementation to check against: `firstperson.network` is live but its
/// example names return 404.
///
/// This backend is therefore deliberately permissive, and every guess is
/// contained here rather than in the crate's data types:
///
/// - any 3xx carrying a `Location` header is accepted (301/302/303/307/308);
/// - the target is accepted as a bare `did:…`, or as a URI whose last path
///   segment is a DID, or with a `did=` query parameter;
/// - up to [`DEFAULT_MAX_HOPS`] hops are followed, so an apex-to-`www`
///   redirect on the way to the DID does not break resolution.
///
/// # Safety
///
/// Redirects are **not** followed automatically by `reqwest`; each hop is
/// inspected explicitly. This mirrors `affinidi-did-web`'s SSRF hardening and
/// is what makes the hop cap and the HTTPS requirement enforceable.
#[derive(Debug, Clone)]
pub struct HttpRedirectResolver {
    client: reqwest::Client,
    max_hops: u8,
    allow_insecure_http: bool,
}

impl HttpRedirectResolver {
    /// A resolver with redirects disabled, a 20s timeout, and HTTPS required.
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(DEFAULT_TIMEOUT)
            .build()
            .unwrap_or_default();
        Self {
            client,
            max_hops: DEFAULT_MAX_HOPS,
            allow_insecure_http: false,
        }
    }

    /// Use a caller-supplied client.
    ///
    /// The client **must** have redirects disabled
    /// (`reqwest::redirect::Policy::none()`); otherwise the hop cap and the
    /// per-hop HTTPS check are bypassed.
    pub fn with_client(client: reqwest::Client) -> Self {
        Self {
            client,
            max_hops: DEFAULT_MAX_HOPS,
            allow_insecure_http: false,
        }
    }

    /// Override the redirect hop cap.
    pub fn with_max_hops(mut self, max_hops: u8) -> Self {
        self.max_hops = max_hops;
        self
    }

    /// Permit plain-HTTP agent names.
    ///
    /// Off by default and intended for local development and tests. A plain
    /// HTTP redirect can be rewritten in transit, which lets an attacker point
    /// the name at a DID of their choosing — `alsoKnownAs` verification will
    /// usually catch that, but do not rely on it in production.
    pub fn allow_insecure_http(mut self, allow: bool) -> Self {
        self.allow_insecure_http = allow;
        self
    }

    async fn resolve_inner(&self, name: &AgentName) -> Result<String, AgentNameError> {
        if !name.is_https() && !self.allow_insecure_http {
            return Err(AgentNameError::InsecureScheme(name.as_str().to_string()));
        }

        let mut url = name.resolution_url()?;

        for hop in 0..self.max_hops {
            debug!(hop, %url, "resolving agent name");
            let response = self.client.get(url.clone()).send().await?;
            let status = response.status();

            if !status.is_redirection() {
                return Err(AgentNameError::NoRedirect {
                    name: name.as_str().to_string(),
                    status: status.as_u16(),
                });
            }

            let location = response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| AgentNameError::NoRedirect {
                    name: name.as_str().to_string(),
                    status: status.as_u16(),
                })?
                .to_string();

            if let Some(did) = extract_did(&location) {
                return Ok(did);
            }

            // Not a DID yet — could be an apex→www or http→https hop. Resolve
            // the target relative to the current URL and keep going.
            let next = url.join(&location).map_err(|_| AgentNameError::NotADid {
                name: name.as_str().to_string(),
                target: location.clone(),
            })?;

            if next.scheme() != "https" && !self.allow_insecure_http {
                return Err(AgentNameError::InsecureScheme(next.to_string()));
            }
            let _ = hop;
            url = next;
        }

        Err(AgentNameError::TooManyRedirects {
            name: name.as_str().to_string(),
            limit: self.max_hops,
        })
    }
}

impl Default for HttpRedirectResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl AgentNameResolver for HttpRedirectResolver {
    fn name(&self) -> &str {
        "http-redirect"
    }

    fn resolve<'a>(
        &'a self,
        name: &'a AgentName,
    ) -> Pin<Box<dyn Future<Output = NameResolution> + Send + 'a>> {
        Box::pin(async move { Some(self.resolve_inner(name).await) })
    }
}

/// Pull a DID out of a redirect target.
///
/// Accepts, in order: a bare `did:…`; a `did=` query parameter; a URI whose
/// last path segment is a DID. Returns `None` if the target carries no DID,
/// which the caller treats as "keep following".
fn extract_did(target: &str) -> Option<String> {
    let trimmed = target.trim();

    if is_did(trimmed) {
        return Some(trimmed.to_string());
    }

    if let Ok(url) = Url::parse(trimmed) {
        if let Some((_, value)) = url.query_pairs().find(|(k, _)| k == "did")
            && is_did(&value)
        {
            return Some(value.into_owned());
        }
        // A DID in a path arrives percent-encoded, since ':' is reserved.
        if let Some(last) = url.path_segments().and_then(|mut s| s.next_back())
            && let Ok(decoded) = percent_decode(last)
            && is_did(&decoded)
        {
            return Some(decoded);
        }
    }

    None
}

fn is_did(s: &str) -> bool {
    // did:<method>:<id> — enough structure to distinguish a DID from a URL.
    let mut parts = s.splitn(3, ':');
    parts.next() == Some("did")
        && parts.next().is_some_and(|m| {
            !m.is_empty()
                && m.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        })
        && parts.next().is_some_and(|id| !id.is_empty())
}

fn percent_decode(s: &str) -> Result<String, ()> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err(());
            }
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).map_err(|_| ())?;
            out.push(u8::from_str_radix(hex, 16).map_err(|_| ())?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- is_did ---

    #[test]
    fn recognises_dids() {
        assert!(is_did("did:web:example.com"));
        assert!(is_did("did:key:z6Mk"));
        assert!(is_did("did:webvh:QmScid:example.com"));
        assert!(is_did("did:scid:vh:1:QmScid"));
    }

    #[test]
    fn rejects_non_dids() {
        assert!(!is_did("https://example.com"));
        assert!(!is_did("did:"));
        assert!(!is_did("did::abc"));
        assert!(!is_did("did:web:"));
        assert!(!is_did("notdid:web:example.com"));
        // Method names are lowercase alphanumeric.
        assert!(!is_did("did:WEB:example.com"));
        assert!(!is_did("did:we-b:example.com"));
    }

    // --- extract_did ---

    #[test]
    fn extracts_bare_did() {
        assert_eq!(
            extract_did("did:web:example.com").as_deref(),
            Some("did:web:example.com")
        );
    }

    #[test]
    fn extracts_did_with_surrounding_whitespace() {
        assert_eq!(
            extract_did("  did:web:example.com  ").as_deref(),
            Some("did:web:example.com")
        );
    }

    #[test]
    fn extracts_did_from_query_parameter() {
        assert_eq!(
            extract_did("https://example.com/resolve?did=did:web:example.com").as_deref(),
            Some("did:web:example.com")
        );
    }

    #[test]
    fn extracts_percent_encoded_did_from_path() {
        assert_eq!(
            extract_did("https://example.com/dids/did%3Aweb%3Aexample.com").as_deref(),
            Some("did:web:example.com")
        );
    }

    #[test]
    fn returns_none_for_plain_url() {
        // An apex->www hop carries no DID; the caller keeps following.
        assert_eq!(extract_did("https://www.example.com/@alice"), None);
    }

    // --- percent_decode ---

    #[test]
    fn percent_decodes() {
        assert_eq!(percent_decode("did%3Aweb%3Ax").unwrap(), "did:web:x");
        assert_eq!(percent_decode("plain").unwrap(), "plain");
        assert!(percent_decode("%zz").is_err());
        assert!(percent_decode("truncated%4").is_err());
    }

    #[test]
    fn resolver_reports_its_name() {
        assert_eq!(HttpRedirectResolver::new().name(), "http-redirect");
    }
}
