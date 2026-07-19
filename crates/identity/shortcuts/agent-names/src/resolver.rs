//! Backends that turn an agent name into a DID.

use std::{
    future::Future,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    pin::Pin,
    time::Duration,
};

use tokio::net::lookup_host;
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
    allow_private_addresses: bool,
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
            allow_private_addresses: false,
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
            allow_private_addresses: false,
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

    /// Permit agent names that resolve to private, loopback or link-local
    /// addresses.
    ///
    /// Off by default. Agent names are public-web identifiers, so a name
    /// pointing at `127.0.0.1`, `10.0.0.0/8` or the cloud metadata address
    /// `169.254.169.254` is almost always an SSRF attempt rather than a real
    /// name. That matters most when this resolver runs **server-side** (the DID
    /// cache server), where the attacker supplies the name and the server makes
    /// the request from inside your network.
    ///
    /// Turn it on only for local development and tests.
    pub fn allow_private_addresses(mut self, allow: bool) -> Self {
        self.allow_private_addresses = allow;
        self
    }

    /// Reject a URL whose host is, or resolves to, a non-public address.
    ///
    /// # Limitation
    ///
    /// This checks the addresses a host resolves to *now*; the subsequent
    /// request performs its own resolution. A hostile DNS server can therefore
    /// answer differently for the two lookups (**DNS rebinding**) and reach an
    /// internal address anyway. Closing that hole requires pinning the checked
    /// IP into the connection itself, which `reqwest` does not expose. Treat
    /// this as raising the cost of SSRF, not as eliminating it, and do not rely
    /// on it as the only control on an untrusted network boundary.
    async fn check_address(&self, url: &Url, name: &AgentName) -> Result<(), AgentNameError> {
        if self.allow_private_addresses {
            return Ok(());
        }
        let host = url.host_str().ok_or_else(|| AgentNameError::InvalidName {
            input: url.to_string(),
            reason: "no host".to_string(),
        })?;
        let port = url.port_or_known_default().unwrap_or(443);

        // An IP literal needs no DNS lookup.
        if let Ok(ip) = host.parse::<IpAddr>() {
            return if is_public(&ip) {
                Ok(())
            } else {
                Err(AgentNameError::BlockedAddress {
                    name: name.as_str().to_string(),
                    address: ip.to_string(),
                })
            };
        }

        let addrs = lookup_host((host, port))
            .await
            .map_err(|e| AgentNameError::InvalidName {
                input: host.to_string(),
                reason: format!("DNS lookup failed: {e}"),
            })?;

        let mut saw_any = false;
        for addr in addrs {
            saw_any = true;
            if !is_public(&addr.ip()) {
                return Err(AgentNameError::BlockedAddress {
                    name: name.as_str().to_string(),
                    address: addr.ip().to_string(),
                });
            }
        }
        if !saw_any {
            return Err(AgentNameError::InvalidName {
                input: host.to_string(),
                reason: "host resolved to no addresses".to_string(),
            });
        }
        Ok(())
    }

    async fn resolve_inner(&self, name: &AgentName) -> Result<String, AgentNameError> {
        if !name.is_https() && !self.allow_insecure_http {
            return Err(AgentNameError::InsecureScheme(name.as_str().to_string()));
        }

        let mut url = name.resolution_url()?;

        for hop in 0..self.max_hops {
            // Re-checked on *every* hop: a public host can redirect inward.
            self.check_address(&url, name).await?;
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

/// Is this address on the public internet?
///
/// Conservative: anything loopback, private, link-local, unspecified,
/// multicast, broadcast or otherwise special-purpose is treated as non-public.
/// `Ipv4Addr::is_global` is still unstable, so the ranges are spelled out.
fn is_public(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => is_public_v6(v6),
    }
}

fn is_public_v4(ip: &Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();
    !(ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_documentation()
        // 100.64.0.0/10 carrier-grade NAT
        || (a == 100 && (64..128).contains(&b))
        // 192.0.0.0/24 IETF protocol assignments
        || (a == 192 && b == 0 && ip.octets()[2] == 0)
        // 198.18.0.0/15 benchmarking
        || (a == 198 && (18..20).contains(&b))
        // 240.0.0.0/4 reserved
        || a >= 240)
}

fn is_public_v6(ip: &Ipv6Addr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return false;
    }
    // An IPv4-mapped address must be judged by its IPv4 rules, or
    // ::ffff:127.0.0.1 would sail through.
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_public_v4(&v4);
    }
    let seg = ip.segments()[0];
    // fc00::/7 unique-local, fe80::/10 link-local
    !((seg & 0xfe00) == 0xfc00 || (seg & 0xffc0) == 0xfe80)
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

    // --- is_public ---

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn blocks_loopback_and_private_v4() {
        for a in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "0.0.0.0",
            "169.254.169.254", // cloud metadata — the classic SSRF target
            "100.64.0.1",      // carrier-grade NAT
            "198.18.0.1",      // benchmarking
            "255.255.255.255",
            "240.0.0.1",
        ] {
            assert!(!is_public(&ip(a)), "{a} must be blocked");
        }
    }

    #[test]
    fn allows_public_v4() {
        for a in ["1.1.1.1", "8.8.8.8", "93.184.216.34", "172.32.0.1"] {
            assert!(is_public(&ip(a)), "{a} should be allowed");
        }
    }

    #[test]
    fn blocks_loopback_and_local_v6() {
        for a in ["::1", "::", "fc00::1", "fd00::1", "fe80::1", "ff02::1"] {
            assert!(!is_public(&ip(a)), "{a} must be blocked");
        }
    }

    /// ::ffff:127.0.0.1 must be judged by IPv4 rules, or it bypasses the check.
    #[test]
    fn blocks_ipv4_mapped_loopback() {
        assert!(!is_public(&ip("::ffff:127.0.0.1")));
        assert!(!is_public(&ip("::ffff:10.0.0.1")));
        assert!(is_public(&ip("::ffff:8.8.8.8")));
    }

    #[test]
    fn allows_public_v6() {
        assert!(is_public(&ip("2606:4700:4700::1111")));
    }

    #[test]
    fn resolver_reports_its_name() {
        assert_eq!(HttpRedirectResolver::new().name(), "http-redirect");
    }
}
