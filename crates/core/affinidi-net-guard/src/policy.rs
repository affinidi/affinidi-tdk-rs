//! [`EgressPolicy`]: what an egress may reach, and the URL-vetting half of
//! the guard.

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Once};

use url::{Host, Url};

use crate::classify::{IpClass, classify, embedded_v4};
use crate::{Cidr, EgressError};

/// A URL scheme an [`EgressPolicy`] can admit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Scheme {
    /// `https`.
    Https,
    /// `wss`.
    Wss,
    /// `http`. Only ever admitted for a loopback host under [`DevLoopback`].
    Http,
    /// `ws`. Only ever admitted for a loopback host under [`DevLoopback`].
    Ws,
}

impl Scheme {
    /// The scheme as it appears in a URL.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Https => "https",
            Self::Wss => "wss",
            Self::Http => "http",
            Self::Ws => "ws",
        }
    }

    /// `true` for `https` and `wss`.
    pub fn is_secure(self) -> bool {
        matches!(self, Self::Https | Self::Wss)
    }

    fn from_url_scheme(scheme: &str) -> Option<Self> {
        match scheme {
            "https" => Some(Self::Https),
            "wss" => Some(Self::Wss),
            "http" => Some(Self::Http),
            "ws" => Some(Self::Ws),
            _ => None,
        }
    }

    const fn bit(self) -> u8 {
        match self {
            Self::Https => 1,
            Self::Wss => 2,
            Self::Http => 4,
            Self::Ws => 8,
        }
    }
}

const ALL_SCHEMES: u8 = 0b1111;

/// Which ports an [`EgressPolicy`] admits, checked against the URL's port or
/// the scheme's default.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PortPolicy {
    /// Any port. The default, because a `did:web` host may name its port.
    Any,
    /// Only these ports.
    Only(Vec<u16>),
}

/// One entry of an operator [`AllowList`].
///
/// Hosts are compared in canonical form: lowercase, IDNA (punycode), no
/// trailing root dot, IPv6 in brackets.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum HostRule {
    /// Exactly this host.
    Exact(String),
    /// Any host strictly below this domain: `.push.apple.com` (or
    /// `push.apple.com`) matches `api.push.apple.com` but not `push.apple.com`.
    Suffix(String),
    /// Exactly this scheme, host and port.
    Origin {
        /// Scheme.
        scheme: Scheme,
        /// Host.
        host: String,
        /// Port.
        port: u16,
    },
}

/// An operator allow-list. See [`EgressPolicy::with_allow_list`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowList {
    rules: Vec<Rule>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Rule {
    Exact(String),
    Suffix(String),
    Origin(Scheme, String, u16),
}

impl AllowList {
    /// Normalise `rules` into an allow-list.
    ///
    /// # Errors
    ///
    /// [`EgressError::InvalidConfig`] if the list is empty or a rule's host
    /// is not a valid host name or IP literal.
    pub fn new(rules: impl IntoIterator<Item = HostRule>) -> Result<Self, EgressError> {
        let rules = rules
            .into_iter()
            .map(|rule| match rule {
                HostRule::Exact(host) => canonical_rule_host(&host).map(Rule::Exact),
                HostRule::Suffix(domain) => canonical_rule_host(domain.trim_start_matches('.'))
                    .map(|domain| Rule::Suffix(format!(".{domain}"))),
                HostRule::Origin { scheme, host, port } => {
                    canonical_rule_host(&host).map(|host| Rule::Origin(scheme, host, port))
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        if rules.is_empty() {
            return Err(EgressError::InvalidConfig(
                "an allow-list needs at least one rule".into(),
            ));
        }
        Ok(Self { rules })
    }

    fn matches(&self, scheme: Scheme, host: &str, port: u16) -> bool {
        self.rules.iter().any(|rule| match rule {
            Rule::Exact(exact) => exact == host,
            Rule::Suffix(suffix) => host.len() > suffix.len() && host.ends_with(suffix.as_str()),
            Rule::Origin(rule_scheme, rule_host, rule_port) => {
                *rule_scheme == scheme && rule_host == host && *rule_port == port
            }
        })
    }
}

fn canonical_rule_host(raw: &str) -> Result<String, EgressError> {
    let invalid =
        || EgressError::InvalidConfig(format!("allow-list host {raw:?} is not a valid host"));
    let trimmed = raw.trim().trim_end_matches('.');
    if trimmed.is_empty() {
        return Err(invalid());
    }
    Host::parse(trimmed)
        .map(|host| host.to_string())
        .map_err(|_| invalid())
}

/// The acknowledgement that turns on loopback access; see
/// [`EgressPolicy::with_dev_loopback`].
///
/// It can only be constructed when the crate is compiled with the
/// `dev-loopback` feature (or for this crate's own tests), so a release binary
/// built without that feature cannot opt in, whatever its configuration says.
///
#[cfg_attr(not(feature = "dev-loopback"), doc = "```compile_fail")]
#[cfg_attr(feature = "dev-loopback", doc = "```")]
/// // Only compiles with `--features dev-loopback`.
/// let token = affinidi_net_guard::DevLoopback::acknowledge_ssrf_protection_disabled_for_loopback();
/// let policy = affinidi_net_guard::EgressPolicy::public_internet().with_dev_loopback(token);
/// ```
#[derive(Debug)]
pub struct DevLoopback(());

#[cfg(any(test, feature = "dev-loopback"))]
impl DevLoopback {
    /// Acknowledge that the policy this is passed to will reach loopback
    /// hosts. For development and test builds only.
    pub fn acknowledge_ssrf_protection_disabled_for_loopback() -> Self {
        Self(())
    }
}

/// What an egress may reach.
///
/// Start from [`EgressPolicy::public_internet`]. [`with_allow_list`],
/// [`with_schemes`] and [`with_ports`] only ever narrow it. Two things widen
/// it, each deliberately: [`allow_cidrs`] re-admits named private ranges, and
/// [`with_dev_loopback`] admits loopback hosts in development builds.
///
/// Cloning is cheap.
///
/// [`with_allow_list`]: EgressPolicy::with_allow_list
/// [`with_schemes`]: EgressPolicy::with_schemes
/// [`with_ports`]: EgressPolicy::with_ports
/// [`allow_cidrs`]: EgressPolicy::allow_cidrs
/// [`with_dev_loopback`]: EgressPolicy::with_dev_loopback
#[derive(Debug, Clone)]
pub struct EgressPolicy {
    inner: Arc<PolicyInner>,
}

#[derive(Debug, Clone)]
struct PolicyInner {
    schemes: u8,
    ports: Option<Vec<u16>>,
    allow_lists: Vec<AllowList>,
    allow_cidrs: Vec<Cidr>,
    dev_loopback: bool,
}

impl EgressPolicy {
    /// `https` and `wss` only; globally routable addresses only; no
    /// special-use names (`localhost`, `*.localhost`, `*.local`,
    /// `*.internal`, `*.home.arpa`, single-label names, each with or without
    /// a trailing dot); no userinfo; any port.
    pub fn public_internet() -> Self {
        Self {
            inner: Arc::new(PolicyInner {
                schemes: ALL_SCHEMES,
                ports: None,
                allow_lists: Vec::new(),
                allow_cidrs: Vec::new(),
                dev_loopback: false,
            }),
        }
    }

    /// Admit only hosts that match `list`. Applying a second list requires a
    /// host to match both.
    ///
    /// An allow-list never re-admits a blocked address class. It is, however,
    /// the way to name an internal host that the special-use name rule would
    /// refuse (`metadata`, `*.svc.cluster.local`); that host's resolved
    /// addresses are still checked. `localhost` needs [`DevLoopback`].
    pub fn with_allow_list(mut self, list: AllowList) -> Self {
        Arc::make_mut(&mut self.inner).allow_lists.push(list);
        self
    }

    /// Keep only the schemes in `schemes`.
    pub fn with_schemes(mut self, schemes: &[Scheme]) -> Self {
        let mask = schemes.iter().fold(0, |mask, scheme| mask | scheme.bit());
        Arc::make_mut(&mut self.inner).schemes &= mask;
        self
    }

    /// Keep only the ports `ports` admits.
    pub fn with_ports(mut self, ports: PortPolicy) -> Self {
        if let PortPolicy::Only(only) = ports {
            let inner = Arc::make_mut(&mut self.inner);
            inner.ports = Some(match inner.ports.take() {
                None => only,
                Some(current) => current
                    .into_iter()
                    .filter(|port| only.contains(port))
                    .collect(),
            });
        }
        self
    }

    /// Admit addresses in these ranges, for internal deployments
    /// (`10.20.0.0/16`), one explicit range at a time.
    ///
    /// A range never re-admits loopback, link-local (cloud metadata),
    /// unspecified, multicast or broadcast addresses, even if it covers them:
    /// `0.0.0.0/0` admits private space but not `169.254.169.254`. An IPv4
    /// range also covers that address's embedded IPv6 forms.
    pub fn allow_cidrs(mut self, cidrs: impl IntoIterator<Item = Cidr>) -> Self {
        Arc::make_mut(&mut self.inner).allow_cidrs.extend(cidrs);
        self
    }

    /// Admit loopback hosts, and plain `http`/`ws` to them: the literals
    /// `127.0.0.0/8` and `::1`, and the names `localhost` and `*.localhost`.
    ///
    /// Only those hosts. A name that is not a localhost name still may not
    /// resolve to loopback, so DNS rebinding stays closed in development too,
    /// and embedded forms such as `::ffff:127.0.0.1` stay blocked. Logs a
    /// warning once per process.
    pub fn with_dev_loopback(mut self, acknowledged: DevLoopback) -> Self {
        let DevLoopback(()) = acknowledged;
        static WARNED: Once = Once::new();
        WARNED.call_once(|| {
            tracing::warn!(
                "egress guard: dev loopback is enabled, so loopback hosts (and plain http/ws to \
                 them) are reachable from this process; never build a release with the \
                 `dev-loopback` feature"
            );
        });
        Arc::make_mut(&mut self.inner).dev_loopback = true;
        self
    }

    /// Whether [`EgressPolicy::with_dev_loopback`] was applied.
    pub fn is_dev_loopback(&self) -> bool {
        self.inner.dev_loopback
    }

    /// Parse and vet a URL.
    ///
    /// # Errors
    ///
    /// [`EgressError::InvalidUrl`] if `raw` does not parse, otherwise as
    /// [`EgressPolicy::vet_url`].
    pub fn vet(&self, raw: &str) -> Result<VettedUrl, EgressError> {
        let url = Url::parse(raw).map_err(|e| EgressError::InvalidUrl(e.to_string()))?;
        self.vet_url(&url)
    }

    /// Vet a parsed URL: scheme, userinfo, literal address class, special-use
    /// names, allow-list and port.
    ///
    /// This is the half of the guard that sees IP literals. The other half,
    /// what a name resolves to, runs at connect time in
    /// [`GuardedResolver`](crate::GuardedResolver).
    ///
    /// # Errors
    ///
    /// A refusal ([`EgressError::is_refusal`]), or
    /// [`EgressError::InvalidUrl`] for a URL with no host.
    pub fn vet_url(&self, url: &Url) -> Result<VettedUrl, EgressError> {
        let policy = &*self.inner;
        let scheme = Scheme::from_url_scheme(url.scheme())
            .filter(|scheme| policy.schemes & scheme.bit() != 0)
            .filter(|scheme| scheme.is_secure() || policy.dev_loopback)
            .ok_or_else(|| EgressError::SchemeNotAllowed(url.scheme().to_owned()))?;
        if !url.username().is_empty() || url.password().is_some() {
            return Err(EgressError::UserinfoNotAllowed);
        }
        let host = url
            .host_str()
            .map(|host| host.trim_end_matches('.'))
            .filter(|host| !host.is_empty())
            .ok_or_else(|| EgressError::InvalidUrl("URL has no host".into()))?
            .to_owned();
        let port = url
            .port_or_known_default()
            .ok_or_else(|| EgressError::InvalidUrl("URL has no port".into()))?;
        let loopback_host = match url.host() {
            Some(Host::Ipv4(addr)) => {
                self.admit_address(&host, IpAddr::V4(addr), true)?;
                addr.is_loopback()
            }
            Some(Host::Ipv6(addr)) => {
                self.admit_address(&host, IpAddr::V6(addr), true)?;
                addr.is_loopback()
            }
            Some(Host::Domain(_)) => {
                self.admit_name(scheme, &host, port)?;
                is_localhost_name(&host)
            }
            None => return Err(EgressError::InvalidUrl("URL has no host".into())),
        };
        if !scheme.is_secure() && !loopback_host {
            return Err(EgressError::SchemeNotAllowed(url.scheme().to_owned()));
        }
        if !policy
            .allow_lists
            .iter()
            .all(|list| list.matches(scheme, &host, port))
        {
            return Err(EgressError::HostNotAllowed(host));
        }
        if let Some(ports) = &policy.ports
            && !ports.contains(&port)
        {
            return Err(EgressError::PortNotAllowed(port));
        }
        Ok(VettedUrl {
            url: url.clone(),
            host,
            policy: self.clone(),
        })
    }

    /// The connect-time check: every address `host` resolved to must be
    /// admitted, and there must be at least one.
    pub(crate) fn check_resolved(
        &self,
        host: &str,
        addrs: &[SocketAddr],
    ) -> Result<(), EgressError> {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        if addrs.is_empty() {
            return Err(EgressError::NoAddresses(host));
        }
        let localhost = is_localhost_name(&host);
        addrs
            .iter()
            .try_for_each(|addr| self.admit_address(&host, addr.ip(), localhost))
    }

    /// `loopback_host`: the host names loopback itself (a literal, or a
    /// localhost name), which is the only case dev loopback admits.
    fn admit_address(
        &self,
        host: &str,
        addr: IpAddr,
        loopback_host: bool,
    ) -> Result<(), EgressError> {
        let class = classify(addr);
        if class.is_globally_routable() {
            return Ok(());
        }
        let policy = &*self.inner;
        if policy.dev_loopback && loopback_host && class == IpClass::Loopback {
            return Ok(());
        }
        if readmittable(&class)
            && policy
                .allow_cidrs
                .iter()
                .any(|cidr| cidr_covers(cidr, addr))
        {
            return Ok(());
        }
        Err(EgressError::BlockedAddress {
            host: host.to_owned(),
            addr,
            class,
        })
    }

    fn admit_name(&self, scheme: Scheme, host: &str, port: u16) -> Result<(), EgressError> {
        let policy = &*self.inner;
        let admitted = match special_use(host) {
            None => true,
            Some(SpecialUse::Localhost) => policy.dev_loopback,
            Some(SpecialUse::Other) => {
                !policy.allow_lists.is_empty()
                    && policy
                        .allow_lists
                        .iter()
                        .all(|list| list.matches(scheme, host, port))
            }
        };
        if admitted {
            Ok(())
        } else {
            Err(EgressError::BlockedName(host.to_owned()))
        }
    }
}

fn readmittable(class: &IpClass) -> bool {
    match class {
        IpClass::Loopback
        | IpClass::ThisNetwork
        | IpClass::LinkLocal
        | IpClass::Broadcast
        | IpClass::Multicast => false,
        IpClass::Embedded { inner, .. } => readmittable(inner),
        _ => true,
    }
}

fn cidr_covers(cidr: &Cidr, addr: IpAddr) -> bool {
    if cidr.contains(addr) {
        return true;
    }
    match addr {
        IpAddr::V6(v6) => embedded_v4(v6).is_some_and(|(_, v4)| cidr.contains(IpAddr::V4(v4))),
        IpAddr::V4(_) => false,
    }
}

enum SpecialUse {
    Localhost,
    Other,
}

fn special_use(host: &str) -> Option<SpecialUse> {
    if is_localhost_name(host) {
        return Some(SpecialUse::Localhost);
    }
    let single_label = !host.contains('.');
    let reserved = ["local", "internal", "home.arpa"]
        .iter()
        .any(|domain| is_at_or_below(host, domain));
    (single_label || reserved).then_some(SpecialUse::Other)
}

fn is_localhost_name(host: &str) -> bool {
    is_at_or_below(host, "localhost")
}

fn is_at_or_below(host: &str, domain: &str) -> bool {
    host.strip_suffix(domain)
        .is_some_and(|rest| rest.is_empty() || rest.ends_with('.'))
}

/// A URL that passed [`EgressPolicy::vet`]: scheme, userinfo, literal address
/// class, special-use names, allow-list and port.
///
/// It can only be built by vetting, and it keeps the policy that vetted it.
/// What a name resolves to is checked later, at connect time.
#[derive(Debug, Clone)]
pub struct VettedUrl {
    url: Url,
    host: String,
    policy: EgressPolicy,
}

impl VettedUrl {
    /// The vetted URL.
    pub fn as_url(&self) -> &Url {
        &self.url
    }

    /// The vetted URL, by value.
    pub fn into_url(self) -> Url {
        self.url
    }

    /// The canonical host: lowercase, IDNA, no trailing root dot, IPv6 in
    /// brackets. Show this to an operator rather than the raw input:
    /// `https://2130706433/` shows as `127.0.0.1`.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The policy that vetted this URL.
    pub fn policy(&self) -> &EgressPolicy {
        &self.policy
    }

    /// Resolve `reference` against this URL and vet the result under the same
    /// policy, refusing anything that leaves this URL's origin.
    ///
    /// # Errors
    ///
    /// [`EgressError::CrossOrigin`] if the result has a different scheme,
    /// host or port (including a `//host` reference), otherwise as
    /// [`EgressPolicy::vet_url`].
    pub fn join_same_origin(&self, reference: &str) -> Result<VettedUrl, EgressError> {
        let joined = self
            .url
            .join(reference)
            .map_err(|e| EgressError::InvalidUrl(e.to_string()))?;
        if joined.origin() != self.url.origin() {
            return Err(EgressError::CrossOrigin(
                joined.origin().ascii_serialization(),
            ));
        }
        self.policy.vet_url(&joined)
    }
}

impl fmt::Display for VettedUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.url.fmt(f)
    }
}
