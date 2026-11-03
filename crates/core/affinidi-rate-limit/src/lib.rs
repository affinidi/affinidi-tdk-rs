/*!
 * Request rate limiting for `axum` services: a token bucket keyed by client
 * IP, applied as a `tower` layer, or keyed by anything a handler chooses.
 *
 * ```no_run
 * use affinidi_rate_limit::{RateLimitLayer, RateLimiterState};
 * # use tokio_util::sync::CancellationToken;
 * # fn build(shutdown: CancellationToken) {
 * // 20 requests/second sustained, bursts up to 50.
 * let limiter = RateLimiterState::new(20, 50);
 * limiter.spawn_gc(shutdown);
 *
 * let app = axum::Router::<()>::new().layer(RateLimitLayer::new(limiter));
 * # }
 * ```
 *
 * Setting `per_second` to `0` disables limiting entirely, and the layer becomes
 * a pass-through.
 *
 * [`RateLimiterState::per_window`] states the same bucket as "`max` requests
 * per `window`": a burst of up to `max`, refilled evenly across the window.
 *
 * # Limiting inside a handler
 *
 * A service that limits after reading the request (by sender, by task, or
 * against one global budget) uses [`KeyedRateLimiterState`] with any hashable
 * key and calls [`check`](KeyedRateLimiterState::check) itself.
 * [`ClientIpExtractor::client_key`] gives it the same key the layer would
 * charge, including behind trusted proxies. [`RateLimiterState`] is the
 * `IpAddr`-keyed limiter the layer takes.
 *
 * # Saying who refused
 *
 * A `429` reaches an operator through several hops — a proxy, a mediator, a DID
 * host, the service they were actually calling — and each is tuned in a
 * different place. [`RateLimiterState::with_source`] names the service, and a
 * refusal then carries the attribution contract a client can parse:
 *
 * - status `429 Too Many Requests`;
 * - [`SOURCE_HEADER`]`: <source>` (`mediator`, `vta`, `vtc`, `did-host`, …);
 * - `Retry-After: <seconds>`;
 * - a JSON body
 *   `{"error":"rate_limited","limiter":"<source>","message":"…","retryAfterSecs":N}`.
 *
 * A service with several limiters can name the one that refused with
 * [`RateLimiterState::with_limiter_name`]: the body's `limiter` is then that
 * name, while the header still names the service. Without a source or a
 * limiter name the response is the unattributed plain-text `429` this crate
 * has always sent.
 *
 * # Two things that are easy to get wrong
 *
 * **The keyed state store must be swept.** `governor` never reclaims keys on its
 * own, so without [`RateLimiterState::spawn_gc`] every source IP the service has
 * ever seen keeps an entry for the process lifetime. The store is keyed on
 * unauthenticated, client-chosen input — a client rotating through an IPv6 /64
 * inserts an entry per request — which makes it an unbounded growth path
 * reachable before any authentication. This crate exists in part so that fix
 * lives in one place rather than in each service that needs a limiter.
 *
 * **A request with no client IP is rejected, not exempted.** Per-IP limiting is
 * meaningless without an IP, and failing open would hand an attacker a trivial
 * bypass. Services must therefore attach [`axum::extract::ConnectInfo`], which
 * means serving with
 * `into_make_service_with_connect_info::<SocketAddr>()`.
 */

use std::{
    collections::HashMap,
    fmt,
    hash::Hash,
    net::IpAddr,
    net::SocketAddr,
    num::NonZeroU32,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use axum::{
    Json,
    body::Body,
    extract::ConnectInfo,
    response::{IntoResponse, Response},
};
use governor::{
    Quota, RateLimiter,
    clock::{Clock, DefaultClock},
    nanos::Nanos,
    state::{
        StateStore,
        keyed::{DashMapStateStore, ShrinkableKeyedStateStore},
    },
};
use http::{HeaderMap, HeaderName, HeaderValue, Request, StatusCode, header};
/// The CIDR type [`RateLimitLayer::trusted_proxies`] takes, re-exported so
/// callers need not depend on `ipnet` themselves.
pub use ipnet::IpNet;
use ipnet::Ipv6Net;
use tokio_util::sync::CancellationToken;
use tower::{Layer, Service};
use tracing::{debug, warn};

/// A `governor` DashMap state store shared behind an `Arc`.
///
/// `governor`'s `RateLimiter::keyed` owns its store privately, exposing only
/// `len` / `retain_recent` / `shrink_to_fit` — enough to *sweep* the map but
/// not to ask whether a key is already present. The distinct-key cap
/// ([`MAX_TRACKED_KEYS`]) needs exactly that: a key already tracked must always
/// be admitted to its bucket (never refused for capacity), while a brand-new key
/// is what the cap gates. So the limiter is built over a store we also hold an
/// `Arc` to, and membership / length are read straight from it.
///
/// `DashMapStateStore<K>` is a type alias for `DashMap<K, InMemoryState>`, so
/// the trait impls below are pure delegation.
#[derive(Clone)]
struct SharedDashMapStore<K: Hash + Eq + Clone>(Arc<DashMapStateStore<K>>);

impl<K: Hash + Eq + Clone> StateStore for SharedDashMapStore<K> {
    type Key = K;

    fn measure_and_replace<T, F, E>(&self, key: &Self::Key, f: F) -> Result<T, E>
    where
        F: Fn(Option<Nanos>) -> Result<(T, Nanos), E>,
    {
        self.0.measure_and_replace(key, f)
    }
}

impl<K: Hash + Eq + Clone> ShrinkableKeyedStateStore<K> for SharedDashMapStore<K> {
    fn retain_recent(&self, drop_below: Nanos) {
        self.0.retain_recent(drop_below);
    }

    fn shrink_to_fit(&self) {
        self.0.shrink_to_fit();
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

type KeyedLimiter<K> = RateLimiter<K, SharedDashMapStore<K>, DefaultClock>;

/// Observer invoked when a request is refused. See
/// [`RateLimiterState::on_refused`].
pub type RefusalCallback = Arc<dyn Fn(&Refusal) + Send + Sync>;

/// How often idle buckets are swept out of the keyed state store.
pub const GC_INTERVAL: Duration = Duration::from_secs(60);

/// Hard cap on the number of *distinct* keys (client addresses, for the layer)
/// tracked at once, and on the keys whose refusals are remembered for logging.
///
/// `governor` bounds the rate *within* each key's bucket but never the *number*
/// of keys, and [`spawn_gc`](RateLimiterState::spawn_gc) only reclaims fully
/// replenished buckets on a 60s tick. The store is keyed on unauthenticated,
/// client-chosen input reachable *before* any authentication — a client
/// rotating through an IPv6 /64 inserts an entry per request — so without a cap
/// this is an unbounded memory-growth path an unauthenticated attacker can
/// drive at line rate (CWE-770). The cap bounds the worst case to
/// O(`MAX_TRACKED_KEYS`).
///
/// 250_000 is deliberately generous: a legitimate deployment — even a large
/// mediator or DID host — sees at most thousands to low tens of thousands of
/// distinct client IPs within a 60s GC window, so steady state sits far below
/// the cap and is never refused by it, while the ceiling still bounds the map
/// to roughly tens of MB for `IpAddr` keys (an address plus a few words of
/// bucket state per entry; a larger key, such as a `String`, costs more). When
/// the cap is hit, a *new* key fails closed — the same `429` a quota refusal
/// returns — rather than growing the map; a key already tracked is unaffected. It is a constant rather than a config knob because it is a
/// safety backstop, not a tuning parameter, and operators size the real limit
/// via `per_second` / `burst`.
const MAX_TRACKED_KEYS: usize = 250_000;

/// `Retry-After` (seconds) on a *capacity* refusal (the cap is full), as
/// opposed to a per-key quota refusal. Tied to the GC interval: the next sweep
/// reclaims replenished buckets and frees space. Advisory — the throttled
/// inline reclaim on the refusal path often frees space sooner.
const CAPACITY_RETRY_AFTER_SECS: u64 = GC_INTERVAL.as_secs();

/// Minimum spacing between *inline* reclaim passes on the refusal path.
///
/// The refusal path may run `retain_recent` (an O(tracked) scan) to make room
/// before failing closed. Running it unconditionally on every full-map request
/// — on this *pre-authentication* path especially — would make the cap a
/// CPU-exhaustion lever (fixing unbounded memory with unbounded CPU). Throttling
/// it to at most one pass per window keeps the refusal path O(1) amortised; the
/// periodic [`GC_INTERVAL`] sweep is the unconditional backstop.
const INLINE_RECLAIM_MIN_INTERVAL: Duration = Duration::from_millis(100);

/// Response header naming the service whose limiter refused the request. Set on
/// a `429` only when the limiter was given a name with
/// [`RateLimiterState::with_source`].
pub const SOURCE_HEADER: &str = "x-rate-limit-source";

/// The `error` value of an attributed refusal's JSON body.
pub const RATE_LIMITED_ERROR: &str = "rate_limited";

const RATE_LIMITED_MESSAGE: &str = "Rate limit exceeded. Please try again later.";
const X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");
/// Most `X-Forwarded-For` entries, across every header line, a trusted proxy's
/// request may carry; more is [`InvalidForwardedFor`].
pub const MAX_FORWARDED_ENTRIES: usize = 64;

/// The `error` value of an attributed [`Refusal::InvalidForwardedFor`] body.
pub const INVALID_FORWARDED_FOR_ERROR: &str = "invalid_forwarded_for";

const INVALID_FORWARDED_FOR_MESSAGE: &str = "Invalid X-Forwarded-For header; request rejected.";

const NO_CLIENT_IP_MESSAGE: &str = "Rate limiting requires client IP; request rejected.";

/// Why a request was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Refusal {
    /// The client exceeded its quota. Carries how long until the next token,
    /// already rounded up to whole seconds (minimum 1) for `Retry-After`.
    RateLimited { retry_after_secs: u64 },
    /// No client IP was available, so the request could not be attributed.
    NoClientIp,
    /// The request came from a trusted proxy but supplied an invalid
    /// `X-Forwarded-For` chain.
    InvalidForwardedFor,
}

/// A trusted-proxy range [`ClientIpExtractor::trusted_proxies`] refuses: one
/// with prefix length 0 (`0.0.0.0/0`, `::/0`).
///
/// Such a range trusts every peer, so any client that can reach the socket
/// sends its own `X-Forwarded-For` and picks its own bucket — and because every
/// hop is then "trusted" too, IPv4 clients behind a real proxy are still all
/// charged to the proxy. It is never what an operator meant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidTrustedProxy {
    /// The offending range.
    pub cidr: IpNet,
}

impl fmt::Display for InvalidTrustedProxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "trusted proxy range {} covers every address; list the proxies' own ranges",
            self.cidr
        )
    }
}

impl std::error::Error for InvalidTrustedProxy {}

/// An `X-Forwarded-For` chain from a trusted proxy that
/// [`ClientIpExtractor::client_ip`] cannot attribute: a malformed entry from
/// the client entry rightwards, more than [`MAX_FORWARDED_ENTRIES`] entries, or
/// a header value that is
/// not visible ASCII.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidForwardedFor;

impl fmt::Display for InvalidForwardedFor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid X-Forwarded-For chain from a trusted proxy")
    }
}

impl std::error::Error for InvalidForwardedFor {}

/// A request refused by [`KeyedRateLimiterState::charge`]: its key is over the
/// limit, or the limiter is full of other keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TooManyRequests {
    /// Seconds until a retry can succeed, rounded up, at least 1.
    pub retry_after_secs: u64,
}

impl fmt::Display for TooManyRequests {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "rate limited; retry after {} s", self.retry_after_secs)
    }
}

impl std::error::Error for TooManyRequests {}

/// A prefix length [`ClientIpExtractor::ipv6_prefix`] refuses: 0, which would
/// put every IPv6 client in one bucket, or more than 128.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidIpv6Prefix {
    /// The offending prefix length.
    pub prefix_len: u8,
}

impl fmt::Display for InvalidIpv6Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "IPv6 prefix length {} is not between 1 and 128",
            self.prefix_len
        )
    }
}

impl std::error::Error for InvalidIpv6Prefix {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ClientIpExtractionError {
    MissingPeer,
    InvalidForwardedFor { peer: IpAddr },
}

/// Works out the client address a request is charged to: the socket peer, or,
/// when the peer is a trusted proxy, the client its `X-Forwarded-For` chain
/// names.
///
/// [`RateLimitLayer`] uses one internally; a service that needs the client
/// address itself (to limit inside a handler, or for anything else) builds its
/// own and calls [`client_ip`](Self::client_ip), so both agree on who the
/// client is.
///
/// When trusted CIDRs are configured, the socket peer must be one of them
/// before `X-Forwarded-For` is considered; otherwise the socket peer is used.
/// The chain is walked right-to-left and the first untrusted hop is the
/// client. This assumes each trusted proxy appends the address of the peer it
/// received the connection from (an ALB appends the client IP), and that the
/// service is reachable only through those proxies.
///
/// Entries left of the client are never parsed as addresses, so client-supplied
/// junk there is ignored rather than refused. They still count towards the
/// [`MAX_FORWARDED_ENTRIES`] cap, and a header value that is not visible ASCII
/// is refused whole.
#[derive(Clone, Debug, Default)]
pub struct ClientIpExtractor {
    trusted_proxy_cidrs: Vec<IpNet>,
    ipv6_prefix_len: Option<u8>,
}

impl ClientIpExtractor {
    /// Charge every request to its socket peer and ignore `X-Forwarded-For`.
    /// The same as [`Default`].
    pub fn direct_peer() -> Self {
        Self::default()
    }

    /// Read `X-Forwarded-For` when the socket peer is inside one of
    /// `trusted_proxy_cidrs`. An empty list is [`Self::direct_peer`].
    ///
    /// List only proxies that append the address of the peer they received
    /// the connection from (an ALB appends the client IP), and do not expose
    /// the service except through them.
    ///
    /// # Errors
    ///
    /// [`InvalidTrustedProxy`] if a range has prefix length 0 (`0.0.0.0/0`,
    /// `::/0`), which would trust every peer.
    pub fn trusted_proxies(trusted_proxy_cidrs: Vec<IpNet>) -> Result<Self, InvalidTrustedProxy> {
        if let Some(cidr) = trusted_proxy_cidrs
            .iter()
            .find(|cidr| cidr.prefix_len() == 0)
        {
            return Err(InvalidTrustedProxy { cidr: *cidr });
        }
        Ok(Self {
            trusted_proxy_cidrs,
            ipv6_prefix_len: None,
        })
    }

    /// Charge an IPv6 client to its `/prefix_len` network rather than its
    /// address, so a host rotating addresses inside the block it was given
    /// (normally a `/64`) does not get a new bucket for each one. IPv4
    /// clients, IPv4-mapped ones included, are unaffected. Applies to
    /// [`client_key`](Self::client_key), not to
    /// [`client_ip`](Self::client_ip).
    ///
    /// Default: each IPv6 address is its own key.
    ///
    /// # Errors
    ///
    /// [`InvalidIpv6Prefix`] for a prefix length of 0 or above 128.
    pub fn ipv6_prefix(mut self, prefix_len: u8) -> Result<Self, InvalidIpv6Prefix> {
        if !(1..=128).contains(&prefix_len) {
            return Err(InvalidIpv6Prefix { prefix_len });
        }
        self.ipv6_prefix_len = Some(prefix_len);
        Ok(self)
    }

    /// The key a request from `peer` carrying `headers` is charged to: its
    /// [`client_ip`](Self::client_ip), with an IPv6 address masked to the
    /// [`ipv6_prefix`](Self::ipv6_prefix) network when one is set. This is
    /// what [`RateLimitLayer`] charges.
    ///
    /// # Errors
    ///
    /// As [`client_ip`](Self::client_ip).
    pub fn client_key(
        &self,
        peer: IpAddr,
        headers: &HeaderMap,
    ) -> Result<IpAddr, InvalidForwardedFor> {
        let client = self.client_ip(peer, headers)?;
        Ok(match (client, self.ipv6_prefix_len) {
            (IpAddr::V6(address), Some(prefix_len)) => Ipv6Net::new(address, prefix_len)
                .map_or(client, |network| IpAddr::V6(network.network())),
            _ => client,
        })
    }

    /// The client address of a request from `peer` carrying `headers`.
    ///
    /// `peer` itself (canonicalised, so an IPv4-mapped address is its IPv4
    /// address) unless it is a trusted proxy. From a trusted proxy, the first
    /// `X-Forwarded-For` entry, walking right to left, that is not itself a
    /// trusted proxy; `peer` when there is no header or every entry is
    /// trusted.
    ///
    /// # Errors
    ///
    /// [`InvalidForwardedFor`] when a trusted proxy sent a chain that cannot be
    /// attributed. Falling back to the proxy's address instead would charge
    /// every client behind it to one bucket.
    pub fn client_ip(
        &self,
        peer: IpAddr,
        headers: &HeaderMap,
    ) -> Result<IpAddr, InvalidForwardedFor> {
        let peer = peer.to_canonical();
        if !self.is_trusted_proxy(peer) {
            return Ok(peer);
        }
        Ok(self.client_from_xff_chain(headers)?.unwrap_or(peer))
    }

    fn is_trusted_proxy(&self, ip: IpAddr) -> bool {
        self.trusted_proxy_cidrs
            .iter()
            .any(|cidr| cidr.contains(&ip))
    }

    fn client_from_xff_chain(
        &self,
        headers: &HeaderMap,
    ) -> Result<Option<IpAddr>, InvalidForwardedFor> {
        // Walk right to left without collecting: the last header line holds
        // the newest hops, and each line's entries are read last first. Once
        // the client is found, the entries left of it are only counted (for
        // the cap), never parsed.
        let mut entries = 0;
        let mut client = None;
        for value in headers.get_all(X_FORWARDED_FOR).iter().rev() {
            let value = value.to_str().map_err(|_| InvalidForwardedFor)?;
            for entry in value
                .rsplit(',')
                .map(str::trim)
                .filter(|entry| !entry.is_empty())
            {
                entries += 1;
                if entries > MAX_FORWARDED_ENTRIES {
                    return Err(InvalidForwardedFor);
                }
                if client.is_some() {
                    continue;
                }
                let ip = parse_forwarded_ip(entry).ok_or(InvalidForwardedFor)?;
                if !self.is_trusted_proxy(ip) {
                    client = Some(ip);
                }
            }
        }
        Ok(client)
    }

    fn extract(&self, request: &Request<Body>) -> Result<IpAddr, ClientIpExtractionError> {
        let peer = request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ci| ci.0.ip())
            .ok_or(ClientIpExtractionError::MissingPeer)?;
        self.client_key(peer, request.headers())
            .map_err(
                |InvalidForwardedFor| ClientIpExtractionError::InvalidForwardedFor {
                    peer: peer.to_canonical(),
                },
            )
    }
}

fn parse_forwarded_ip(value: &str) -> Option<IpAddr> {
    if let Ok(ip) = value.parse::<IpAddr>() {
        return Some(ip.to_canonical());
    }
    if let Ok(address) = value.parse::<SocketAddr>() {
        return Some(address.ip().to_canonical());
    }
    value
        .strip_prefix('[')?
        .strip_suffix(']')?
        .parse::<IpAddr>()
        .ok()
        .map(|ip| ip.to_canonical())
}

/// The live limiter, present only when limiting is enabled. Bundles the
/// `governor` limiter with the shared handle to its state store (for the
/// distinct-IP cap), the cap, and the inline-reclaim throttle state, so they
/// can never drift apart.
#[derive(Clone)]
struct Active<K: Hash + Eq + Clone> {
    limiter: Arc<KeyedLimiter<K>>,
    store: SharedDashMapStore<K>,
    max_tracked: usize,
    /// Monotonic reference for the inline-reclaim throttle. Backdated by
    /// [`INLINE_RECLAIM_MIN_INTERVAL`] at construction so the first reclaim
    /// after the map fills fires immediately rather than waiting out a window.
    epoch: Instant,
    /// Milliseconds (since `epoch`) of the last inline reclaim, `0` until the
    /// first. Shared so all clones throttle against one another.
    last_reclaim_ms: Arc<AtomicU64>,
    /// Keys whose quota refusal has been logged this window.
    refusals_reported: RefusalLog<K>,
    /// Peers whose invalid `X-Forwarded-For` has been logged this window. Kept
    /// apart from `refusals_reported`, so a proxy's bad chain cannot hide a
    /// quota refusal of the same address, or the other way round.
    invalid_forwarded_reported: RefusalLog<IpAddr>,
}

/// When each recently refused key was last logged, so a refusal is logged
/// once per window rather than once per request. Touched only on refusal
/// paths, never for an admitted request, and bounded like the buckets.
#[derive(Clone)]
struct RefusalLog<K: Hash + Eq + Clone> {
    /// How long an empty bucket takes to refill completely.
    window: Duration,
    max_tracked: usize,
    reported: Arc<Mutex<HashMap<K, Instant>>>,
}

impl<K: Hash + Eq + Clone> RefusalLog<K> {
    fn new(window: Duration, max_tracked: usize) -> Self {
        Self {
            window,
            max_tracked,
            reported: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Record a refusal of `key`; `true` if it is the first in the key's
    /// window.
    fn first_in_window(&self, key: &K) -> bool {
        let now = Instant::now();
        let window = self.window;
        let mut reported = self.reported.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(last) = reported.get(key)
            && now.duration_since(*last) < window
        {
            return false;
        }
        if !reported.contains_key(key) && reported.len() >= self.max_tracked {
            reported.retain(|_, last| now.duration_since(*last) < window);
            // Mostly live: clear rather than rescan on every new key of a
            // flood. The cost is at most one more log line per cleared key.
            if reported.len() > self.max_tracked / 4 * 3 {
                reported.clear();
            }
        }
        reported.insert(key.clone(), now);
        true
    }

    /// Forget refusals logged more than a window ago.
    fn sweep(&self) {
        let now = Instant::now();
        let window = self.window;
        self.reported
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|_, last| now.duration_since(*last) < window);
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.reported
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}

impl<K: Hash + Eq + Clone> Active<K> {
    /// Number of distinct keys currently tracked.
    fn tracked(&self) -> usize {
        self.store.0.len()
    }

    /// Is this key already tracked? An already-tracked key is exempt from the
    /// cap — charged against its existing bucket, never refused for capacity.
    fn is_tracked(&self, key: &K) -> bool {
        self.store.0.contains_key(key)
    }

    /// Reclaim fully-replenished buckets, at most once per
    /// [`INLINE_RECLAIM_MIN_INTERVAL`]. A no-op if another reclaim ran within
    /// the window — this keeps the refusal path from amplifying an O(tracked)
    /// scan across every request in a flood.
    fn throttled_reclaim(&self) {
        let now_ms = self.epoch.elapsed().as_millis() as u64;
        let last = self.last_reclaim_ms.load(Ordering::Relaxed);
        let window_ms = INLINE_RECLAIM_MIN_INTERVAL.as_millis() as u64;
        if now_ms.saturating_sub(last) >= window_ms
            && self
                .last_reclaim_ms
                .compare_exchange(last, now_ms, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
        {
            self.limiter.retain_recent();
        }
    }
}

/// Shared limiter state keyed by `K`, cheap to clone.
///
/// The key is whatever a request is charged to: a client address, a sender,
/// or `()` for one budget shared by every caller. [`RateLimitLayer`] takes the
/// `IpAddr`-keyed [`RateLimiterState`]; any other key is checked from the
/// service's own code with [`check`](Self::check).
///
/// # Examples
///
/// ```
/// use affinidi_rate_limit::KeyedRateLimiterState;
/// use std::time::Duration;
///
/// // Ten attempts per sender per minute.
/// let limiter = KeyedRateLimiterState::<String>::per_window(10, Duration::from_secs(60));
/// assert!(limiter.check("vid:did:example:alice".to_owned()).is_ok());
/// ```
#[derive(Clone)]
pub struct KeyedRateLimiterState<K: Hash + Eq + Clone> {
    active: Option<Active<K>>,
    on_refused: Option<RefusalCallback>,
    source: Option<HeaderValue>,
    limiter_name: Option<&'static str>,
}

/// The per-client-IP limiter [`RateLimitLayer`] applies.
pub type RateLimiterState = KeyedRateLimiterState<IpAddr>;

impl<K: Hash + Eq + Clone> std::fmt::Debug for KeyedRateLimiterState<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyedRateLimiterState")
            .field("enabled", &self.active.is_some())
            .field("has_callback", &self.on_refused.is_some())
            .field("source", &self.source())
            .field("limiter_name", &self.limiter_name)
            .finish()
    }
}

fn per_second_quota(per_second: u32, burst: u32) -> Option<Quota> {
    let per_second = NonZeroU32::new(per_second)?;
    let burst = NonZeroU32::new(burst).unwrap_or(NonZeroU32::MIN);
    Some(Quota::per_second(per_second).allow_burst(burst))
}

fn per_period_quota(period: Duration, burst: u32) -> Option<Quota> {
    let burst = NonZeroU32::new(burst).unwrap_or(NonZeroU32::MIN);
    Some(Quota::with_period(period)?.allow_burst(burst))
}

fn per_window_quota(max_per_window: u32, window: Duration) -> Option<Quota> {
    let max_per_window = NonZeroU32::new(max_per_window)?;
    if window.is_zero() {
        return None;
    }
    let period = (window / max_per_window.get()).max(Duration::from_nanos(1));
    Some(Quota::with_period(period)?.allow_burst(max_per_window))
}

impl<K: Hash + Eq + Clone> KeyedRateLimiterState<K> {
    /// Build a limiter allowing `per_second` sustained requests per key with
    /// bursts up to `burst`.
    ///
    /// `per_second == 0` disables limiting; `burst == 0` is treated as 1.
    pub fn new(per_second: u32, burst: u32) -> Self {
        Self::from_quota(per_second_quota(per_second, burst))
    }

    /// Build a limiter allowing `max_per_window` requests per key per
    /// `window`.
    ///
    /// A key may spend all `max_per_window` at once, and regains one every
    /// `window / max_per_window`: the same average as a fixed window, without
    /// its double burst either side of a window boundary. `Retry-After` is the
    /// time to the next request, not to the end of a window.
    ///
    /// `max_per_window == 0` or a zero `window` disables limiting.
    pub fn per_window(max_per_window: u32, window: Duration) -> Self {
        Self::from_quota(per_window_quota(max_per_window, window))
    }

    /// Build a limiter that gives each key one request every `period`, with
    /// bursts up to `burst`: `(Duration::from_secs(5), 10)` is 10 back-to-back
    /// requests, then one every 5 s. For limits slower than one a second,
    /// which [`Self::new`] cannot state.
    ///
    /// A zero `period` disables limiting; `burst == 0` is treated as 1.
    pub fn per_period(period: Duration, burst: u32) -> Self {
        Self::from_quota(per_period_quota(period, burst))
    }

    /// A limiter for `quota`, or a disabled one for `None`.
    fn from_quota(quota: Option<Quota>) -> Self {
        let Some(quota) = quota else {
            return Self::disabled();
        };
        // Build the limiter over a store we keep an `Arc` to, so the cap can
        // read membership/length from the exact map the limiter mutates.
        let store = SharedDashMapStore(Arc::new(DashMapStateStore::default()));
        let window = quota.burst_size_replenished_in();
        let max_tracked = MAX_TRACKED_KEYS;
        let limiter = RateLimiter::new(quota, store.clone(), DefaultClock::default());
        Self {
            active: Some(Active {
                limiter: Arc::new(limiter),
                store,
                max_tracked,
                epoch: Instant::now()
                    .checked_sub(INLINE_RECLAIM_MIN_INTERVAL)
                    .unwrap_or_else(Instant::now),
                last_reclaim_ms: Arc::new(AtomicU64::new(0)),
                refusals_reported: RefusalLog::new(window, max_tracked),
                invalid_forwarded_reported: RefusalLog::new(window, max_tracked),
            }),
            on_refused: None,
            source: None,
            limiter_name: None,
        }
    }

    /// A pass-through limiter that refuses nothing.
    pub fn disabled() -> Self {
        Self {
            active: None,
            on_refused: None,
            source: None,
            limiter_name: None,
        }
    }

    /// Observe refusals — for metrics, say.
    ///
    /// Kept as a callback so this crate need not depend on any particular
    /// metrics library.
    pub fn on_refused(mut self, f: impl Fn(&Refusal) + Send + Sync + 'static) -> Self {
        self.on_refused = Some(Arc::new(f));
        self
    }

    /// Name the service this limiter protects, so its refusals say who refused.
    ///
    /// A `429` then carries [`SOURCE_HEADER`] with this value and a JSON body
    /// naming it as `limiter` (see the crate docs for the full contract). Use
    /// the ecosystem's names — `mediator`, `vta`, `vtc`, `did-host` — which are
    /// what clients match on.
    ///
    /// # Panics
    ///
    /// If `source` is not a valid header value (visible ASCII). It is a literal
    /// naming the service, so this is a programming error that shows the first
    /// time the service builds its limiter.
    pub fn with_source(mut self, source: &'static str) -> Self {
        self.source = Some(HeaderValue::from_static(source));
        self
    }

    /// The name given with [`Self::with_source`], if any.
    pub fn source(&self) -> Option<&str> {
        self.source.as_ref().and_then(|v| v.to_str().ok())
    }

    /// Name this particular limit, for a service that has several.
    ///
    /// A refusal's JSON body then names it as `limiter`
    /// (`"auth-challenge-per-ip"`, say), while [`SOURCE_HEADER`] still names
    /// the service. Clients that match on the header are unaffected; an
    /// operator reading the body sees which limit fired. Setting it without
    /// [`Self::with_source`] gives the JSON body without the header.
    ///
    /// Default: none; the body names the source.
    pub fn with_limiter_name(mut self, limiter_name: &'static str) -> Self {
        self.limiter_name = Some(limiter_name);
        self
    }

    /// Track at most `max_tracked_keys` distinct keys at once, rather than
    /// 250,000. When the limiter is full, a new key is refused (after
    /// reclaiming the keys whose budget has refilled), while a key already
    /// tracked is unaffected. A small cap suits a limiter whose keys are few
    /// or large; `0` is treated as 1. The refusal log is bounded the same way.
    ///
    /// Set it while building the limiter: clones taken earlier keep the cap
    /// they were cloned with.
    ///
    /// Default: 250,000.
    pub fn with_max_tracked_keys(mut self, max_tracked_keys: usize) -> Self {
        if let Some(active) = &mut self.active {
            let max_tracked = max_tracked_keys.max(1);
            active.max_tracked = max_tracked;
            active.refusals_reported.max_tracked = max_tracked;
            active.invalid_forwarded_reported.max_tracked = max_tracked;
        }
        self
    }

    /// The name given with [`Self::with_limiter_name`], if any.
    pub fn limiter_name(&self) -> Option<&'static str> {
        self.limiter_name
    }

    /// Record a refusal of `key` and say whether it is the key's first in its
    /// window (the time an empty bucket takes to refill), so a caller can log
    /// once per window rather than once per request. [`RateLimitLayer`] logs
    /// this way; call it after a refused [`check`](Self::check) to do the
    /// same.
    ///
    /// Best effort: at most 250,000 keys are remembered, and
    /// under a flood of more the record is cleared, so a key may be reported
    /// again early. Always `true` when limiting is disabled.
    pub fn first_refusal_in_window(&self, key: &K) -> bool {
        self.active
            .as_ref()
            .is_none_or(|active| active.refusals_reported.first_in_window(key))
    }

    /// Is limiting active?
    pub fn is_enabled(&self) -> bool {
        self.active.is_some()
    }

    /// Live bucket count, or 0 when disabled. Mainly useful in tests.
    pub fn tracked_keys(&self) -> usize {
        self.active.as_ref().map_or(0, |a| a.tracked())
    }

    /// Charge one request against `key`'s bucket, as [`Self::charge`] does,
    /// with the refusal as the layer's [`Refusal`].
    ///
    /// It only ever refuses with [`Refusal::RateLimited`]; the other
    /// refusals are about a request's client address, which the layer works
    /// out. Code that limits from its own handlers can match on
    /// [`TooManyRequests`] with [`Self::charge`] instead.
    pub fn check(&self, key: K) -> Result<(), Refusal> {
        self.charge(key).map_err(
            |TooManyRequests { retry_after_secs }| Refusal::RateLimited { retry_after_secs },
        )
    }

    /// Charge one request against `key`'s bucket.
    ///
    /// This is the whole decision, separated from the middleware so a service
    /// can call it from its own code. It does not run the
    /// [`on_refused`](Self::on_refused) callback, which belongs to the
    /// refusal responses the layer sends.
    pub fn charge(&self, key: K) -> Result<(), TooManyRequests> {
        let Some(active) = &self.active else {
            return Ok(());
        };

        // Admission control (CWE-770). The store is keyed on unauthenticated,
        // client-chosen IPs, so without a ceiling a client rotating addresses
        // (an IPv6 /64, say) grows it without bound between GC sweeps. Only the
        // *insertion of a new key* is gated: an IP already tracked falls through
        // to its bucket below, so a legitimate steady-state set of clients under
        // the cap is never refused and no in-window IP is evicted by this path.
        if !active.is_tracked(&key) && active.tracked() >= active.max_tracked {
            // Try to make room before refusing: reclaim fully-replenished
            // buckets, throttled so this pre-auth path can't amplify an
            // O(tracked) scan across a flood (see `throttled_reclaim`).
            active.throttled_reclaim();
            if !active.is_tracked(&key) && active.tracked() >= active.max_tracked {
                // Still full: fail closed for the new IP rather than grow
                // unbounded. Same 429 contract as a quota refusal.
                return Err(TooManyRequests {
                    retry_after_secs: CAPACITY_RETRY_AFTER_SECS,
                });
            }
        }

        match active.limiter.check_key(&key) {
            Ok(()) => Ok(()),
            Err(not_until) => {
                // governor reports the instant the next token is available;
                // RFC 7231 wants whole seconds. Round up: a retry sent at a
                // rounded-down time arrives before the token and fails again.
                let wait = not_until.wait_time_from(DefaultClock::default().now());
                let retry_after_secs = (wait.as_secs() + u64::from(wait.subsec_nanos() > 0)).max(1);
                Err(TooManyRequests { retry_after_secs })
            }
        }
    }
}

impl KeyedRateLimiterState<IpAddr> {
    /// Record an invalid `X-Forwarded-For` from `peer`; `true` if it is the
    /// first from that peer in the window.
    fn first_invalid_forwarded_in_window(&self, peer: &IpAddr) -> bool {
        self.active
            .as_ref()
            .is_none_or(|active| active.invalid_forwarded_reported.first_in_window(peer))
    }
}

impl<K: Hash + Eq + Clone + Send + Sync + 'static> KeyedRateLimiterState<K> {
    /// Sweep fully-replenished buckets out of the keyed store every
    /// [`GC_INTERVAL`], until `shutdown` fires.
    ///
    /// `retain_recent` only drops keys whose bucket has fully replenished. Such
    /// a key is by definition indistinguishable from one that was never
    /// present, so sweeping cannot let a client exceed its quota.
    ///
    /// No-op when limiting is disabled — there is no map to sweep.
    pub fn spawn_gc(&self, shutdown: CancellationToken) {
        let Some(active) = self.active.clone() else {
            return;
        };
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(GC_INTERVAL);
            ticker.tick().await; // the first tick fires immediately
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    _ = ticker.tick() => {
                        let limiter = &active.limiter;
                        let before = limiter.len();
                        limiter.retain_recent();
                        limiter.shrink_to_fit();
                        active.refusals_reported.sweep();
                        active.invalid_forwarded_reported.sweep();
                        let after = limiter.len();
                        if before != after {
                            debug!(
                                "Rate limiter GC: reclaimed {} idle bucket(s), {} live",
                                before - after,
                                after
                            );
                        }
                    }
                }
            }
        });
    }

    fn refuse(&self, refusal: &Refusal) -> Response {
        if let Some(cb) = &self.on_refused {
            cb(refusal);
        }
        let mut response = match refusal {
            Refusal::RateLimited { retry_after_secs } => {
                let mut response = self.refusal_body(
                    StatusCode::TOO_MANY_REQUESTS,
                    RATE_LIMITED_ERROR,
                    RATE_LIMITED_MESSAGE,
                    Some(*retry_after_secs),
                );
                response
                    .headers_mut()
                    .insert(header::RETRY_AFTER, HeaderValue::from(*retry_after_secs));
                response
            }
            Refusal::InvalidForwardedFor => self.refusal_body(
                StatusCode::BAD_REQUEST,
                INVALID_FORWARDED_FOR_ERROR,
                INVALID_FORWARDED_FOR_MESSAGE,
                None,
            ),
            Refusal::NoClientIp => (StatusCode::FORBIDDEN, NO_CLIENT_IP_MESSAGE).into_response(),
        };
        // Every refusal from a named limiter says who refused, so a `400` or
        // `403` from behind several hops is as traceable as a `429`.
        if let Some(source) = &self.source {
            response
                .headers_mut()
                .insert(HeaderName::from_static(SOURCE_HEADER), source.clone());
        }
        response
    }

    /// A refusal body: the attributed JSON form when the limiter is named, the
    /// plain-text message otherwise.
    fn refusal_body(
        &self,
        status: StatusCode,
        error: &str,
        message: &'static str,
        retry_after_secs: Option<u64>,
    ) -> Response {
        let Some(limiter) = self.limiter_name().or_else(|| self.source()) else {
            return (status, message).into_response();
        };
        let mut body = serde_json::json!({
            "error": error,
            "limiter": limiter,
            "message": message,
        });
        if let Some(secs) = retry_after_secs {
            body["retryAfterSecs"] = secs.into();
        }
        (status, Json(body)).into_response()
    }
}

/// `tower` layer applying [`RateLimiterState`].
#[derive(Clone, Debug)]
pub struct RateLimitLayer {
    state: RateLimiterState,
    client_ip_extractor: ClientIpExtractor,
}

impl RateLimitLayer {
    pub fn new(state: RateLimiterState) -> Self {
        Self {
            state,
            client_ip_extractor: ClientIpExtractor::direct_peer(),
        }
    }

    /// Charge requests to [`ClientIpExtractor::client_key`], so the layer and
    /// a service's own code share one rule for who the client is. Replaces
    /// anything set before with [`Self::trusted_proxies`] or
    /// [`Self::ipv6_prefix`].
    ///
    /// Default: [`ClientIpExtractor::direct_peer`].
    pub fn client_ip_extractor(mut self, extractor: ClientIpExtractor) -> Self {
        self.client_ip_extractor = extractor;
        self
    }

    /// Shorthand for [`ClientIpExtractor::ipv6_prefix`] on the layer's
    /// extractor.
    ///
    /// # Errors
    ///
    /// [`InvalidIpv6Prefix`] for a prefix length of 0 or above 128.
    pub fn ipv6_prefix(mut self, prefix_len: u8) -> Result<Self, InvalidIpv6Prefix> {
        self.client_ip_extractor = self.client_ip_extractor.ipv6_prefix(prefix_len)?;
        Ok(self)
    }

    /// Trust `X-Forwarded-For` only when the socket peer falls inside one of
    /// the configured CIDRs.
    ///
    /// This is opt-in. Without this call, the layer keys on the socket peer.
    /// For secure attribution, list only proxies that append the address of
    /// the peer they received the connection from to `X-Forwarded-For` (an ALB
    /// appends the client IP), and do not expose the service directly except
    /// through those proxies.
    ///
    /// Sets the trusted proxies on the layer's extractor, keeping any
    /// [`Self::ipv6_prefix`]; see [`ClientIpExtractor::trusted_proxies`].
    ///
    /// # Errors
    ///
    /// [`InvalidTrustedProxy`] if a range has prefix length 0 (`0.0.0.0/0`,
    /// `::/0`), which would trust every peer.
    pub fn trusted_proxies(
        mut self,
        trusted_proxy_cidrs: Vec<IpNet>,
    ) -> Result<Self, InvalidTrustedProxy> {
        let ipv6_prefix_len = self.client_ip_extractor.ipv6_prefix_len;
        self.client_ip_extractor = ClientIpExtractor {
            ipv6_prefix_len,
            ..ClientIpExtractor::trusted_proxies(trusted_proxy_cidrs)?
        };
        Ok(self)
    }
}

impl<S> Layer<S> for RateLimitLayer {
    type Service = RateLimitService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RateLimitService {
            inner,
            state: self.state.clone(),
            client_ip_extractor: self.client_ip_extractor.clone(),
        }
    }
}

/// The service produced by [`RateLimitLayer`].
#[derive(Clone, Debug)]
pub struct RateLimitService<S> {
    inner: S,
    state: RateLimiterState,
    client_ip_extractor: ClientIpExtractor,
}

impl<S> Service<Request<Body>> for RateLimitService<S>
where
    S: Service<Request<Body>, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        // `poll_ready` readied `self.inner`; call *that* service and leave a
        // fresh clone for the next `poll_ready`, as tower's contract requires.
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);

        if !self.state.is_enabled() {
            return Box::pin(async move { inner.call(req).await });
        }

        let key = match self.client_ip_extractor.extract(&req) {
            Ok(key) => key,
            Err(ClientIpExtractionError::MissingPeer) => {
                warn!(
                    "No client IP available; rejecting request (rate limiting requires client IP)"
                );
                let response = self.state.refuse(&Refusal::NoClientIp);
                return Box::pin(async move { Ok(response) });
            }
            Err(ClientIpExtractionError::InvalidForwardedFor { peer }) => {
                if self.state.first_invalid_forwarded_in_window(&peer) {
                    warn!(%peer, "trusted proxy sent an invalid X-Forwarded-For; rejecting its requests with 400");
                }
                let response = self.state.refuse(&Refusal::InvalidForwardedFor);
                return Box::pin(async move { Ok(response) });
            }
        };

        if let Err(refusal) = self.state.check(key) {
            if self.state.first_refusal_in_window(&key) {
                warn!(client = %key, "client over the rate limit; refusing it until its bucket refills");
            }
            let response = self.state.refuse(&refusal);
            return Box::pin(async move { Ok(response) });
        }

        Box::pin(async move { inner.call(req).await })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn disabled_allows_everything() {
        let limiter = RateLimiterState::new(0, 0);
        assert!(!limiter.is_enabled());
        for _ in 0..1_000 {
            assert!(limiter.check(ip("1.2.3.4")).is_ok());
        }
    }

    #[test]
    fn allows_up_to_the_burst_then_refuses() {
        // 1/sec sustained, burst 3: three immediate requests, then refusal.
        let limiter = RateLimiterState::new(1, 3);
        let client = ip("1.2.3.4");
        for i in 0..3 {
            assert!(limiter.check(client).is_ok(), "request {i} should pass");
        }
        assert!(matches!(
            limiter.check(client),
            Err(Refusal::RateLimited { .. })
        ));
    }

    /// One noisy client must not consume another's quota.
    #[test]
    fn buckets_are_per_ip() {
        let limiter = RateLimiterState::new(1, 2);
        let noisy = ip("1.2.3.4");
        let quiet = ip("5.6.7.8");

        while limiter.check(noisy).is_ok() {}
        assert!(
            limiter.check(quiet).is_ok(),
            "a different IP must have its own bucket"
        );
    }

    /// The distinct-IP cap refuses a *new* IP once the store is full, but an
    /// already-tracked IP keeps flowing — the cap gates key insertion, not use.
    ///
    /// `per_second = 1`, burst 5: nothing is refused for its quota within the
    /// test, and the two filled buckets don't replenish, so the store stays
    /// full and the only refusal is the capacity one.
    #[test]
    fn cap_fails_closed_for_a_new_ip_when_full() {
        let limiter = RateLimiterState::new(1, 5).with_max_tracked_keys(2);

        assert!(limiter.check(ip("1.1.1.1")).is_ok());
        assert!(limiter.check(ip("2.2.2.2")).is_ok());
        assert_eq!(limiter.tracked_keys(), 2);

        // A third, new IP is refused for capacity, not quota.
        match limiter.check(ip("3.3.3.3")) {
            Err(Refusal::RateLimited { retry_after_secs }) => {
                assert_eq!(retry_after_secs, CAPACITY_RETRY_AFTER_SECS);
            }
            other => panic!("expected a capacity refusal, got {other:?}"),
        }

        // An already-tracked IP still has quota and is never refused by the cap.
        assert!(limiter.check(ip("1.1.1.1")).is_ok());
    }

    /// Disabled mode (`per_second == 0`) has no store and therefore no cap.
    #[test]
    fn disabled_mode_ignores_the_cap() {
        let limiter = RateLimiterState::new(0, 0);
        assert!(!limiter.is_enabled());
        for i in 0..2000u32 {
            let octet = i.to_be_bytes();
            assert!(
                limiter
                    .check(IpAddr::from([octet[0], octet[1], octet[2], octet[3]]))
                    .is_ok()
            );
        }
    }

    /// A set of distinct IPs comfortably under the cap is never refused by it.
    #[test]
    fn a_client_set_under_the_cap_is_never_refused() {
        let limiter = RateLimiterState::new(1000, 1000).with_max_tracked_keys(200);
        for i in 0..150u32 {
            let o = i.to_be_bytes();
            assert!(
                limiter.check(IpAddr::from([10, o[1], o[2], o[3]])).is_ok(),
                "IP {i} (under the cap) must be admitted"
            );
        }
    }

    /// Once buckets replenish, the refusal-path reclaim frees their slots and
    /// new IPs are admitted again — the cap is a live ceiling, not permanent.
    #[test]
    fn reclaim_frees_capacity_for_new_ips() {
        // burst 1 at 1000/s: a charged bucket fully replenishes in ~1ms.
        let limiter = RateLimiterState::new(1000, 1).with_max_tracked_keys(2);
        assert!(limiter.check(ip("1.1.1.1")).is_ok());
        assert!(limiter.check(ip("2.2.2.2")).is_ok());

        // Let both buckets fully replenish so they become reclaimable.
        std::thread::sleep(Duration::from_millis(50));

        // A new IP now succeeds: the throttled reclaim (first pass fires
        // immediately, epoch is backdated) drops the two replenished buckets.
        assert!(limiter.check(ip("3.3.3.3")).is_ok());
    }

    #[test]
    fn ipv6_is_keyed_separately_from_ipv4() {
        let limiter = RateLimiterState::new(1, 1);
        assert!(limiter.check(ip("1.2.3.4")).is_ok());
        assert!(limiter.check(ip("2606:4700::1111")).is_ok());
    }

    /// `Retry-After` must never be 0 — that invites an immediate retry which is
    /// guaranteed to fail.
    #[test]
    fn retry_after_is_at_least_one_second() {
        let limiter = RateLimiterState::new(1, 1);
        let client = ip("1.2.3.4");
        assert!(limiter.check(client).is_ok());
        match limiter.check(client) {
            Err(Refusal::RateLimited { retry_after_secs }) => {
                assert!(retry_after_secs >= 1, "got {retry_after_secs}");
            }
            other => panic!("expected a rate-limit refusal, got {other:?}"),
        }
    }

    #[test]
    fn burst_of_zero_is_treated_as_one() {
        let limiter = RateLimiterState::new(1, 0);
        let client = ip("1.2.3.4");
        assert!(limiter.check(client).is_ok());
        assert!(limiter.check(client).is_err());
    }

    #[test]
    fn refusals_are_reported_to_the_callback() {
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = hits.clone();
        let limiter = RateLimiterState::new(1, 1).on_refused(move |_| {
            counter.fetch_add(1, Ordering::SeqCst);
        });

        let client = ip("1.2.3.4");
        limiter.check(client).ok();
        // `check` alone does not fire the callback; `refuse` does, as the
        // middleware calls it.
        if let Err(r) = limiter.check(client) {
            let _ = limiter.refuse(&r);
        }
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn tracks_a_bucket_per_seen_ip() {
        let limiter = RateLimiterState::new(10, 10);
        for i in 0..5 {
            limiter.check(ip(&format!("10.0.0.{i}"))).ok();
        }
        assert_eq!(limiter.tracked_keys(), 5);
    }

    /// The GC must not run — or panic — when limiting is disabled.
    #[tokio::test]
    async fn gc_is_a_noop_when_disabled() {
        let limiter = RateLimiterState::disabled();
        limiter.spawn_gc(CancellationToken::new());
        assert_eq!(limiter.tracked_keys(), 0);
    }

    #[tokio::test]
    async fn gc_stops_on_shutdown() {
        let limiter = RateLimiterState::new(10, 10);
        let token = CancellationToken::new();
        limiter.spawn_gc(token.clone());
        token.cancel();
        // Yield so the task observes cancellation; nothing to assert beyond
        // this completing without hanging.
        tokio::task::yield_now().await;
    }

    #[test]
    fn no_client_ip_is_refused_not_exempted() {
        let limiter = RateLimiterState::new(1, 1);
        let response = limiter.refuse(&Refusal::NoClientIp);
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn invalid_forwarded_for_is_refused() {
        let limiter = RateLimiterState::new(1, 1);
        let response = limiter.refuse(&Refusal::InvalidForwardedFor);
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    async fn body_json(response: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    /// The attribution contract: a named limiter's `429` says who refused and
    /// how long to wait, in the headers and in the body.
    #[tokio::test]
    async fn named_limiter_refusal_carries_the_attribution_contract() {
        let limiter = RateLimiterState::new(1, 1).with_source("mediator");
        assert_eq!(limiter.source(), Some("mediator"));
        let response = limiter.refuse(&Refusal::RateLimited {
            retry_after_secs: 4,
        });
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers().get(SOURCE_HEADER).unwrap(), "mediator");
        assert_eq!(response.headers().get(header::RETRY_AFTER).unwrap(), "4");
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        assert_eq!(
            body_json(response).await,
            serde_json::json!({
                "error": "rate_limited",
                "limiter": "mediator",
                "message": "Rate limit exceeded. Please try again later.",
                "retryAfterSecs": 4,
            })
        );
    }

    /// An unnamed limiter keeps the response it always sent. No source header:
    /// claiming an attribution nobody configured would be a guess.
    #[tokio::test]
    async fn unnamed_limiter_refusal_is_unattributed() {
        let limiter = RateLimiterState::new(1, 1);
        assert_eq!(limiter.source(), None);
        let response = limiter.refuse(&Refusal::RateLimited {
            retry_after_secs: 2,
        });
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(response.headers().get(SOURCE_HEADER).is_none());
        assert_eq!(response.headers().get(header::RETRY_AFTER).unwrap(), "2");
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&bytes[..], RATE_LIMITED_MESSAGE.as_bytes());
    }

    /// Through the layer, as a service sees it: the second request from one IP
    /// is refused with the contract, and an allowed request carries none of it.
    #[tokio::test]
    async fn layer_refusal_is_attributed_end_to_end() {
        use tower::ServiceExt;

        let app = axum::Router::new()
            .route("/", axum::routing::get(|| async { "ok" }))
            .layer(RateLimitLayer::new(
                RateLimiterState::new(1, 1).with_source("mediator"),
            ));
        let request = || {
            let mut request = Request::builder().uri("/").body(Body::empty()).unwrap();
            request
                .extensions_mut()
                .insert(ConnectInfo(SocketAddr::from(([10, 0, 0, 1], 4000))));
            request
        };

        let allowed = app.clone().oneshot(request()).await.unwrap();
        assert_eq!(allowed.status(), StatusCode::OK);
        assert!(allowed.headers().get(SOURCE_HEADER).is_none());

        let refused = app.oneshot(request()).await.unwrap();
        assert_eq!(refused.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(refused.headers().get(SOURCE_HEADER).unwrap(), "mediator");
        let retry_after: u64 = refused.headers()[header::RETRY_AFTER]
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        assert!(retry_after >= 1);
        let body = body_json(refused).await;
        assert_eq!(body["limiter"], "mediator");
        assert_eq!(body["retryAfterSecs"], retry_after);
    }

    #[tokio::test]
    async fn trusted_proxy_uses_rightmost_untrusted_xff_entry() {
        use tower::ServiceExt;

        let app = axum::Router::new()
            .route("/", axum::routing::get(|| async { "ok" }))
            .layer(
                RateLimitLayer::new(RateLimiterState::new(1, 1))
                    .trusted_proxies(vec!["10.0.0.0/8".parse().unwrap()])
                    .unwrap(),
            );

        let request = || {
            let mut request = Request::builder().uri("/").body(Body::empty()).unwrap();
            request.headers_mut().insert(
                X_FORWARDED_FOR,
                HeaderValue::from_static("198.51.100.7, 10.0.0.5"),
            );
            request
                .extensions_mut()
                .insert(ConnectInfo(SocketAddr::from(([10, 0, 0, 5], 4000))));
            request
        };

        let allowed = app.clone().oneshot(request()).await.unwrap();
        assert_eq!(allowed.status(), StatusCode::OK);
        let refused = app.oneshot(request()).await.unwrap();
        assert_eq!(refused.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn junk_left_of_the_client_entry_is_ignored_not_refused() {
        use tower::ServiceExt;

        let app = trusted_app(1);
        let first = app
            .clone()
            .oneshot(xff_request([10, 0, 0, 5], "garbage, 198.51.100.7"))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);

        let other_junk = app
            .clone()
            .oneshot(xff_request([10, 0, 0, 5], "more-garbage, 198.51.100.7"))
            .await
            .unwrap();
        assert_eq!(
            other_junk.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "changing client-supplied junk must not give the client a new bucket"
        );

        let other_client = app
            .oneshot(xff_request([10, 0, 0, 5], "garbage, 198.51.100.8"))
            .await
            .unwrap();
        assert_eq!(other_client.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn malformed_xff_from_trusted_proxy_is_rejected() {
        use tower::ServiceExt;

        let app = axum::Router::new()
            .route("/", axum::routing::get(|| async { "ok" }))
            .layer(
                RateLimitLayer::new(RateLimiterState::new(1, 1))
                    .trusted_proxies(vec!["10.0.0.0/8".parse().unwrap()])
                    .unwrap(),
            );

        let mut request = Request::builder().uri("/").body(Body::empty()).unwrap();
        request.headers_mut().insert(
            X_FORWARDED_FOR,
            HeaderValue::from_static("198.51.100.7, not-an-ip"),
        );
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([10, 0, 0, 5], 4000))));

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    fn xff_request(peer: [u8; 4], xff: &str) -> Request<Body> {
        let mut request = Request::builder().uri("/").body(Body::empty()).unwrap();
        request
            .headers_mut()
            .insert(X_FORWARDED_FOR, HeaderValue::from_str(xff).unwrap());
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from((peer, 4000))));
        request
    }

    fn trusted_app(burst: u32) -> axum::Router {
        axum::Router::new()
            .route("/", axum::routing::get(|| async { "ok" }))
            .layer(
                RateLimitLayer::new(RateLimiterState::new(1, burst))
                    .trusted_proxies(vec!["10.0.0.0/8".parse().unwrap()])
                    .unwrap(),
            )
    }

    #[tokio::test]
    async fn oversized_xff_chain_from_trusted_proxy_is_rejected() {
        use tower::ServiceExt;

        let xff = vec!["203.0.113.1"; MAX_FORWARDED_ENTRIES + 1].join(", ");
        let response = trusted_app(1)
            .oneshot(xff_request([10, 0, 0, 5], &xff))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn untrusted_peer_cannot_choose_its_key_via_xff() {
        use tower::ServiceExt;

        let app = trusted_app(1);
        let first = app
            .clone()
            .oneshot(xff_request([192, 0, 2, 1], "198.51.100.1"))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        let spoofed = app
            .oneshot(xff_request([192, 0, 2, 1], "198.51.100.2"))
            .await
            .unwrap();
        assert_eq!(
            spoofed.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "a spoofed X-Forwarded-For from an untrusted peer must share the peer's bucket"
        );
    }

    #[tokio::test]
    async fn all_trusted_chain_falls_back_to_the_peer() {
        use tower::ServiceExt;

        let app = trusted_app(1);
        let first = app
            .clone()
            .oneshot(xff_request([10, 0, 0, 5], "10.0.0.7"))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        let second = app
            .oneshot(xff_request([10, 0, 0, 5], "10.0.0.8"))
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn canonicalises_only_ipv4_mapped_addresses() {
        let loopback = parse_forwarded_ip("::1").unwrap();
        assert_eq!(loopback, "::1".parse::<IpAddr>().unwrap());
        let mapped = parse_forwarded_ip("::ffff:192.0.2.1").unwrap();
        assert_eq!(mapped, "192.0.2.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn catch_all_trusted_ranges_are_refused() {
        for net in ["0.0.0.0/0", "::/0"] {
            let err = RateLimitLayer::new(RateLimiterState::new(1, 1))
                .trusted_proxies(vec!["10.0.0.0/8".parse().unwrap(), net.parse().unwrap()])
                .unwrap_err();
            assert_eq!(err.cidr, net.parse::<IpNet>().unwrap());
            assert!(err.to_string().contains(net));
        }
    }

    /// A named limiter's `400` carries the attribution contract and reaches
    /// the refusal callback, so an operator can see and count it.
    #[tokio::test]
    async fn invalid_forwarded_for_is_attributed_and_observed() {
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = hits.clone();
        let limiter = RateLimiterState::new(1, 1)
            .with_source("mediator")
            .on_refused(move |refusal| {
                assert_eq!(refusal, &Refusal::InvalidForwardedFor);
                counter.fetch_add(1, Ordering::SeqCst);
            });
        let response = limiter.refuse(&Refusal::InvalidForwardedFor);
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(response.headers().get(SOURCE_HEADER).unwrap(), "mediator");
        assert!(response.headers().get(header::RETRY_AFTER).is_none());
        assert_eq!(
            body_json(response).await,
            serde_json::json!({
                "error": "invalid_forwarded_for",
                "limiter": "mediator",
                "message": "Invalid X-Forwarded-For header; request rejected.",
            })
        );

        let unnamed = RateLimiterState::new(1, 1).refuse(&Refusal::InvalidForwardedFor);
        assert_eq!(unnamed.status(), StatusCode::BAD_REQUEST);
        assert!(unnamed.headers().get(SOURCE_HEADER).is_none());
    }

    #[test]
    fn named_limiter_no_client_ip_refusal_says_who_refused() {
        let response = RateLimiterState::new(1, 1)
            .with_source("mediator")
            .refuse(&Refusal::NoClientIp);
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(response.headers().get(SOURCE_HEADER).unwrap(), "mediator");
    }

    /// Later header lines are newer hops, so the walk reads the last line
    /// first.
    #[test]
    fn later_xff_lines_are_newer_hops() {
        let extractor =
            ClientIpExtractor::trusted_proxies(vec!["10.0.0.0/8".parse().unwrap()]).unwrap();
        let mut headers = http::HeaderMap::new();
        headers.append(X_FORWARDED_FOR, HeaderValue::from_static("9.9.9.9"));
        headers.append(
            X_FORWARDED_FOR,
            HeaderValue::from_static("203.0.113.1, 10.0.0.3"),
        );
        assert_eq!(
            extractor.client_from_xff_chain(&headers),
            Ok(Some("203.0.113.1".parse().unwrap()))
        );
    }

    /// A proxy on IPv6 loopback must match `::1/128`: `::1` is not `0.0.0.1`.
    #[tokio::test]
    async fn ipv6_loopback_proxy_is_trusted() {
        use tower::ServiceExt;

        let app = axum::Router::new()
            .route("/", axum::routing::get(|| async { "ok" }))
            .layer(
                RateLimitLayer::new(RateLimiterState::new(1, 1))
                    .trusted_proxies(vec!["::1/128".parse().unwrap()])
                    .unwrap(),
            );
        let request = |client: &'static str| {
            let mut request = Request::builder().uri("/").body(Body::empty()).unwrap();
            request
                .headers_mut()
                .insert(X_FORWARDED_FOR, HeaderValue::from_static(client));
            request
                .extensions_mut()
                .insert(ConnectInfo("[::1]:4000".parse::<SocketAddr>().unwrap()));
            request
        };
        let status = |client| {
            let app = app.clone();
            async move { app.oneshot(request(client)).await.unwrap().status() }
        };
        assert_eq!(status("198.51.100.1").await, StatusCode::OK);
        assert_eq!(status("198.51.100.2").await, StatusCode::OK);
    }

    /// A service that must be readied before each call. A clone starts
    /// unready, so calling a fresh clone instead of the readied service panics.
    struct NeedsReady {
        ready: bool,
    }

    impl Clone for NeedsReady {
        fn clone(&self) -> Self {
            Self { ready: false }
        }
    }

    impl Service<Request<Body>> for NeedsReady {
        type Response = Response;
        type Error = std::convert::Infallible;
        type Future = std::future::Ready<Result<Response, Self::Error>>;

        fn poll_ready(
            &mut self,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            self.ready = true;
            std::task::Poll::Ready(Ok(()))
        }

        fn call(&mut self, _: Request<Body>) -> Self::Future {
            assert!(self.ready, "called before poll_ready");
            self.ready = false;
            std::future::ready(Ok(StatusCode::OK.into_response()))
        }
    }

    #[tokio::test]
    async fn the_readied_service_is_the_one_called() {
        use tower::ServiceExt;

        for state in [
            RateLimiterState::new(100, 100),
            RateLimiterState::disabled(),
        ] {
            let mut service = RateLimitLayer::new(state).layer(NeedsReady { ready: false });
            for _ in 0..3 {
                let mut request = Request::builder().uri("/").body(Body::empty()).unwrap();
                request
                    .extensions_mut()
                    .insert(ConnectInfo(SocketAddr::from(([10, 0, 0, 1], 1))));
                let response = service.ready().await.unwrap().call(request).await.unwrap();
                assert_eq!(response.status(), StatusCode::OK);
            }
        }
    }

    #[test]
    fn rate_limited_response_carries_retry_after() {
        let limiter = RateLimiterState::new(1, 1);
        let response = limiter.refuse(&Refusal::RateLimited {
            retry_after_secs: 7,
        });
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers().get(header::RETRY_AFTER).unwrap(), "7");
    }

    /// A window's whole allowance can be spent at once, and the next request
    /// waits for one refill (window / max), not for the window to end.
    #[test]
    fn per_window_spends_the_allowance_then_waits_one_refill() {
        let limiter = RateLimiterState::per_window(3, Duration::from_secs(60));
        let client = ip("203.0.113.1");
        for request in 0..3 {
            assert!(
                limiter.check(client).is_ok(),
                "request {request} should pass"
            );
        }
        match limiter.check(client) {
            Err(Refusal::RateLimited { retry_after_secs }) => {
                assert_eq!(
                    retry_after_secs, 20,
                    "a wait just under 20s rounds up, so a retry on time succeeds"
                );
            }
            other => panic!("expected a rate-limit refusal, got {other:?}"),
        }
        assert!(limiter.check(ip("203.0.113.2")).is_ok());
    }

    #[test]
    fn per_window_of_nothing_disables_limiting() {
        assert!(!RateLimiterState::per_window(0, Duration::from_secs(60)).is_enabled());
        assert!(!RateLimiterState::per_window(5, Duration::ZERO).is_enabled());
    }

    /// A huge allowance in a short window still limits, rather than failing to
    /// build because the refill period rounds to zero.
    #[test]
    fn per_window_with_a_sub_nanosecond_refill_still_limits() {
        let limiter = RateLimiterState::per_window(u32::MAX, Duration::from_secs(1));
        assert!(limiter.is_enabled());
        assert!(limiter.check(ip("203.0.113.1")).is_ok());
    }

    /// A limiter can key on what a service authenticates (a sender, say), and
    /// each key keeps its own budget.
    #[test]
    fn string_keys_have_their_own_buckets() {
        let limiter = KeyedRateLimiterState::<String>::per_window(1, Duration::from_secs(60));
        assert!(limiter.check("ip:203.0.113.1".to_owned()).is_ok());
        assert!(limiter.check("ip:203.0.113.1".to_owned()).is_err());
        assert!(limiter.check("vid:did:example:alice".to_owned()).is_ok());
    }

    /// The unit key is one budget every caller shares.
    #[test]
    fn the_unit_key_is_one_shared_budget() {
        let limiter = KeyedRateLimiterState::<()>::per_window(2, Duration::from_secs(60));
        assert!(limiter.check(()).is_ok());
        assert!(limiter.check(()).is_ok());
        assert!(matches!(
            limiter.check(()),
            Err(Refusal::RateLimited { .. })
        ));
    }

    /// With several limiters behind one service, the body names the limit
    /// that fired and the header still names the service.
    #[tokio::test]
    async fn limiter_name_names_the_limit_and_source_the_service() {
        let response = RateLimiterState::new(1, 1)
            .with_source("did-host")
            .with_limiter_name("resolve-per-address")
            .refuse(&Refusal::RateLimited {
                retry_after_secs: 3,
            });
        assert_eq!(response.headers().get(SOURCE_HEADER).unwrap(), "did-host");
        assert_eq!(
            body_json(response).await,
            serde_json::json!({
                "error": "rate_limited",
                "limiter": "resolve-per-address",
                "message": "Rate limit exceeded. Please try again later.",
                "retryAfterSecs": 3,
            })
        );
    }

    #[tokio::test]
    async fn limiter_name_without_source_sends_json_without_the_header() {
        let response = RateLimiterState::new(1, 1)
            .with_limiter_name("auth-challenge-per-ip")
            .refuse(&Refusal::RateLimited {
                retry_after_secs: 3,
            });
        assert!(response.headers().get(SOURCE_HEADER).is_none());
        assert_eq!(
            body_json(response).await["limiter"],
            "auth-challenge-per-ip"
        );
    }

    fn request_from(peer: SocketAddr) -> Request<Body> {
        let mut request = Request::builder().uri("/").body(Body::empty()).unwrap();
        request.extensions_mut().insert(ConnectInfo(peer));
        request
    }

    /// With a `/64` prefix, addresses inside one IPv6 network share a bucket
    /// and another network gets its own; IPv4 is keyed per address.
    #[tokio::test]
    async fn ipv6_prefix_charges_a_client_to_its_network() {
        use tower::ServiceExt;

        let app = axum::Router::new()
            .route("/", axum::routing::get(|| async { "ok" }))
            .layer(
                RateLimitLayer::new(RateLimiterState::per_window(1, Duration::from_secs(60)))
                    .ipv6_prefix(64)
                    .unwrap(),
            );
        let status = |peer: &str| {
            let app = app.clone();
            let request = request_from(peer.parse().unwrap());
            async move { app.oneshot(request).await.unwrap().status() }
        };

        assert_eq!(status("[2001:db8:1:2::1]:4000").await, StatusCode::OK);
        assert_eq!(
            status("[2001:db8:1:2:ffff::9]:4000").await,
            StatusCode::TOO_MANY_REQUESTS,
            "another address in the same /64 shares the bucket"
        );
        assert_eq!(status("[2001:db8:1:3::1]:4000").await, StatusCode::OK);
        assert_eq!(status("192.0.2.1:4000").await, StatusCode::OK);
        assert_eq!(status("192.0.2.2:4000").await, StatusCode::OK);
        assert_eq!(
            status("[::ffff:192.0.2.3]:4000").await,
            StatusCode::OK,
            "an IPv4-mapped peer is keyed as its IPv4 address, not masked"
        );
    }

    /// A refused key is reported once, then not again until its window has
    /// passed; another key is reported on its own.
    #[test]
    fn a_refusal_is_reported_once_per_window() {
        let limiter = RateLimiterState::per_window(1, Duration::from_millis(50));
        let client = ip("203.0.113.1");
        assert!(limiter.first_refusal_in_window(&client));
        assert!(!limiter.first_refusal_in_window(&client));
        assert!(limiter.first_refusal_in_window(&ip("203.0.113.2")));

        std::thread::sleep(Duration::from_millis(60));
        assert!(
            limiter.first_refusal_in_window(&client),
            "a new window reports again"
        );
        assert!(RateLimiterState::disabled().first_refusal_in_window(&client));
    }

    /// `charge` answers with only what can happen on a handler's path, and
    /// `check` with the same refusal as the layer's `Refusal`.
    #[test]
    fn charge_refuses_with_the_retry_time_and_check_agrees() {
        let limiter = RateLimiterState::per_period(Duration::from_secs(5), 1);
        let client = ip("203.0.113.1");
        assert_eq!(limiter.charge(client), Ok(()));
        assert_eq!(
            limiter.charge(client),
            Err(TooManyRequests {
                retry_after_secs: 5
            })
        );
        assert_eq!(
            limiter.check(client),
            Err(Refusal::RateLimited {
                retry_after_secs: 5
            })
        );
    }

    /// A small cap refuses a new key once full of live ones, and never a key
    /// it already tracks; a cap of 0 tracks one key rather than none.
    #[test]
    fn max_tracked_keys_bounds_new_keys_only() {
        let limiter = KeyedRateLimiterState::<String>::per_period(Duration::from_secs(3600), 5)
            .with_max_tracked_keys(2);
        assert!(limiter.charge("a".to_owned()).is_ok());
        assert!(limiter.charge("b".to_owned()).is_ok());
        assert_eq!(
            limiter.charge("c".to_owned()),
            Err(TooManyRequests {
                retry_after_secs: CAPACITY_RETRY_AFTER_SECS
            })
        );
        assert!(limiter.charge("a".to_owned()).is_ok());

        let one =
            RateLimiterState::per_period(Duration::from_secs(3600), 5).with_max_tracked_keys(0);
        assert!(one.charge(ip("203.0.113.1")).is_ok());
        assert!(one.charge(ip("203.0.113.2")).is_err());

        let disabled = RateLimiterState::disabled().with_max_tracked_keys(1);
        assert!(disabled.charge(ip("203.0.113.1")).is_ok());
        assert!(disabled.charge(ip("203.0.113.2")).is_ok());
    }

    /// One request every period after the burst: slower than one a second,
    /// which `new` cannot state.
    #[test]
    fn per_period_spends_the_burst_then_one_per_period() {
        let limiter = RateLimiterState::per_period(Duration::from_secs(5), 2);
        let client = ip("203.0.113.1");
        assert!(limiter.check(client).is_ok());
        assert!(limiter.check(client).is_ok());
        assert_eq!(
            limiter.check(client),
            Err(Refusal::RateLimited {
                retry_after_secs: 5
            })
        );
    }

    #[test]
    fn per_period_of_zero_disables_limiting() {
        assert!(!RateLimiterState::per_period(Duration::ZERO, 10).is_enabled());
        let burst_of_zero = RateLimiterState::per_period(Duration::from_secs(5), 0);
        assert!(burst_of_zero.check(ip("203.0.113.1")).is_ok());
        assert!(burst_of_zero.check(ip("203.0.113.1")).is_err());
    }

    /// A proxy's bad chain is logged once per window, and on a record of its
    /// own: it neither hides nor is hidden by a quota refusal of the same
    /// address.
    #[test]
    fn an_invalid_chain_is_logged_once_per_peer_on_its_own_record() {
        let limiter = RateLimiterState::per_window(1, Duration::from_secs(60));
        let proxy = ip("10.0.0.5");
        assert!(limiter.first_invalid_forwarded_in_window(&proxy));
        assert!(!limiter.first_invalid_forwarded_in_window(&proxy));
        assert!(limiter.first_invalid_forwarded_in_window(&ip("10.0.0.6")));
        assert!(
            limiter.first_refusal_in_window(&proxy),
            "a quota refusal of the proxy's own address is still logged"
        );
    }

    /// Logging once does not mean refusing once: every bad chain gets its 400.
    #[tokio::test]
    async fn every_invalid_chain_is_refused_though_logged_once() {
        use tower::ServiceExt;

        let app = trusted_app(100);
        for _ in 0..3 {
            let response = app
                .clone()
                .oneshot(xff_request([10, 0, 0, 5], "not-an-address"))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }
    }

    /// A flood of new keys past the cap clears the record rather than
    /// growing it.
    #[test]
    fn the_refusal_record_is_bounded() {
        let limiter = RateLimiterState::new(1, 1).with_max_tracked_keys(4);
        for last_octet in 0..20u8 {
            assert!(limiter.first_refusal_in_window(&IpAddr::from([198, 51, 100, last_octet])));
        }
        let reported = limiter.active.as_ref().unwrap().refusals_reported.len();
        assert!(reported <= 4, "got {reported}");
    }

    /// A handler charging `client_key` charges what the layer charges,
    /// /64 grouping included, while `client_ip` keeps the address.
    #[test]
    fn client_key_masks_ipv6_and_client_ip_does_not() {
        let extractor = ClientIpExtractor::trusted_proxies(vec!["10.0.0.0/8".parse().unwrap()])
            .unwrap()
            .ipv6_prefix(64)
            .unwrap();
        let headers = forwarded_for("2001:db8:1:2::7");
        assert_eq!(
            extractor.client_key(ip("10.0.0.5"), &headers),
            Ok(ip("2001:db8:1:2::"))
        );
        assert_eq!(
            extractor.client_ip(ip("10.0.0.5"), &headers),
            Ok(ip("2001:db8:1:2::7"))
        );
        assert_eq!(
            extractor.client_key(ip("::ffff:192.0.2.3"), &HeaderMap::new()),
            Ok(ip("192.0.2.3"))
        );
    }

    /// `ipv6_prefix` then `trusted_proxies` on the layer keeps both.
    #[tokio::test]
    async fn layer_keeps_the_prefix_when_proxies_are_set_after_it() {
        use tower::ServiceExt;

        let app = axum::Router::new()
            .route("/", axum::routing::get(|| async { "ok" }))
            .layer(
                RateLimitLayer::new(RateLimiterState::per_window(1, Duration::from_secs(60)))
                    .ipv6_prefix(64)
                    .unwrap()
                    .trusted_proxies(vec!["10.0.0.0/8".parse().unwrap()])
                    .unwrap(),
            );
        let first = app
            .clone()
            .oneshot(xff_request([10, 0, 0, 5], "2001:db8:1:2::1"))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        let same_network = app
            .oneshot(xff_request([10, 0, 0, 5], "2001:db8:1:2::2"))
            .await
            .unwrap();
        assert_eq!(same_network.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn ipv6_prefix_outside_1_to_128_is_refused() {
        for prefix_len in [0, 129] {
            let error = RateLimitLayer::new(RateLimiterState::new(1, 1))
                .ipv6_prefix(prefix_len)
                .unwrap_err();
            assert_eq!(error, InvalidIpv6Prefix { prefix_len });
        }
        assert!(
            RateLimitLayer::new(RateLimiterState::new(1, 1))
                .ipv6_prefix(128)
                .is_ok()
        );
    }

    fn forwarded_for(chain: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(X_FORWARDED_FOR, HeaderValue::from_str(chain).unwrap());
        headers
    }

    /// A service resolving the client itself gets the layer's answer.
    #[test]
    fn client_ip_names_the_client_behind_a_trusted_proxy() {
        let extractor =
            ClientIpExtractor::trusted_proxies(vec!["10.0.0.0/8".parse().unwrap()]).unwrap();
        let headers = forwarded_for("198.51.100.1, 198.51.100.7, 10.0.0.9");

        assert_eq!(
            extractor.client_ip(ip("10.0.0.5"), &headers),
            Ok(ip("198.51.100.7"))
        );
        assert_eq!(
            extractor.client_ip(ip("::ffff:10.0.0.5"), &headers),
            Ok(ip("198.51.100.7")),
            "an IPv4-mapped proxy matches its IPv4 range"
        );
        assert_eq!(
            extractor.client_ip(ip("192.0.2.1"), &headers),
            Ok(ip("192.0.2.1")),
            "an untrusted peer cannot name its own client"
        );
        assert_eq!(
            extractor.client_ip(ip("10.0.0.5"), &forwarded_for("not-an-address")),
            Err(InvalidForwardedFor)
        );
        assert_eq!(
            ClientIpExtractor::direct_peer().client_ip(ip("10.0.0.5"), &headers),
            Ok(ip("10.0.0.5"))
        );
    }

    #[test]
    fn client_ip_extractor_refuses_catch_all_ranges() {
        let error = ClientIpExtractor::trusted_proxies(vec!["::/0".parse().unwrap()]).unwrap_err();
        assert_eq!(error.cidr, "::/0".parse::<IpNet>().unwrap());
    }

    /// An extractor handed to the layer is the rule the layer charges by.
    #[tokio::test]
    async fn layer_charges_by_the_extractor_it_is_given() {
        use tower::ServiceExt;

        let extractor =
            ClientIpExtractor::trusted_proxies(vec!["10.0.0.0/8".parse().unwrap()]).unwrap();
        let app = axum::Router::new()
            .route("/", axum::routing::get(|| async { "ok" }))
            .layer(
                RateLimitLayer::new(RateLimiterState::per_window(1, Duration::from_secs(60)))
                    .client_ip_extractor(extractor),
            );
        let first = app
            .clone()
            .oneshot(xff_request([10, 0, 0, 5], "198.51.100.1"))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        let second_client = app
            .oneshot(xff_request([10, 0, 0, 5], "198.51.100.2"))
            .await
            .unwrap();
        assert_eq!(second_client.status(), StatusCode::OK);
    }
}
