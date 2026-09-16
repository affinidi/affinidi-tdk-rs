/*!
 * Per-IP request rate limiting for `axum` services.
 *
 * A token bucket keyed by client IP, applied as a `tower` layer:
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
 * Without a source the response is the unattributed plain-text `429` this crate
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
    net::IpAddr,
    net::SocketAddr,
    num::NonZeroU32,
    sync::{
        Arc,
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
use http::{HeaderName, HeaderValue, Request, StatusCode, header};
use tokio_util::sync::CancellationToken;
use tower::{Layer, Service};
use tracing::{debug, warn};

/// A `governor` DashMap state store shared behind an `Arc`.
///
/// `governor`'s `RateLimiter::keyed` owns its store privately, exposing only
/// `len` / `retain_recent` / `shrink_to_fit` — enough to *sweep* the map but
/// not to ask whether a key is already present. The distinct-IP cap
/// ([`MAX_TRACKED_IPS`]) needs exactly that: an IP already tracked must always
/// be admitted to its bucket (never refused for capacity), while a brand-new IP
/// is what the cap gates. So the limiter is built over a store we also hold an
/// `Arc` to, and membership / length are read straight from it.
///
/// `DashMapStateStore<K>` is a type alias for `DashMap<K, InMemoryState>`, so
/// the trait impls below are pure delegation.
#[derive(Clone)]
struct SharedDashMapStore(Arc<DashMapStateStore<IpAddr>>);

impl StateStore for SharedDashMapStore {
    type Key = IpAddr;

    fn measure_and_replace<T, F, E>(&self, key: &Self::Key, f: F) -> Result<T, E>
    where
        F: Fn(Option<Nanos>) -> Result<(T, Nanos), E>,
    {
        self.0.measure_and_replace(key, f)
    }
}

impl ShrinkableKeyedStateStore<IpAddr> for SharedDashMapStore {
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

type KeyedLimiter = RateLimiter<IpAddr, SharedDashMapStore, DefaultClock>;

/// Observer invoked when a request is refused. See
/// [`RateLimiterState::on_refused`].
pub type RefusalCallback = Arc<dyn Fn(&Refusal) + Send + Sync>;

/// How often idle buckets are swept out of the keyed state store.
pub const GC_INTERVAL: Duration = Duration::from_secs(60);

/// Hard cap on the number of *distinct* source IPs tracked at once.
///
/// `governor` bounds the rate *within* each key's bucket but never the *number*
/// of keys, and [`spawn_gc`](RateLimiterState::spawn_gc) only reclaims fully
/// replenished buckets on a 60s tick. The store is keyed on unauthenticated,
/// client-chosen input reachable *before* any authentication — a client
/// rotating through an IPv6 /64 inserts an entry per request — so without a cap
/// this is an unbounded memory-growth path an unauthenticated attacker can
/// drive at line rate (CWE-770). The cap bounds the worst case to
/// O(`MAX_TRACKED_IPS`).
///
/// 250_000 is deliberately generous: a legitimate deployment — even a large
/// mediator or DID host — sees at most thousands to low tens of thousands of
/// distinct client IPs within a 60s GC window, so steady state sits far below
/// the cap and is never refused by it, while the ceiling still bounds the map
/// to roughly tens of MB (an `IpAddr` plus a few words of bucket state per
/// entry). When the cap is hit, a *new* IP fails closed — the same `429` a
/// quota refusal returns — rather than growing the map; an IP already tracked
/// is unaffected. It is a constant rather than a config knob because it is a
/// safety backstop, not a tuning parameter, and operators size the real limit
/// via `per_second` / `burst`.
const MAX_TRACKED_IPS: usize = 250_000;

/// `Retry-After` (seconds) on a *capacity* refusal (the cap is full), as
/// opposed to a per-IP quota refusal. Tied to the GC interval: the next sweep
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

/// Why a request was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Refusal {
    /// The client exceeded its quota. Carries how long until the next token,
    /// already rounded up to whole seconds (minimum 1) for `Retry-After`.
    RateLimited { retry_after_secs: u64 },
    /// No client IP was available, so the request could not be attributed.
    NoClientIp,
}

/// The live limiter, present only when limiting is enabled. Bundles the
/// `governor` limiter with the shared handle to its state store (for the
/// distinct-IP cap), the cap, and the inline-reclaim throttle state, so they
/// can never drift apart.
#[derive(Clone)]
struct Active {
    limiter: Arc<KeyedLimiter>,
    store: SharedDashMapStore,
    max_tracked: usize,
    /// Monotonic reference for the inline-reclaim throttle. Backdated by
    /// [`INLINE_RECLAIM_MIN_INTERVAL`] at construction so the first reclaim
    /// after the map fills fires immediately rather than waiting out a window.
    epoch: Instant,
    /// Milliseconds (since `epoch`) of the last inline reclaim, `0` until the
    /// first. Shared so all clones throttle against one another.
    last_reclaim_ms: Arc<AtomicU64>,
}

impl Active {
    /// Number of distinct IPs currently tracked.
    fn tracked(&self) -> usize {
        self.store.0.len()
    }

    /// Is this IP already tracked? An already-tracked IP is exempt from the cap
    /// — charged against its existing bucket, never refused for capacity.
    fn is_tracked(&self, ip: &IpAddr) -> bool {
        self.store.0.contains_key(ip)
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

/// Shared limiter state, cheap to clone.
#[derive(Clone)]
pub struct RateLimiterState {
    active: Option<Active>,
    on_refused: Option<RefusalCallback>,
    source: Option<HeaderValue>,
}

impl std::fmt::Debug for RateLimiterState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RateLimiterState")
            .field("enabled", &self.active.is_some())
            .field("has_callback", &self.on_refused.is_some())
            .field("source", &self.source())
            .finish()
    }
}

impl RateLimiterState {
    /// Build a limiter allowing `per_second` sustained requests per IP with
    /// bursts up to `burst`.
    ///
    /// `per_second == 0` disables limiting; `burst == 0` is treated as 1.
    pub fn new(per_second: u32, burst: u32) -> Self {
        Self::with_capacity(per_second, burst, MAX_TRACKED_IPS)
    }

    /// As [`Self::new`], but with an explicit distinct-IP cap. The public
    /// constructor always uses [`MAX_TRACKED_IPS`]; tests use a small cap so the
    /// admission-control path can be exercised without inserting 250k keys.
    fn with_capacity(per_second: u32, burst: u32, max_tracked: usize) -> Self {
        let Some(per_second) = NonZeroU32::new(per_second) else {
            return Self::disabled();
        };
        let burst = NonZeroU32::new(burst).unwrap_or(NonZeroU32::MIN);
        // Build the limiter over a store we keep an `Arc` to, so the cap can
        // read membership/length from the exact map the limiter mutates.
        let store = SharedDashMapStore(Arc::new(DashMapStateStore::default()));
        let limiter = RateLimiter::new(
            Quota::per_second(per_second).allow_burst(burst),
            store.clone(),
            DefaultClock::default(),
        );
        Self {
            active: Some(Active {
                limiter: Arc::new(limiter),
                store,
                // A cap of 0 would refuse every IP; clamp so a misconfigured
                // caller degrades to "track one" rather than "deny all".
                max_tracked: max_tracked.max(1),
                epoch: Instant::now()
                    .checked_sub(INLINE_RECLAIM_MIN_INTERVAL)
                    .unwrap_or_else(Instant::now),
                last_reclaim_ms: Arc::new(AtomicU64::new(0)),
            }),
            on_refused: None,
            source: None,
        }
    }

    /// A pass-through limiter that refuses nothing.
    pub fn disabled() -> Self {
        Self {
            active: None,
            on_refused: None,
            source: None,
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

    /// Is limiting active?
    pub fn is_enabled(&self) -> bool {
        self.active.is_some()
    }

    /// Live bucket count, or 0 when disabled. Mainly useful in tests.
    pub fn tracked_keys(&self) -> usize {
        self.active.as_ref().map_or(0, |a| a.tracked())
    }

    /// Charge one request against `ip`'s bucket.
    ///
    /// This is the whole decision, separated from the middleware so it can be
    /// exercised directly.
    pub fn check(&self, ip: IpAddr) -> Result<(), Refusal> {
        let Some(active) = &self.active else {
            return Ok(());
        };

        // Admission control (CWE-770). The store is keyed on unauthenticated,
        // client-chosen IPs, so without a ceiling a client rotating addresses
        // (an IPv6 /64, say) grows it without bound between GC sweeps. Only the
        // *insertion of a new key* is gated: an IP already tracked falls through
        // to its bucket below, so a legitimate steady-state set of clients under
        // the cap is never refused and no in-window IP is evicted by this path.
        if !active.is_tracked(&ip) && active.tracked() >= active.max_tracked {
            // Try to make room before refusing: reclaim fully-replenished
            // buckets, throttled so this pre-auth path can't amplify an
            // O(tracked) scan across a flood (see `throttled_reclaim`).
            active.throttled_reclaim();
            if !active.is_tracked(&ip) && active.tracked() >= active.max_tracked {
                // Still full: fail closed for the new IP rather than grow
                // unbounded. Same 429 contract as a quota refusal.
                return Err(Refusal::RateLimited {
                    retry_after_secs: CAPACITY_RETRY_AFTER_SECS,
                });
            }
        }

        match active.limiter.check_key(&ip) {
            Ok(()) => Ok(()),
            Err(not_until) => {
                // governor reports the instant the next token is available;
                // RFC 7231 wants whole seconds, and 0 would invite an immediate
                // retry that is guaranteed to fail.
                let retry_after_secs = not_until
                    .wait_time_from(DefaultClock::default().now())
                    .as_secs()
                    .max(1);
                Err(Refusal::RateLimited { retry_after_secs })
            }
        }
    }

    /// Sweep fully-replenished buckets out of the keyed store every
    /// [`GC_INTERVAL`], until `shutdown` fires.
    ///
    /// `retain_recent` only drops keys whose bucket has fully replenished. Such
    /// a key is by definition indistinguishable from one that was never
    /// present, so sweeping cannot let a client exceed its quota.
    ///
    /// No-op when limiting is disabled — there is no map to sweep.
    pub fn spawn_gc(&self, shutdown: CancellationToken) {
        let Some(limiter) = self.active.as_ref().map(|a| a.limiter.clone()) else {
            return;
        };
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(GC_INTERVAL);
            ticker.tick().await; // the first tick fires immediately
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    _ = ticker.tick() => {
                        let before = limiter.len();
                        limiter.retain_recent();
                        limiter.shrink_to_fit();
                        let after = limiter.len();
                        if before != after {
                            debug!(
                                "Per-IP rate limiter GC: reclaimed {} idle bucket(s), {} live",
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
        match refusal {
            Refusal::RateLimited { retry_after_secs } => {
                let mut response = match self.source() {
                    Some(limiter) => (
                        StatusCode::TOO_MANY_REQUESTS,
                        Json(serde_json::json!({
                            "error": RATE_LIMITED_ERROR,
                            "limiter": limiter,
                            "message": RATE_LIMITED_MESSAGE,
                            "retryAfterSecs": retry_after_secs,
                        })),
                    )
                        .into_response(),
                    None => (StatusCode::TOO_MANY_REQUESTS, RATE_LIMITED_MESSAGE).into_response(),
                };
                if let Some(source) = &self.source {
                    response
                        .headers_mut()
                        .insert(HeaderName::from_static(SOURCE_HEADER), source.clone());
                }
                response
                    .headers_mut()
                    .insert(header::RETRY_AFTER, HeaderValue::from(*retry_after_secs));
                response
            }
            Refusal::NoClientIp => (
                StatusCode::FORBIDDEN,
                "Rate limiting requires client IP; request rejected.",
            )
                .into_response(),
        }
    }
}

/// `tower` layer applying [`RateLimiterState`].
#[derive(Clone, Debug)]
pub struct RateLimitLayer {
    state: RateLimiterState,
}

impl RateLimitLayer {
    pub fn new(state: RateLimiterState) -> Self {
        Self { state }
    }
}

impl<S> Layer<S> for RateLimitLayer {
    type Service = RateLimitService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RateLimitService {
            inner,
            state: self.state.clone(),
        }
    }
}

/// The service produced by [`RateLimitLayer`].
#[derive(Clone, Debug)]
pub struct RateLimitService<S> {
    inner: S,
    state: RateLimiterState,
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
        if !self.state.is_enabled() {
            let mut inner = self.inner.clone();
            return Box::pin(async move { inner.call(req).await });
        }

        let ip = req
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ci| ci.0.ip());

        let Some(ip) = ip else {
            warn!("No client IP available; rejecting request (rate limiting requires client IP)");
            let response = self.state.refuse(&Refusal::NoClientIp);
            return Box::pin(async move { Ok(response) });
        };

        if let Err(refusal) = self.state.check(ip) {
            warn!("Rate limit exceeded for IP: {ip}");
            let response = self.state.refuse(&refusal);
            return Box::pin(async move { Ok(response) });
        }

        let mut inner = self.inner.clone();
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
        let limiter = RateLimiterState::with_capacity(1, 5, 2);

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
        let limiter = RateLimiterState::with_capacity(1000, 1000, 200);
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
        let limiter = RateLimiterState::with_capacity(1000, 1, 2);
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

    #[test]
    fn rate_limited_response_carries_retry_after() {
        let limiter = RateLimiterState::new(1, 1);
        let response = limiter.refuse(&Refusal::RateLimited {
            retry_after_secs: 7,
        });
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers().get(header::RETRY_AFTER).unwrap(), "7");
    }
}
