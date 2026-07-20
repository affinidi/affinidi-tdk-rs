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

use std::{net::IpAddr, net::SocketAddr, num::NonZeroU32, sync::Arc, time::Duration};

use axum::{
    body::Body,
    extract::ConnectInfo,
    response::{IntoResponse, Response},
};
use governor::{
    Quota, RateLimiter,
    clock::{Clock, DefaultClock},
    state::keyed::DashMapStateStore,
};
use http::{HeaderValue, Request, StatusCode, header};
use tokio_util::sync::CancellationToken;
use tower::{Layer, Service};
use tracing::{debug, warn};

type KeyedLimiter = RateLimiter<IpAddr, DashMapStateStore<IpAddr>, DefaultClock>;

/// Observer invoked when a request is refused. See
/// [`RateLimiterState::on_refused`].
pub type RefusalCallback = Arc<dyn Fn(&Refusal) + Send + Sync>;

/// How often idle buckets are swept out of the keyed state store.
pub const GC_INTERVAL: Duration = Duration::from_secs(60);

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

/// Shared limiter state, cheap to clone.
#[derive(Clone)]
pub struct RateLimiterState {
    limiter: Option<Arc<KeyedLimiter>>,
    on_refused: Option<RefusalCallback>,
}

impl std::fmt::Debug for RateLimiterState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RateLimiterState")
            .field("enabled", &self.limiter.is_some())
            .field("has_callback", &self.on_refused.is_some())
            .finish()
    }
}

impl RateLimiterState {
    /// Build a limiter allowing `per_second` sustained requests per IP with
    /// bursts up to `burst`.
    ///
    /// `per_second == 0` disables limiting; `burst == 0` is treated as 1.
    pub fn new(per_second: u32, burst: u32) -> Self {
        let Some(per_second) = NonZeroU32::new(per_second) else {
            return Self::disabled();
        };
        let burst = NonZeroU32::new(burst).unwrap_or(NonZeroU32::MIN);
        Self {
            limiter: Some(Arc::new(RateLimiter::keyed(
                Quota::per_second(per_second).allow_burst(burst),
            ))),
            on_refused: None,
        }
    }

    /// A pass-through limiter that refuses nothing.
    pub fn disabled() -> Self {
        Self {
            limiter: None,
            on_refused: None,
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

    /// Is limiting active?
    pub fn is_enabled(&self) -> bool {
        self.limiter.is_some()
    }

    /// Live bucket count, or 0 when disabled. Mainly useful in tests.
    pub fn tracked_keys(&self) -> usize {
        self.limiter.as_ref().map_or(0, |l| l.len())
    }

    /// Charge one request against `ip`'s bucket.
    ///
    /// This is the whole decision, separated from the middleware so it can be
    /// exercised directly.
    pub fn check(&self, ip: IpAddr) -> Result<(), Refusal> {
        let Some(limiter) = &self.limiter else {
            return Ok(());
        };
        match limiter.check_key(&ip) {
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
        let Some(limiter) = self.limiter.clone() else {
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
                let mut response = (
                    StatusCode::TOO_MANY_REQUESTS,
                    "Rate limit exceeded. Please try again later.",
                )
                    .into_response();
                if let Ok(value) = HeaderValue::from_str(&retry_after_secs.to_string()) {
                    response.headers_mut().insert(header::RETRY_AFTER, value);
                }
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
    fn rate_limited_response_carries_retry_after() {
        let limiter = RateLimiterState::new(1, 1);
        let response = limiter.refuse(&Refusal::RateLimited {
            retry_after_secs: 7,
        });
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers().get(header::RETRY_AFTER).unwrap(), "7");
    }
}
