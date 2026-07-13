//! Per-IP rate limiting middleware using the governor crate.
//!
//! Applies a token bucket rate limiter keyed by client IP address.
//! Configurable via `rate_limit_per_ip` and `rate_limit_burst` in LimitsConfig.

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
use std::{net::SocketAddr, num::NonZeroU32, sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;
use tower::{Layer, Service};
use tracing::{debug, warn};

type KeyedLimiter =
    RateLimiter<std::net::IpAddr, DashMapStateStore<std::net::IpAddr>, DefaultClock>;

/// How often to sweep fully-replenished buckets out of the keyed state store.
const GC_INTERVAL: Duration = Duration::from_secs(60);

/// Shared rate limiter state
#[derive(Clone)]
pub struct RateLimiterState {
    limiter: Option<Arc<KeyedLimiter>>,
}

impl RateLimiterState {
    /// Create a new rate limiter. If `per_second` is 0, rate limiting is disabled.
    pub fn new(per_second: u32, burst: u32) -> Self {
        let Some(per_second) = NonZeroU32::new(per_second) else {
            return Self { limiter: None };
        };
        let burst = NonZeroU32::new(burst).unwrap_or(NonZeroU32::MIN);
        let quota = Quota::per_second(per_second).allow_burst(burst);
        Self {
            limiter: Some(Arc::new(RateLimiter::keyed(quota))),
        }
    }

    /// Spawn the background sweep that reclaims idle buckets.
    ///
    /// `governor` never reclaims keys on its own, so without this every source
    /// IP the mediator has ever seen keeps a `DashMap` entry for the process
    /// lifetime. The store is keyed on unauthenticated, client-chosen input —
    /// a client rotating through an IPv6 /64 inserts an entry per request — so
    /// it is an unbounded growth path reachable pre-auth.
    ///
    /// `retain_recent` only drops keys whose bucket has fully replenished. Such
    /// a key is by definition indistinguishable from one that was never
    /// present, so sweeping cannot let a client exceed its quota.
    ///
    /// No-op when rate limiting is disabled (there is no map to sweep).
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
}

/// Tower Layer that applies per-IP rate limiting
#[derive(Clone)]
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

/// Tower Service that checks the rate limiter before forwarding requests
#[derive(Clone)]
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
        let Some(limiter) = &self.state.limiter else {
            // Rate limiting disabled
            let mut inner = self.inner.clone();
            return Box::pin(async move { inner.call(req).await });
        };

        // Extract client IP from ConnectInfo
        let ip = req
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ci| ci.0.ip());

        let Some(ip) = ip else {
            warn!("No client IP available; rejecting request (rate limiting requires client IP)");
            return Box::pin(async move {
                Ok((
                    StatusCode::FORBIDDEN,
                    "Rate limiting requires client IP; request rejected.",
                )
                    .into_response())
            });
        };

        if let Err(not_until) = limiter.check_key(&ip) {
            warn!("Rate limit exceeded for IP: {}", ip);
            metrics::counter!(super::metrics::names::RATE_LIMITED_TOTAL).increment(1);
            // Accurate Retry-After: governor reports the instant the next token
            // is available; round up to whole seconds (min 1), per RFC 7231.
            let retry_after = not_until
                .wait_time_from(DefaultClock::default().now())
                .as_secs()
                .max(1);
            return Box::pin(async move {
                let mut response = (
                    StatusCode::TOO_MANY_REQUESTS,
                    "Rate limit exceeded. Please try again later.",
                )
                    .into_response();
                if let Ok(value) = HeaderValue::from_str(&retry_after.to_string()) {
                    response.headers_mut().insert(header::RETRY_AFTER, value);
                }
                Ok(response)
            });
        }

        let mut inner = self.inner.clone();
        Box::pin(async move { inner.call(req).await })
    }
}
