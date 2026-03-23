//! Per-IP rate limiting middleware using the governor crate.
//!
//! Applies a token bucket rate limiter keyed by client IP address.
//! Configurable via `rate_limit_per_ip` and `rate_limit_burst` in LimitsConfig.

use axum::{
    body::Body,
    extract::ConnectInfo,
    response::{IntoResponse, Response},
};
use governor::{Quota, RateLimiter, clock::DefaultClock, state::keyed::DashMapStateStore};
use http::{Request, StatusCode};
use std::{net::SocketAddr, num::NonZeroU32, sync::Arc};
use tower::{Layer, Service};
use tracing::warn;

type KeyedLimiter = RateLimiter<std::net::IpAddr, DashMapStateStore<std::net::IpAddr>, DefaultClock>;

/// Shared rate limiter state
#[derive(Clone)]
pub struct RateLimiterState {
    limiter: Option<Arc<KeyedLimiter>>,
}

impl RateLimiterState {
    /// Create a new rate limiter. If `per_second` is 0, rate limiting is disabled.
    pub fn new(per_second: u32, burst: u32) -> Self {
        if per_second == 0 {
            return Self { limiter: None };
        }

        let quota = Quota::per_second(NonZeroU32::new(per_second).expect("per_second checked non-zero above"))
            .allow_burst(NonZeroU32::new(burst.max(1)).expect("burst.max(1) is always non-zero"));

        Self {
            limiter: Some(Arc::new(RateLimiter::keyed(quota))),
        }
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

        if limiter.check_key(&ip).is_err() {
            warn!("Rate limit exceeded for IP: {}", ip);
            metrics::counter!(super::metrics::names::RATE_LIMITED_TOTAL).increment(1);
            return Box::pin(async move {
                Ok((
                    StatusCode::TOO_MANY_REQUESTS,
                    "Rate limit exceeded. Please try again later.",
                )
                    .into_response())
            });
        }

        let mut inner = self.inner.clone();
        Box::pin(async move { inner.call(req).await })
    }
}
