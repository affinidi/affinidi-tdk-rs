//! Request ID middleware.
//!
//! Assigns a unique UUID v4 to each incoming request. If the request already
//! carries an `x-request-id` header, that value is reused. The ID is inserted
//! as a request extension (accessible to handlers) and echoed back as the
//! `x-request-id` response header.

use axum::{body::Body, response::Response};
use http::{HeaderValue, Request};
use std::task::{Context, Poll};
use tower::{Layer, Service};
use uuid::Uuid;

const REQUEST_ID_HEADER: &str = "x-request-id";

/// A new-type so handlers can extract the request ID from extensions.
#[derive(Clone, Debug)]
pub struct RequestId(pub String);

/// Tower Layer that injects a request ID.
#[derive(Clone, Default)]
pub struct RequestIdLayer;

impl RequestIdLayer {
    pub fn new() -> Self {
        Self
    }
}

impl<S> Layer<S> for RequestIdLayer {
    type Service = RequestIdService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RequestIdService { inner }
    }
}

/// Tower Service that generates / propagates a request ID.
#[derive(Clone)]
pub struct RequestIdService<S> {
    inner: S,
}

impl<S> Service<Request<Body>> for RequestIdService<S>
where
    S: Service<Request<Body>, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future =
        std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<Body>) -> Self::Future {
        // Reuse an existing header value or generate a new UUID v4.
        let id = req
            .headers()
            .get(REQUEST_ID_HEADER)
            .and_then(|v| v.to_str().ok())
            .map(String::from)
            .unwrap_or_else(|| Uuid::new_v4().to_string());

        // Make the ID available to downstream handlers via request extensions.
        req.extensions_mut().insert(RequestId(id.clone()));

        let mut inner = self.inner.clone();
        Box::pin(async move {
            let mut response = inner.call(req).await?;
            if let Ok(value) = HeaderValue::from_str(&id) {
                response.headers_mut().insert(REQUEST_ID_HEADER, value);
            }
            Ok(response)
        })
    }
}
