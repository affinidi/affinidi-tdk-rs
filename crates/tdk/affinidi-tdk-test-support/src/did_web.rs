//! An in-process HTTP server that stands in for a `did:web` / `did:webvh`
//! origin, with fault injection.
//!
//! [`MockDidWebServer`] serves DID documents (`did.json`) and `did:webvh` logs
//! (`did.jsonl` + witness) from an ephemeral `127.0.0.1` port so tests can
//! exercise the real HTTP fetch path — including the failure modes that matter
//! for hardening the resolver edge: slow responses, hangs, error statuses,
//! malformed bodies, and oversized bodies. Every request is counted so a test
//! can assert how many fetches actually hit the origin.
//!
//! # Addressing
//!
//! The listener binds `127.0.0.1`; [`MockDidWebServer::base_url`] returns the
//! `http://127.0.0.1:<port>` form used directly by HTTP clients in tests.
//!
//! `did:webvh` is the one method whose resolver emits `http://` (only) for the
//! host `localhost`, so [`MockDidWebServer::webvh_authority`] returns
//! `localhost%3A<port>` for minting `did:webvh:…:localhost%3A<port>:…` DIDs.
//! That path relies on `localhost` resolving to the loopback the server is
//! bound on (the standard configuration).
//!
//! ```
//! use affinidi_tdk_test_support::did_web::{Fault, MockDidWebServer};
//!
//! // The server is async; drive it from a runtime (your test would be
//! // `#[tokio::test]`).
//! tokio::runtime::Runtime::new().unwrap().block_on(async {
//!     let server = MockDidWebServer::start().await;
//!     server.register(
//!         "/.well-known/did.json",
//!         200,
//!         "application/did+ld+json",
//!         r#"{"id":"did:web:localhost"}"#,
//!     );
//!
//!     // A resolver would now fetch `<base_url>/.well-known/did.json`.
//!     assert!(server.base_url().starts_with("http://127.0.0.1:"));
//!     assert_eq!(server.hits("/.well-known/did.json"), 0, "no fetch yet");
//!
//!     // Inject a fault to exercise the resolver's hardening (timeouts,
//!     // status handling, …); every later response carries it until cleared.
//!     server.set_fault(Fault::Status(503));
//!     server.clear_fault();
//! });
//! ```

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use affinidi_did_common::Document;
use axum::{
    Router,
    extract::{Request, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

/// A fault applied to every response until cleared.
///
/// `#[non_exhaustive]`: new fault kinds may be added in a minor release, so
/// match arms over `Fault` must include a `_` wildcard.
#[derive(Clone, Default)]
#[non_exhaustive]
pub enum Fault {
    /// Serve registered responses normally.
    #[default]
    None,
    /// Sleep this long before serving (still serves the registered response).
    Delay(Duration),
    /// Accept the request but never respond — drives client read timeouts.
    Hang,
    /// Replace every response with this status code and an empty body.
    Status(u16),
    /// Serve a 200 with a body that is not valid JSON.
    Garbage,
    /// Serve a 200 with a body of this many bytes — drives size-limit guards.
    Oversize(usize),
}

#[derive(Clone)]
struct Canned {
    status: u16,
    content_type: String,
    body: String,
}

#[derive(Default)]
struct Inner {
    routes: RwLock<HashMap<String, Canned>>,
    fault: RwLock<Fault>,
    hits: RwLock<HashMap<String, usize>>,
}

#[derive(Clone, Default)]
struct MockState {
    inner: Arc<Inner>,
}

/// Aborts the server task when the [`MockDidWebServer`] is dropped, so tests
/// don't leak listeners.
struct AbortOnDrop(JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// In-process did:web / did:webvh origin. See the module docs.
pub struct MockDidWebServer {
    addr: SocketAddr,
    state: MockState,
    _task: AbortOnDrop,
}

impl MockDidWebServer {
    /// Bind an ephemeral `127.0.0.1` port and start serving.
    pub async fn start() -> Self {
        let state = MockState::default();
        let app = Router::new().fallback(handle).with_state(state.clone());
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind mock did:web server");
        let addr = listener.local_addr().expect("mock server local_addr");
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Self {
            addr,
            state,
            _task: AbortOnDrop(task),
        }
    }

    /// The bound address (`127.0.0.1:<port>`).
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The bound port.
    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    /// Base URL for direct HTTP clients, e.g. `http://127.0.0.1:54321`.
    pub fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// `localhost%3A<port>` — the authority to embed in a `did:webvh` DID so
    /// its resolver fetches the log over `http://localhost:<port>/…`.
    pub fn webvh_authority(&self) -> String {
        format!("localhost%3A{}", self.addr.port())
    }

    /// Register a raw response at an exact request path (e.g.
    /// `/.well-known/did.json`).
    pub fn register(
        &self,
        path: impl Into<String>,
        status: u16,
        content_type: impl Into<String>,
        body: impl Into<String>,
    ) {
        self.state.inner.routes.write().unwrap().insert(
            path.into(),
            Canned {
                status,
                content_type: content_type.into(),
                body: body.into(),
            },
        );
    }

    /// Register a DID document at the `did:web` location for `segments`
    /// (empty ⇒ `/.well-known/did.json`, else `/seg1/seg2/did.json`).
    pub fn register_did_document(&self, segments: &[&str], document: &Document) {
        let body = serde_json::to_string(document).expect("serialize DID document");
        self.register(
            doc_path(segments, "did.json"),
            200,
            "application/did+ld+json",
            body,
        );
    }

    /// Register a `did:webvh` JSONL log at the location for `segments`
    /// (empty ⇒ `/.well-known/did.jsonl`, else `/seg1/seg2/did.jsonl`).
    pub fn register_webvh_log(&self, segments: &[&str], jsonl: impl Into<String>) {
        self.register(
            doc_path(segments, "did.jsonl"),
            200,
            "application/jsonl",
            jsonl,
        );
    }

    /// Apply a fault to every subsequent response.
    pub fn set_fault(&self, fault: Fault) {
        *self.state.inner.fault.write().unwrap() = fault;
    }

    /// Clear any active fault.
    pub fn clear_fault(&self) {
        self.set_fault(Fault::None);
    }

    /// How many requests have hit an exact path.
    pub fn hits(&self, path: &str) -> usize {
        self.state
            .inner
            .hits
            .read()
            .unwrap()
            .get(path)
            .copied()
            .unwrap_or(0)
    }

    /// Total requests across all paths.
    pub fn total_hits(&self) -> usize {
        self.state.inner.hits.read().unwrap().values().sum()
    }
}

/// Build the document path for a did:web/webvh location.
fn doc_path(segments: &[&str], file: &str) -> String {
    if segments.is_empty() {
        format!("/.well-known/{file}")
    } else {
        format!("/{}/{file}", segments.join("/"))
    }
}

async fn handle(State(state): State<MockState>, req: Request) -> Response {
    let path = req.uri().path().to_string();
    *state
        .inner
        .hits
        .write()
        .unwrap()
        .entry(path.clone())
        .or_insert(0) += 1;

    let fault = state.inner.fault.read().unwrap().clone();
    match fault {
        Fault::Hang => {
            // Hold the connection open without ever responding.
            std::future::pending::<()>().await;
            unreachable!("pending() never resolves")
        }
        Fault::Delay(d) => tokio::time::sleep(d).await,
        Fault::Status(code) => {
            let status = StatusCode::from_u16(code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            return (status, "").into_response();
        }
        Fault::Garbage => {
            return (
                [(header::CONTENT_TYPE, "application/json")],
                "}{ not valid json",
            )
                .into_response();
        }
        Fault::Oversize(n) => {
            return ([(header::CONTENT_TYPE, "application/json")], "x".repeat(n)).into_response();
        }
        Fault::None => {}
    }

    match state.inner.routes.read().unwrap().get(&path) {
        Some(canned) => {
            let status =
                StatusCode::from_u16(canned.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (
                status,
                [(header::CONTENT_TYPE, canned.content_type.clone())],
                canned.body.clone(),
            )
                .into_response()
        }
        None => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn serves_registered_did_document() {
        let server = MockDidWebServer::start().await;
        let did = "did:web:example.com";
        server.register_did_document(&[], &Document::new(did).unwrap());

        let url = format!("{}/.well-known/did.json", server.base_url());
        let resp = reqwest::get(&url).await.unwrap();
        assert!(resp.status().is_success());
        let doc: Document = resp.json().await.unwrap();
        assert_eq!(doc.id.as_str(), did);
        assert_eq!(server.hits("/.well-known/did.json"), 1);
    }

    #[tokio::test]
    async fn serves_path_scoped_document() {
        let server = MockDidWebServer::start().await;
        let did = "did:web:example.com:user:alice";
        server.register_did_document(&["user", "alice"], &Document::new(did).unwrap());

        let url = format!("{}/user/alice/did.json", server.base_url());
        let resp = reqwest::get(&url).await.unwrap();
        assert!(resp.status().is_success());
    }

    #[tokio::test]
    async fn unregistered_path_is_404() {
        let server = MockDidWebServer::start().await;
        let resp = reqwest::get(format!("{}/.well-known/did.json", server.base_url()))
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 404);
    }

    #[tokio::test]
    async fn status_fault_overrides_response() {
        let server = MockDidWebServer::start().await;
        server.register_did_document(&[], &Document::new("did:web:example.com").unwrap());
        server.set_fault(Fault::Status(503));

        let resp = reqwest::get(format!("{}/.well-known/did.json", server.base_url()))
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 503);

        server.clear_fault();
        let resp = reqwest::get(format!("{}/.well-known/did.json", server.base_url()))
            .await
            .unwrap();
        assert!(resp.status().is_success());
    }

    #[tokio::test]
    async fn garbage_fault_serves_invalid_json() {
        let server = MockDidWebServer::start().await;
        server.register_did_document(&[], &Document::new("did:web:example.com").unwrap());
        server.set_fault(Fault::Garbage);

        let resp = reqwest::get(format!("{}/.well-known/did.json", server.base_url()))
            .await
            .unwrap();
        assert!(resp.status().is_success());
        let body = resp.text().await.unwrap();
        assert!(serde_json::from_str::<Document>(&body).is_err());
    }

    #[tokio::test]
    async fn oversize_fault_serves_large_body() {
        let server = MockDidWebServer::start().await;
        server.set_fault(Fault::Oversize(2048));
        let resp = reqwest::get(format!("{}/.well-known/did.json", server.base_url()))
            .await
            .unwrap();
        assert_eq!(resp.text().await.unwrap().len(), 2048);
    }

    #[tokio::test]
    async fn hang_fault_never_responds() {
        let server = MockDidWebServer::start().await;
        server.set_fault(Fault::Hang);
        let client = reqwest::Client::new();
        let res = client
            .get(format!("{}/.well-known/did.json", server.base_url()))
            .timeout(Duration::from_millis(300))
            .send()
            .await;
        assert!(
            res.is_err(),
            "client should time out against a hanging server"
        );
    }

    #[tokio::test]
    async fn counts_hits_per_path() {
        let server = MockDidWebServer::start().await;
        server.register_did_document(&[], &Document::new("did:web:example.com").unwrap());
        for _ in 0..2 {
            let _ = reqwest::get(format!("{}/.well-known/did.json", server.base_url())).await;
        }
        let _ = reqwest::get(format!("{}/other", server.base_url())).await;
        assert_eq!(server.hits("/.well-known/did.json"), 2);
        assert_eq!(server.total_hits(), 3);
    }
}
