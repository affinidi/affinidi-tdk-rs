//! Limits on the `/did/v1/ws` endpoint: per-client rate limiting of request
//! messages (shared with HTTP), connection caps, the idle timeout and the
//! message size limit.
//!
//! Each test serves the application routes on an ephemeral port behind the
//! same rate-limit layer the server uses, and talks to them with a minimal
//! WebSocket client written over a TCP stream.

#![cfg(feature = "network")]

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use affinidi_did_resolver_cache_server::{
    SharedData, config::Config, handlers::application_routes, limits::WsLimits,
    statistics::Statistics,
};
use affinidi_rate_limit::{ClientIpExtractor, RateLimitLayer, RateLimiterState};
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Mutex, Semaphore},
    time::timeout,
};

const DID_KEY: &str = "did:key:z6MkiToqovww7vYtxm1xNM15u9JzqzUFZ1k7s7MazYJUyAxv";
const LOOPBACK: IpAddr = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
const WAIT: Duration = Duration::from_secs(10);

const OP_TEXT: u8 = 0x1;
const OP_CLOSE: u8 = 0x8;

fn limits(max: usize, per_client: usize, idle: Duration, max_message_size: usize) -> WsLimits {
    WsLimits::new(
        max,
        per_client,
        idle,
        Duration::from_secs(5),
        max_message_size,
    )
}

fn default_limits() -> WsLimits {
    limits(16, 16, Duration::from_secs(60), 4096)
}

/// Serve the application routes, wrapped in the rate-limit layer, with
/// `ws_limits` and `rate_limiter`. Returns the address and the shared state.
async fn serve(ws_limits: WsLimits, rate_limiter: RateLimiterState) -> (SocketAddr, SharedData) {
    let resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
        .await
        .unwrap();
    let state = SharedData {
        service_start_timestamp: chrono::Utc::now(),
        stats: Arc::new(Mutex::new(Statistics::default())),
        resolver,
        resolve_timeout: Duration::from_secs(5),
        max_did_size: 1024,
        webvh_client: reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap(),
        webvh_log_cache: None,
        agent_name_resolver: None,
        agent_name_permits: Arc::new(Semaphore::new(1)),
        rate_limiter: rate_limiter.clone(),
        client_ip_extractor: ClientIpExtractor::direct_peer(),
        ws_limits: Arc::new(ws_limits),
    };
    let app =
        application_routes(&state, &Config::default()).layer(RateLimitLayer::new(rate_limiter));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
    });
    (addr, state)
}

/// A WebSocket client connection, or the HTTP status of a refused upgrade.
struct Ws {
    stream: TcpStream,
}

/// Open a WebSocket to `/did/v1/ws`. `Err` carries the HTTP status when the
/// server does not switch protocols.
async fn connect(addr: SocketAddr) -> Result<Ws, u16> {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let request = format!(
        "GET /did/v1/ws HTTP/1.1\r\nHost: {addr}\r\nUpgrade: websocket\r\n\
         Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         Sec-WebSocket-Version: 13\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.unwrap();

    // Read the response head one byte at a time so no frame bytes are
    // consumed with it.
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        let mut byte = [0u8; 1];
        let n = timeout(WAIT, stream.read(&mut byte))
            .await
            .expect("response head in time")
            .unwrap();
        assert_ne!(n, 0, "connection closed before the response head");
        head.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&head);
    let status: u16 = head
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .expect("status code");
    if status == 101 {
        Ok(Ws { stream })
    } else {
        Err(status)
    }
}

impl Ws {
    /// Send one masked frame, as a client must. Write errors are ignored: the
    /// server may already have closed the connection.
    async fn send(&mut self, opcode: u8, payload: &[u8]) {
        let mut frame = vec![0x80 | opcode];
        let len = payload.len();
        if len < 126 {
            frame.push(0x80 | len as u8);
        } else if len <= usize::from(u16::MAX) {
            frame.push(0x80 | 126);
            frame.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            frame.push(0x80 | 127);
            frame.extend_from_slice(&(len as u64).to_be_bytes());
        }
        let mask = [0x12u8, 0x34, 0x56, 0x78];
        frame.extend_from_slice(&mask);
        frame.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
        let _ = self.stream.write_all(&frame).await;
    }

    async fn request(&mut self, did: &str) {
        let body = serde_json::json!({ "did": did }).to_string();
        self.send(OP_TEXT, body.as_bytes()).await;
    }

    /// The next frame as `(opcode, payload)`, or `None` once the connection
    /// is closed.
    async fn recv(&mut self) -> Option<(u8, Vec<u8>)> {
        let mut header = [0u8; 2];
        timeout(WAIT, self.stream.read_exact(&mut header))
            .await
            .expect("a frame or a close in time")
            .ok()?;
        let opcode = header[0] & 0x0f;
        let mut len = u64::from(header[1] & 0x7f);
        if len == 126 {
            let mut ext = [0u8; 2];
            self.stream.read_exact(&mut ext).await.ok()?;
            len = u64::from(u16::from_be_bytes(ext));
        } else if len == 127 {
            let mut ext = [0u8; 8];
            self.stream.read_exact(&mut ext).await.ok()?;
            len = u64::from_be_bytes(ext);
        }
        let mut payload = vec![0u8; usize::try_from(len).unwrap()];
        self.stream.read_exact(&mut payload).await.ok()?;
        Some((opcode, payload))
    }

    /// The next text frame's payload.
    async fn text(&mut self) -> String {
        match self.recv().await {
            Some((OP_TEXT, payload)) => String::from_utf8(payload).unwrap(),
            other => panic!("expected a text frame, got {other:?}"),
        }
    }

    /// Read until the server closes: a close frame or the end of the stream.
    /// Panics on a data frame. Returns the close code, if one was sent.
    async fn expect_closed(&mut self) -> Option<u16> {
        loop {
            match self.recv().await {
                None => return None,
                Some((OP_CLOSE, payload)) => {
                    return payload
                        .get(..2)
                        .map(|code| u16::from_be_bytes([code[0], code[1]]));
                }
                Some((OP_TEXT, payload)) => {
                    panic!(
                        "expected the connection to close, got {}",
                        String::from_utf8_lossy(&payload)
                    )
                }
                // Pings and pongs are not what is being tested.
                Some(_) => continue,
            }
        }
    }
}

/// Wait until `client` has `expected` connections open on the server.
async fn wait_for_open(state: &SharedData, client: IpAddr, expected: usize) {
    timeout(WAIT, async {
        while state.ws_limits.open_connections_from(client) != expected {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "expected {expected} open connection(s), have {}",
            state.ws_limits.open_connections_from(client)
        )
    });
}

/// Each request message on a WebSocket is charged to the client's bucket, the
/// same bucket its HTTP requests use. Over the limit a request is answered
/// with an error and the connection stays open.
#[tokio::test]
async fn websocket_requests_share_the_http_rate_limit() {
    // Three requests, then none for an hour.
    let limiter = RateLimiterState::per_period(Duration::from_secs(3600), 3);
    let (addr, _state) = serve(default_limits(), limiter).await;

    // The upgrade request is the first of the three.
    let mut ws = connect(addr).await.expect("upgrade within the limit");

    ws.request(DID_KEY).await;
    let first = ws.text().await;
    assert!(first.starts_with("{\"Response\""), "got {first}");
    ws.request(DID_KEY).await;
    let second = ws.text().await;
    assert!(second.starts_with("{\"Response\""), "got {second}");

    ws.request(DID_KEY).await;
    let refused = ws.text().await;
    assert!(refused.starts_with("{\"Error\""), "got {refused}");
    assert!(refused.contains("Too many requests"), "got {refused}");
    assert!(
        refused.contains(DID_KEY),
        "the error names the request: {refused}"
    );

    // The connection is still usable: another request gets another answer.
    ws.request(DID_KEY).await;
    assert!(ws.text().await.contains("Too many requests"));

    // HTTP from the same client is refused too: one bucket.
    let status = reqwest::Client::new()
        .get(format!("http://{addr}/did/v1/resolve/{DID_KEY}"))
        .timeout(WAIT)
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(status, reqwest::StatusCode::TOO_MANY_REQUESTS);
}

/// With rate limiting disabled, requests on a WebSocket are not refused.
#[tokio::test]
async fn websocket_requests_are_not_refused_with_limiting_disabled() {
    let (addr, _state) = serve(default_limits(), RateLimiterState::new(0, 0)).await;
    let mut ws = connect(addr).await.unwrap();
    for _ in 0..20 {
        ws.request(DID_KEY).await;
        let answer = ws.text().await;
        assert!(answer.starts_with("{\"Response\""), "got {answer}");
    }
}

#[tokio::test]
async fn connections_per_client_are_capped() {
    let (addr, state) = serve(
        limits(16, 2, Duration::from_secs(60), 4096),
        RateLimiterState::new(0, 0),
    )
    .await;

    let first = connect(addr).await.unwrap();
    let _second = connect(addr).await.unwrap();
    assert_eq!(connect(addr).await.err(), Some(429));
    wait_for_open(&state, LOOPBACK, 2).await;

    // Closing one frees its place.
    drop(first);
    wait_for_open(&state, LOOPBACK, 1).await;
    let _third = connect(addr).await.expect("a freed place is reusable");
}

#[tokio::test]
async fn connections_in_all_are_capped() {
    let (addr, state) = serve(
        limits(1, 16, Duration::from_secs(60), 4096),
        RateLimiterState::new(0, 0),
    )
    .await;

    let first = connect(addr).await.unwrap();
    assert_eq!(connect(addr).await.err(), Some(503));

    drop(first);
    wait_for_open(&state, LOOPBACK, 0).await;
    assert_eq!(state.ws_limits.open_connections(), 0);
    let _second = connect(addr).await.expect("a freed place is reusable");
}

/// A connection that receives nothing for the idle timeout is closed, and
/// stops counting against the limits.
#[tokio::test]
async fn an_idle_connection_is_closed() {
    let (addr, state) = serve(
        limits(16, 16, Duration::from_secs(1), 4096),
        RateLimiterState::new(0, 0),
    )
    .await;

    let mut ws = connect(addr).await.unwrap();
    let code = ws.expect_closed().await;
    assert!(
        code.is_none() || code == Some(1001),
        "unexpected close code {code:?}"
    );
    wait_for_open(&state, LOOPBACK, 0).await;
}

/// Activity keeps a connection open past the idle timeout.
#[tokio::test]
async fn an_active_connection_stays_open() {
    let (addr, _state) = serve(
        limits(16, 16, Duration::from_secs(1), 4096),
        RateLimiterState::new(0, 0),
    )
    .await;

    let mut ws = connect(addr).await.unwrap();
    for _ in 0..4 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        ws.request(DID_KEY).await;
        let answer = ws.text().await;
        assert!(answer.starts_with("{\"Response\""), "got {answer}");
    }
}

/// A message over the size limit closes the connection unanswered.
#[tokio::test]
async fn an_oversized_message_closes_the_connection() {
    let (addr, state) = serve(
        limits(16, 16, Duration::from_secs(60), 512),
        RateLimiterState::new(0, 0),
    )
    .await;

    let mut ws = connect(addr).await.unwrap();
    // Within the limit: answered.
    ws.request(DID_KEY).await;
    assert!(ws.text().await.starts_with("{\"Response\""));

    let oversized = format!("did:key:{}", "z".repeat(1024));
    ws.request(&oversized).await;
    ws.expect_closed().await;
    wait_for_open(&state, LOOPBACK, 0).await;
}
