//! Browser-friendly WebSocket authentication.
//!
//! Browsers cannot set an `Authorization` header on `new WebSocket(url,
//! protocols)`, so the mediator also accepts the JWT through the
//! `Sec-WebSocket-Protocol` request header as a `bearer.<jwt>` entry.
//! These tests drive raw clients (not the SDK, so we control the
//! upgrade headers directly) against the embedded fixture and assert:
//!
//! 1. A `bearer.<jwt>` subprotocol authenticates and upgrades (101).
//! 2. The 101 response never echoes the `bearer.<jwt>` value — echoing
//!    it back would leak the token in the response header.
//! 3. The existing `Authorization: Bearer` header path still upgrades —
//!    regression guard for native clients (the SDK uses this path).
//! 4. An invalid token in the subprotocol is rejected (401), exactly
//!    like an invalid header token.
//!
//! Test 1 offers a benign application subprotocol alongside the bearer
//! entry (`["affinidi.didcomm.v1", "bearer.<jwt>"]`) so the server has
//! something safe to echo — this both confirms the negotiation and
//! lets `tokio-tungstenite`'s strict client (which errors if it offered
//! a subprotocol the server didn't select) complete the handshake.
//!
//! Test 2 exercises the *exact* documented browser call — a single
//! `bearer.<jwt>` entry with nothing to echo — over a hand-rolled
//! socket, because `tokio-tungstenite`'s client refuses a handshake
//! where the server selects no subprotocol (real browsers accept it).

mod common;

use affinidi_messaging_test_mediator::{TestEnvironment, TestUser};
use common::{init_tracing, skip_if_no_redis};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{ClientRequestBuilder, Error as WsError, http::Uri},
};

/// A genuine application subprotocol offered alongside the bearer entry.
/// The server echoes this (never the bearer entry) in the 101 response.
const APP_SUBPROTOCOL: &str = "affinidi.didcomm.v1";

/// Authenticate `user` against the environment's mediator and return a
/// fresh access token plus the mediator's `ws://…/ws` upgrade URI.
///
/// This is the same token a browser would obtain from the REST
/// `/authenticate` flow; here we mint it through the SDK's auth task so
/// the test doesn't reimplement the challenge/response handshake.
async fn token_and_ws_uri(env: &TestEnvironment, user: &TestUser) -> (String, Uri) {
    let mediator_did = env.mediator.did().to_string();
    let tokens = env
        .tdk
        .authentication()
        .authenticate(user.did.clone(), mediator_did, 3, None)
        .await
        .expect("authenticate user");

    let ws_uri: Uri = env
        .mediator
        .ws_endpoint()
        .as_str()
        .parse()
        .expect("parse ws endpoint");

    (tokens.access_token, ws_uri)
}

#[tokio::test]
async fn bearer_subprotocol_authenticates_and_does_not_echo_token() {
    init_tracing();
    if skip_if_no_redis() {
        return;
    }

    let env = TestEnvironment::spawn().await.expect("spawn environment");
    let alice = env.add_user("Alice").await.expect("add user");
    let (access_token, ws_uri) = token_and_ws_uri(&env, &alice).await;

    // Browser-shaped offer: a benign app subprotocol plus the
    // `bearer.<jwt>` entry, and no Authorization header.
    let request = ClientRequestBuilder::new(ws_uri)
        .with_sub_protocol(APP_SUBPROTOCOL)
        .with_sub_protocol(format!("bearer.{access_token}"));

    let (stream, response) = connect_async(request)
        .await
        .expect("bearer subprotocol upgrade must succeed");

    assert_eq!(
        response.status().as_u16(),
        101,
        "expected 101 Switching Protocols"
    );

    // The server must echo the benign app subprotocol — and crucially
    // NOT the bearer entry, which would leak the token.
    let echoed = response
        .headers()
        .get("sec-websocket-protocol")
        .expect("server should echo the app subprotocol")
        .to_str()
        .expect("subprotocol is ASCII");
    assert_eq!(
        echoed, APP_SUBPROTOCOL,
        "must echo the benign app subprotocol"
    );
    assert!(
        !echoed.contains("bearer."),
        "the 101 response must never contain the bearer token"
    );

    // Dropping the stream tears down the connection.
    drop(stream);

    env.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn bearer_only_subprotocol_upgrades_without_echoing_anything() {
    // The exact documented browser call: `new WebSocket(url, ["bearer."
    // + token])` — a single bearer entry, nothing else to negotiate.
    // The server authenticates from it and selects no subprotocol, so
    // the 101 carries no `Sec-WebSocket-Protocol` header. Browsers
    // accept this; tokio-tungstenite's client doesn't, so we hand-roll
    // the handshake and inspect the raw response.
    init_tracing();
    if skip_if_no_redis() {
        return;
    }

    let env = TestEnvironment::spawn().await.expect("spawn environment");
    let dave = env.add_user("Dave").await.expect("add user");
    let (access_token, ws_uri) = token_and_ws_uri(&env, &dave).await;

    let (status, headers) = raw_ws_handshake(
        &ws_uri,
        &format!("Sec-WebSocket-Protocol: bearer.{access_token}\r\n"),
    )
    .await;

    assert_eq!(status, 101, "bearer-only upgrade must switch protocols");
    assert!(
        !headers.lines().any(|l| l
            .to_ascii_lowercase()
            .starts_with("sec-websocket-protocol:")),
        "bearer-only upgrade must not echo any Sec-WebSocket-Protocol header (would leak the token)"
    );

    env.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn browser_origin_rejected_when_no_cors_configured() {
    // Defence-in-depth Origin check. The fixture leaves
    // `cors_allow_origin` unset (policy = None), so a browser-style
    // upgrade that announces an `Origin` must be refused with 403 —
    // even carrying an otherwise-valid token, because the Origin check
    // runs before auth. Header-less native clients are unaffected (the
    // other tests, which send no Origin, all still upgrade).
    init_tracing();
    if skip_if_no_redis() {
        return;
    }

    let env = TestEnvironment::spawn().await.expect("spawn environment");
    let erin = env.add_user("Erin").await.expect("add user");
    let (access_token, ws_uri) = token_and_ws_uri(&env, &erin).await;

    let (status, _) = raw_ws_handshake(
        &ws_uri,
        &format!(
            "Origin: https://evil.example\r\n\
             Sec-WebSocket-Protocol: bearer.{access_token}\r\n"
        ),
    )
    .await;

    assert_eq!(
        status, 403,
        "a browser Origin must be rejected when no CORS origins are configured"
    );

    env.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn authorization_header_upgrade_still_works() {
    // Regression guard: native clients authenticate the upgrade with an
    // `Authorization: Bearer` header. This path must keep working with
    // zero changes now that the subprotocol path exists.
    init_tracing();
    if skip_if_no_redis() {
        return;
    }

    let env = TestEnvironment::spawn().await.expect("spawn environment");
    let bob = env.add_user("Bob").await.expect("add user");
    let (access_token, ws_uri) = token_and_ws_uri(&env, &bob).await;

    let request = ClientRequestBuilder::new(ws_uri)
        .with_header("Authorization", format!("Bearer {access_token}"));

    let (stream, response) = connect_async(request)
        .await
        .expect("authorization header upgrade must succeed");

    assert_eq!(
        response.status().as_u16(),
        101,
        "header path must still upgrade"
    );

    drop(stream);

    env.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn invalid_bearer_subprotocol_token_is_rejected() {
    // A malformed/forged token in the subprotocol must be rejected with
    // 401, identical to an invalid header token — the subprotocol path
    // does not weaken validation.
    init_tracing();
    if skip_if_no_redis() {
        return;
    }

    let env = TestEnvironment::spawn().await.expect("spawn environment");
    // A user must exist + be LOCAL so that the *only* reason the upgrade
    // fails is the bad token, not the ACL check.
    let _carol = env.add_user("Carol").await.expect("add user");
    let ws_uri: Uri = env
        .mediator
        .ws_endpoint()
        .as_str()
        .parse()
        .expect("parse ws endpoint");

    let request =
        ClientRequestBuilder::new(ws_uri).with_sub_protocol("bearer.not.a.valid.jwt".to_string());

    let err = connect_async(request)
        .await
        .expect_err("invalid subprotocol token must be rejected");

    match err {
        WsError::Http(resp) => assert_eq!(
            resp.status().as_u16(),
            401,
            "invalid subprotocol token must yield 401"
        ),
        other => panic!("expected HTTP 401 rejection, got: {other:?}"),
    }

    env.shutdown().await.expect("shutdown");
}

/// Perform a minimal HTTP/1.1 WebSocket upgrade handshake by hand and
/// return `(status_code, raw_response_headers)`. `extra_header_lines`
/// is inserted verbatim (each line CRLF-terminated) before the blank
/// line — used here to inject `Sec-WebSocket-Protocol`.
///
/// We don't validate `Sec-WebSocket-Accept`; the test only cares about
/// the status line and which response headers the server emitted.
async fn raw_ws_handshake(uri: &Uri, extra_header_lines: &str) -> (u16, String) {
    let host = uri.host().expect("ws uri has host");
    let port = uri.port_u16().expect("ws uri has port");
    let path = uri.path();

    let mut stream = TcpStream::connect((host, port))
        .await
        .expect("connect to mediator");

    let request = format!(
        "GET {path} HTTP/1.1\r\n\
         Host: {host}:{port}\r\n\
         Connection: Upgrade\r\n\
         Upgrade: websocket\r\n\
         Sec-WebSocket-Version: 13\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         {extra_header_lines}\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write handshake");

    // Read until the end of the response header block.
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let n = stream.read(&mut chunk).await.expect("read response");
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }

    let text = String::from_utf8_lossy(&buf).into_owned();
    let status = text
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .expect("parse status line");

    (status, text)
}
