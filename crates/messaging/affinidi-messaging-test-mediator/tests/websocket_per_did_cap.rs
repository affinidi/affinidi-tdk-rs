//! Per-DID WebSocket connection cap (mediator T13a).
//!
//! `limits.max_websocket_connections_per_did` bounds how many concurrent
//! WebSocket connections a single DID may hold, so one DID can't exhaust the
//! global `max_websocket_connections` budget. The cap is enforced inside
//! `handle_socket` — i.e. *after* the HTTP→WS upgrade returns `101` — so a
//! rejected connection completes the handshake and then immediately receives
//! a server `Close` frame.

mod common;

use std::time::Duration;

use affinidi_messaging_test_mediator::{TestEnvironment, TestMediator, TestUser};
use common::init_tracing;
use futures_util::StreamExt;
use tokio::time::timeout;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{ClientRequestBuilder, Message, http::Uri},
};

/// Authenticate `user` against the mediator and return a fresh access token
/// plus the `ws://…/ws` upgrade URI (the same shape a browser would use).
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

/// Open a WebSocket for `user` via the `bearer.<jwt>` subprotocol (each call
/// mints a fresh session token but the same DID, so both count against that
/// DID's cap).
async fn open_ws(
    env: &TestEnvironment,
    user: &TestUser,
) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>> {
    let (access_token, ws_uri) = token_and_ws_uri(env, user).await;
    // Offer a benign app subprotocol alongside the bearer entry so the server
    // selects (echoes) it — tokio-tungstenite's strict client refuses a
    // handshake where the server selects no subprotocol at all.
    let request = ClientRequestBuilder::new(ws_uri)
        .with_sub_protocol("affinidi.test")
        .with_sub_protocol(format!("bearer.{access_token}"));
    let (stream, response) = connect_async(request)
        .await
        .expect("bearer subprotocol upgrade must reach 101");
    assert_eq!(response.status().as_u16(), 101, "expected 101 upgrade");
    stream
}

#[tokio::test]
async fn second_connection_for_one_did_over_the_cap_is_closed() {
    init_tracing();

    // Cap a single DID at one concurrent WebSocket connection.
    let mediator = TestMediator::builder()
        .max_websocket_connections_per_did(1)
        .spawn()
        .await
        .expect("spawn mediator with per-DID WS cap = 1");
    let env = TestEnvironment::new(mediator)
        .await
        .expect("wire SDK environment");
    let alice = env.add_user("Alice").await.expect("add user");

    // First connection consumes Alice's single slot. Hold it open and give
    // `handle_socket` a moment to reserve the per-DID slot (the cap check runs
    // after the 101 upgrade the client already observed).
    let mut conn1 = open_ws(&env, &alice).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Second connection for the SAME DID is over the cap: it completes the
    // handshake but must then be closed by the server.
    let mut conn2 = open_ws(&env, &alice).await;

    let frame = timeout(Duration::from_secs(5), conn2.next())
        .await
        .expect("the over-cap connection should be closed promptly, not hang");
    match frame {
        Some(Ok(Message::Close(_))) | None => { /* rejected as expected */ }
        other => panic!("expected a Close frame on the over-cap connection, got: {other:?}"),
    }

    // The first connection keeps its slot — closing conn2 frees nothing it
    // was using, so conn1 remains usable. A fresh read should not surface a
    // Close within a short window (it may see a keepalive ping, which is
    // fine — anything other than Close/None means still-open).
    if let Ok(Some(Ok(msg))) = timeout(Duration::from_secs(1), conn1.next()).await {
        assert!(
            !matches!(msg, Message::Close(_)),
            "the first (in-cap) connection must stay open, not be closed"
        );
    }

    drop(conn1);
    env.shutdown().await.expect("shutdown");
}
