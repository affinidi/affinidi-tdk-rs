//! End-to-end TSP **WebSocket delivery** through the mediator.
//!
//! A client opts into raw-TSP WebSocket delivery by offering a `tsp`
//! subprotocol alongside `bearer.<jwt>` on the upgrade. In that mode the
//! socket carries raw TSP (`Message::Binary`) and uses a
//! *flush-on-connect + delete-on-successful-send* delivery contract — not
//! the DIDComm message-pickup delete-to-ack.
//!
//! This test drives a raw `tokio-tungstenite` client (so it controls the
//! `Sec-WebSocket-Protocol` header directly, like
//! `websocket_subprotocol_auth.rs`) against the embedded fixture and asserts:
//!
//! 1. Alice's queued TSP Direct message to Bob is flushed onto the socket as
//!    a `Binary` frame the instant Bob connects in TSP mode.
//! 2. The frame bytes are recognised as a TSP message and unpack to Alice's
//!    original payload + sender VID.
//! 3. The message is *deleted on send*: a subsequent fetch of Bob's mailbox
//!    is empty.
#![cfg(feature = "tsp")]

mod common;

use affinidi_messaging_sdk::messages::fetch::FetchOptions;
use affinidi_messaging_test_mediator::{TestEnvironment, TestUser};
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use common::init_tracing;
use futures_util::StreamExt;
use std::time::Duration;
use tokio::time::timeout;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{ClientRequestBuilder, Message, http::Uri},
};

/// Authenticate `user` against the environment's mediator and return a
/// fresh access token plus the mediator's `ws://…/ws` upgrade URI.
///
/// Mirrors `websocket_subprotocol_auth.rs`: we mint the token through the
/// SDK's auth task so the test doesn't reimplement the challenge/response
/// handshake.
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
async fn tsp_websocket_flushes_and_deletes_queued_message() {
    init_tracing();

    let env = TestEnvironment::spawn()
        .await
        .expect("spawn test environment");

    let alice = env.add_user("alice").await.expect("add alice");
    let bob = env.add_user("bob").await.expect("add bob");

    let payload = b"hello over the TSP websocket";

    // Alice sends a TSP Direct message to Bob; it is stored for Bob's mailbox
    // (no socket is open yet, so it sits in the inbox awaiting delivery).
    env.atm
        .tsp()
        .send(&alice.profile, &bob.did, payload)
        .await
        .expect("alice sends a TSP message to bob");

    // Bob authenticates and opens a raw WS in TSP mode: `["bearer.<jwt>",
    // "tsp"]`. The server echoes `tsp` (a genuine app subprotocol, never the
    // bearer entry), which both confirms the mode was accepted and lets
    // tokio-tungstenite's strict client complete the handshake.
    let (access_token, ws_uri) = token_and_ws_uri(&env, &bob).await;
    let request = ClientRequestBuilder::new(ws_uri)
        .with_sub_protocol(format!("bearer.{access_token}"))
        .with_sub_protocol("tsp");

    let (mut stream, response) = connect_async(request)
        .await
        .expect("tsp websocket upgrade must succeed");
    assert_eq!(
        response.status().as_u16(),
        101,
        "expected 101 Switching Protocols"
    );
    // The 101 echoes `tsp`, confirming the mode was accepted.
    let echoed = response
        .headers()
        .get("sec-websocket-protocol")
        .expect("server should echo the tsp subprotocol")
        .to_str()
        .expect("subprotocol is ASCII");
    assert_eq!(echoed, "tsp", "server must echo the tsp subprotocol");

    // Flush-on-connect: the queued TSP message arrives as a Binary frame.
    // (Skip any control frames like Ping the server may interleave.)
    let qb2 = loop {
        let frame = timeout(Duration::from_secs(5), stream.next())
            .await
            .expect("a frame arrives within the timeout")
            .expect("stream not closed")
            .expect("frame is not an error");
        match frame {
            Message::Binary(bytes) => break bytes.to_vec(),
            Message::Ping(_) | Message::Pong(_) => continue,
            other => panic!("expected a Binary TSP frame, got: {other:?}"),
        }
    };

    assert!(!qb2.is_empty(), "the flushed TSP frame must be non-empty");
    assert!(
        affinidi_tsp::is_tsp(&qb2),
        "the flushed frame must be recognised as a TSP message"
    );

    // The raw qb2 bytes re-encode to the stored base64url form, which Bob can
    // unpack to recover Alice's payload + sender VID.
    let stored = BASE64_URL_SAFE_NO_PAD.encode(&qb2);
    let (recovered, sender) = env
        .atm
        .tsp()
        .unpack(&bob.profile, &stored)
        .await
        .expect("bob unpacks the flushed TSP message");
    assert_eq!(recovered, payload, "payload round-trips over the websocket");
    assert_eq!(sender, alice.did, "sender VID is recovered");

    // Delete-on-send: the message was deleted after a successful send, so Bob's
    // mailbox is now empty.
    let fetched = env
        .atm
        .fetch_messages(&bob.profile, &FetchOptions::default())
        .await
        .expect("bob fetches messages");
    assert!(
        fetched.success.is_empty(),
        "the delivered TSP message must be deleted on send (inbox is empty), got {} message(s)",
        fetched.success.len()
    );

    drop(stream);
    env.shutdown().await.expect("shutdown");
}
