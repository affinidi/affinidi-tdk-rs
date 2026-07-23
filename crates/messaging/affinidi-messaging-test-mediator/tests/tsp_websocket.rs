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

/// The same flush-on-connect + delete-on-send contract, but driven through the
/// SDK's ergonomic `atm.tsp().connect_websocket()` consumer instead of a raw
/// tungstenite client. This covers the public SDK API surface (the test above
/// covers the wire contract directly).
#[tokio::test]
async fn tsp_websocket_sdk_consumer_flushes_and_deletes() {
    init_tracing();

    let env = TestEnvironment::spawn()
        .await
        .expect("spawn test environment");

    let alice = env.add_user("alice").await.expect("add alice");
    let bob = env.add_user("bob").await.expect("add bob");

    let payload = b"hello over the SDK TSP websocket";

    // Alice queues a TSP Direct message to Bob (no socket open yet).
    env.atm
        .tsp()
        .send(&alice.profile, &bob.did, payload)
        .await
        .expect("alice sends a TSP message to bob");

    // Bob opens the raw-TSP websocket via the SDK consumer.
    let mut ws = env
        .atm
        .tsp()
        .connect_websocket(&bob.profile)
        .await
        .expect("bob opens the TSP websocket");

    // Flush-on-connect: the queued message arrives as the next frame.
    let qb2 = timeout(Duration::from_secs(5), ws.recv())
        .await
        .expect("a frame arrives within the timeout")
        .expect("recv succeeds")
        .expect("a flushed frame");

    // Unpack the raw qb2 directly (no re-encode to base64url needed).
    let (recovered, sender) = env
        .atm
        .tsp()
        .unpack_bytes(&bob.profile, &qb2)
        .await
        .expect("bob unpacks the flushed TSP message");
    assert_eq!(recovered, payload, "payload round-trips over the websocket");
    assert_eq!(sender, alice.did, "sender VID is recovered");

    // Delete-on-send: Bob's mailbox is empty after the flush.
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

    ws.close().await.ok();
    env.shutdown().await.expect("shutdown");
}

/// **Live delivery**: a message sent while the raw-TSP socket is already open
/// must be pushed onto it, not left in the inbox.
///
/// Every test above queues the message *before* Bob connects, so they all pass
/// on flush-on-connect alone — which is exactly how this shipped broken. A
/// raw-TSP socket registered with the streaming task but never reached
/// `StreamingClientState::Live` (only the DIDComm `live-delivery-change`
/// message promotes a client, and a raw-TSP socket cannot send one), so
/// `store_message` skipped the streaming publish and the socket's re-drain
/// never fired. Delivery worked exactly once, at connect time, and every
/// message after that was stored and forgotten: senders saw success, receivers
/// heard nothing, and the whole transport looked intermittent because the
/// outcome depended on whether the frame beat the socket.
#[tokio::test]
async fn tsp_websocket_delivers_messages_that_arrive_after_connect() {
    init_tracing();

    let env = TestEnvironment::spawn()
        .await
        .expect("spawn test environment");

    let alice = env.add_user("alice").await.expect("add alice");
    let bob = env.add_user("bob").await.expect("add bob");

    // Bob connects FIRST, with an empty inbox — so nothing here can be
    // satisfied by the flush-on-connect drain.
    let mut ws = env
        .atm
        .tsp()
        .connect_websocket(&bob.profile)
        .await
        .expect("bob opens the TSP websocket");

    // Several messages, to catch a fix that only pushes the first one.
    for round in 0..3u8 {
        let payload = format!("live TSP frame {round}").into_bytes();
        env.atm
            .tsp()
            .send(&alice.profile, &bob.did, &payload)
            .await
            .unwrap_or_else(|e| panic!("alice sends live TSP message {round}: {e}"));

        let qb2 = timeout(Duration::from_secs(5), ws.recv())
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "TSP frame {round} was sent successfully but never delivered — the socket is \
                     open and the mediator is holding the message"
                )
            })
            .expect("recv succeeds")
            .expect("a pushed frame");

        let (recovered, sender) = env
            .atm
            .tsp()
            .unpack_bytes(&bob.profile, &qb2)
            .await
            .expect("bob unpacks the pushed TSP message");
        assert_eq!(recovered, payload, "payload round-trips (frame {round})");
        assert_eq!(sender, alice.did, "sender VID is recovered (frame {round})");
    }

    // Delete-on-send holds for pushed frames too.
    let fetched = env
        .atm
        .fetch_messages(&bob.profile, &FetchOptions::default())
        .await
        .expect("bob fetches messages");
    assert!(
        fetched.success.is_empty(),
        "pushed TSP messages must be deleted on send, got {} left in the inbox",
        fetched.success.len()
    );

    ws.close().await.ok();
    env.shutdown().await.expect("shutdown");
}
