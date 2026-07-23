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

/// Poll Bob's mailbox until it is empty, or give up. Deletion is queued on the
/// SDK's background handler, so the ack is not synchronous with the delete.
async fn wait_for_empty_inbox(env: &TestEnvironment, user: &TestUser) -> bool {
    for _ in 0..40 {
        let fetched = env
            .atm
            .fetch_messages(&user.profile, &FetchOptions::default())
            .await
            .expect("fetch messages");
        if fetched.success.is_empty() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

/// **`tsp-ack`: send and keep.** The mediator must NOT delete the message when
/// it writes it to the socket — only when the client acknowledges.
///
/// Plain `tsp` deletes on send, which is at-most-once past the write: a
/// successful write means the frame reached the local sink, so a connection
/// that dies before the peer reads it loses the message with nothing left to
/// redeliver. That is fine for a liveness probe and wrong for anything that
/// matters, so `tsp-ack` moves the delete to the ack.
#[tokio::test]
async fn tsp_ack_mode_keeps_the_message_until_the_client_acks() {
    init_tracing();

    let env = TestEnvironment::spawn()
        .await
        .expect("spawn test environment");

    let alice = env.add_user("alice").await.expect("add alice");
    let bob = env.add_user("bob").await.expect("add bob");

    let payload = b"a TSP message that must survive until acked";
    env.atm
        .tsp()
        .send(&alice.profile, &bob.did, payload)
        .await
        .expect("alice sends a TSP message to bob");

    let mut ws = env
        .atm
        .tsp()
        .connect_websocket_acked(&bob.profile)
        .await
        .expect("bob opens the TSP websocket in ack mode");
    assert!(
        ws.is_acked(),
        "the mediator must negotiate `tsp-ack`; a silent downgrade would leave \
         delivery at-most-once while the caller believes otherwise"
    );

    let qb2 = timeout(Duration::from_secs(5), ws.recv())
        .await
        .expect("a frame arrives within the timeout")
        .expect("recv succeeds")
        .expect("a flushed frame");

    let (recovered, sender) = env
        .atm
        .tsp()
        .unpack_bytes(&bob.profile, &qb2)
        .await
        .expect("bob unpacks the message");
    assert_eq!(recovered, payload, "payload round-trips");
    assert_eq!(sender, alice.did, "sender VID is recovered");

    // THE POINT: delivered to the socket, still held by the mediator.
    let fetched = env
        .atm
        .fetch_messages(&bob.profile, &FetchOptions::default())
        .await
        .expect("bob fetches messages");
    assert_eq!(
        fetched.success.len(),
        1,
        "in tsp-ack mode the message must still be held until acked — deleting on \
         send is what loses it when the socket dies mid-flight"
    );

    // Ack, and only now may it go.
    ws.ack(&qb2).await.expect("ack succeeds");
    assert!(
        wait_for_empty_inbox(&env, &bob).await,
        "the acked message must be deleted"
    );

    ws.close().await.ok();
    env.shutdown().await.expect("shutdown");
}

/// The recovery this buys: a frame that was sent but never acked is still there
/// on the next connection. Under delete-on-send it would be gone for good.
#[tokio::test]
async fn an_unacked_tsp_message_is_redelivered_on_reconnect() {
    init_tracing();

    let env = TestEnvironment::spawn()
        .await
        .expect("spawn test environment");

    let alice = env.add_user("alice").await.expect("add alice");
    let bob = env.add_user("bob").await.expect("add bob");

    let payload = b"a TSP message the client never acknowledges";
    env.atm
        .tsp()
        .send(&alice.profile, &bob.did, payload)
        .await
        .expect("alice sends a TSP message to bob");

    // First connection: receive it, then walk away without acking — standing in
    // for a consumer that crashed between reading the frame and handling it.
    {
        let mut ws = env
            .atm
            .tsp()
            .connect_websocket_acked(&bob.profile)
            .await
            .expect("bob connects in ack mode");
        let first = timeout(Duration::from_secs(5), ws.recv())
            .await
            .expect("a frame arrives")
            .expect("recv succeeds")
            .expect("a flushed frame");
        assert!(!first.is_empty(), "a non-empty frame");
        ws.close().await.ok();
    }

    // Second connection: it is still ours to collect.
    let mut ws = env
        .atm
        .tsp()
        .connect_websocket_acked(&bob.profile)
        .await
        .expect("bob reconnects in ack mode");
    let again = timeout(Duration::from_secs(5), ws.recv())
        .await
        .expect(
            "the un-acked message must be redelivered on reconnect — this is the \
             at-most-once loss window that tsp-ack closes",
        )
        .expect("recv succeeds")
        .expect("a redelivered frame");

    let (recovered, _) = env
        .atm
        .tsp()
        .unpack_bytes(&bob.profile, &again)
        .await
        .expect("bob unpacks the redelivered message");
    assert_eq!(recovered, payload, "the same message came back");

    ws.ack(&again).await.expect("ack succeeds");
    assert!(
        wait_for_empty_inbox(&env, &bob).await,
        "the acked message must be deleted"
    );

    ws.close().await.ok();
    env.shutdown().await.expect("shutdown");
}

/// Redelivery is for *recovery*, not the steady state: within one connection an
/// un-acked frame must not be sent again. Without the in-flight set, every
/// live-delivery wake-up re-walks the inbox and re-sends everything not yet
/// acked, so a consumer that acks a moment later sees constant duplicates.
#[tokio::test]
async fn an_unacked_message_is_not_resent_within_the_same_connection() {
    init_tracing();

    let env = TestEnvironment::spawn()
        .await
        .expect("spawn test environment");

    let alice = env.add_user("alice").await.expect("add alice");
    let bob = env.add_user("bob").await.expect("add bob");

    let mut ws = env
        .atm
        .tsp()
        .connect_websocket_acked(&bob.profile)
        .await
        .expect("bob connects in ack mode");

    // Two messages, neither acked. Each must arrive exactly once.
    for round in 0..2u8 {
        let payload = format!("unacked message {round}").into_bytes();
        env.atm
            .tsp()
            .send(&alice.profile, &bob.did, &payload)
            .await
            .expect("alice sends");

        let qb2 = timeout(Duration::from_secs(5), ws.recv())
            .await
            .unwrap_or_else(|_| panic!("frame {round} arrives"))
            .expect("recv succeeds")
            .expect("a pushed frame");
        let (recovered, _) = env
            .atm
            .tsp()
            .unpack_bytes(&bob.profile, &qb2)
            .await
            .expect("unpack");
        assert_eq!(recovered, payload, "frame {round} is the one just sent");
    }

    // Nothing further: no re-send of the two outstanding frames.
    let extra = timeout(Duration::from_secs(2), ws.recv()).await;
    assert!(
        extra.is_err(),
        "an un-acked frame must not be re-sent on the same connection — \
         redelivery is a reconnect-time recovery, not the steady state"
    );

    ws.close().await.ok();
    env.shutdown().await.expect("shutdown");
}

/// **The negotiation must be an honest capability signal.**
///
/// By default the mediator echoes the client's subprotocol list back unchanged,
/// which means a mediator that has never heard of a subprotocol still echoes
/// it. Left alone, a client asking for `tsp-ack` against an older mediator
/// would be told "yes" and silently get delete-on-send — the same silent loss
/// delete-to-ack exists to remove.
///
/// The fix is ordering: clients list `tsp` first, and selection picks the first
/// client-listed protocol the server also offers. An older mediator reflects
/// the client's list and so lands on `tsp`; this mediator narrows its offer to
/// `tsp-ack` and so lands on `tsp-ack` despite it being second. This test pins
/// that override — if the mediator ever goes back to plain reflection, a client
/// would read `tsp` here and correctly (if unhelpfully) conclude there is no
/// ack support, but the *positive* signal must keep working.
#[tokio::test]
async fn tsp_ack_is_selected_even_though_the_client_lists_it_second() {
    init_tracing();

    let env = TestEnvironment::spawn()
        .await
        .expect("spawn test environment");
    let bob = env.add_user("bob").await.expect("add bob");
    let (access_token, ws_uri) = token_and_ws_uri(&env, &bob).await;

    // Client order mirrors the SDK: `tsp` first, `tsp-ack` second.
    let request = ClientRequestBuilder::new(ws_uri.clone())
        .with_sub_protocol(format!("bearer.{access_token}"))
        .with_sub_protocol("tsp")
        .with_sub_protocol("tsp-ack");
    let (stream, response) = connect_async(request)
        .await
        .expect("bob upgrades offering tsp + tsp-ack");
    assert_eq!(
        response
            .headers()
            .get("sec-websocket-protocol")
            .and_then(|v| v.to_str().ok()),
        Some("tsp-ack"),
        "a mediator that supports delete-to-ack must answer `tsp-ack`, or the \
         client cannot tell support from mere reflection"
    );
    drop(stream);

    // And a plain `tsp` client still negotiates plain `tsp`.
    let (access_token, ws_uri) = token_and_ws_uri(&env, &bob).await;
    let request = ClientRequestBuilder::new(ws_uri)
        .with_sub_protocol(format!("bearer.{access_token}"))
        .with_sub_protocol("tsp");
    let (stream, response) = connect_async(request)
        .await
        .expect("bob upgrades offering tsp only");
    assert_eq!(
        response
            .headers()
            .get("sec-websocket-protocol")
            .and_then(|v| v.to_str().ok()),
        Some("tsp"),
        "a client that did not ask for delete-to-ack must not be given it"
    );
    drop(stream);

    env.shutdown().await.expect("shutdown");
}
