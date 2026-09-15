//! Anonymous inter-mediator relay over WebSocket, and the acknowledgement that
//! makes it safe.
//!
//! A relay hop carries no credential — the relaying mediator holds no session
//! on its peer — so the WebSocket route admits it the way `/inbound` does:
//! only when the operator has turned relay on, and only for a socket that
//! identifies itself by offering the `relay-ack` subprotocol.
//!
//! The subprotocol is the point. A bare WebSocket write says only that bytes
//! left the sender, so relaying over one would let the forwarding processor ACK
//! its queue entry for a message the peer *refused* — the rejection surviving
//! as nothing but a log line on the far side, while every "delivered" claim
//! downstream is built on the REST path's status check. These tests pin the
//! three properties that keep the two transports equivalent:
//!
//! 1. A relay-enabled mediator admits the anonymous upgrade, echoes
//!    `relay-ack`, and answers an accepted frame with `ok: true` — and the
//!    message really is delivered to the recipient, so the ack means what it
//!    says.
//! 2. A frame the mediator refuses comes back `ok: false` with the mediator's
//!    error code, which is what turns a rejection into a retry and eventually a
//!    problem report to the original sender.
//! 3. A mediator that is not a relay refuses the upgrade outright.
//!
//! A fourth test drives the whole thing between two real mediators, which is
//! the only place the *sending* half — subprotocol negotiation and waiting on
//! the ack — is exercised. It has to ask for the WebSocket transport
//! explicitly: the processor's rate threshold is measured over a 300-second
//! window, so a handful of messages reads as ~0.03 msgs/10s and every short
//! test would otherwise relay over REST.

mod common;

use std::time::Duration;

use affinidi_messaging_didcomm::Message;
use affinidi_messaging_mediator::store::MemoryStore;
use affinidi_messaging_mediator_common::store::MediatorStore;
use affinidi_messaging_mediator_common::tasks::forwarding::relay_ack::{
    RELAY_ACK_SUBPROTOCOL, RelayAck, frame_id,
};
use affinidi_messaging_sdk::messages::fetch::FetchOptions;
use affinidi_messaging_test_mediator::{TestEnvironment, TestMediator, TestUser, acl};
use common::init_tracing;
use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{ClientRequestBuilder, Message as WsMessage, http::Uri},
};
use uuid::Uuid;

/// Spawn a relay-enabled mediator wired to an SDK environment.
///
/// `enable_inter_mediator_relay` is the explicit opt-in the WebSocket route
/// checks; the allow-all default ACL is what lets a cross-mediator forward
/// sender auto-register, exactly as in `cross_mediator_forwarding.rs`.
async fn spawn_relay_environment() -> TestEnvironment {
    let mediator = TestMediator::builder()
        .enable_forwarding(true)
        .enable_external_forwarding(true)
        .global_acl_default(acl::allow_all())
        .enable_inter_mediator_relay(true)
        .spawn()
        .await
        .expect("spawn relay mediator");
    TestEnvironment::new(mediator)
        .await
        .expect("wire SDK environment to relay mediator")
}

/// The mediator's `ws://…/ws` upgrade URI.
fn ws_uri(env: &TestEnvironment) -> Uri {
    env.mediator
        .ws_endpoint()
        .as_str()
        .parse()
        .expect("parse ws endpoint")
}

/// Build the frame a relaying mediator puts on the wire in blind relay mode:
/// a `routing/2.0` forward addressed to the receiving mediator, whose
/// attachment is an authcrypt from `sender` to `recipient`.
async fn relayed_forward(
    env: &TestEnvironment,
    sender: &TestUser,
    recipient: &TestUser,
    text: &str,
) -> String {
    relayed_forward_to(env, sender, env.mediator.did(), recipient, text).await
}

/// As [`relayed_forward`], but addressed to an arbitrary next-hop mediator.
async fn relayed_forward_to(
    env: &TestEnvironment,
    sender: &TestUser,
    target_mediator: &str,
    recipient: &TestUser,
    text: &str,
) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let msg = Message::build(
        Uuid::new_v4().to_string(),
        "https://didcomm.org/basicmessage/2.0/message".to_string(),
        json!({ "content": text }),
    )
    .to(recipient.did.clone())
    .from(sender.did.clone())
    .created_time(now)
    .expires_time(now + 60)
    .finalize();

    let (packed, _) = env
        .atm
        .pack_encrypted(&msg, &recipient.did, Some(&sender.did), Some(&sender.did))
        .await
        .expect("authcrypt for the recipient");

    let (_id, forward) = env
        .atm
        .routing()
        .forward_message(
            &sender.profile,
            false,
            &packed,
            target_mediator,
            &recipient.did,
            None,
            None,
        )
        .await
        .expect("wrap in a forward addressed to the mediator");

    forward
}

/// Read frames until one parses as a [`RelayAck`], or the deadline passes.
async fn next_ack<S>(stream: &mut S) -> RelayAck
where
    S: StreamExt<Item = Result<WsMessage, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        let frame = tokio::time::timeout_at(deadline, stream.next())
            .await
            .expect("a relay-ack must arrive before the deadline")
            .expect("the relay socket must stay open")
            .expect("the relay socket must not error");

        if let WsMessage::Text(text) = frame
            && let Ok(ack) = serde_json::from_str::<RelayAck>(&text)
        {
            return ack;
        }
    }
}

/// A relay-enabled mediator admits the anonymous upgrade, and its ack means the
/// message was really delivered — not merely received.
#[tokio::test]
async fn relay_socket_is_admitted_and_its_ack_means_delivered() {
    init_tracing();

    let env = spawn_relay_environment().await;
    let alice = env.add_user("Alice").await.expect("add alice");
    let bob = env.add_user("Bob").await.expect("add bob");
    let frame = relayed_forward(&env, &alice, &bob, "relayed over a websocket").await;

    // The shape a relaying mediator opens: no Authorization header, no bearer
    // subprotocol, just `relay-ack`.
    let request = ClientRequestBuilder::new(ws_uri(&env)).with_sub_protocol(RELAY_ACK_SUBPROTOCOL);
    let (mut stream, response) = connect_async(request)
        .await
        .expect("relay upgrade must be admitted");

    assert_eq!(response.status().as_u16(), 101, "expected 101");
    assert_eq!(
        response
            .headers()
            .get("sec-websocket-protocol")
            .and_then(|v| v.to_str().ok()),
        Some(RELAY_ACK_SUBPROTOCOL),
        "the mediator must echo `relay-ack` — the peer relays only on that promise"
    );

    stream
        .send(WsMessage::Text(frame.clone().into()))
        .await
        .expect("send the relayed frame");

    let ack = next_ack(&mut stream).await;
    assert!(
        ack.answers(&frame_id(frame.as_bytes())),
        "the ack must be content-addressed to the frame it answers"
    );
    assert!(ack.ok, "the frame was accepted: {ack:?}");

    // And the ack was telling the truth.
    let mut delivered = None;
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    while std::time::Instant::now() < deadline {
        let fetched = env
            .atm
            .fetch_messages(&bob.profile, &FetchOptions::default())
            .await
            .expect("bob fetches messages");
        if let Some(element) = fetched.success.first()
            && element.msg.is_some()
        {
            delivered = element.msg.clone();
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        delivered.is_some(),
        "a positive ack must mean the mediator took responsibility for the message"
    );

    drop(stream);
    env.shutdown().await.expect("shutdown");
}

/// A refused frame comes back as a negative ack carrying the mediator's error
/// code. This is the property the whole subprotocol exists for: without it the
/// relaying peer would ACK its queue entry and drop a message the peer threw
/// away.
#[tokio::test]
async fn a_refused_frame_is_nacked_rather_than_silently_dropped() {
    init_tracing();

    let env = spawn_relay_environment().await;

    let request = ClientRequestBuilder::new(ws_uri(&env)).with_sub_protocol(RELAY_ACK_SUBPROTOCOL);
    let (mut stream, _response) = connect_async(request)
        .await
        .expect("relay upgrade must be admitted");

    // Not a DIDComm envelope: the mediator cannot deliver it and must say so.
    let frame = "this is not a DIDComm envelope";
    stream
        .send(WsMessage::Text(frame.into()))
        .await
        .expect("send the malformed frame");

    let ack = next_ack(&mut stream).await;
    assert!(
        ack.answers(&frame_id(frame.as_bytes())),
        "the nack must answer the frame that was refused"
    );
    assert!(!ack.ok, "the frame was refused, so the ack must say so");
    assert!(
        ack.code.is_some(),
        "a refusal carries the mediator error code so the peer can log and \
         report it: {ack:?}"
    );

    drop(stream);
    env.shutdown().await.expect("shutdown");
}

/// An authenticated client is not a relay, so it must never be told it will
/// get acks. Reflecting the offer back — the default echo behaviour — would be
/// the mediator promising a contract it only honours for relay sockets.
#[tokio::test]
async fn an_authenticated_client_is_never_told_it_will_get_acks() {
    init_tracing();

    let env = spawn_relay_environment().await;
    let alice = env.add_user("Alice").await.expect("add alice");

    let mediator_did = env.mediator.did().to_string();
    let tokens = env
        .tdk
        .authentication()
        .authenticate(alice.did.clone(), mediator_did, 3, None)
        .await
        .expect("authenticate alice");

    let request = ClientRequestBuilder::new(ws_uri(&env))
        .with_sub_protocol(RELAY_ACK_SUBPROTOCOL)
        .with_sub_protocol(format!("bearer.{}", tokens.access_token));
    // tokio-tungstenite's client errors when the server selects none of the
    // offered subprotocols — which is exactly the answer being asserted.
    let result = connect_async(request).await;

    match result {
        Err(_) => { /* no subprotocol selected: the mediator promised nothing */ }
        Ok((stream, response)) => {
            assert_ne!(
                response
                    .headers()
                    .get("sec-websocket-protocol")
                    .and_then(|v| v.to_str().ok()),
                Some(RELAY_ACK_SUBPROTOCOL),
                "an authenticated client must not be told `relay-ack` was accepted"
            );
            drop(stream);
        }
    }

    env.shutdown().await.expect("shutdown");
}

/// A mediator that is not configured as a relay refuses the anonymous upgrade,
/// exactly as it refuses an anonymous `/inbound`.
#[tokio::test]
async fn a_non_relay_mediator_refuses_the_anonymous_upgrade() {
    init_tracing();

    let mediator = TestMediator::builder()
        .enable_forwarding(true)
        .global_acl_default(acl::deny_all())
        .enable_inter_mediator_relay(false)
        .spawn()
        .await
        .expect("spawn non-relay mediator");
    let env = TestEnvironment::new(mediator)
        .await
        .expect("wire SDK environment");

    let request = ClientRequestBuilder::new(ws_uri(&env)).with_sub_protocol(RELAY_ACK_SUBPROTOCOL);
    let result = connect_async(request).await;

    assert!(
        result.is_err(),
        "a mediator that is not a relay must refuse an anonymous upgrade"
    );

    env.shutdown().await.expect("shutdown");
}

/// Two mediators, relaying over the negotiated socket: mediator A opens a
/// `relay-ack` WebSocket to mediator B, B admits it anonymously, and the
/// message arrives.
///
/// This is the only coverage of the sending half — building the upgrade with
/// the subprotocol, refusing to relay if the peer doesn't echo it, and holding
/// the frame open until the ack comes back.
#[tokio::test]
async fn a_forward_relays_between_two_mediators_over_the_negotiated_socket() {
    init_tracing();

    // B's store is held by the test so the relay socket can be *observed*
    // rather than assumed: nothing else in this test opens a WebSocket to B,
    // so a non-zero `websocket_open` is the relay hop and only the relay hop.
    let bob_store = std::sync::Arc::new(MemoryStore::new());

    let mediator_a = TestMediator::builder()
        .enable_forwarding(true)
        .enable_external_forwarding(true)
        .global_acl_default(acl::allow_all())
        .enable_inter_mediator_relay(true)
        // Force the WebSocket transport on the first relayed message.
        .forwarding_ws_threshold(0)
        .spawn()
        .await
        .expect("spawn mediator A");
    let mediator_b = TestMediator::builder()
        .enable_forwarding(true)
        .enable_external_forwarding(true)
        .global_acl_default(acl::allow_all())
        .enable_inter_mediator_relay(true)
        .store(bob_store.clone())
        .spawn()
        .await
        .expect("spawn mediator B");

    let env_a = TestEnvironment::new(mediator_a).await.expect("env A");
    let env_b = TestEnvironment::new(mediator_b).await.expect("env B");

    let alice = env_a.add_user("Alice").await.expect("add alice on A");
    let bob = env_b.add_user("Bob").await.expect("add bob on B");

    assert_eq!(
        bob_store
            .get_global_stats()
            .await
            .expect("read B's stats")
            .websocket_open,
        0,
        "no WebSocket has been opened to B before the relay hop"
    );

    // The routing-2.0 double forward: an INNER forward addressed to B with
    // next = Bob, wrapped in an OUTER forward addressed to A with next = B, so
    // A relays the inner one over the wire.
    let inner = relayed_forward_to(
        &env_a,
        &alice,
        env_b.mediator.did(),
        &bob,
        "over the socket",
    )
    .await;
    let (outer_id, outer) = env_a
        .atm
        .routing()
        .forward_message(
            &alice.profile,
            false,
            &inner,
            env_a.mediator.did(),
            env_b.mediator.did(),
            None,
            None,
        )
        .await
        .expect("outer forward");
    env_a
        .atm
        .send_message(&alice.profile, &outer, &outer_id, false, false)
        .await
        .expect("send the outer forward to A");

    // Bob receives it, having crossed A → B over the relay socket.
    let mut delivered = None;
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while std::time::Instant::now() < deadline {
        let fetched = env_b
            .atm
            .fetch_messages(&bob.profile, &FetchOptions::default())
            .await
            .expect("bob fetches messages");
        if let Some(element) = fetched.success.first()
            && element.msg.is_some()
        {
            delivered = element.msg.clone();
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        delivered.is_some(),
        "the relayed message must reach Bob on mediator B"
    );

    assert!(
        bob_store
            .get_global_stats()
            .await
            .expect("read B's stats")
            .websocket_open
            > 0,
        "the hop must have gone over the relay WebSocket, not fallen back to REST"
    );

    env_a.shutdown().await.expect("shutdown A");
    env_b.shutdown().await.expect("shutdown B");
}
