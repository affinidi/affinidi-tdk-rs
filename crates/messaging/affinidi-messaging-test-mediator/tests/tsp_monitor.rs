//! A monitor subscription opened over **TSP** is delivered over TSP.
//!
//! Monitor batches are pushed live and stored nowhere. A raw-TSP socket
//! answers an ordinary push by draining its *stored* inbox and discarding the
//! body, so a TSP subscription used to be refused outright: accepting it would
//! have promised a feed that never arrived (R1.1).
//!
//! It is served now. A batch for a TSP subscriber is sealed to its VID as the
//! mediator and published *verbatim* — the frame itself rather than a signal
//! to go and fetch something — and this test drives the whole path: subscribe
//! over TSP, make traffic, and read the batch off the raw-TSP socket.
#![cfg(feature = "tsp")]

mod common;

use std::time::Duration;

use affinidi_messaging_test_mediator::{TestEnvironment, TestUser};
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use common::init_tracing;
use futures_util::StreamExt;
use serde_json::{Value, json};
use tokio::time::timeout;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{ClientRequestBuilder, Message, http::Uri},
};
use uuid::Uuid;

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
async fn a_subscription_opened_over_tsp_delivers_its_batches_over_tsp() {
    init_tracing();

    let env = TestEnvironment::spawn_with_direct_delivery()
        .await
        .expect("spawn test environment");
    let alice = env.add_user("alice").await.expect("add alice");
    let bob = env.add_user("bob").await.expect("add bob");
    env.relate_directly(&alice, &bob)
        .await
        .expect("seed the TSP relationship");

    // §7.2.2 gates application messages on a relationship, and the batches
    // are sealed by the mediator — so a TSP client that talks to the mediator
    // at all holds one with it. Seeded here rather than handshaken, for the
    // same reason as Alice's above.
    let mediator_vid = env.mediator.did().to_string();
    for (ours, theirs) in [(&bob.did, &mediator_vid), (&mediator_vid, &bob.did)] {
        env.relationship_store
            .set(
                ours,
                theirs,
                affinidi_messaging_sdk::protocols::tsp::RelationshipState::Bidirectional,
            )
            .await
            .expect("seed bob's relationship with the mediator");
    }

    // Bob subscribes over TSP: the Trust Task document is the payload of an
    // ordinary TSP Direct message to the mediator. Its filter defaults to his
    // own account, which is all a non-administrator may watch.
    let mediator_did = mediator_vid.clone();
    let subscribe = json!({
        "id": format!("urn:uuid:{}", Uuid::new_v4()),
        "type": "https://trusttasks.org/spec/messaging/monitor/subscribe/0.1",
        "issuer": bob.did,
        "recipient": mediator_did,
        "payload": { "leaseSeconds": 300 },
    });
    env.atm
        .tsp()
        .send(
            &bob.profile,
            &mediator_did,
            &serde_json::to_vec(&subscribe).expect("subscribe document serialises"),
        )
        .await
        .expect("bob subscribes to the monitor over TSP");

    // Bob opens the raw-TSP socket — the one that discards an ordinary push.
    let (access_token, ws_uri) = token_and_ws_uri(&env, &bob).await;
    let request = ClientRequestBuilder::new(ws_uri)
        .with_sub_protocol(format!("bearer.{access_token}"))
        .with_sub_protocol("tsp");
    let (mut stream, response) = connect_async(request)
        .await
        .expect("tsp websocket upgrade must succeed");
    assert_eq!(response.status().as_u16(), 101);

    // Traffic to watch: Alice sends Bob a message. Bob's own management
    // traffic with the mediator is excluded from his feed by default, so this
    // is what the batch must carry.
    env.atm
        .tsp()
        .send(&alice.profile, &bob.did, b"traffic for the monitor")
        .await
        .expect("alice sends bob a TSP message");

    // Read frames until a monitor batch arrives. The subscribe response and
    // Alice's own message ride the same socket and are skipped; a batch is a
    // Trust Task document of the monitor event type.
    let batch: Value = timeout(Duration::from_secs(10), async {
        loop {
            let frame = stream
                .next()
                .await
                .expect("stream not closed")
                .expect("frame is not an error");
            let qb2 = match frame {
                Message::Binary(bytes) => bytes.to_vec(),
                Message::Ping(_) | Message::Pong(_) | Message::Text(_) => continue,
                other => panic!("expected a Binary TSP frame, got: {other:?}"),
            };
            assert!(
                affinidi_tsp::is_tsp(&qb2),
                "every frame on this socket is a TSP message"
            );
            let (payload, sender) = env
                .atm
                .tsp()
                .unpack(&bob.profile, &BASE64_URL_SAFE_NO_PAD.encode(&qb2))
                .await
                .expect("bob unpacks the frame");
            let Ok(doc) = serde_json::from_slice::<Value>(&payload) else {
                continue; // Alice's plain payload, not a Trust Task document.
            };
            if doc["type"] == "https://trusttasks.org/spec/messaging/monitor/event/0.1" {
                assert_eq!(sender, mediator_did, "batches are sealed by the mediator");
                break doc;
            }
        }
    })
    .await
    .expect("a monitor batch arrives over TSP within the timeout");

    // The batch is addressed to Bob, carries his subscription, and holds the
    // events it was opened to watch.
    assert_eq!(batch["recipient"], Value::String(bob.did.clone()));
    let payload = &batch["payload"];
    assert!(
        payload["subscriptionId"].is_string(),
        "a batch names its subscription: {payload}"
    );
    let events = payload["events"]
        .as_array()
        .expect("a batch carries its events");
    assert!(
        events
            .iter()
            .any(|e| e["to"] == Value::String(bob.did_hash().to_string())),
        "the batch carries the traffic addressed to bob: {events:?}"
    );
    assert!(
        batch["proof"].is_object(),
        "a batch is signed by the mediator: {batch}"
    );
}
