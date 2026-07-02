//! End-to-end coverage of the `atm.send_to` protocol-selection façade: with a
//! non-`Off` [`TspPolicy`], send_to picks TSP or DIDComm per the peer's known
//! capability and delivers over the chosen wire, and the recipient recovers the
//! same DIDComm [`Message`] either way.
#![cfg(feature = "tsp")]

use affinidi_messaging_didcomm::Message;
use affinidi_messaging_sdk::messages::MessageProtocol;
use affinidi_messaging_sdk::messages::fetch::FetchOptions;
use affinidi_messaging_sdk::{SendProtocol, TspPolicy, TspSupport};
use affinidi_messaging_test_mediator::TestEnvironment;
use serde_json::json;
use uuid::Uuid;

fn basic_message(from: &str, to: &str, text: &str) -> Message {
    Message::build(
        Uuid::new_v4().to_string(),
        "https://didcomm.org/basicmessage/2.0/message".to_string(),
        json!({ "content": text }),
    )
    .to(to.to_string())
    .from(from.to_string())
    .finalize()
}

/// `Preferred` policy + a `Supported` capability → send_to uses TSP, and the
/// recipient recovers the DIDComm `Message` from the TSP payload.
#[tokio::test]
async fn send_to_uses_tsp_when_capability_supported() {
    let env = TestEnvironment::spawn_with_tsp_policy(TspPolicy::Preferred)
        .await
        .expect("spawn env with Preferred policy");
    let alice = env.add_user("alice").await.expect("add alice");
    let bob = env.add_user("bob").await.expect("add bob");

    // Record that bob's agent speaks TSP.
    env.atm
        .tsp()
        .set_peer_capability(&alice.profile, &bob.did, TspSupport::Supported)
        .await
        .expect("record bob's TSP capability");

    let msg = basic_message(&alice.did, &bob.did, "hi over the façade");
    let via = env
        .atm
        .send_to(&alice.profile, &msg, &bob.did, Some(&alice.did), None)
        .await
        .expect("send_to bob");
    assert_eq!(via, SendProtocol::Tsp, "capability Supported selects TSP");

    let fetched = env
        .atm
        .fetch_messages(&bob.profile, &FetchOptions::default())
        .await
        .expect("bob fetches");
    let element = fetched.success.first().expect("bob has a message");
    assert_eq!(element.protocol, Some(MessageProtocol::Tsp));
    let stored = element.msg.as_ref().expect("body");

    let (payload, sender) = env
        .atm
        .tsp()
        .unpack(&bob.profile, stored)
        .await
        .expect("bob unpacks the TSP message");
    let recovered: Message = serde_json::from_slice(&payload).expect("payload is a DIDComm Message");
    assert_eq!(recovered.body["content"], "hi over the façade");
    assert_eq!(sender, alice.did);
}

/// `Preferred` policy + an `Unsupported` capability → send_to falls back to
/// DIDComm, delivered via a forward the recipient unpacks natively.
#[tokio::test]
async fn send_to_falls_back_to_didcomm_when_unsupported() {
    let env = TestEnvironment::spawn_with_tsp_policy(TspPolicy::Preferred)
        .await
        .expect("spawn env with Preferred policy");
    let alice = env.add_user("alice").await.expect("add alice");
    let bob = env.add_user("bob").await.expect("add bob");

    env.atm
        .tsp()
        .set_peer_capability(&alice.profile, &bob.did, TspSupport::Unsupported)
        .await
        .expect("record bob as not TSP-capable");

    let msg = basic_message(&alice.did, &bob.did, "hi over didcomm");
    let via = env
        .atm
        .send_to(&alice.profile, &msg, &bob.did, Some(&alice.did), None)
        .await
        .expect("send_to bob");
    assert_eq!(
        via,
        SendProtocol::DidComm,
        "capability Unsupported falls back to DIDComm"
    );

    let fetched = env
        .atm
        .fetch_messages(&bob.profile, &FetchOptions::default())
        .await
        .expect("bob fetches");
    let element = fetched.success.first().expect("bob has a message");
    assert_eq!(element.protocol, Some(MessageProtocol::DidComm));
    let stored = element.msg.as_ref().expect("body");

    let (recovered, _meta) = env
        .atm
        .unpack(stored)
        .await
        .expect("bob unpacks the DIDComm message");
    assert_eq!(recovered.body["content"], "hi over didcomm");
}

/// `Required` policy + no TSP capability → send_to errors instead of silently
/// falling back to DIDComm.
#[tokio::test]
async fn send_to_required_errors_without_capability() {
    let env = TestEnvironment::spawn_with_tsp_policy(TspPolicy::Required)
        .await
        .expect("spawn env with Required policy");
    let alice = env.add_user("alice").await.expect("add alice");
    let bob = env.add_user("bob").await.expect("add bob");

    // Explicitly Unsupported so the outcome is deterministic regardless of what
    // bob's DID document advertises.
    env.atm
        .tsp()
        .set_peer_capability(&alice.profile, &bob.did, TspSupport::Unsupported)
        .await
        .expect("record bob as not TSP-capable");

    let msg = basic_message(&alice.did, &bob.did, "nope");
    let err = env
        .atm
        .send_to(&alice.profile, &msg, &bob.did, Some(&alice.did), None)
        .await
        .expect_err("Required + no TSP capability must error");
    assert!(
        format!("{err}").contains("Required"),
        "error should explain the Required-policy denial, got: {err}"
    );
}
