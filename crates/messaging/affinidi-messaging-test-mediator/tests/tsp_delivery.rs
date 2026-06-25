//! End-to-end TSP Direct delivery through the mediator, driven entirely by the
//! SDK's `atm.tsp()`: Alice packs a TSP Direct message and POSTs it to
//! `/inbound`; the mediator sniffs the TSP magic byte and stores it for Bob; Bob
//! fetches and unpacks it. Exercises the full sniff → store → fetch → unpack path
//! across the SDK + mediator (memory backend, no Redis needed).
#![cfg(feature = "tsp")]

use affinidi_messaging_didcomm::Message;
use affinidi_messaging_sdk::messages::MessageProtocol;
use affinidi_messaging_sdk::messages::fetch::FetchOptions;
use affinidi_messaging_test_mediator::TestEnvironment;
use affinidi_tdk::dids::{DID, KeyType, PeerKeyRole, PeerService, PeerServiceEndpoint};
use affinidi_tsp::message::control::{ControlMessage, ControlType};
use serde_json::json;
use uuid::Uuid;

#[tokio::test]
async fn tsp_direct_message_round_trips_through_the_mediator() {
    let env = TestEnvironment::spawn()
        .await
        .expect("spawn test environment");

    // Two locally-served, authenticated users (did:peer profiles).
    let alice = env.add_user("alice").await.expect("add alice");
    let bob = env.add_user("bob").await.expect("add bob");

    let payload = b"hello over TSP";

    // Alice packs a TSP Direct message to Bob and sends it to the mediator.
    env.atm
        .tsp()
        .send(&alice.profile, &bob.did, payload)
        .await
        .expect("alice sends a TSP message to bob");

    // Bob fetches his mailbox; the message is the stored TSP (CESR qb64) string.
    let fetched = env
        .atm
        .fetch_messages(&bob.profile, &FetchOptions::default())
        .await
        .expect("bob fetches messages");

    let element = fetched
        .success
        .first()
        .expect("bob has one fetched message");
    let stored = element
        .msg
        .as_ref()
        .expect("fetched message carries its body");

    // It is recognised as TSP and unpacks to the original payload + sender.
    assert!(
        env.atm.tsp().is_tsp(stored),
        "the stored message is recognised as TSP"
    );
    // The mediator tags the wire protocol on pickup, so the client doesn't have
    // to inspect the body itself.
    assert_eq!(
        element.protocol,
        Some(MessageProtocol::Tsp),
        "fetch tags the message as TSP"
    );
    let (recovered, sender) = env
        .atm
        .tsp()
        .unpack(&bob.profile, stored)
        .await
        .expect("bob unpacks the TSP message");

    assert_eq!(recovered, payload, "payload round-trips end to end");
    assert_eq!(sender, alice.did, "sender VID is recovered");
}

/// End-to-end TSP **Routed** relay: Alice sends through the mediator as a relay
/// hop to Bob. The payload is sealed end-to-end to Bob; the outer routing layer
/// is sealed to the mediator, which unwraps it and forwards the opaque inner to
/// Bob (a local recipient). Proves the mediator's routed-relay path: derive its
/// own TSP identity → unpack the layer sealed to it → `next_hop` → deliver.
#[tokio::test]
async fn tsp_routed_message_relays_through_the_mediator() {
    let env = TestEnvironment::spawn()
        .await
        .expect("spawn test environment");

    let alice = env.add_user("alice").await.expect("add alice");
    let bob = env.add_user("bob").await.expect("add bob");
    let mediator_did = env.mediator.did().to_string();

    let payload = b"routed hello over TSP";

    // Route: alice -> mediator (relay hop) -> bob.
    let route = vec![mediator_did, bob.did.clone()];
    env.atm
        .tsp()
        .send_routed(&alice.profile, &route, payload)
        .await
        .expect("alice sends a routed TSP message via the mediator");

    // Bob fetches the relayed (now opaque Direct) message and unpacks it.
    let fetched = env
        .atm
        .fetch_messages(&bob.profile, &FetchOptions::default())
        .await
        .expect("bob fetches messages");
    let element = fetched
        .success
        .first()
        .expect("bob has one relayed message");
    let stored = element
        .msg
        .as_ref()
        .expect("relayed message carries its body");

    let (recovered, sender) = env
        .atm
        .tsp()
        .unpack(&bob.profile, stored)
        .await
        .expect("bob unpacks the relayed TSP message");

    assert_eq!(recovered, payload, "payload survives the relay end to end");
    assert_eq!(
        sender, alice.did,
        "original sender VID is recovered, not the relay"
    );
}

/// End-to-end TSP **Nested** relay: Alice wraps an inner Direct message (sealed to
/// Bob) in an outer **Nested** envelope sealed to the mediator — a metadata-privacy
/// carriage where Bob's identity is hidden from anyone but the mediator. The
/// mediator unwraps its outer layer and forwards the opaque inner to Bob (a local
/// recipient). Proves the mediator's nested-relay path: derive its own TSP identity
/// → unpack the layer sealed to it → route the inner by its own envelope → deliver.
#[tokio::test]
async fn tsp_nested_message_relays_through_the_mediator() {
    let env = TestEnvironment::spawn()
        .await
        .expect("spawn test environment");

    let alice = env.add_user("alice").await.expect("add alice");
    let bob = env.add_user("bob").await.expect("add bob");
    let mediator_did = env.mediator.did().to_string();

    let payload = b"nested hello over TSP";

    // Alice nests an inner Direct (sealed to bob) inside a Nested envelope sealed to
    // the mediator, which unwraps its layer and forwards the inner to bob.
    env.atm
        .tsp()
        .send_nested(&alice.profile, &mediator_did, &bob.did, payload)
        .await
        .expect("alice sends a nested TSP message via the mediator");

    // Bob fetches the forwarded (now opaque Direct) message and unpacks it.
    let fetched = env
        .atm
        .fetch_messages(&bob.profile, &FetchOptions::default())
        .await
        .expect("bob fetches messages");
    let element = fetched
        .success
        .first()
        .expect("bob has one forwarded message");
    let stored = element
        .msg
        .as_ref()
        .expect("forwarded message carries its body");

    let (recovered, sender) = env
        .atm
        .tsp()
        .unpack(&bob.profile, stored)
        .await
        .expect("bob unpacks the forwarded TSP message");

    assert_eq!(
        recovered, payload,
        "payload survives the nested relay end to end"
    );
    assert_eq!(
        sender, alice.did,
        "original sender VID is recovered, not the intermediary"
    );
}

/// End-to-end TSP **Control** relay: Alice sends a relationship-forming *invite* (a
/// `Control` message) to Bob through the mediator. The mediator relays it like a
/// Direct message — payload-agnostic, never inspecting the control payload — and Bob
/// unpacks it and decodes the invite. Completes the mediator's TSP message-type
/// coverage (Direct / Routed / Nested / Control).
#[tokio::test]
async fn tsp_control_message_relays_through_the_mediator() {
    let env = TestEnvironment::spawn()
        .await
        .expect("spawn test environment");

    let alice = env.add_user("alice").await.expect("add alice");
    let bob = env.add_user("bob").await.expect("add bob");

    // Alice sends a relationship-forming invite (a Control message) to Bob.
    let invite = ControlMessage::invite();
    env.atm
        .tsp()
        .send_control(&alice.profile, &bob.did, &invite)
        .await
        .expect("alice sends a TSP control message via the mediator");

    // Bob fetches the relayed control message and unpacks it.
    let fetched = env
        .atm
        .fetch_messages(&bob.profile, &FetchOptions::default())
        .await
        .expect("bob fetches messages");
    let element = fetched
        .success
        .first()
        .expect("bob has one control message");
    let stored = element
        .msg
        .as_ref()
        .expect("control message carries its body");

    let (payload, sender) = env
        .atm
        .tsp()
        .unpack(&bob.profile, stored)
        .await
        .expect("bob unpacks the relayed control message");

    assert_eq!(
        sender, alice.did,
        "control message is authenticated from alice"
    );
    let control = ControlMessage::decode(&payload).expect("payload decodes as a control message");
    assert_eq!(
        control.control_type,
        ControlType::RelationshipFormingInvite,
        "the relayed control message is the invite alice sent"
    );
}

/// End-to-end **TSP↔DIDComm bridge**: Alice sends a *DIDComm* message to Bob, but
/// carried over TSP routing. She authcrypts a normal DIDComm message to Bob, then
/// routes it through the mediator with `send_routed_opaque`. The mediator unwraps
/// the TSP routing layer and delivers the opaque inner to Bob, who recognises it
/// as DIDComm (not TSP) and unpacks it natively. Proves the mediator bridges
/// protocols by forwarding on the route, blind to the inner's protocol.
#[tokio::test]
async fn tsp_routed_bridges_a_didcomm_message_to_the_recipient() {
    let env = TestEnvironment::spawn()
        .await
        .expect("spawn test environment");

    let alice = env.add_user("alice").await.expect("add alice");
    let bob = env.add_user("bob").await.expect("add bob");
    let mediator_did = env.mediator.did().to_string();

    let text = "hello bob — DIDComm carried over TSP";

    // Alice builds and authcrypts a DIDComm message to Bob — the bridged inner.
    let msg = Message::build(
        Uuid::new_v4().to_string(),
        "https://didcomm.org/basicmessage/2.0/message".to_string(),
        json!({ "content": text }),
    )
    .to(bob.did.clone())
    .from(alice.did.clone())
    .finalize();
    let (jwe, _) = env
        .atm
        .pack_encrypted(&msg, &bob.did, Some(&alice.did), Some(&alice.did))
        .await
        .expect("authcrypt the DIDComm message for bob");

    // Alice routes that DIDComm message through the mediator to Bob.
    let route = vec![mediator_did, bob.did.clone()];
    env.atm
        .tsp()
        .send_routed_opaque(&alice.profile, &route, jwe.as_bytes())
        .await
        .expect("route the DIDComm message over TSP to bob");

    // Bob fetches it — stored as a plain DIDComm JWE, not a TSP message — and
    // unpacks it with the DIDComm stack.
    let fetched = env
        .atm
        .fetch_messages(&bob.profile, &FetchOptions::default())
        .await
        .expect("bob fetches messages");
    let element = fetched
        .success
        .first()
        .expect("bob has one bridged message");
    let stored = element
        .msg
        .as_ref()
        .expect("bridged message carries its body");

    assert!(
        !env.atm.tsp().is_tsp(stored),
        "the bridged inner is a DIDComm message, not TSP"
    );
    // And the mediator tags it as DIDComm on pickup — a unified fetch, with the
    // protocol surfaced transparently in the metadata.
    assert_eq!(
        element.protocol,
        Some(MessageProtocol::DidComm),
        "fetch tags the bridged message as DIDComm"
    );

    let (received, _meta) = env
        .atm
        .unpack(stored)
        .await
        .expect("bob unpacks the bridged DIDComm message");
    assert_eq!(
        received.body.get("content").and_then(|c| c.as_str()),
        Some(text),
        "DIDComm payload survives the TSP bridge"
    );
    assert_eq!(
        received.from.as_deref(),
        Some(alice.did.as_str()),
        "DIDComm sender is recovered"
    );
}

/// End-to-end TSP **remote forwarding**: the final recipient lives on *another*
/// mediator. Bob's `did:peer` advertises a TSP transport endpoint elsewhere (via
/// a `tsp` service entry) and he is not a local account here. Alice routes a
/// message through this mediator to Bob; the mediator resolves Bob's remote
/// endpoint and enqueues the message for the forwarding processor to deliver over
/// the wire (responding `Forwarded`). Exercises the did:peer `tsp` service
/// resolution + the remote-forward enqueue path.
#[tokio::test]
async fn tsp_routed_forwards_to_a_remote_recipients_mediator() {
    let env = TestEnvironment::spawn()
        .await
        .expect("spawn test environment");

    let alice = env.add_user("alice").await.expect("add alice");
    let mediator_did = env.mediator.did().to_string();

    // Bob lives on another mediator: his DID advertises a TSP transport endpoint
    // there (a `tsp` service, which resolves to type `TSPTransport`), and he is
    // not registered locally here.
    let (bob_remote, _secrets) = DID::generate_did_peer_with_services(
        vec![
            (PeerKeyRole::Verification, KeyType::Ed25519),
            (PeerKeyRole::Encryption, KeyType::X25519),
        ],
        Some(vec![PeerService {
            type_: "tsp".into(),
            endpoint: PeerServiceEndpoint::Uri("https://remote.example/".into()),
            id: None,
        }]),
    )
    .expect("generate bob's remote DID");

    // Alice routes to Bob via this mediator → the mediator resolves Bob's remote
    // TSP endpoint and enqueues the message for forwarding (HTTP 200 Forwarded).
    let route = vec![mediator_did, bob_remote];
    env.atm
        .tsp()
        .send_routed(&alice.profile, &route, b"forward me onward")
        .await
        .expect("mediator resolves the remote endpoint and enqueues the forward");
}
