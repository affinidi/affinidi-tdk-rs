//! Two-mediator **TSP forward to a mediated recipient**: the recipient's DID
//! names its mediator **by DID**, and the sending mediator has to find the
//! transport URL in that mediator's own document.
//!
//! This is the shape a real persona/agent publishes, and the one that failed in
//! production:
//!
//! ```text
//! WARN forwarding::processor: FORWARD_FAILED
//!   endpoint=did:webvh:Qmb…:dids.firstperson.dev:firstperson-mediator
//!   error=Connection error to did:webvh:…/inbound:
//!         builder error for url (did:webvh:…/inbound)
//!   retry_count=5  → FORWARD_ABANDONED
//! ```
//!
//! The `endpoint` was a DID, because `did:` parses as a URL and a DID-valued
//! `TSPTransport` `serviceEndpoint` was taken for a transport URL all the way
//! down to reqwest.
//!
//! The two documents involved:
//!
//! ```text
//! bob        #tsp  TSPTransport  serviceEndpoint: <mediator B's DID>
//! mediator B #tsp  TSPTransport  serviceEndpoint: http://127.0.0.1:PORT/mediator/v1
//! ```
//!
//! Alice is homed on mediator A, Bob on mediator B. Alice sends Bob a TSP
//! message routed `[mediator_A, bob]` — note that mediator B is **not** in the
//! route. A unwraps its routing layer, sees the next hop is Bob (not a local
//! account), resolves Bob's document, finds a `TSPTransport` service naming
//! mediator B's DID, resolves *that* document one hop for the transport URL, and
//! forwards there. B unwraps nothing — the message is sealed Alice → Bob — sees
//! itself as the carrier for a local account, and stores it. Bob fetches and
//! unpacks it.
//!
//! `tsp_federation.rs` is the sibling case that already worked: it names
//! mediator B's DID *in the route*, so A resolves the mediator's own document
//! directly and reads a URL out of it. No indirection, so the defect never
//! showed there.
//!
//! All identities are `did:peer:2.*`, so every DID resolves locally; the only
//! real socket traffic is the forwarding processor's loopback HTTP hop A → B.
#![cfg(feature = "tsp")]

mod common;

use std::time::Duration;

use affinidi_messaging_sdk::messages::fetch::FetchOptions;
use affinidi_messaging_test_mediator::TestTopology;
use common::init_tracing;

/// Alice (on mediator A) sends a TSP message to Bob (on mediator B) naming only
/// Bob in the onward route; A discovers B's transport URL through Bob's
/// `TSPTransport` mediator DID, and Bob recovers Alice's plaintext + VID.
#[tokio::test]
async fn tsp_forward_follows_a_recipients_mediator_did() {
    init_tracing();

    let topology = TestTopology::builder()
        .mediators(2)
        .spawn()
        .await
        .expect("spawn two-mediator topology");

    let mediator_a_did = topology
        .mediator_did(0)
        .expect("mediator A did")
        .to_string();

    let alice = topology.add_user(0, "alice").await.expect("add alice on A");
    // Bob's DID advertises `#tsp` -> mediator B's *DID*. Mediator A has never
    // heard of him and is given no URL for him anywhere in the message.
    let bob = topology
        .add_tsp_mediated_user(1, "bob")
        .await
        .expect("add mediated bob on B");

    // §7.2.2 gates application messages on an existing relationship. The
    // subject here is that forwarding follows the recipient's mediator DID,
    // not relationship forming, so the relationship is seeded on every node.
    topology
        .relate_directly(&alice, &bob)
        .await
        .expect("seed the TSP relationship");

    let payload = b"hello bob, via the mediator your document names";

    // Route: alice -> mediator A (the routing-layer recipient) -> bob (the final
    // recipient, and the *only* onward hop named). Mediator B is absent by
    // design: A has to learn about it from Bob's document.
    let route = vec![mediator_a_did.clone(), bob.did.clone()];
    topology
        .node(0)
        .expect("node A")
        .atm
        .tsp()
        .send_routed(&alice.profile, &route, payload)
        .await
        .expect("alice sends a routed TSP message via mediator A onward to bob");

    // The forwarding processor delivers A -> B's /inbound asynchronously.
    let bob_env = topology.node(1).expect("node B");
    let stored = {
        let mut found = None;
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        while std::time::Instant::now() < deadline {
            let fetched = bob_env
                .atm
                .fetch_messages(&bob.profile, &FetchOptions::default())
                .await
                .expect("bob fetches messages");
            if let Some(element) = fetched.success.first()
                && let Some(msg) = element.msg.as_ref()
            {
                found = Some(msg.clone());
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        found.expect(
            "bob received the TSP message within the deadline — a DID-valued TSPTransport \
             endpoint must be followed to the mediator's document, not POSTed to",
        )
    };

    assert!(
        bob_env.atm.tsp().is_tsp(&stored),
        "the forwarded message is recognised as TSP"
    );
    let (recovered, sender) = bob_env
        .atm
        .tsp()
        .unpack(&bob.profile, &stored)
        .await
        .expect("bob unpacks the forwarded TSP message");

    assert_eq!(
        recovered, payload,
        "payload round-trips end to end across both mediators"
    );
    assert_eq!(
        sender, alice.did,
        "the original sender VID is recovered (alice), not the relaying mediator"
    );

    topology.shutdown().await.expect("shutdown topology");
}
