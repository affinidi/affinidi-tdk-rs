//! Cross-mediator TSP delivery for service-less (`did:key`-style) peers (#577 P1).
//!
//! - The metadata-private carriage primitive (`send_nested_routed`) delivers a
//!   Nested-wrapped Direct message across two mediators, with the recipient
//!   hidden from the sender's mediator (it is not a route hop).
//! - `atm.send_to` routes cross-mediator automatically when the peer's mediator
//!   is known and differs from the sender's.
//! - The peer's mediator is learned from a routed relationship invite
//!   (`form_relationship_routed` → `record_incoming_control`).
#![cfg(feature = "tsp")]

use affinidi_messaging_didcomm::Message;
use affinidi_messaging_sdk::messages::fetch::FetchOptions;
use affinidi_messaging_sdk::{SendProtocol, TspPolicy, TspSupport};
use affinidi_messaging_test_mediator::{TestEnvironment, topology::TestTopology};
use serde_json::json;
use std::time::Duration;
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

/// Poll a node's mailbox until a message lands (cross-mediator forwarding is
/// asynchronous), returning the stored message.
async fn poll_inbox(
    env: &TestEnvironment,
    profile: &std::sync::Arc<affinidi_messaging_sdk::profiles::ATMProfile>,
) -> String {
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    while std::time::Instant::now() < deadline {
        let fetched = env
            .atm
            .fetch_messages(profile, &FetchOptions::default())
            .await
            .expect("fetch messages");
        if let Some(msg) = fetched.success.first().and_then(|e| e.msg.as_ref()) {
            return msg.clone();
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!("no message received within the deadline");
}

/// The carriage primitive: `send_nested_routed` delivers across two mediators
/// while the recipient stays off the route (hidden from the sender's mediator).
#[tokio::test]
async fn send_nested_routed_delivers_cross_mediator() {
    let topology = TestTopology::builder()
        .mediators(2)
        .spawn()
        .await
        .expect("spawn two-mediator topology");
    let mediator_a = topology.mediator_did(0).expect("mediator A").to_string();
    let mediator_b = topology.mediator_did(1).expect("mediator B").to_string();
    let alice = topology.add_user(0, "alice").await.expect("add alice on A");
    let bob = topology.add_user(1, "bob").await.expect("add bob on B");

    // §7.2.2 gates application messages on an existing relationship. The
    // subject here is delivery across mediators, not relationship forming, so
    // the relationship is seeded on every node — each side's SDK has its own
    // store, and one alone would leave the other discarding.
    topology
        .relate_directly(&alice, &bob)
        .await
        .expect("seed the TSP relationship");

    let payload = b"hello bob, nested over routed, recipient hidden from mediator A";
    let route = vec![mediator_a, mediator_b];
    topology
        .node(0)
        .unwrap()
        .atm
        .tsp()
        .send_nested_routed(&alice.profile, &route, &bob.did, payload)
        .await
        .expect("alice sends nested+routed to bob on B");

    let bob_env = topology.node(1).unwrap();
    let stored = poll_inbox(bob_env, &bob.profile).await;
    let (recovered, sender) = bob_env
        .atm
        .tsp()
        .unpack(&bob.profile, &stored)
        .await
        .expect("bob unpacks");
    assert_eq!(recovered, payload);
    assert_eq!(sender, alice.did);

    topology.shutdown().await.expect("shutdown");
}

/// `send_to` routes cross-mediator automatically when the peer's mediator is
/// known (here injected out-of-band) and differs from the sender's.
#[tokio::test]
async fn send_to_routes_cross_mediator_when_peer_mediator_known() {
    let topology = TestTopology::builder()
        .mediators(2)
        .tsp_policy(TspPolicy::Preferred)
        .spawn()
        .await
        .expect("spawn two-mediator topology with Preferred policy");
    let mediator_b = topology.mediator_did(1).expect("mediator B").to_string();
    let alice = topology.add_user(0, "alice").await.expect("add alice on A");
    let bob = topology.add_user(1, "bob").await.expect("add bob on B");

    // §7.2.2 gates application messages on an existing relationship. The
    // subject here is delivery across mediators, not relationship forming, so
    // the relationship is seeded on every node — each side's SDK has its own
    // store, and one alone would leave the other discarding.
    topology
        .relate_directly(&alice, &bob)
        .await
        .expect("seed the TSP relationship");
    let a = topology.node(0).unwrap();

    // Alice knows bob speaks TSP and lives on mediator B (learned out-of-band).
    a.atm
        .tsp()
        .set_peer_capability(&alice.profile, &bob.did, TspSupport::Supported)
        .await
        .expect("set bob supported");
    a.atm
        .tsp()
        .set_peer_mediator(&alice.profile, &bob.did, Some(mediator_b.clone()))
        .await
        .expect("set bob's mediator");

    let msg = basic_message(&alice.did, &bob.did, "cross-mediator via send_to");
    let via = a
        .atm
        .send_to(&alice.profile, &msg, &bob.did, Some(&alice.did), None)
        .await
        .expect("send_to bob");
    assert_eq!(via, SendProtocol::Tsp, "known peer capability → TSP");

    // Bob, on mediator B, receives and unpacks the routed message.
    let bob_env = topology.node(1).unwrap();
    let stored = poll_inbox(bob_env, &bob.profile).await;
    let (payload, sender) = bob_env
        .atm
        .tsp()
        .unpack(&bob.profile, &stored)
        .await
        .expect("bob unpacks");
    assert_eq!(sender, alice.did);
    let recovered: Message = serde_json::from_slice(&payload).expect("payload is a Message");
    assert_eq!(
        recovered.body,
        json!({ "content": "cross-mediator via send_to" })
    );

    topology.shutdown().await.expect("shutdown");
}

/// A **routed** invite advertises the inviter's mediator; the recipient learns
/// and caches it via `record_incoming_control`, so a later `send_to` can route
/// to that peer. (Single mediator — this exercises the learning wire path; the
/// cross-mediator delivery is covered above.)
#[tokio::test]
async fn routed_invite_teaches_peer_mediator() {
    let env = TestEnvironment::spawn_with_tsp_policy(TspPolicy::Preferred)
        .await
        .expect("spawn env with Preferred policy");
    let alice = env.add_user("alice").await.expect("add alice");
    let bob = env.add_user("bob").await.expect("add bob");
    // No relationship is seeded here: this test forms one, and §7.2.2 does not
    // gate the control messages that do the forming.

    // Alice's own mediator DID — what her routed invite advertises.
    let (_, alice_mediator) = alice.profile.dids().expect("alice dids");
    let alice_mediator = alice_mediator.to_string();

    // Alice forms a relationship with a routed invite (advertises her mediator).
    env.atm
        .tsp()
        .form_relationship_routed(&alice.profile, &bob.did)
        .await
        .expect("alice forms routed relationship");

    // Bob fetches and records the invite.
    let stored = poll_inbox(&env, &bob.profile).await;
    let invite_qb2 = env.atm.tsp().decode(&stored).expect("decode invite");
    let (invite, sender, _digest) = env
        .atm
        .tsp()
        .unpack_control(&bob.profile, &invite_qb2)
        .await
        .expect("bob unpacks the invite control");
    assert_eq!(sender, alice.did);
    env.atm
        .tsp()
        .record_incoming_control(&bob.profile, &alice.did, &invite)
        .await
        .expect("bob records the invite");

    // Bob now knows alice's mediator.
    let cap = env
        .atm
        .tsp()
        .peer_capability(&bob.profile, &alice.did)
        .await
        .unwrap()
        .expect("bob has a capability record for alice");
    assert_eq!(
        cap.mediator,
        Some(alice_mediator),
        "bob learned alice's mediator from the routed invite"
    );
}

/// Rev 3 §7.2.4, relationship forming over a routed path: an invite that
/// carries a `Reply_Path` obliges the responder to send its accept back over
/// that path — "If the `Reply_Path` is present, then `B` MUST use the routed
/// path specified by `Reply_Path` to send the `TSP_RFA` message".
///
/// Sending the accept directly is not merely a missed optimisation. It
/// discloses to the inviter, and to anyone watching the wire, an endpoint that
/// the route exists to keep out of view. So this asserts the accept arrives and
/// completes the relationship having gone through the mediator as a routed
/// message, rather than as a direct one.
#[tokio::test]
async fn an_accept_travels_the_reply_path_the_invite_supplied() {
    let env = TestEnvironment::spawn_with_tsp_policy(TspPolicy::Preferred)
        .await
        .expect("spawn env with Preferred policy");
    let alice = env.add_user("alice").await.expect("add alice");
    let bob = env.add_user("bob").await.expect("add bob");

    let (_, alice_mediator) = alice.profile.dids().expect("alice dids");
    let alice_mediator = alice_mediator.to_string();

    // Alice invites over a routed path: her mediator, then herself. §5.3.3 puts
    // the destination's own VID last, so the exit delivers to her.
    env.atm
        .tsp()
        .form_relationship_routed(&alice.profile, &bob.did)
        .await
        .expect("alice forms a routed relationship");

    let stored = poll_inbox(&env, &bob.profile).await;
    let invite_qb2 = env.atm.tsp().decode(&stored).expect("decode invite");
    let (invite, sender, invite_digest) = env
        .atm
        .tsp()
        .unpack_control(&bob.profile, &invite_qb2)
        .await
        .expect("bob unpacks the invite");
    assert_eq!(sender, alice.did);

    // The invite carries the path, ending at Alice herself.
    assert_eq!(
        invite.route,
        vec![alice_mediator.clone(), alice.did.clone()],
        "the reply path names alice's mediator, then alice"
    );

    let incoming = env
        .atm
        .tsp()
        .record_incoming_control(&bob.profile, &alice.did, &invite)
        .await
        .expect("bob records the invite");
    assert_eq!(
        incoming.reply_path,
        vec![alice_mediator, alice.did.clone()],
        "the reply path is reported to the caller as well as kept"
    );

    // Bob accepts. He passes no route: the stored reply path is used without
    // being asked, because §7.2.4 makes it mandatory rather than optional.
    env.atm
        .tsp()
        .accept_relationship(&bob.profile, &alice.did, invite_digest)
        .await
        .expect("bob accepts over the reply path");

    // The accept reached Alice through the mediator and completes her side.
    let stored = poll_inbox(&env, &alice.profile).await;
    let accept_qb2 = env.atm.tsp().decode(&stored).expect("decode accept");
    let (accept, accept_sender, _) = env
        .atm
        .tsp()
        .unpack_control(&alice.profile, &accept_qb2)
        .await
        .expect("alice unpacks the accept");
    assert_eq!(accept_sender, bob.did);

    let final_state = env
        .atm
        .tsp()
        .record_incoming_control(&alice.profile, &bob.did, &accept)
        .await
        .expect("alice records the accept");
    assert_eq!(
        final_state.state,
        affinidi_messaging_sdk::protocols::tsp::RelationshipState::Bidirectional
    );
}

/// Rev 3 §5.3.3: a relayed endpoint-to-endpoint VID is not written to disk.
///
/// > the intermediaries SHOULD not process the endpoint-to-endpoint VIDs
/// > `VID_a2` and `VID_b2` and MUST NOT store `VID_a2` and `VID_b2` in any
/// > persistent storage
///
/// Alice sends a nested message *to mediator A*, carrying an inner message
/// sealed to bob, who lives on mediator B. A unwraps the nesting — that is what
/// a metadata-privacy intermediary is for — sees a recipient it does not hold,
/// and queues the inner for delivery to B. The forward queue is durable: a
/// retry queue that survives restarts and holds entries until they expire. So
/// whatever A writes there, it keeps.
///
/// The property under test is an *absence*, which is why this reaches into the
/// store rather than watching messages arrive. A retained VID leaves no trace
/// in anything delivered; the only place the requirement can be checked is the
/// thing that does the retaining.
///
/// Forwarding is disabled on both mediators so the entry stays put. This is
/// about what gets written, not whether it is delivered, and a running
/// processor would drain the queue underneath the assertion.
#[tokio::test]
async fn a_relayed_endpoint_to_endpoint_vid_is_not_persisted() {
    let topology = TestTopology::builder()
        .mediators(2)
        .configure_each(|b| b.enable_forwarding(false))
        .spawn()
        .await
        .expect("spawn two-mediator topology");
    let mediator_a = topology.mediator_did(0).expect("mediator A").to_string();

    let alice = topology.add_user(0, "alice").await.expect("add alice on A");
    // Bob must publish a TSPTransport endpoint, or mediator A has nowhere to
    // forward to and refuses before ever building a queue entry.
    let bob = topology
        .add_tsp_mediated_user(1, "bob")
        .await
        .expect("add bob on B");
    topology
        .relate_directly(&alice, &bob)
        .await
        .expect("seed the TSP relationship");

    topology
        .node(0)
        .unwrap()
        .atm
        .tsp()
        .send_nested(
            &alice.profile,
            &mediator_a,
            &bob.did,
            b"the mediator must not keep bob's VID",
        )
        .await
        .expect("alice sends a nested message via her own mediator");

    // Read what mediator A queued.
    let store = topology.node(0).unwrap().mediator.store();
    let mut entries = Vec::new();
    for _ in 0..40 {
        entries = store
            .forward_queue_read(
                "e2e-privacy",
                "test",
                10,
                std::time::Duration::from_millis(100),
            )
            .await
            .expect("read the forward queue");
        if !entries.is_empty() {
            break;
        }
    }
    assert_eq!(
        entries.len(),
        1,
        "mediator A should have queued exactly one forward"
    );
    let entry = &entries[0];

    assert!(
        entry.to_did.is_empty(),
        "bob's VID must not be in the durable queue, found {:?}",
        entry.to_did
    );

    // What delivery actually needs is still there, so withholding the VID costs
    // nothing operationally.
    assert_eq!(
        entry.to_did_hash,
        sha256::digest(bob.did.as_bytes()),
        "the hash identifies the destination"
    );
    assert!(
        !entry.endpoint_url.is_empty(),
        "the endpoint was resolved at enqueue time, so the VID is not needed again"
    );

    // Belt and braces: the VID must not have survived anywhere else in the
    // record — not in the sender field, and not inside the relayed bytes, which
    // are the inner message's *ciphertext* and envelope.
    let serialized = serde_json::to_string(entry).expect("serialize the queue entry");
    assert!(
        !serialized.contains(&bob.did),
        "bob's VID appears somewhere in the persisted entry"
    );

    topology.shutdown().await.expect("shutdown");
}

/// Alice on mediator A invites bob on mediator B with a routed invite, and
/// bob accepts over the reply path `[A, alice]` it carries — returning the
/// accept from B, a mediator the path does not start at.
///
/// Keyring VTI-41. Before the fix the SDK sealed the routing layer to the
/// path's first hop, A, and posted it to bob's own mediator B, which is the
/// only place `send_raw` posts to. B saw a frame not addressed to itself,
/// took it for Direct delivery to a local account, and refused it with 403
/// "recipient is not local to this mediator". Now B is prepended — Rev 3
/// §7.2.4 lets the responder add hops of its own — so the accept travels
/// `[B, A, alice]`: B relays it to A over the wire, and A delivers it.
///
/// The invite leg crosses mediators too. Alice knows bob's mediator (set out
/// of band here), so her invite is routed `[A, B, bob]` rather than sent
/// Direct to an account A does not hold.
///
/// Relay admission is set explicitly rather than left to the topology's
/// defaults: the hop from B arrives at A with no Authorization header, and A
/// admits it only because `enable_inter_mediator_relay` is on. The topology
/// also grants `SEND_FORWARDED` in `global_acl_default`, which is the legacy
/// implicit way to the same thing; naming the flag keeps the dependency
/// visible. The next test turns it off.
#[tokio::test]
async fn an_accept_crosses_mediators_over_the_reply_path() {
    let topology = TestTopology::builder()
        .mediators(2)
        .tsp_policy(TspPolicy::Preferred)
        .configure_each(|b| b.enable_inter_mediator_relay(true))
        .spawn()
        .await
        .expect("spawn two relay-enabled mediators");
    let mediator_a = topology.mediator_did(0).expect("mediator A").to_string();
    let mediator_b = topology.mediator_did(1).expect("mediator B").to_string();
    let alice = topology.add_user(0, "alice").await.expect("add alice on A");
    let bob = topology.add_user(1, "bob").await.expect("add bob on B");
    let a = topology.node(0).unwrap();
    let b = topology.node(1).unwrap();

    let bob_accepts = invite_and_accept(a, b, &alice, &bob, &mediator_a, &mediator_b).await;
    bob_accepts.expect("bob accepts over the reply path");

    // The accept came back B → A and completes alice's side.
    let stored = poll_inbox(a, &alice.profile).await;
    let accept_qb2 = a.atm.tsp().decode(&stored).expect("decode accept");
    let (accept, accept_sender, _) = a
        .atm
        .tsp()
        .unpack_control(&alice.profile, &accept_qb2)
        .await
        .expect("alice unpacks the accept");
    assert_eq!(accept_sender, bob.did);
    let recorded = a
        .atm
        .tsp()
        .record_incoming_control(&alice.profile, &bob.did, &accept)
        .await
        .expect("alice records the accept");
    assert_eq!(
        recorded.state,
        affinidi_messaging_sdk::protocols::tsp::RelationshipState::Bidirectional
    );

    topology.shutdown().await.expect("shutdown");
}

/// The operator-side half of VTI-41: the receiving mediator has to admit the
/// relayed hop. With A not configured as a relay (`enable_inter_mediator_relay`
/// off, and no `SEND_FORWARDED` in its `global_acl_default`), the accept bob's
/// mediator relays to A is refused, and the refusal is a clear one — an HTTP
/// 401 at A's `/inbound` — rather than a delivery that silently happens.
///
/// B's forwarding processor is turned off so the relayed frame stays in its
/// queue, where the test can pick it up and present it to A exactly as the
/// processor would (unauthenticated `application/tsp` POST to the queued
/// endpoint). With the processor running, the refusal would surface only as
/// an abandoned forward on B — reported to B itself, since B re-sealed the
/// layer as its own sender — so bob's `accept_relationship` returning `Ok`
/// means "B took it", not "alice has it".
#[tokio::test]
async fn an_accept_is_refused_when_the_inviters_mediator_does_not_admit_relays() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let node = Arc::new(AtomicUsize::new(0));
    let topology = TestTopology::builder()
        .mediators(2)
        .tsp_policy(TspPolicy::Preferred)
        .configure_each(move |b| match node.fetch_add(1, Ordering::SeqCst) {
            // A: not a relay. Its users are registered with their own
            // allow-all ACL, so only anonymous inbound is affected.
            0 => b
                .global_acl_default(affinidi_messaging_test_mediator::acl::deny_all())
                .enable_inter_mediator_relay(false),
            // B: a relay, with its forwarding processor off so the accept
            // it relays towards A stays queued.
            _ => b.enable_inter_mediator_relay(true).enable_forwarding(false),
        })
        .spawn()
        .await
        .expect("spawn the two mediators");
    let mediator_a = topology.mediator_did(0).expect("mediator A").to_string();
    let mediator_b = topology.mediator_did(1).expect("mediator B").to_string();
    let alice = topology.add_user(0, "alice").await.expect("add alice on A");
    let bob = topology.add_user(1, "bob").await.expect("add bob on B");
    let a = topology.node(0).unwrap();
    let b = topology.node(1).unwrap();

    // B accepts the routed accept from its own authenticated user and queues
    // it for A. This is not the failure point, and not proof of delivery.
    invite_and_accept(a, b, &alice, &bob, &mediator_a, &mediator_b)
        .await
        .expect("B queues bob's accept for A");

    let store = b.mediator.store();
    let mut entries = Vec::new();
    for _ in 0..40 {
        entries = store
            .forward_queue_read("vti41", "test", 10, Duration::from_millis(100))
            .await
            .expect("read B's forward queue");
        if !entries.is_empty() {
            break;
        }
    }
    assert_eq!(entries.len(), 1, "B queued exactly one forward, to A");
    let entry = &entries[0];
    assert_eq!(entry.to_did, mediator_a, "the next hop is alice's mediator");

    let qb2 = base64::Engine::decode(
        &base64::prelude::BASE64_URL_SAFE_NO_PAD,
        entry.message.as_bytes(),
    )
    .expect("a TSP forward is queued as base64url(qb2)");
    let inbound = format!("{}/inbound", entry.endpoint_url.trim_end_matches('/'));
    let response = reqwest::Client::new()
        .post(&inbound)
        .header("Content-Type", "application/tsp")
        .body(qb2)
        .send()
        .await
        .expect("POST the relayed hop to A");
    assert_eq!(
        response.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "A must refuse an unauthenticated relay hop when relay admission is off"
    );

    // And nothing reached alice.
    let fetched = a
        .atm
        .fetch_messages(&alice.profile, &FetchOptions::default())
        .await
        .expect("alice fetches");
    assert!(
        fetched.success.is_empty(),
        "no accept may reach alice through a mediator that refuses relays"
    );

    topology.shutdown().await.expect("shutdown");
}

/// The shared first half of the two VTI-41 tests: alice (on A) sends bob (on
/// B) a routed invite; bob receives it, checks the reply path, records it and
/// accepts. Returns the result of bob's `accept_relationship`.
async fn invite_and_accept(
    a: &TestEnvironment,
    b: &TestEnvironment,
    alice: &affinidi_messaging_test_mediator::TestUser,
    bob: &affinidi_messaging_test_mediator::TestUser,
    mediator_a: &str,
    mediator_b: &str,
) -> Result<
    affinidi_messaging_sdk::protocols::tsp::RelationshipState,
    affinidi_messaging_sdk::errors::ATMError,
> {
    // Alice knows where bob lives, so her invite is routed to B.
    a.atm
        .tsp()
        .set_peer_mediator(&alice.profile, &bob.did, Some(mediator_b.to_string()))
        .await
        .expect("alice learns bob's mediator");
    a.atm
        .tsp()
        .form_relationship_routed(&alice.profile, &bob.did)
        .await
        .expect("alice sends a routed invite across mediators");

    let stored = poll_inbox(b, &bob.profile).await;
    let invite_qb2 = b.atm.tsp().decode(&stored).expect("decode invite");
    let (invite, sender, invite_digest) = b
        .atm
        .tsp()
        .unpack_control(&bob.profile, &invite_qb2)
        .await
        .expect("bob unpacks the invite");
    assert_eq!(sender, alice.did);
    assert_eq!(
        invite.route,
        vec![mediator_a.to_string(), alice.did.clone()],
        "the reply path starts at alice's mediator, not bob's"
    );
    b.atm
        .tsp()
        .record_incoming_control(&bob.profile, &alice.did, &invite)
        .await
        .expect("bob records the invite");

    b.atm
        .tsp()
        .accept_relationship(&bob.profile, &alice.did, invite_digest)
        .await
}
