//! Unified messaging example — same code, two protocols.
//!
//! Demonstrates how the `affinidi-messaging-core` traits allow the same
//! application code to work with both TSP and DIDComm transparently.
//!
//! Run with:
//!   cargo run --release -p affinidi-messaging-helpers --example unified_messaging

use affinidi_messaging_core::{MessagingProtocol, RelationshipManager};

use affinidi_messaging_didcomm::adapter::DIDCommAdapter;
use affinidi_messaging_didcomm::identity::PrivateIdentity;
use affinidi_messaging_didcomm::DIDCommAgent;

use affinidi_tsp::adapter::TspAdapter;
use affinidi_tsp::vid::PrivateVid;
use affinidi_tsp::TspAgent;

/// A protocol-agnostic messaging demo.
///
/// This function works identically regardless of whether the underlying
/// protocol is DIDComm or TSP — it only uses the `MessagingProtocol` and
/// `RelationshipManager` trait methods.
async fn demo_conversation(
    protocol_name: &str,
    alice: &(impl MessagingProtocol + RelationshipManager),
    bob: &(impl MessagingProtocol + RelationshipManager),
    alice_id: &str,
    bob_id: &str,
) {
    println!("\n─── {} ───", protocol_name);
    println!("Protocol: {}", alice.protocol());

    // Step 1: Check relationship state
    // DIDComm: always Bidirectional (implicit)
    // TSP: may already be established, or needs RFI/RFA handshake
    let state = alice.relationship_state(alice_id, bob_id).await.unwrap();
    println!("Relationship state: {state:?}");

    // Step 2: Alice sends a message to Bob
    let message = b"Hello from the unified messaging API!";
    let packed = alice.pack(message, alice_id, bob_id).await.unwrap();
    println!(
        "Alice packed {} bytes → {} bytes on the wire",
        message.len(),
        packed.len()
    );

    // Step 3: Bob unpacks the message
    let received = bob.unpack(&packed).await.unwrap();
    println!("Bob received:");
    println!("  Protocol:  {}", received.protocol);
    println!("  Sender:    {:?}", received.sender);
    println!("  Recipient: {}", received.recipient);
    println!("  Verified:  {}", received.verified);
    println!("  Encrypted: {}", received.encrypted);
    println!(
        "  Payload:   {}",
        String::from_utf8_lossy(&received.payload)
    );

    // Step 4: Try anonymous messaging (only DIDComm supports this)
    match alice.pack_anonymous(b"Anonymous test", bob_id).await {
        Ok(anon_packed) => {
            let anon_received = bob.unpack(&anon_packed).await.unwrap();
            println!("  Anonymous message: {} ({} bytes)", !anon_received.verified, anon_packed.len());
        }
        Err(e) => {
            println!("  Anonymous: not supported ({e})");
        }
    }
}

/// Set up DIDComm adapters — returns (alice_adapter, bob_adapter, alice_did, bob_did).
fn setup_didcomm() -> (DIDCommAdapter, DIDCommAdapter, String, String) {
    let mut alice_agent = DIDCommAgent::new();
    let mut bob_agent = DIDCommAgent::new();

    let alice = PrivateIdentity::generate("did:example:dc-alice");
    let bob = PrivateIdentity::generate("did:example:dc-bob");

    alice_agent.add_peer(bob.to_resolved());
    bob_agent.add_peer(alice.to_resolved());

    alice_agent.add_identity(alice);
    bob_agent.add_identity(bob);

    (
        DIDCommAdapter::new(alice_agent),
        DIDCommAdapter::new(bob_agent),
        "did:example:dc-alice".to_string(),
        "did:example:dc-bob".to_string(),
    )
}

/// Set up TSP adapters — returns (alice_adapter, bob_adapter, alice_vid, bob_vid).
fn setup_tsp() -> (TspAdapter, TspAdapter, String, String) {
    let alice_agent = TspAgent::new();
    let bob_agent = TspAgent::new();

    let alice_vid = PrivateVid::generate("did:example:tsp-alice");
    let bob_vid = PrivateVid::generate("did:example:tsp-bob");

    let alice_pub = alice_vid.to_resolved();
    let bob_pub = bob_vid.to_resolved();

    alice_agent.add_private_vid(alice_vid);
    alice_agent.add_verified_vid(bob_pub.clone());
    bob_agent.add_private_vid(bob_vid);
    bob_agent.add_verified_vid(alice_pub);

    let alice_id = "did:example:tsp-alice".to_string();
    let bob_id = "did:example:tsp-bob".to_string();

    // TSP requires an explicit relationship handshake
    let rfi = alice_agent
        .send_relationship_invite(&alice_id, &bob_id)
        .unwrap();
    bob_agent.receive(&bob_id, &rfi.bytes).unwrap();
    let digest = affinidi_tsp::message::direct::message_digest(&rfi).to_vec();
    let rfa = bob_agent
        .send_relationship_accept(&bob_id, &alice_id, digest)
        .unwrap();
    alice_agent.receive(&alice_id, &rfa.bytes).unwrap();

    let alice = TspAdapter::new(alice_agent).with_default_vid(&alice_id);
    let bob = TspAdapter::new(bob_agent).with_default_vid(&bob_id);

    (alice, bob, alice_id, bob_id)
}

#[tokio::main]
async fn main() {
    println!("╔══════════════════════════════════════════════════════╗");
    println!("║  Unified Messaging: Same API, Multiple Protocols    ║");
    println!("╚══════════════════════════════════════════════════════╝");

    // Demo with DIDComm
    let (dc_alice, dc_bob, dc_alice_id, dc_bob_id) = setup_didcomm();
    demo_conversation("DIDComm v2.1", &dc_alice, &dc_bob, &dc_alice_id, &dc_bob_id).await;

    // Demo with TSP — exact same demo function!
    let (tsp_alice, tsp_bob, tsp_alice_id, tsp_bob_id) = setup_tsp();
    demo_conversation("TSP", &tsp_alice, &tsp_bob, &tsp_alice_id, &tsp_bob_id).await;

    println!("\n═══════════════════════════════════════════════════════");
    println!("Both protocols used the identical `demo_conversation` function.");
    println!("Application code doesn't need to know which protocol is active.");
}
