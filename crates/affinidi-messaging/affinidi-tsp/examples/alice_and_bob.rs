//! # Alice and Bob: A Complete TSP Messaging Example
//!
//! This example demonstrates the full lifecycle of Trust Spanning Protocol (TSP)
//! communication between two parties — Alice and Bob. It covers:
//!
//! 1. **Identity creation** — generating cryptographic key pairs (VIDs)
//! 2. **Key exchange** — sharing public keys so each party can verify the other
//! 3. **Relationship establishment** — the TSP handshake (invite → accept)
//! 4. **Secure messaging** — sending authenticated, encrypted messages
//! 5. **Bidirectional conversation** — both parties sending and receiving
//! 6. **Relationship termination** — gracefully ending the relationship
//!
//! ## TSP vs Traditional Messaging
//!
//! Unlike protocols that allow anonymous messages, TSP requires an explicit
//! relationship handshake before any data messages can be sent. This ensures
//! both parties have mutually agreed to communicate before any payload is
//! exchanged — similar to a TLS handshake, but at the identity layer.
//!
//! ## Wire Format
//!
//! Every TSP message on the wire looks like:
//! ```text
//! [envelope] [enc:32] [ciphertext] [signature:64]
//!
//! Where:
//!   envelope   = version (1B) + type (1B) + sender VID + receiver VID
//!   enc        = X25519 ephemeral public key for HPKE
//!   ciphertext = AES-128-GCM encrypted payload (authenticated)
//!   signature  = Ed25519 signature over everything preceding it
//! ```
//!
//! The envelope is **not encrypted** — intermediaries can see sender/receiver
//! VIDs for routing. But the payload is end-to-end encrypted and authenticated.
//!
//! Run with: `cargo run --example alice_and_bob`

use affinidi_tsp::{
    TspAgent,
    message::{MessageType, direct},
    relationship::RelationshipState,
    vid::PrivateVid,
};

fn main() {
    println!("=== TSP Messaging Example: Alice and Bob ===\n");

    // =========================================================================
    // Step 1: Create agents and generate identities
    // =========================================================================
    //
    // Each party creates a TspAgent (their local state) and generates a VID
    // (Verifiable Identifier). A VID bundles:
    //   - An Ed25519 signing key pair (for message authentication)
    //   - An X25519 encryption key pair (for HPKE-Auth encryption)
    //   - An identifier string (here we use DIDs, but any string works)

    let alice_agent = TspAgent::new();
    let bob_agent = TspAgent::new();

    // Generate fresh cryptographic key pairs for each identity.
    // In production, these would be persisted and tied to DID documents.
    let alice_vid = PrivateVid::generate("did:example:alice");
    let bob_vid = PrivateVid::generate("did:example:bob");

    println!("Alice's VID: {}", alice_vid.id);
    println!("Bob's VID:   {}", bob_vid.id);

    // =========================================================================
    // Step 2: Exchange public keys
    // =========================================================================
    //
    // Before communicating, each party needs the other's public key material.
    // In a real system, this happens through DID resolution — you resolve the
    // other party's DID document to get their public keys and service endpoints.
    //
    // Here we simulate this by extracting the public portion of each VID
    // and registering it with the other agent.

    // Extract public keys (safe to share — contains only public key material)
    let alice_public = alice_vid.to_resolved();
    let bob_public = bob_vid.to_resolved();

    // Register private VID (own identity) and the other party's public VID
    alice_agent.add_private_vid(alice_vid);
    alice_agent.add_verified_vid(bob_public);

    bob_agent.add_private_vid(bob_vid);
    bob_agent.add_verified_vid(alice_public);

    println!("\nPublic keys exchanged. Both parties know each other's identity.\n");

    // =========================================================================
    // Step 3: Establish a relationship (TSP handshake)
    // =========================================================================
    //
    // TSP requires an explicit relationship before data messages can flow.
    // This is a two-step handshake:
    //
    //   Alice                          Bob
    //     |                             |
    //     |--- Relationship Invite ---->|   (RFI: "I want to talk")
    //     |                             |
    //     |<-- Relationship Accept -----|   (RFA: "OK, let's talk")
    //     |                             |
    //   [Bidirectional]            [Bidirectional]
    //
    // Both messages are encrypted and signed — even the handshake is secure.

    println!("--- Step 3: Relationship Handshake ---\n");

    // Alice sends a Relationship Forming Invite (RFI) to Bob
    let rfi_packed = alice_agent
        .send_relationship_invite("did:example:alice", "did:example:bob")
        .expect("Failed to create relationship invite");

    println!(
        "Alice sent RFI ({} bytes on the wire)",
        rfi_packed.bytes.len()
    );
    println!(
        "  Alice's state: {:?}",
        alice_agent.relationship_state("did:example:alice", "did:example:bob")
    );
    assert_eq!(
        alice_agent.relationship_state("did:example:alice", "did:example:bob"),
        RelationshipState::Pending
    );

    // Bob receives and processes the RFI.
    // The agent automatically updates the relationship state.
    let rfi_received = bob_agent
        .receive("did:example:bob", &rfi_packed.bytes)
        .expect("Bob failed to receive RFI");

    assert_eq!(rfi_received.message_type, MessageType::Control);
    println!(
        "Bob received RFI from {}",
        rfi_received.sender
    );
    println!(
        "  Bob's state:   {:?}",
        bob_agent.relationship_state("did:example:bob", "did:example:alice")
    );

    // Bob accepts the invite by sending a Relationship Forming Accept (RFA).
    // The accept references the invite via its cryptographic digest (BLAKE2s-256),
    // binding the accept to the specific invite it responds to.
    let rfi_digest = direct::message_digest(&rfi_packed).to_vec();
    let rfa_packed = bob_agent
        .send_relationship_accept("did:example:bob", "did:example:alice", rfi_digest)
        .expect("Failed to create relationship accept");

    println!(
        "\nBob sent RFA ({} bytes on the wire)",
        rfa_packed.bytes.len()
    );

    // Alice receives the RFA — relationship is now bidirectional on both sides
    let rfa_received = alice_agent
        .receive("did:example:alice", &rfa_packed.bytes)
        .expect("Alice failed to receive RFA");

    assert_eq!(rfa_received.message_type, MessageType::Control);
    println!(
        "Alice received RFA from {}",
        rfa_received.sender
    );
    println!(
        "\n  Alice's state: {:?}",
        alice_agent.relationship_state("did:example:alice", "did:example:bob")
    );
    println!(
        "  Bob's state:   {:?}",
        bob_agent.relationship_state("did:example:bob", "did:example:alice")
    );
    assert_eq!(
        alice_agent.relationship_state("did:example:alice", "did:example:bob"),
        RelationshipState::Bidirectional
    );
    assert_eq!(
        bob_agent.relationship_state("did:example:bob", "did:example:alice"),
        RelationshipState::Bidirectional
    );

    println!("\nRelationship established! Both parties can now exchange messages.\n");

    // =========================================================================
    // Step 4: Send encrypted, authenticated messages
    // =========================================================================
    //
    // With a bidirectional relationship, either party can send messages.
    // Every message is:
    //   - Encrypted with HPKE-Auth (X25519 + AES-128-GCM) — only the
    //     intended recipient can decrypt it
    //   - Authenticated — the sender's identity is cryptographically bound
    //     to the ciphertext (not just signed, but part of the HPKE auth mode)
    //   - Signed with Ed25519 — integrity protection over the entire wire format

    println!("--- Step 4: Secure Messaging ---\n");

    // Alice sends a message to Bob
    let message1 = b"Hello Bob! This is a secure TSP message.";
    let packed1 = alice_agent
        .send("did:example:alice", "did:example:bob", message1)
        .expect("Alice failed to send message");

    println!(
        "Alice sent: \"{}\" ({} bytes plaintext -> {} bytes on wire)",
        String::from_utf8_lossy(message1),
        message1.len(),
        packed1.bytes.len()
    );

    // Bob receives and decrypts the message
    let received1 = bob_agent
        .receive("did:example:bob", &packed1.bytes)
        .expect("Bob failed to receive message");

    assert_eq!(received1.payload, message1);
    assert_eq!(received1.sender, "did:example:alice");
    assert_eq!(received1.message_type, MessageType::Direct);

    println!(
        "Bob received: \"{}\" (from: {})",
        String::from_utf8_lossy(&received1.payload),
        received1.sender
    );

    // =========================================================================
    // Step 5: Bob replies — bidirectional conversation
    // =========================================================================

    println!("\n--- Step 5: Bob Replies ---\n");

    let message2 = b"Hi Alice! Got your message. TSP is working great!";
    let packed2 = bob_agent
        .send("did:example:bob", "did:example:alice", message2)
        .expect("Bob failed to send reply");

    println!(
        "Bob sent: \"{}\" ({} bytes on wire)",
        String::from_utf8_lossy(message2),
        packed2.bytes.len()
    );

    let received2 = alice_agent
        .receive("did:example:alice", &packed2.bytes)
        .expect("Alice failed to receive reply");

    assert_eq!(received2.payload, message2);
    println!(
        "Alice received: \"{}\" (from: {})",
        String::from_utf8_lossy(&received2.payload),
        received2.sender
    );

    // Multiple messages can flow in either direction
    let message3 = b"Let's keep chatting securely!";
    let packed3 = alice_agent
        .send("did:example:alice", "did:example:bob", message3)
        .expect("Alice failed to send second message");

    let received3 = bob_agent
        .receive("did:example:bob", &packed3.bytes)
        .expect("Bob failed to receive second message");

    assert_eq!(received3.payload, message3);
    println!(
        "\nAlice sent: \"{}\"",
        String::from_utf8_lossy(message3)
    );
    println!(
        "Bob received: \"{}\"",
        String::from_utf8_lossy(&received3.payload)
    );

    // =========================================================================
    // Step 6: Binary data — TSP payloads are arbitrary bytes
    // =========================================================================

    println!("\n--- Step 6: Binary Data ---\n");

    // TSP payloads are raw bytes — not just text. You can send any binary data:
    // protocol buffers, CBOR, images, or application-specific formats.
    let binary_payload: Vec<u8> = (0..=255).collect();
    let packed_binary = alice_agent
        .send("did:example:alice", "did:example:bob", &binary_payload)
        .expect("Failed to send binary data");

    let received_binary = bob_agent
        .receive("did:example:bob", &packed_binary.bytes)
        .expect("Failed to receive binary data");

    assert_eq!(received_binary.payload, binary_payload);
    println!(
        "Sent and received {} bytes of binary data successfully",
        binary_payload.len()
    );

    // =========================================================================
    // Step 7: Error case — sending without a relationship
    // =========================================================================

    println!("\n--- Step 7: Security Guarantees ---\n");

    // Create a third party (Carol) who has no relationship with Alice
    let carol_agent = TspAgent::new();
    let carol_vid = PrivateVid::generate("did:example:carol");
    let carol_public = carol_vid.to_resolved();

    // Alice knows Carol's public key, but has no relationship
    alice_agent.add_verified_vid(carol_public);
    carol_agent.add_private_vid(carol_vid);

    // Attempting to send without a relationship fails
    let result = alice_agent.send("did:example:alice", "did:example:carol", b"Hey Carol!");
    assert!(result.is_err());
    println!(
        "Sending to Carol without relationship: ERROR (expected) - {}",
        result.unwrap_err()
    );

    // A message intended for Bob cannot be decrypted by Alice
    let msg_for_bob = alice_agent
        .send("did:example:alice", "did:example:bob", b"For Bob only")
        .expect("Failed to send");

    let wrong_recipient = alice_agent.receive("did:example:alice", &msg_for_bob.bytes);
    assert!(wrong_recipient.is_err());
    println!("Decrypting as wrong recipient: ERROR (expected)");

    // =========================================================================
    // Step 8: End the relationship
    // =========================================================================
    //
    // Either party can terminate the relationship at any time by sending a
    // Relationship Cancel message. After cancellation, no more data messages
    // can be sent until a new relationship is established.

    println!("\n--- Step 8: Relationship Termination ---\n");

    let cancel = alice_agent
        .send_relationship_cancel("did:example:alice", "did:example:bob")
        .expect("Failed to send cancel");

    println!(
        "Alice sent relationship cancel ({} bytes)",
        cancel.bytes.len()
    );
    assert_eq!(
        alice_agent.relationship_state("did:example:alice", "did:example:bob"),
        RelationshipState::None
    );

    // Bob receives the cancellation
    let cancel_received = bob_agent
        .receive("did:example:bob", &cancel.bytes)
        .expect("Bob failed to receive cancel");

    assert_eq!(cancel_received.message_type, MessageType::Control);
    assert_eq!(
        bob_agent.relationship_state("did:example:bob", "did:example:alice"),
        RelationshipState::None
    );
    println!("Bob received cancel. Relationship terminated.");

    // After cancellation, sending fails
    let post_cancel = alice_agent.send("did:example:alice", "did:example:bob", b"Are you there?");
    assert!(post_cancel.is_err());
    println!("Sending after cancel: ERROR (expected) - relationship no longer active");

    // =========================================================================
    // Summary
    // =========================================================================

    println!("\n=== Summary ===\n");
    println!("TSP provides:");
    println!("  - Explicit relationship consent before any data exchange");
    println!("  - End-to-end encryption (HPKE-Auth: X25519 + AES-128-GCM)");
    println!("  - Sender authentication bound to the ciphertext");
    println!("  - Ed25519 signatures for integrity protection");
    println!("  - Arbitrary binary payloads (not limited to text/JSON)");
    println!("  - Graceful relationship termination");
    println!("\nAll messages are compact binary — no JSON overhead on the wire.");
}
