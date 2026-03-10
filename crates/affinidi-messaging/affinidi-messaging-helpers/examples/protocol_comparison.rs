//! Performance comparison: TSP vs DIDComm
//!
//! Benchmarks pack, unpack, and forward operations for 1,000 messages
//! using both protocols with comparable cryptographic parameters.
//!
//! Run with:
//!   cargo run --release -p affinidi-messaging-helpers --example protocol_comparison

use std::time::{Duration, Instant};

use affinidi_messaging_didcomm::identity::PrivateIdentity;
use affinidi_messaging_didcomm::message::Message;
use affinidi_messaging_didcomm::DIDCommAgent;

use affinidi_tsp::vid::PrivateVid;
use affinidi_tsp::TspAgent;
use serde_json::json;

const NUM_MESSAGES: usize = 1_000;

// ─── Benchmark stats ───

struct BenchResult {
    name: String,
    pack_total: Duration,
    unpack_total: Duration,
    forward_total: Duration,
    pack_sizes: Vec<usize>,
}

impl BenchResult {
    fn print(&self) {
        let pack_avg = self.pack_total / NUM_MESSAGES as u32;
        let unpack_avg = self.unpack_total / NUM_MESSAGES as u32;
        let forward_avg = self.forward_total / NUM_MESSAGES as u32;
        let avg_size: usize = self.pack_sizes.iter().sum::<usize>() / self.pack_sizes.len();

        println!("\n=== {} ===", self.name);
        println!("  Messages:        {NUM_MESSAGES}");
        println!("  Avg packed size: {avg_size} bytes");
        println!(
            "  Pack   total: {:>10.2?}  avg: {:>8.2?}",
            self.pack_total, pack_avg
        );
        println!(
            "  Unpack total: {:>10.2?}  avg: {:>8.2?}",
            self.unpack_total, unpack_avg
        );
        println!(
            "  Forward total:{:>10.2?}  avg: {:>8.2?}",
            self.forward_total, forward_avg
        );
        println!(
            "  Total:        {:>10.2?}",
            self.pack_total + self.unpack_total + self.forward_total
        );
    }
}

// ─── TSP Benchmark ───

fn bench_tsp() -> BenchResult {
    let alice_agent = TspAgent::new();
    let bob_agent = TspAgent::new();
    let mediator_agent = TspAgent::new();

    let alice_vid = PrivateVid::generate("did:example:tsp-alice");
    let bob_vid = PrivateVid::generate("did:example:tsp-bob");
    let mediator_vid = PrivateVid::generate("did:example:tsp-mediator");

    let alice_pub = alice_vid.to_resolved();
    let bob_pub = bob_vid.to_resolved();
    let mediator_pub = mediator_vid.to_resolved();

    alice_agent.add_private_vid(alice_vid);
    alice_agent.add_verified_vid(bob_pub.clone());
    alice_agent.add_verified_vid(mediator_pub.clone());

    bob_agent.add_private_vid(bob_vid);
    bob_agent.add_verified_vid(alice_pub.clone());
    bob_agent.add_verified_vid(mediator_pub.clone());

    mediator_agent.add_private_vid(mediator_vid);
    mediator_agent.add_verified_vid(alice_pub);
    mediator_agent.add_verified_vid(bob_pub);

    let alice_id = "did:example:tsp-alice";
    let bob_id = "did:example:tsp-bob";
    let mediator_id = "did:example:tsp-mediator";

    // Establish relationships
    let rfi = alice_agent
        .send_relationship_invite(alice_id, bob_id)
        .unwrap();
    bob_agent.receive(bob_id, &rfi.bytes).unwrap();
    let digest = affinidi_tsp::message::direct::message_digest(&rfi).to_vec();
    let rfa = bob_agent
        .send_relationship_accept(bob_id, alice_id, digest)
        .unwrap();
    alice_agent.receive(alice_id, &rfa.bytes).unwrap();

    let rfi = alice_agent
        .send_relationship_invite(alice_id, mediator_id)
        .unwrap();
    mediator_agent.receive(mediator_id, &rfi.bytes).unwrap();
    let digest = affinidi_tsp::message::direct::message_digest(&rfi).to_vec();
    let rfa = mediator_agent
        .send_relationship_accept(mediator_id, alice_id, digest)
        .unwrap();
    alice_agent.receive(alice_id, &rfa.bytes).unwrap();

    let rfi = mediator_agent
        .send_relationship_invite(mediator_id, bob_id)
        .unwrap();
    bob_agent.receive(bob_id, &rfi.bytes).unwrap();
    let digest = affinidi_tsp::message::direct::message_digest(&rfi).to_vec();
    let rfa = bob_agent
        .send_relationship_accept(bob_id, mediator_id, digest)
        .unwrap();
    mediator_agent.receive(mediator_id, &rfa.bytes).unwrap();

    // --- Pack ---
    let mut packed_messages = Vec::with_capacity(NUM_MESSAGES);
    let mut pack_sizes = Vec::with_capacity(NUM_MESSAGES);

    let pack_start = Instant::now();
    for i in 0..NUM_MESSAGES {
        let payload = format!("TSP message #{i}: Hello from Alice to Bob!");
        let packed = alice_agent
            .send(alice_id, bob_id, payload.as_bytes())
            .unwrap();
        pack_sizes.push(packed.bytes.len());
        packed_messages.push(packed);
    }
    let pack_total = pack_start.elapsed();

    // --- Unpack ---
    let unpack_start = Instant::now();
    for packed in &packed_messages {
        let _received = bob_agent.receive(bob_id, &packed.bytes).unwrap();
    }
    let unpack_total = unpack_start.elapsed();

    // --- Forward ---
    let forward_start = Instant::now();
    for i in 0..NUM_MESSAGES {
        let payload = format!("TSP forwarded message #{i}");
        let to_mediator = alice_agent
            .send(alice_id, mediator_id, payload.as_bytes())
            .unwrap();
        let received = mediator_agent
            .receive(mediator_id, &to_mediator.bytes)
            .unwrap();
        let _to_bob = mediator_agent
            .send(mediator_id, bob_id, &received.payload)
            .unwrap();
    }
    let forward_total = forward_start.elapsed();

    BenchResult {
        name: "TSP (HPKE-Auth + Ed25519 + CESR)".to_string(),
        pack_total,
        unpack_total,
        forward_total,
        pack_sizes,
    }
}

// ─── DIDComm Benchmark ───

fn bench_didcomm() -> BenchResult {
    let mut alice_agent = DIDCommAgent::new();
    let mut bob_agent = DIDCommAgent::new();
    let mut mediator_agent = DIDCommAgent::new();

    let alice = PrivateIdentity::generate("did:example:dc-alice");
    let bob = PrivateIdentity::generate("did:example:dc-bob");
    let mediator = PrivateIdentity::generate("did:example:dc-mediator");

    alice_agent.add_peer(bob.to_resolved());
    alice_agent.add_peer(mediator.to_resolved());

    bob_agent.add_peer(alice.to_resolved());
    bob_agent.add_peer(mediator.to_resolved());

    mediator_agent.add_peer(alice.to_resolved());
    mediator_agent.add_peer(bob.to_resolved());

    alice_agent.add_identity(alice);
    bob_agent.add_identity(bob);
    mediator_agent.add_identity(mediator);

    let alice_did = "did:example:dc-alice";
    let bob_did = "did:example:dc-bob";
    let mediator_did = "did:example:dc-mediator";

    // --- Pack ---
    let mut packed_messages = Vec::with_capacity(NUM_MESSAGES);
    let mut pack_sizes = Vec::with_capacity(NUM_MESSAGES);

    let pack_start = Instant::now();
    for i in 0..NUM_MESSAGES {
        let msg = Message::new(
            "benchmark/v1",
            json!(format!(
                "DIDComm message #{i}: Hello from Alice to Bob!"
            )),
        )
        .from(alice_did)
        .to(vec![bob_did.into()]);

        let packed = alice_agent
            .pack_authcrypt(&msg, alice_did, bob_did)
            .unwrap();

        pack_sizes.push(packed.len());
        packed_messages.push(packed);
    }
    let pack_total = pack_start.elapsed();

    // --- Unpack ---
    let unpack_start = Instant::now();
    for packed in &packed_messages {
        let _result = bob_agent.unpack(packed, Some(alice_did)).unwrap();
    }
    let unpack_total = unpack_start.elapsed();

    // --- Forward (via mediator: Alice->Mediator, Mediator->Bob) ---
    let forward_start = Instant::now();
    for i in 0..NUM_MESSAGES {
        let msg = Message::new(
            "benchmark/v1",
            json!(format!("DIDComm forwarded message #{i}")),
        )
        .from(alice_did)
        .to(vec![mediator_did.into()]);

        let packed_for_mediator = alice_agent
            .pack_authcrypt(&msg, alice_did, mediator_did)
            .unwrap();

        let result = mediator_agent
            .unpack(&packed_for_mediator, Some(alice_did))
            .unwrap();

        let received = match result {
            affinidi_messaging_didcomm::message::unpack::UnpackResult::Encrypted { message, .. } => message,
            _ => panic!("expected encrypted"),
        };

        let fwd_msg = Message::new(received.typ.clone(), received.body.clone())
            .from(mediator_did)
            .to(vec![bob_did.into()]);

        let _packed_for_bob = mediator_agent
            .pack_authcrypt(&fwd_msg, mediator_did, bob_did)
            .unwrap();
    }
    let forward_total = forward_start.elapsed();

    BenchResult {
        name: "DIDComm (ECDH-1PU + X25519 + pure Rust)".to_string(),
        pack_total,
        unpack_total,
        forward_total,
        pack_sizes,
    }
}

// ─── Comparison helpers ───

fn speed_label(ratio: f64) -> String {
    if ratio >= 1.0 {
        format!("{ratio:.2}x (first is faster)")
    } else {
        format!("{ratio:.2}x (second is faster)")
    }
}

fn print_comparison(name: &str, a: &BenchResult, b: &BenchResult) {
    let pack_ratio = b.pack_total.as_nanos() as f64 / a.pack_total.as_nanos() as f64;
    let unpack_ratio = b.unpack_total.as_nanos() as f64 / a.unpack_total.as_nanos() as f64;
    let forward_ratio = b.forward_total.as_nanos() as f64 / a.forward_total.as_nanos() as f64;

    let a_avg_size: usize = a.pack_sizes.iter().sum::<usize>() / NUM_MESSAGES;
    let b_avg_size: usize = b.pack_sizes.iter().sum::<usize>() / NUM_MESSAGES;

    println!("\n--- {name} ---");
    println!("  Pack:    {}", speed_label(pack_ratio));
    println!("  Unpack:  {}", speed_label(unpack_ratio));
    println!("  Forward: {}", speed_label(forward_ratio));
    if a_avg_size > 0 && b_avg_size > 0 {
        let smaller = a_avg_size.min(b_avg_size);
        let larger = a_avg_size.max(b_avg_size);
        let pct = ((larger - smaller) as f64 / larger as f64) * 100.0;
        println!(
            "  Size:    {a_avg_size}B vs {b_avg_size}B ({pct:.0}% difference)",
        );
    }
}

// ─── Main ───

fn main() {
    println!("╔══════════════════════════════════════════════════════╗");
    println!("║  Protocol Comparison: TSP vs DIDComm                ║");
    println!("║  Messages: {NUM_MESSAGES:>6}                                  ║");
    println!("╚══════════════════════════════════════════════════════╝");

    println!("\nRunning TSP benchmark...");
    let tsp_result = bench_tsp();

    println!("Running DIDComm benchmark...");
    let didcomm_result = bench_didcomm();

    tsp_result.print();
    didcomm_result.print();

    println!("\n=== Comparison ===");
    print_comparison("TSP vs DIDComm", &tsp_result, &didcomm_result);

    println!("\nNote: Forward benchmark simulates relay via unpack + re-pack.");
    println!("TSP native nested/routed mode would be more efficient.");
    println!("Both benchmarks are fully synchronous (no async runtime overhead).");
}
