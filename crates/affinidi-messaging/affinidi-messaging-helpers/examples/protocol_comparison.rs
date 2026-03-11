//! Performance comparison: TSP vs DIDComm across payload sizes
//!
//! Benchmarks pack and unpack operations at 1KB, 100KB, 1MB, and 10MB payload
//! sizes to show how performance scales with data volume. At small payloads,
//! cryptographic setup overhead dominates; at larger payloads, symmetric
//! encryption throughput takes over.
//!
//! Run with:
//!   cargo run --release -p affinidi-messaging-helpers --example protocol_comparison

use std::time::{Duration, Instant};

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};

use affinidi_messaging_didcomm::identity::PrivateIdentity;
use affinidi_messaging_didcomm::message::Message;
use affinidi_messaging_didcomm::DIDCommAgent;

use affinidi_tsp::vid::PrivateVid;
use affinidi_tsp::TspAgent;
use serde_json::json;

/// Number of iterations per payload size.
/// Scaled down for larger payloads to keep total runtime reasonable.
fn iterations_for_size(size: usize) -> usize {
    match size {
        s if s <= 1_024 => 1_000,
        s if s <= 102_400 => 500,
        s if s <= 1_048_576 => 50,
        _ => 10,
    }
}

// ─── Payload sizes to benchmark ───

const PAYLOAD_SIZES: &[(usize, &str)] = &[
    (1_024, "1 KB"),
    (102_400, "100 KB"),
    (1_048_576, "1 MB"),
    (10_485_760, "10 MB"),
];

// ─── Benchmark result for a single payload size ───

struct SizeResult {
    payload_size: usize,
    payload_label: String,
    iterations: usize,
    tsp_pack: Duration,
    tsp_unpack: Duration,
    tsp_packed_size: usize,
    didcomm_pack: Duration,
    didcomm_unpack: Duration,
    didcomm_packed_size: usize,
}

impl SizeResult {
    fn print(&self) {
        let tsp_pack_avg = self.tsp_pack / self.iterations as u32;
        let tsp_unpack_avg = self.tsp_unpack / self.iterations as u32;
        let dc_pack_avg = self.didcomm_pack / self.iterations as u32;
        let dc_unpack_avg = self.didcomm_unpack / self.iterations as u32;

        let pack_ratio =
            self.didcomm_pack.as_nanos() as f64 / self.tsp_pack.as_nanos() as f64;
        let unpack_ratio =
            self.didcomm_unpack.as_nanos() as f64 / self.tsp_unpack.as_nanos() as f64;

        let pack_winner = if pack_ratio >= 1.0 { "TSP" } else { "DIDComm" };
        let unpack_winner = if unpack_ratio >= 1.0 { "TSP" } else { "DIDComm" };

        let size_overhead_tsp = self.tsp_packed_size as f64 - self.payload_size as f64;
        let size_overhead_dc = self.didcomm_packed_size as f64 - self.payload_size as f64;

        println!(
            "\n┌─ Payload: {} ({} bytes) ─ {} iterations ─────────────",
            self.payload_label, self.payload_size, self.iterations
        );
        println!("│");
        println!("│  {:>20} {:>14} {:>14}", "", "TSP", "DIDComm");
        println!("│  {:>20} {:>14.2?} {:>14.2?}", "Pack avg:", tsp_pack_avg, dc_pack_avg);
        println!("│  {:>20} {:>14.2?} {:>14.2?}", "Unpack avg:", tsp_unpack_avg, dc_unpack_avg);
        println!(
            "│  {:>20} {:>13} {:>13}",
            "Packed size:",
            format_bytes(self.tsp_packed_size),
            format_bytes(self.didcomm_packed_size)
        );
        println!(
            "│  {:>20} {:>13} {:>13}",
            "Overhead:",
            format_bytes(size_overhead_tsp as usize),
            format_bytes(size_overhead_dc as usize)
        );
        println!("│");
        println!(
            "│  Pack winner:   {pack_winner} ({:.2}x)",
            if pack_ratio >= 1.0 { pack_ratio } else { 1.0 / pack_ratio }
        );
        println!(
            "│  Unpack winner: {unpack_winner} ({:.2}x)",
            if unpack_ratio >= 1.0 { unpack_ratio } else { 1.0 / unpack_ratio }
        );
        println!("└────────────────────────────────────────────────────");
    }
}

fn format_bytes(bytes: usize) -> String {
    if bytes >= 10_000_000 {
        format!("{:.1} MB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 10_000 {
        format!("{:.1} KB", bytes as f64 / 1_024.0)
    } else {
        format!("{bytes} B")
    }
}

// ─── Generate payload of a given size ───

fn generate_payload(size: usize) -> Vec<u8> {
    // Repeating pattern of printable ASCII for readability in debug
    let pattern = b"The quick brown fox jumps over the lazy dog. ";
    let mut payload = Vec::with_capacity(size);
    while payload.len() < size {
        let remaining = size - payload.len();
        let chunk = remaining.min(pattern.len());
        payload.extend_from_slice(&pattern[..chunk]);
    }
    payload
}

// ─── TSP benchmark for a given payload ───

fn bench_tsp_payload(payload: &[u8], iterations: usize) -> (Duration, Duration, usize) {
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

    let alice_id = "did:example:tsp-alice";
    let bob_id = "did:example:tsp-bob";

    // Establish relationship
    let rfi = alice_agent
        .send_relationship_invite(alice_id, bob_id)
        .unwrap();
    bob_agent.receive(bob_id, &rfi.bytes).unwrap();
    let digest = affinidi_tsp::message::direct::message_digest(&rfi).to_vec();
    let rfa = bob_agent
        .send_relationship_accept(bob_id, alice_id, digest)
        .unwrap();
    alice_agent.receive(alice_id, &rfa.bytes).unwrap();

    // --- Pack ---
    let mut packed_messages = Vec::with_capacity(iterations);
    let pack_start = Instant::now();
    for _ in 0..iterations {
        let packed = alice_agent.send(alice_id, bob_id, payload).unwrap();
        packed_messages.push(packed);
    }
    let pack_total = pack_start.elapsed();

    let packed_size = packed_messages[0].bytes.len();

    // --- Unpack ---
    let unpack_start = Instant::now();
    for packed in &packed_messages {
        let _received = bob_agent.receive(bob_id, &packed.bytes).unwrap();
    }
    let unpack_total = unpack_start.elapsed();

    (pack_total, unpack_total, packed_size)
}

// ─── DIDComm benchmark for a given payload ───

fn bench_didcomm_payload(payload: &[u8], iterations: usize) -> (Duration, Duration, usize) {
    let mut alice_agent = DIDCommAgent::new();
    let mut bob_agent = DIDCommAgent::new();

    let alice = PrivateIdentity::generate("did:example:dc-alice");
    let bob = PrivateIdentity::generate("did:example:dc-bob");

    alice_agent.add_peer(bob.to_resolved());
    bob_agent.add_peer(alice.to_resolved());

    alice_agent.add_identity(alice);
    bob_agent.add_identity(bob);

    let alice_did = "did:example:dc-alice";
    let bob_did = "did:example:dc-bob";

    // Encode payload as base64 in the JSON body to ensure fair comparison
    // (both protocols encrypt the same raw bytes)
    let payload_b64 = BASE64.encode(payload);

    // --- Pack ---
    let mut packed_messages = Vec::with_capacity(iterations);
    let pack_start = Instant::now();
    for _ in 0..iterations {
        let msg = Message::new("benchmark/v1", json!({ "data": payload_b64 }))
            .from(alice_did)
            .to(vec![bob_did.into()]);

        let packed = alice_agent
            .pack_authcrypt(&msg, alice_did, bob_did)
            .unwrap();
        packed_messages.push(packed);
    }
    let pack_total = pack_start.elapsed();

    let packed_size = packed_messages[0].len();

    // --- Unpack ---
    let unpack_start = Instant::now();
    for packed in &packed_messages {
        let _result = bob_agent.unpack(packed, Some(alice_did)).unwrap();
    }
    let unpack_total = unpack_start.elapsed();

    (pack_total, unpack_total, packed_size)
}

// ─── Main ───

fn main() {
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║  Protocol Comparison: TSP vs DIDComm                     ║");
    println!("║  Payload sizes: 1KB, 100KB, 1MB, 10MB                    ║");
    println!("╠═══════════════════════════════════════════════════════════╣");
    println!("║                                                           ║");
    println!("║  TSP:     HPKE-Auth (X25519 + AES-128-GCM) + Ed25519     ║");
    println!("║           Binary CESR envelope, ~160B overhead             ║");
    println!("║                                                           ║");
    println!("║  DIDComm: ECDH-1PU (X25519) + A256CBC-HS512              ║");
    println!("║           JSON JWE envelope, ~950B overhead                ║");
    println!("║                                                           ║");
    println!("╚═══════════════════════════════════════════════════════════╝");

    let mut results = Vec::new();

    for &(size, label) in PAYLOAD_SIZES {
        let iterations = iterations_for_size(size);
        println!("\nBenchmarking {label} payload ({iterations} iterations)...");

        let payload = generate_payload(size);

        print!("  TSP...");
        let (tsp_pack, tsp_unpack, tsp_size) = bench_tsp_payload(&payload, iterations);
        println!(" done");

        print!("  DIDComm...");
        let (dc_pack, dc_unpack, dc_size) = bench_didcomm_payload(&payload, iterations);
        println!(" done");

        results.push(SizeResult {
            payload_size: size,
            payload_label: label.to_string(),
            iterations,
            tsp_pack,
            tsp_unpack,
            tsp_packed_size: tsp_size,
            didcomm_pack: dc_pack,
            didcomm_unpack: dc_unpack,
            didcomm_packed_size: dc_size,
        });
    }

    println!("\n\n══════════════════════════════════════════════════════════");
    println!("  RESULTS");
    println!("══════════════════════════════════════════════════════════");

    for result in &results {
        result.print();
    }

    // Summary table
    println!("\n\n══════════════════════════════════════════════════════════");
    println!("  SUMMARY");
    println!("══════════════════════════════════════════════════════════\n");
    println!(
        "  {:>8}  {:>12} {:>12}  {:>12} {:>12}  {:>8}",
        "Payload", "TSP Pack", "DC Pack", "TSP Unpack", "DC Unpack", "Size %"
    );
    println!("  {}", "─".repeat(76));

    for r in &results {
        let tsp_pack_avg = r.tsp_pack / r.iterations as u32;
        let dc_pack_avg = r.didcomm_pack / r.iterations as u32;
        let tsp_unpack_avg = r.tsp_unpack / r.iterations as u32;
        let dc_unpack_avg = r.didcomm_unpack / r.iterations as u32;
        let size_pct = (r.tsp_packed_size as f64 / r.didcomm_packed_size as f64) * 100.0;

        println!(
            "  {:>8}  {:>12.2?} {:>12.2?}  {:>12.2?} {:>12.2?}  {:>7.0}%",
            r.payload_label, tsp_pack_avg, dc_pack_avg, tsp_unpack_avg, dc_unpack_avg, size_pct
        );
    }

    println!("\n  Size %: TSP packed size as percentage of DIDComm packed size (lower = smaller)");
    println!("\n  Notes:");
    println!("  - TSP uses AES-128-GCM (HPKE) while DIDComm uses A256CBC-HS512");
    println!("  - TSP adds a separate Ed25519 signature; DIDComm relies on ECDH-1PU for auth");
    println!("  - TSP produces binary (CESR) output; DIDComm produces JSON (JWE) with base64");
    println!("  - DIDComm JSON body includes base64-encoded payload for fair byte comparison");
}
