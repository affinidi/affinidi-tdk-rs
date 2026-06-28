//! TSP interop experiment: affinidi-tsp <-> tsp_sdk 0.9.0-alpha2
//!
//! Generates ONE set of raw Ed25519 + X25519 keypairs and feeds the SAME raw
//! bytes to both libraries, then attempts a Direct-message round-trip both
//! directions.

use affinidi_tsp::message::direct as atsp;
use affinidi_tsp::message::MessageType;
use base64ct::{Base64UrlUnpadded, Encoding};
use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use tsp_sdk::cesr::CryptoType;
use tsp_sdk::definitions::Payload;
use tsp_sdk::OwnedVid;
use x25519_dalek::{PublicKey, StaticSecret};

fn hexdump(label: &str, b: &[u8]) {
    print!("{label} ({} bytes):\n  ", b.len());
    for (i, byte) in b.iter().enumerate() {
        if i > 0 && i % 32 == 0 {
            print!("\n  ");
        }
        print!("{byte:02x}");
    }
    println!();
}

struct Keys {
    sign_sk: [u8; 32],
    sign_pk: [u8; 32],
    enc_sk: [u8; 32],
    enc_pk: [u8; 32],
}

fn gen_keys() -> Keys {
    let sign = SigningKey::generate(&mut OsRng);
    let enc = StaticSecret::random_from_rng(OsRng);
    Keys {
        sign_sk: sign.to_bytes(),
        sign_pk: sign.verifying_key().to_bytes(),
        enc_sk: enc.to_bytes(),
        enc_pk: PublicKey::from(&enc).to_bytes(),
    }
}

/// Build a tsp_sdk OwnedVid from explicit raw key bytes via its serde JSON form.
fn owned_vid(id: &str, k: &Keys) -> OwnedVid {
    let json = serde_json::json!({
        "id": id,
        "transport": "tcp://127.0.0.1:1",
        "publicSigkey": Base64UrlUnpadded::encode_string(&k.sign_pk),
        "publicEnckey": Base64UrlUnpadded::encode_string(&k.enc_pk),
        "sigkey": Base64UrlUnpadded::encode_string(&k.sign_sk),
        "enckey": Base64UrlUnpadded::encode_string(&k.enc_sk),
    });
    // tsp_sdk's key-data Deserialize borrows &str, which from_value can't give —
    // serialize to a string first, then from_str.
    let s = serde_json::to_string(&json).expect("json to_string");
    serde_json::from_str(&s).expect("OwnedVid deserialize")
}

fn main() {
    println!("=== TSP interop: affinidi-tsp vs tsp_sdk 0.9.0-alpha2 ===\n");

    let alice = gen_keys();
    let bob = gen_keys();
    let alice_id = "did:web:alice.example";
    let bob_id = "did:web:bob.example";
    let payload = b"interop ping";

    // ---- Reference: what does each library produce for the same input? ----
    println!("--- Byte production comparison (Alice -> Bob, same keys) ---\n");

    // affinidi-tsp pack
    let a_packed = atsp::pack(
        payload,
        MessageType::Direct,
        alice_id,
        bob_id,
        &alice.sign_sk,
        &alice.enc_sk,
        &bob.enc_pk,
    )
    .expect("affinidi pack");
    hexdump("affinidi-tsp wire", &a_packed.bytes);
    println!("  first byte: 0x{:02x}\n", a_packed.bytes[0]);

    // tsp_sdk seal
    let alice_vid = owned_vid(alice_id, &alice);
    let bob_vid = owned_vid(bob_id, &bob);
    let r_sealed = tsp_sdk::crypto::seal(
        &alice_vid,
        bob_vid.vid(),
        None,
        Payload::Content(payload.as_slice()),
    )
    .expect("tsp_sdk seal");
    hexdump("tsp_sdk wire", &r_sealed);
    println!("  first byte: 0x{:02x}\n", r_sealed[0]);

    println!(
        "First-byte match: {}\n",
        a_packed.bytes[0] == r_sealed[0]
    );

    // ---- Direction A -> R: affinidi packs, tsp_sdk opens ----
    println!("--- A->R: affinidi-tsp pack -> tsp_sdk open ---");
    {
        // tsp_sdk open needs receiver(private)=bob, sender(verified)=alice
        let mut buf = a_packed.bytes.clone();
        match tsp_sdk::crypto::open(&bob_vid, alice_vid.vid(), &mut buf) {
            Ok((_ncd, pl, ct, st)) => {
                println!("  RESULT: OK  crypto={ct:?} sig={st:?}");
                if let Payload::Content(c) = pl {
                    println!("  payload = {:?}", String::from_utf8_lossy(c));
                }
            }
            Err(e) => println!("  RESULT: FAIL -> {e:?}"),
        }
    }
    println!();

    // ---- Direction R -> A: tsp_sdk seals, affinidi unpacks ----
    println!("--- R->A: tsp_sdk seal -> affinidi-tsp unpack ---");
    {
        // tsp_sdk: alice -> bob (alice signs/encrypts, bob receives)
        let sealed = tsp_sdk::crypto::seal(
            &alice_vid,
            bob_vid.vid(),
            None,
            Payload::Content(payload.as_slice()),
        )
        .expect("tsp_sdk seal");
        match atsp::unpack(&sealed, &bob.enc_sk, &alice.enc_pk, &alice.sign_pk) {
            Ok(u) => {
                println!("  RESULT: OK");
                println!("  payload = {:?}", String::from_utf8_lossy(&u.payload));
                println!("  sender={} receiver={}", u.sender, u.receiver);
            }
            Err(e) => println!("  RESULT: FAIL -> {e:?}"),
        }
    }
    println!();

    // ---- Diagnostic: does tsp_sdk round-trip with itself using these keys? ----
    println!("--- Sanity: tsp_sdk self round-trip with the same raw keys ---");
    {
        let mut sealed = tsp_sdk::crypto::seal(
            &alice_vid,
            bob_vid.vid(),
            None,
            Payload::Content(payload.as_slice()),
        )
        .expect("seal");
        match tsp_sdk::crypto::open(&bob_vid, alice_vid.vid(), &mut sealed) {
            Ok((_n, Payload::Content(c), ct, _st)) => {
                println!(
                    "  tsp_sdk self round-trip OK (crypto={ct:?}), payload={:?}",
                    String::from_utf8_lossy(c)
                );
                let _ = CryptoType::HpkeAuth;
            }
            Ok(_) => println!("  tsp_sdk self round-trip OK (non-content payload)"),
            Err(e) => println!("  tsp_sdk self round-trip FAIL -> {e:?}"),
        }
    }

    // ---- Diagnostic: affinidi self round-trip ----
    println!("--- Sanity: affinidi-tsp self round-trip with the same raw keys ---");
    {
        match atsp::unpack(&a_packed.bytes, &bob.enc_sk, &alice.enc_pk, &alice.sign_pk) {
            Ok(u) => println!(
                "  affinidi self round-trip OK, payload={:?}",
                String::from_utf8_lossy(&u.payload)
            ),
            Err(e) => println!("  affinidi self round-trip FAIL -> {e:?}"),
        }
    }
}
