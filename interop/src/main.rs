//! TSP interop harness: affinidi-tsp <-> tsp_sdk 0.10.0 (Rev 3)
//!
//! Generates ONE set of raw Ed25519 + X25519 keypairs and feeds the SAME raw
//! bytes to both libraries, then round-trips every message type in both
//! directions.
//!
//! The post-quantum case is the exception and uses the specification's own
//! published `pq_alice`/`pq_bob` instead of fresh keys. Generating an ML-DSA-65
//! key pair and a hybrid KEM key pair here would mean adding both algorithms to
//! the harness as dependencies, and the published identities are better
//! evidence anyway: a third party fixed them, so agreement is agreement with
//! the specification rather than with whichever library generated the keys.

use affinidi_tsp::message::control::ControlMessage;
use affinidi_tsp::message::direct as atsp;
use affinidi_tsp::message::routed as artd;
use affinidi_tsp::crypto::{hpke_pq, ml_dsa};
use affinidi_tsp::message::direct::{DecryptionKey, VerifyingKey};
use affinidi_tsp::message::MessageType;
use base64ct::{Base64UrlUnpadded, Encoding};
use ed25519_dalek::SigningKey;
#[allow(unused_imports)]
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
    let sign = SigningKey::generate(&mut rand_10::rng());
    let enc = StaticSecret::random_from_rng(&mut rand_10::rng());
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

/// The specification's published post-quantum identities (Rev 3 Appendix A),
/// read from the same fixture the crate's vector suite uses.
struct PqKeys {
    id: String,
    sign_sk: Box<[u8; ml_dsa::SK_LEN]>,
    sign_pk: Box<[u8; ml_dsa::PK_LEN]>,
    enc_sk: Box<[u8; hpke_pq::SK_LEN]>,
    enc_pk: Box<[u8; hpke_pq::PK_LEN]>,
    raw: serde_json::Value,
}

fn pq_keys(name: &str) -> PqKeys {
    const FIXTURE: &str =
        include_str!("../../crates/messaging/affinidi-tsp/tests/vectors/rev3.json");
    let json: serde_json::Value = serde_json::from_str(FIXTURE).expect("fixture parses");
    let id = json["identifiers"][name].clone();
    let field = |k: &str| -> Vec<u8> {
        Base64UrlUnpadded::decode_vec(id[k].as_str().expect("field present")).expect("base64url")
    };
    let sized = |v: Vec<u8>, n: usize| -> Box<[u8]> {
        assert_eq!(v.len(), n, "{name}: unexpected key length");
        v.into_boxed_slice()
    };
    PqKeys {
        id: id["id"].as_str().expect("id").to_string(),
        sign_sk: sized(field("skS"), ml_dsa::SK_LEN).try_into().unwrap(),
        sign_pk: sized(field("pkS"), ml_dsa::PK_LEN).try_into().unwrap(),
        enc_sk: sized(field("skE"), hpke_pq::SK_LEN).try_into().unwrap(),
        enc_pk: sized(field("pkE"), hpke_pq::PK_LEN).try_into().unwrap(),
        raw: id,
    }
}

/// The tsp_sdk side of a post-quantum identity.
///
/// Same shape as [`owned_vid`] plus the two key-type tags, which are what tell
/// the reference to use the hybrid KEM and ML-DSA-65 — §8.2.1 selects the KEM
/// from the recipient VID's key type, so without these the same bytes would be
/// read as X25519.
fn owned_vid_pq(k: &PqKeys) -> OwnedVid {
    let json = serde_json::json!({
        "id": k.id,
        "transport": "tcp://127.0.0.1:1",
        "sigKeyType": k.raw["sigKeyType"],
        "encKeyType": k.raw["encKeyType"],
        "publicSigkey": k.raw["pkS"],
        "publicEnckey": k.raw["pkE"],
        "sigkey": k.raw["skS"],
        "enckey": k.raw["skE"],
    });
    let s = serde_json::to_string(&json).expect("json to_string");
    serde_json::from_str(&s).expect("post-quantum OwnedVid deserialize")
}

fn main() {
    println!("=== TSP interop: affinidi-tsp vs tsp_sdk 0.10.0 (Rev 3) ===\n");

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
            Ok((pl, ct, st)) => {
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
            Payload::Content(payload.as_slice()),
        )
        .expect("tsp_sdk seal");
        match atsp::unpack(&sealed, &bob.enc_sk, &alice.sign_pk) {
            Ok(u) => {
                println!("  RESULT: OK");
                println!("  payload = {:?}", String::from_utf8_lossy(&u.payload));
                println!("  sender={} receiver={}", u.sender, u.receiver);
            }
            Err(e) => println!("  RESULT: FAIL -> {e:?}"),
        }
    }
    println!();

    // A running PASS/FAIL tally for the four interop gate cases (Routed/Nested
    // both directions). Direct is exercised above and re-checked here.
    let mut results: Vec<(&str, bool)> = Vec::new();

    // Re-run the two Direct cases into the tally so the gate report is complete.
    {
        let mut buf = a_packed.bytes.clone();
        let ok = matches!(
            tsp_sdk::crypto::open(&bob_vid, alice_vid.vid(), &mut buf),
            Ok((Payload::Content(c), _, _)) if c == payload
        );
        results.push(("Direct A->R", ok));
    }
    {
        let sealed = tsp_sdk::crypto::seal(
            &alice_vid,
            bob_vid.vid(),
            Payload::Content(payload.as_slice()),
        )
        .expect("tsp_sdk seal");
        let ok = matches!(
            atsp::unpack(&sealed, &bob.enc_sk, &alice.sign_pk),
            Ok(u) if u.payload == payload
        );
        results.push(("Direct R->A", ok));
    }

    // ---- Sealed Box, both directions ----
    //
    // The specification's own vectors already prove we can *read* a sealed box.
    // What they cannot prove is that anything else can read what we *write*: a
    // vector is a fixed message someone else produced, so it only ever exercises
    // our unpack. These two cases close that half.
    //
    // Worth the trouble for this scheme in particular. §8.3's construction has
    // three details that a self-consistent implementation gets wrong silently —
    // the HSalsa20 key-derivation step, libsodium's MAC-before-ciphertext
    // layout, and the nonce being derived from both public keys — and a sender
    // that got any of them wrong would still open its own messages perfectly.
    println!("--- Sealed Box A->R: affinidi pack -> tsp_sdk open ---");
    {
        let packed = atsp::pack_sealed_box(
            payload.as_slice(),
            MessageType::Direct,
            alice_id,
            bob_id,
            &alice.sign_sk,
            &bob.enc_pk,
        )
        .expect("affinidi pack_sealed_box");
        let mut buf = packed.bytes.clone();
        let ok = matches!(
            tsp_sdk::crypto::open(&bob_vid, alice_vid.vid(), &mut buf),
            Ok((Payload::Content(c), _, _)) if c == payload
        );
        println!("  RESULT: {}", if ok { "OK" } else { "FAIL" });
        results.push(("SealedBox A->R", ok));
    }

    println!("--- Sealed Box R->A: tsp_sdk seal -> affinidi unpack ---");
    {
        let sealed = tsp_sdk::crypto::seal_with_crypto_type(
            &alice_vid,
            bob_vid.vid(),
            Payload::Content(payload.as_slice()),
            CryptoType::SealedBox,
        )
        .expect("tsp_sdk seal under the sealed box");
        let ok = matches!(
            atsp::unpack(&sealed, &bob.enc_sk, &alice.sign_pk),
            Ok(u) if u.payload == payload
        );
        println!("  RESULT: {}", if ok { "OK" } else { "FAIL" });
        results.push(("SealedBox R->A", ok));
    }

    // Large-payload Direct: 2 MiB exercises the *large* CESR variable-data code
    // (>12 KiB) AND proves the raised MAX_FIELD_SIZE accepts what the old 1 MiB
    // cap would have rejected. Confirms the size-cap alignment interoperates.
    {
        let big = vec![0x5au8; 2 * 1024 * 1024];
        let packed = atsp::pack(
            &big,
            MessageType::Direct,
            alice_id,
            bob_id,
            &alice.sign_sk,
            &bob.enc_pk,
        )
        .expect("affinidi pack 2MiB");
        let mut buf = packed.bytes.clone();
        let ar = matches!(
            tsp_sdk::crypto::open(&bob_vid, alice_vid.vid(), &mut buf),
            Ok((Payload::Content(c), _, _)) if c == big.as_slice()
        );
        results.push(("Direct(2MiB) A->R", ar));

        let sealed = tsp_sdk::crypto::seal(
            &alice_vid,
            bob_vid.vid(),
            Payload::Content(big.as_slice()),
        )
        .expect("tsp_sdk seal 2MiB");
        let ra = matches!(
            atsp::unpack(&sealed, &bob.enc_sk, &alice.sign_pk),
            Ok(u) if u.payload == big
        );
        results.push(("Direct(2MiB) R->A", ra));
    }

    // The route hops carried inside the payload frame. They are arbitrary VID
    // byte strings as far as the framing is concerned.
    let route_strs = vec!["did:web:hop2.example".to_string(), bob_id.to_string()];
    let route_bytes: Vec<&[u8]> = route_strs.iter().map(|s| s.as_bytes()).collect();
    let inner = b"opaque inner message!";  // quadlet-aligned: a real inner is a packed message

    // ================= ROUTED =================
    println!("\n========== ROUTED ==========");

    // ---- A->R: affinidi pack_routed -> tsp_sdk open (expect RoutedMessage) ----
    println!("--- A->R: affinidi pack_routed -> tsp_sdk open ---");
    {
        let packed = artd::pack_routed(
            inner,
            &route_strs,
            alice_id,
            bob_id,
            &alice.sign_sk,
            &bob.enc_pk,
        )
        .expect("affinidi pack_routed");
        let mut buf = packed.bytes.clone();
        let ok = match tsp_sdk::crypto::open(&bob_vid, alice_vid.vid(), &mut buf) {
            Ok((Payload::RoutedMessage(hops, body), ct, st)) => {
                let hops_match = hops == route_bytes;
                let body_match = body == inner;
                println!(
                    "  RESULT: OK crypto={ct:?} sig={st:?} hops_match={hops_match} body_match={body_match}"
                );
                hops_match && body_match
            }
            Ok((other, _, _)) => {
                println!("  RESULT: FAIL -> unexpected payload kind: {other:?}");
                false
            }
            Err(e) => {
                println!("  RESULT: FAIL -> {e:?}");
                false
            }
        };
        results.push(("Routed A->R", ok));
    }

    // ---- R->A: tsp_sdk seal RoutedMessage -> affinidi unpack ----
    println!("--- R->A: tsp_sdk seal RoutedMessage -> affinidi unpack ---");
    {
        let sealed = tsp_sdk::crypto::seal(
            &alice_vid,
            bob_vid.vid(),
            Payload::RoutedMessage(route_bytes.clone(), inner.as_slice()),
        )
        .expect("tsp_sdk seal routed");
        let ok = match atsp::unpack(&sealed, &bob.enc_sk, &alice.sign_pk) {
            Ok(u) => {
                let kind_ok = u.message_type == MessageType::Routed;
                let hops_match = u.hops == route_strs;
                let body_match = u.payload == inner;
                println!(
                    "  RESULT: OK kind={:?} hops_match={hops_match} body_match={body_match}",
                    u.message_type
                );
                kind_ok && hops_match && body_match
            }
            Err(e) => {
                println!("  RESULT: FAIL -> {e:?}");
                false
            }
        };
        results.push(("Routed R->A", ok));
    }

    // ================= NESTED =================
    println!("\n========== NESTED ==========");

    // ---- A->R: affinidi pack_nested -> tsp_sdk open (expect NestedMessage) ----
    println!("--- A->R: affinidi pack_nested -> tsp_sdk open ---");
    {
        // pack_nested wraps an already-packed PackedMessage; for a framing test we
        // can wrap any opaque bytes by constructing a PackedMessage via a Direct
        // pack so the inner is a real TSP message.
        let inner_packed = atsp::pack(
            b"for bob only",
            MessageType::Direct,
            alice_id,
            bob_id,
            &alice.sign_sk,
            &bob.enc_pk,
        )
        .expect("inner pack");
        let packed = artd::pack_nested(
            &inner_packed,
            alice_id,
            bob_id,
            &alice.sign_sk,
            &bob.enc_pk,
        )
        .expect("affinidi pack_nested");
        let mut buf = packed.bytes.clone();
        let ok = match tsp_sdk::crypto::open(&bob_vid, alice_vid.vid(), &mut buf) {
            Ok((Payload::NestedMessage(body), ct, st)) => {
                let body_match = body.as_ref() == inner_packed.bytes.as_slice();
                println!("  RESULT: OK crypto={ct:?} sig={st:?} body_match={body_match}");
                body_match
            }
            Ok((other, _, _)) => {
                println!("  RESULT: FAIL -> unexpected payload kind: {other:?}");
                false
            }
            Err(e) => {
                println!("  RESULT: FAIL -> {e:?}");
                false
            }
        };
        results.push(("Nested A->R", ok));
    }

    // ---- R->A: tsp_sdk seal NestedMessage -> affinidi unpack ----
    println!("--- R->A: tsp_sdk seal NestedMessage -> affinidi unpack ---");
    {
        let nested_inner = b"nested inner bytes";
        let sealed = tsp_sdk::crypto::seal(
            &alice_vid,
            bob_vid.vid(),
            Payload::NestedMessage(nested_inner.as_slice()),
        )
        .expect("tsp_sdk seal nested");
        let ok = match atsp::unpack(&sealed, &bob.enc_sk, &alice.sign_pk) {
            Ok(u) => {
                let kind_ok = u.message_type == MessageType::Nested;
                let body_match = u.payload == nested_inner;
                let hops_empty = u.hops.is_empty();
                println!(
                    "  RESULT: OK kind={:?} body_match={body_match} hops_empty={hops_empty}",
                    u.message_type
                );
                kind_ok && body_match && hops_empty
            }
            Err(e) => {
                println!("  RESULT: FAIL -> {e:?}");
                false
            }
        };
        results.push(("Nested R->A", ok));
    }

    // ================= RELATIONSHIP CONTROL =================
    // Invite (XRFI / RequestRelationship), Accept (XRFA / AcceptRelationship),
    // Cancel (XRFD / CancelRelationship). The correlation key is the TSP thread
    // digest: SHA256 of the plaintext payload frame. affinidi exposes it as
    // `PackedMessage::thread_digest` / `UnpackedMessage::thread_digest`; the
    // reference exposes it as `seal_and_hash`'s `digest` out-param and as the
    // `thread_id` it derives when opening a proposal.
    println!("\n========== RELATIONSHIP CONTROL ==========");

    // ---- INVITE A->R: affinidi invite -> tsp_sdk open (RequestRelationship) ----
    println!("--- Invite A->R: affinidi pack -> tsp_sdk open ---");
    {
        let invite = ControlMessage::invite();
        let packed = atsp::pack(
            &invite.encode(),
            MessageType::Control,
            alice_id,
            bob_id,
            &alice.sign_sk,
            &bob.enc_pk,
        )
        .expect("affinidi pack invite");
        let mut buf = packed.bytes.clone();
        let ok = match tsp_sdk::crypto::open(&bob_vid, alice_vid.vid(), &mut buf) {
            Ok((
                Payload::RequestRelationship {
                    reply_path,
                    thread_id,
                    ..
                },
                ct,
                st,
            )) => {
                let route_empty = reply_path.is_empty();
                // The reference's derived thread_id must equal affinidi's
                // thread_digest for the same invite message.
                let digest_match = thread_id == packed.thread_digest;
                println!(
                    "  RESULT: OK crypto={ct:?} sig={st:?} route_empty={route_empty} thread_id_match={digest_match}"
                );
                route_empty && digest_match
            }
            Ok((other, _, _)) => {
                println!("  RESULT: FAIL -> unexpected payload kind: {other:?}");
                false
            }
            Err(e) => {
                println!("  RESULT: FAIL -> {e:?}");
                false
            }
        };
        results.push(("Invite A->R", ok));
    }

    // ---- INVITE R->A: tsp_sdk seal RequestRelationship -> affinidi unpack ----
    println!("--- Invite R->A: tsp_sdk seal -> affinidi unpack ---");
    {
        let mut ref_digest = [0u8; 32];
        let sealed = tsp_sdk::crypto::seal_and_hash(
            &alice_vid,
            bob_vid.vid(),
            Payload::RequestRelationship {
                thread_id: [0u8; 32],
                form: tsp_sdk::definitions::RelationshipForm::Direct,
                reply_path: Vec::new(),
            },
            Some(&mut ref_digest),
        )
        .expect("tsp_sdk seal invite");
        let ok = match atsp::unpack(&sealed, &bob.enc_sk, &alice.sign_pk) {
            Ok(u) => {
                let is_control = u.message_type == MessageType::Control;
                let control = u.control.as_ref();
                // Rev 3 narrowed the nonce to 128 bits (spec 9.2, D9); Rev 2
                // used 256. Asserting 32 here was the Rev 2 expectation.
                let nonce_ok = control
                    .and_then(|c| c.nonce.as_ref())
                    .map(|n| n.len() == 16)
                    .unwrap_or(false);
                // affinidi's thread_digest must equal the reference's seal-time
                // digest of the same message.
                let digest_match = u.thread_digest == ref_digest;
                println!(
                    "  RESULT: OK kind={:?} nonce_128={nonce_ok} thread_digest_match={digest_match}",
                    u.message_type
                );
                is_control && nonce_ok && digest_match
            }
            Err(e) => {
                println!("  RESULT: FAIL -> {e:?}");
                false
            }
        };
        results.push(("Invite R->A", ok));
    }

    // A fixed 32-byte digest used as the accept/cancel `reply` (thread_id) so we
    // can assert the value survives the round-trip in both directions.
    let reply_digest: [u8; 32] = {
        let mut d = [0u8; 32];
        for (i, b) in d.iter_mut().enumerate() {
            *b = i as u8;
        }
        d
    };

    // ---- ACCEPT A->R: affinidi accept -> tsp_sdk open (AcceptRelationship) ----
    println!("--- Accept A->R: affinidi pack -> tsp_sdk open ---");
    {
        let accept = ControlMessage::accept(reply_digest);
        let packed = atsp::pack(
            &accept.encode(),
            MessageType::Control,
            alice_id,
            bob_id,
            &alice.sign_sk,
            &bob.enc_pk,
        )
        .expect("affinidi pack accept");
        let mut buf = packed.bytes.clone();
        let ok = match tsp_sdk::crypto::open(&bob_vid, alice_vid.vid(), &mut buf) {
            Ok((
                Payload::AcceptRelationship {
                    thread_id,
                    reply_thread_id,
                    ..
                },
                ct,
                st,
            )) => {
                // thread_id is the invite this accept answers, echoed verbatim.
                let digest_match = thread_id == reply_digest;
                let _ = reply_thread_id;
                println!("  RESULT: OK crypto={ct:?} sig={st:?} reply_match={digest_match}");
                digest_match
            }
            Ok((other, _, _)) => {
                println!("  RESULT: FAIL -> unexpected payload kind: {other:?}");
                false
            }
            Err(e) => {
                println!("  RESULT: FAIL -> {e:?}");
                false
            }
        };
        results.push(("Accept A->R", ok));
    }

    // ---- ACCEPT R->A: tsp_sdk seal AcceptRelationship -> affinidi unpack ----
    println!("--- Accept R->A: tsp_sdk seal -> affinidi unpack ---");
    {
        let sealed = tsp_sdk::crypto::seal(
            &alice_vid,
            bob_vid.vid(),
            Payload::AcceptRelationship {
                // the invite being answered, echoed verbatim
                thread_id: reply_digest,
                // the accept's own self-addressing digest; the reference fills
                // this in during sealing, so the value here is a placeholder
                reply_thread_id: [0u8; 32],
                form: tsp_sdk::definitions::RelationshipForm::Direct,
            },
        )
        .expect("tsp_sdk seal accept");
        let ok = match atsp::unpack(&sealed, &bob.enc_sk, &alice.sign_pk) {
            Ok(u) => {
                let reply_match = u.control.as_ref().and_then(|c| c.reply) == Some(reply_digest);
                println!(
                    "  RESULT: OK kind={:?} reply_match={reply_match}",
                    u.message_type
                );
                u.message_type == MessageType::Control && reply_match
            }
            Err(e) => {
                println!("  RESULT: FAIL -> {e:?}");
                false
            }
        };
        results.push(("Accept R->A", ok));
    }

    // ---- CANCEL A->R: affinidi cancel -> tsp_sdk open (CancelRelationship) ----
    println!("--- Cancel A->R: affinidi pack -> tsp_sdk open ---");
    {
        let cancel = ControlMessage::cancel(reply_digest);
        let packed = atsp::pack(
            &cancel.encode(),
            MessageType::Control,
            alice_id,
            bob_id,
            &alice.sign_sk,
            &bob.enc_pk,
        )
        .expect("affinidi pack cancel");
        let mut buf = packed.bytes.clone();
        let ok = match tsp_sdk::crypto::open(&bob_vid, alice_vid.vid(), &mut buf) {
            Ok((Payload::CancelRelationship { thread_id }, ct, st)) => {
                let digest_match = thread_id == reply_digest;
                println!("  RESULT: OK crypto={ct:?} sig={st:?} reply_match={digest_match}");
                digest_match
            }
            Ok((other, _, _)) => {
                println!("  RESULT: FAIL -> unexpected payload kind: {other:?}");
                false
            }
            Err(e) => {
                println!("  RESULT: FAIL -> {e:?}");
                false
            }
        };
        results.push(("Cancel A->R", ok));
    }

    // ---- CANCEL R->A: tsp_sdk seal CancelRelationship -> affinidi unpack ----
    println!("--- Cancel R->A: tsp_sdk seal -> affinidi unpack ---");
    {
        let sealed = tsp_sdk::crypto::seal(
            &alice_vid,
            bob_vid.vid(),
            Payload::CancelRelationship {
                thread_id: reply_digest,
            },
        )
        .expect("tsp_sdk seal cancel");
        let ok = match atsp::unpack(&sealed, &bob.enc_sk, &alice.sign_pk) {
            Ok(u) => {
                let reply_match = u.control.as_ref().and_then(|c| c.reply) == Some(reply_digest);
                println!(
                    "  RESULT: OK kind={:?} reply_match={reply_match}",
                    u.message_type
                );
                u.message_type == MessageType::Control && reply_match
            }
            Err(e) => {
                println!("  RESULT: FAIL -> {e:?}");
                false
            }
        };
        results.push(("Cancel R->A", ok));
    }

    // ================= POST-QUANTUM =================
    //
    // The pairing that makes this worth running: our hand-written hybrid-KEM
    // and ML-DSA-65 path against the reference's, over identities neither of us
    // generated. The vector suite already proves we can *read* the reference's
    // post-quantum bytes; this proves it can read ours, which no published
    // vector can establish because HPKE seals with fresh randomness.
    println!("\n========== POST-QUANTUM ==========");
    {
        let pq_alice = pq_keys("pq_alice");
        let pq_bob = pq_keys("pq_bob");
        let pq_alice_vid = owned_vid_pq(&pq_alice);
        let pq_bob_vid = owned_vid_pq(&pq_bob);

        println!("--- A->R: affinidi pack_pq -> tsp_sdk open ---");
        let packed = atsp::pack_pq(
            payload,
            MessageType::Direct,
            &pq_alice.id,
            &pq_bob.id,
            &pq_alice.sign_sk,
            &pq_bob.enc_pk,
        )
        .expect("affinidi pack_pq");
        let ok = {
            let mut buf = packed.bytes.clone();
            match tsp_sdk::crypto::open(&pq_bob_vid, pq_alice_vid.vid(), &mut buf) {
                Ok((Payload::Content(c), ct, st)) => {
                    println!("  RESULT: OK crypto={ct:?} sig={st:?}");
                    c == payload
                }
                Ok((other, _, _)) => {
                    println!("  RESULT: FAIL unexpected payload {other:?}");
                    false
                }
                Err(e) => {
                    println!("  RESULT: FAIL -> {e:?}");
                    false
                }
            }
        };
        results.push(("PQ Direct A->R", ok));

        println!("--- R->A: tsp_sdk seal -> affinidi unpack_with ---");
        let sealed = tsp_sdk::crypto::seal(
            &pq_alice_vid,
            pq_bob_vid.vid(),
            Payload::Content(payload.as_slice()),
        )
        .expect("tsp_sdk post-quantum seal");
        let ok = match atsp::unpack_with(
            &sealed,
            DecryptionKey::MlKem768X25519(&pq_bob.enc_sk),
            VerifyingKey::MlDsa65(&pq_alice.sign_pk),
        ) {
            Ok(u) => {
                println!(
                    "  RESULT: OK kind={:?} confidential={}",
                    u.message_type, u.confidential
                );
                u.payload == payload && u.sender == pq_alice.id && u.receiver == pq_bob.id
            }
            Err(e) => {
                println!("  RESULT: FAIL -> {e:?}");
                false
            }
        };
        results.push(("PQ Direct R->A", ok));

        // The two libraries must disagree about a classical key here: reading a
        // hybrid ciphertext as X25519 splits `enc` at 32 bytes instead of 1120,
        // and that has to fail rather than produce something.
        let classical = atsp::unpack(&sealed, &bob.enc_sk, &alice.sign_pk);
        println!(
            "  post-quantum bytes under classical keys: {}",
            if classical.is_err() { "refused" } else { "ACCEPTED (wrong)" }
        );
        results.push(("PQ not read as classical", classical.is_err()));
    }

    // ================= SUMMARY =================
    println!("\n========== INTEROP GATE SUMMARY ==========");
    let mut all_ok = true;
    for (name, ok) in &results {
        println!("  {:<24} {}", name, if *ok { "PASS" } else { "FAIL" });
        all_ok &= ok;
    }
    println!(
        "  ----\n  OVERALL: {}",
        if all_ok { "PASS" } else { "FAIL" }
    );

    // ---- Diagnostic: does tsp_sdk round-trip with itself using these keys? ----
    println!("\n--- Sanity: tsp_sdk self round-trip with the same raw keys ---");
    {
        let mut sealed = tsp_sdk::crypto::seal(
            &alice_vid,
            bob_vid.vid(),
            Payload::Content(payload.as_slice()),
        )
        .expect("seal");
        match tsp_sdk::crypto::open(&bob_vid, alice_vid.vid(), &mut sealed) {
            Ok((Payload::Content(c), ct, _st)) => {
                println!(
                    "  tsp_sdk self round-trip OK (crypto={ct:?}), payload={:?}",
                    String::from_utf8_lossy(c)
                );
                // `CryptoType` is now used in earnest by the sealed-box cases.
            }
            Ok(_) => println!("  tsp_sdk self round-trip OK (non-content payload)"),
            Err(e) => println!("  tsp_sdk self round-trip FAIL -> {e:?}"),
        }
    }

    // ---- Diagnostic: affinidi self round-trip ----
    println!("--- Sanity: affinidi-tsp self round-trip with the same raw keys ---");
    {
        match atsp::unpack(&a_packed.bytes, &bob.enc_sk, &alice.sign_pk) {
            Ok(u) => println!(
                "  affinidi self round-trip OK, payload={:?}",
                String::from_utf8_lossy(&u.payload)
            ),
            Err(e) => println!("  affinidi self round-trip FAIL -> {e:?}"),
        }
    }
}
