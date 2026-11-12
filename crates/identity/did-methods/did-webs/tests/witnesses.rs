//! A key event log that declares witnesses is only valid once enough of them
//! have receipted it.
//!
//! The published conformance artifact has `bt: 0` and no witnesses, so this is
//! built here with real keys and real signatures rather than taken from a
//! fixture. Everything is genuine except the transport.

use affinidi_cesr::Counter;
use affinidi_did_webs::{DidWebs, Kels, resolve_from_artifacts};
use affinidi_keri_core::said;
use affinidi_keri_core::serder::Serder;
use affinidi_keri_core::version::SerializationKind;
use affinidi_keri_core::{SadValue, sad};
use affinidi_keri_crypto::Signer;

fn signer(seed: u8, transferable: bool) -> Signer {
    let code = "A";
    let s = Signer::new(code, [seed; 32].to_vec()).expect("signer");
    assert!(
        transferable || s.verfer().qb64().is_ok(),
        "signer construction"
    );
    s
}

/// Fix the `v` size before computing the SAID, so the SAID covers the bytes
/// the event is actually serialized as.
fn fix_version(sad: &mut SadValue) {
    let placeholder = "#".repeat(44);
    let (d, i) = (sad["d"].clone(), sad["i"].clone());
    let self_addressing = d == i;
    sad["d"] = sad!(placeholder);
    if self_addressing {
        sad["i"] = sad!(placeholder);
    }
    let len = serde_json::to_vec(sad).expect("serialize").len();
    sad["v"] = sad!(format!("KERI10JSON{len:06x}_"));
    sad["d"] = d;
    sad["i"] = i;
}

/// An inception naming `witness` as a backer with threshold 1.
fn witnessed_inception(controller: &Signer, next: &Signer, witness_prefix: &str) -> Serder {
    let next_digest =
        affinidi_keri_crypto::Diger::from_data("E", next.verfer().qb64().expect("qb64").as_bytes())
            .expect("digest")
            .qb64()
            .expect("qb64");

    let mut sad = sad!({
        "v": "KERI10JSON000000_",
        "t": "icp",
        "d": "",
        "i": "",
        "s": "0",
        "kt": "1",
        "k": [controller.verfer().qb64().expect("qb64")],
        "nt": "1",
        "n": [next_digest],
        "bt": "1",
        "b": [witness_prefix],
        "c": [],
        "a": [],
    });
    fix_version(&mut sad);
    said::compute_said(&mut sad, "d", "E", SerializationKind::Json).expect("said");
    Serder::new(SerializationKind::Json, sad).expect("serder")
}

/// Serialize the event with controller signatures, and optionally a witness
/// receipt couple, using the KERI 1.x counter codes.
fn stream(serder: &Serder, controller: &Signer, witness: Option<&Signer>) -> Vec<u8> {
    let mut out = serder.raw().to_vec();

    let sig = controller
        .sign_indexed(serder.raw(), 0, false)
        .expect("sign")
        .qb64()
        .expect("qb64");
    // `-A` is controller indexed signatures in the 1.x table.
    out.extend_from_slice(
        Counter::new("-A", 1)
            .expect("counter")
            .qb64()
            .expect("qb64")
            .as_bytes(),
    );
    out.extend_from_slice(sig.as_bytes());

    if let Some(w) = witness {
        // `-C` is non-transferable receipt couples in the 1.x table.
        out.extend_from_slice(
            Counter::new("-C", 1)
                .expect("counter")
                .qb64()
                .expect("qb64")
                .as_bytes(),
        );
        out.extend_from_slice(w.verfer().qb64().expect("qb64").as_bytes());
        out.extend_from_slice(
            w.sign(serder.raw())
                .expect("sign")
                .qb64()
                .expect("qb64")
                .as_bytes(),
        );
    }

    out
}

fn parts() -> (Signer, Signer, Signer) {
    // The witness is non-transferable: its prefix *is* its public key, which is
    // what lets a receipt be checked without resolving the witness first.
    (signer(1, true), signer(2, true), signer(3, false))
}

#[test]
fn a_witnessed_kel_verifies_when_the_receipt_is_present() {
    let (controller, next, witness) = parts();
    let witness_prefix = witness.verfer().qb64().expect("qb64");
    let icp = witnessed_inception(&controller, &next, &witness_prefix);

    let bytes = stream(&icp, &controller, Some(&witness));
    let kels = Kels::parse(&bytes).expect("parses");
    let state = kels
        .key_state(&icp.prefix().expect("prefix"))
        .expect("a receipted witnessed KEL must verify");

    assert_eq!(state.backer_threshold, 1);
    assert_eq!(state.backers, vec![witness_prefix]);
}

#[test]
fn a_witnessed_kel_without_its_receipt_is_refused() {
    let (controller, next, witness) = parts();
    let icp = witnessed_inception(&controller, &next, &witness.verfer().qb64().expect("qb64"));

    // Correctly signed by the controller, and complete in every other way —
    // the only thing missing is the witnessing the KEL itself demands.
    let bytes = stream(&icp, &controller, None);
    let kels = Kels::parse(&bytes).expect("parses");

    let err = kels
        .key_state(&icp.prefix().expect("prefix"))
        .expect_err("an unwitnessed event must not establish key state");
    assert!(err.to_string().contains("witness"), "{err}");
}

#[test]
fn a_receipt_from_an_undesignated_witness_does_not_count() {
    let (controller, next, witness) = parts();
    let icp = witnessed_inception(&controller, &next, &witness.verfer().qb64().expect("qb64"));

    // Someone else receipts it. They are not in the backer list, so the
    // threshold is still unmet.
    let impostor = signer(9, false);
    let bytes = stream(&icp, &controller, Some(&impostor));
    let kels = Kels::parse(&bytes).expect("parses");

    assert!(
        kels.key_state(&icp.prefix().expect("prefix")).is_err(),
        "a receipt from an undesignated witness must not satisfy the threshold",
    );
}

#[test]
fn resolution_refuses_an_unwitnessed_did() {
    let (controller, next, witness) = parts();
    let icp = witnessed_inception(&controller, &next, &witness.verfer().qb64().expect("qb64"));
    let aid = icp.prefix().expect("prefix");

    let did = DidWebs::parse(&format!("did:webs:example.com:{aid}")).expect("valid did");
    let bytes = stream(&icp, &controller, None);

    assert!(
        resolve_from_artifacts(&did, &bytes, None).is_err(),
        "resolution must not return a document for a KEL missing its witnessing",
    );
}

/// The digest an establishment event commits to for `signer`'s key.
fn commitment(signer: &Signer) -> String {
    affinidi_keri_crypto::Diger::from_data("E", signer.verfer().qb64().expect("qb64").as_bytes())
        .expect("digest")
        .qb64()
        .expect("qb64")
}

/// A rotation of `prefix` at `sn` to `key`, committing to `next`, with the
/// given witness changes and a threshold of one.
fn rotation(
    prefix: &str,
    sn: u64,
    prior: &str,
    key: &Signer,
    next: &Signer,
    cut: &[String],
    add: &[String],
) -> Serder {
    let mut sad = sad!({
        "v": "KERI10JSON000000_",
        "t": "rot",
        "d": "",
        "i": prefix,
        "s": format!("{sn:x}"),
        "p": prior,
        "kt": "1",
        "k": [key.verfer().qb64().expect("qb64")],
        "nt": "1",
        "n": [commitment(next)],
        "bt": "1",
        "br": SadValue::Array(cut.iter().map(|w| sad!(w.as_str())).collect()),
        "ba": SadValue::Array(add.iter().map(|w| sad!(w.as_str())).collect()),
        "a": [],
    });
    fix_version(&mut sad);
    said::compute_said(&mut sad, "d", "E", SerializationKind::Json).expect("said");
    Serder::new(SerializationKind::Json, sad).expect("serder")
}

#[test]
fn the_key_state_at_each_establishment_event_matches_a_replay_to_it() {
    let keys: Vec<Signer> = (1..=5).map(|seed| signer(seed, true)).collect();
    let witness = signer(20, false);
    let second = signer(21, false);
    let witness_prefix = witness.verfer().qb64().expect("qb64");
    let second_prefix = second.verfer().qb64().expect("qb64");

    let icp = witnessed_inception(&keys[0], &keys[1], &witness_prefix);
    let prefix = icp.prefix().expect("prefix");
    let mut events = vec![icp];
    // Add a witness, keep the set, then cut it again.
    let changes: [(&[String], &[String]); 3] = [
        (&[], std::slice::from_ref(&second_prefix)),
        (&[], &[]),
        (std::slice::from_ref(&second_prefix), &[]),
    ];
    for (n, (cut, add)) in changes.into_iter().enumerate() {
        let prior = events.last().expect("an event").said().expect("said");
        events.push(rotation(
            &prefix,
            n as u64 + 1,
            &prior,
            &keys[n + 1],
            &keys[n + 2],
            cut,
            add,
        ));
    }
    let bytes: Vec<u8> = events
        .iter()
        .enumerate()
        .flat_map(|(n, event)| stream(event, &keys[n], Some(&witness)))
        .collect();

    let kels = Kels::parse(&bytes).expect("parses");
    kels.key_state(&prefix).expect("the log verifies");
    let mut witness_counts = Vec::new();
    for (sn, event) in events.iter().enumerate() {
        let said = event.said().expect("said");
        let recorded = kels.key_state_at(&prefix, &said).expect("recorded");
        let replayed = Kels::parse(&bytes)
            .expect("parses")
            .as_of(&prefix, sn as u64)
            .expect("narrows")
            .key_state(&prefix)
            .expect("replays to it");
        assert_eq!(recorded.sn, replayed.sn);
        assert_eq!(recorded.said, replayed.said);
        assert_eq!(recorded.keys, replayed.keys);
        assert_eq!(recorded.next_keys, replayed.next_keys);
        assert_eq!(recorded.backers, replayed.backers);
        assert_eq!(recorded.backer_threshold, replayed.backer_threshold);
        assert_eq!(recorded.last_event_digest, replayed.last_event_digest);
        assert_eq!(recorded.next_keys, vec![commitment(&keys[sn + 1])]);
        witness_counts.push(recorded.backers.len());
    }
    assert_eq!(witness_counts, [1, 2, 2, 1]);
}
