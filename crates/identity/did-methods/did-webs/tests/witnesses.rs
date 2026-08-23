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
use affinidi_keri_crypto::Signer;
use serde_json::json;

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
fn fix_version(sad: &mut serde_json::Value) {
    let placeholder = "#".repeat(44);
    let (d, i) = (sad["d"].clone(), sad["i"].clone());
    let self_addressing = d == i;
    sad["d"] = json!(placeholder);
    if self_addressing {
        sad["i"] = json!(placeholder);
    }
    let len = serde_json::to_vec(sad).expect("serialize").len();
    sad["v"] = json!(format!("KERI10JSON{len:06x}_"));
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

    let mut sad = json!({
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
        .sign_indexed(serder.raw(), 0, true)
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
