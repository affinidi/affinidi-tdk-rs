//! Interop known-answer tests against the official DIF BBS test vectors
//! (`decentralized-identity/bbs-signature`, BLS12-381-SHA-256 ciphersuite).
//!
//! These lock `affinidi-bbs` to `draft-irtf-cfrg-bbs-signatures` byte-for-byte
//! and are the cross-implementation conformance contract (ADR 0002):
//!
//! - **Signatures are deterministic** → `sign(...)` must reproduce the fixture
//!   signature exactly.
//! - **Proofs are randomized** → a proof produced by the *reference*
//!   implementation must `proof_verify(...)` here (and invalid fixtures must
//!   fail), proving our verifier interoperates with conforming provers.
//!
//! Fixtures live in `tests/fixtures/bls12-381-sha-256/`.

use affinidi_bbs::{Proof, PublicKey, SecretKey, proof_verify, sign, verify};
use serde_json::Value;

fn hexd(s: &str) -> Vec<u8> {
    hex::decode(s).expect("fixture hex")
}

fn load(name: &str) -> Value {
    let path = format!(
        "{}/tests/fixtures/bls12-381-sha-256/{}",
        env!("CARGO_MANIFEST_DIR"),
        name
    );
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    serde_json::from_str(&text).expect("fixture json")
}

fn messages(v: &Value) -> Vec<Vec<u8>> {
    v["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| hexd(m.as_str().unwrap()))
        .collect()
}

// --- signature KATs (exact-match, deterministic) ---------------------------

fn check_signature(name: &str) {
    let v = load(name);
    let sk_bytes: [u8; 32] = hexd(v["signerKeyPair"]["secretKey"].as_str().unwrap())
        .try_into()
        .unwrap();
    let sk = SecretKey::from_bytes(&sk_bytes).unwrap();
    let pk_bytes: [u8; 96] = hexd(v["signerKeyPair"]["publicKey"].as_str().unwrap())
        .try_into()
        .unwrap();
    let pk = PublicKey::from_bytes(&pk_bytes).unwrap();
    let header = hexd(v["header"].as_str().unwrap());
    let msgs = messages(&v);
    let refs: Vec<&[u8]> = msgs.iter().map(|m| m.as_slice()).collect();

    let sig = sign(&sk, &pk, &header, &refs).unwrap();
    assert_eq!(
        hex::encode(sig.to_bytes()),
        v["signature"].as_str().unwrap(),
        "signature bytes diverge from the IETF vector ({name})"
    );
    // The reproduced signature must also verify.
    assert!(verify(&pk, &sig, &header, &refs).unwrap());
}

#[test]
fn signature_single_message_kat() {
    check_signature("signature001.json");
}

#[test]
fn signature_multi_message_kat() {
    check_signature("signature004.json");
}

// --- proof KATs (verify reference-generated proofs) ------------------------

fn check_proof(name: &str) {
    let v = load(name);
    let pk_bytes: [u8; 96] = hexd(v["signerPublicKey"].as_str().unwrap())
        .try_into()
        .unwrap();
    let pk = PublicKey::from_bytes(&pk_bytes).unwrap();
    let header = hexd(v["header"].as_str().unwrap());
    let ph = hexd(v["presentationHeader"].as_str().unwrap());
    let all = messages(&v);
    let disclosed_indexes: Vec<usize> = v["disclosedIndexes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i.as_u64().unwrap() as usize)
        .collect();
    let disclosed: Vec<&[u8]> = disclosed_indexes
        .iter()
        .map(|&i| all[i].as_slice())
        .collect();
    let proof = Proof::from_bytes(&hexd(v["proof"].as_str().unwrap()));
    let expected = v["result"]["valid"].as_bool().unwrap();

    let got =
        proof_verify(&pk, &proof, &header, &ph, &disclosed, &disclosed_indexes).unwrap_or(false);
    assert_eq!(
        got, expected,
        "proof_verify of the reference proof diverged from the vector ({name})"
    );
}

#[test]
fn proof_single_disclosed_kat() {
    check_proof("proof001.json");
}

#[test]
fn proof_partial_disclosure_kat() {
    check_proof("proof003.json");
}

#[test]
fn proof_invalid_presentation_header_kat() {
    check_proof("proof004.json");
}
