//! A `keri.cesr` whose bodies are native CESR, keripy's default kind (P8 of
//! `did-webs-keri-v2.md` in OpenVTC/verifiable-trust-infrastructure).

use affinidi_did_webs::Kels;

#[test]
fn a_kel_with_native_bodies_reaches_keripys_key_state() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/keripy-native");
    let stream = std::fs::read(format!("{dir}/v2-basic-native.cesr")).unwrap();
    let expected: serde_json::Value =
        serde_json::from_slice(&std::fs::read(format!("{dir}/v2-basic-native.json")).unwrap())
            .unwrap();
    let k = &expected["keripy"];

    let kels = Kels::parse(&stream).expect("a native stream parses");
    let state = kels
        .key_state(k["prefix"].as_str().unwrap())
        .expect("a native KEL verifies");
    assert_eq!(state.sn, k["sn"].as_u64().unwrap());
    assert_eq!(state.last_event_digest, k["said"].as_str().unwrap());
    assert_eq!(state.said, k["establishment"]["said"].as_str().unwrap());
    let keys: Vec<&str> = k["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(state.keys, keys);
}
