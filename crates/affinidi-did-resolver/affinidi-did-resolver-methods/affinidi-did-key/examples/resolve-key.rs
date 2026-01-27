use affinidi_did_common::DID;
use affinidi_did_key::DIDKey;
use std::env::{self};

fn main() {
    let args: Vec<String> = env::args().collect();
    let did: DID = args[1].parse().expect("Couldn't parse DID");
    let doc = DIDKey::resolve(&did).expect("Couldn't resolve DID");

    println!(
        "{}",
        serde_json::to_string_pretty(&doc).expect("Couldn't serialize DID Document")
    );
}
