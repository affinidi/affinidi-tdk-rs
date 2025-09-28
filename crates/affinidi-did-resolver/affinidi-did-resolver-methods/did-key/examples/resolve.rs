use affinidi_did_key::DIDKey;
use std::env::{self};

fn main() {
    let args: Vec<String> = env::args().collect();
    let doc = DIDKey::resolve(&args[1]).expect("Couldn't resolve DID");

    println!(
        "{}",
        serde_json::to_string_pretty(&doc).expect("Couldn't serialize DID Document")
    );
}
