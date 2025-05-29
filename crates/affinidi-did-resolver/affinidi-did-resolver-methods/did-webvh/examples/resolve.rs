use std::env;

use did_webvh::DIDWebVH;
use ssi::dids::{DID, DIDResolver};

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    // First argument is the command executed, second is the DID to parse
    if args.len() != 2 {
        eprintln!("Usage: {} <did:webvh>", args[0]);
        std::process::exit(1);
    }

    // Resolve the did:webvh DID to a Document
    let webvh = DIDWebVH;

    let output = unsafe {
        match webvh.resolve(DID::new_unchecked(args[1].as_bytes())).await {
            Ok(res) => res,
            Err(e) => {
                println!("Error: {:?}", e);
                return;
            }
        }
    };

    println!(
        "DID Document:\n{}",
        serde_json::to_string_pretty(&output.document).unwrap()
    );
    println!("Metadata: {:?}", output.metadata);
}
