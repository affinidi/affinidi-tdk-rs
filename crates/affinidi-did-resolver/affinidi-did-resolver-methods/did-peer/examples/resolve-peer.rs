use did_peer::DIDPeer;
use std::env;

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    // First argument is the command executed, second is the DID to parse
    if args.len() != 2 {
        eprintln!("Usage: {} <did:peer>", args[0]);
        std::process::exit(1);
    }

    // Resolve the did:peer DID to a Document
    let peer = DIDPeer;

    let document = match peer.resolve(&args[1]).await {
        Ok(document) => document,
        Err(e) => {
            println!("Error: {e:?}");
            return;
        }
    };

    println!(
        "DID Document:\n{}",
        serde_json::to_string_pretty(&document).unwrap()
    );
}
