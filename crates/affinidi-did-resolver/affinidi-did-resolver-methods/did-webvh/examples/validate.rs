use std::env;

use did_webvh::{DIDWebVH, log_entry::LogEntry};
use ssi::dids::{DID, DIDResolver};

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    // First argument is the command executed, second is the file to parse
    if args.len() != 2 {
        eprintln!("Usage: {} file", args[0]);
        std::process::exit(1);
    }

    let result = LogEntry::get_log_entry_from_file(&args[1], None, None, None)
        .expect("Couldn't read from file");
}
