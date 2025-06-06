use std::env;

use did_webvh::log_entry::LogEntry;

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    // First argument is the command executed, second is the file to parse
    if args.len() != 2 {
        eprintln!("Usage: {} file", args[0]);
        std::process::exit(1);
    }

    let _ = LogEntry::get_log_entry_from_file(&args[1], None, None, None)
        .expect("Couldn't read from file");
}
