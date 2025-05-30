use common::load_test_file;
use did_webvh::log_entry::LogEntry;
use std::env;

mod common;

#[test]
fn test_first_log_entry_good() {
    println!(
        "The current directory is {}",
        env::current_dir().unwrap().display()
    );
    let first_log_entry = load_test_file("tests/test_vectors/first_log_entry_good.jsonl");

    let first_log_entry: LogEntry =
        serde_json::from_str(&first_log_entry).expect("Failed to parse first log entry JSON");

    let parameters = first_log_entry
        .parameters
        .validate_udpate(None)
        .expect("Couldn't validate first log entry parameters");
}
