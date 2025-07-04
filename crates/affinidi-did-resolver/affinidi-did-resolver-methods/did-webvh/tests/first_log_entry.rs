use affinidi_data_integrity::{SignedDocument, verification_proof::verify_data};
use common::load_test_file;
use did_webvh::log_entry::LogEntry;

mod common;

#[test]
fn test_first_log_entry_good() {
    let first_log_entry = load_test_file("tests/test_vectors/first_log_entry_good.jsonl");

    let first_log_entry: LogEntry =
        serde_json::from_str(&first_log_entry).expect("Failed to parse first log entry JSON");

    assert!(first_log_entry.parameters.validate(None).is_ok());


#[ignore]
#[test]
fn test_first_log_entry_deactivated_error() {
    let first_log_entry =
        load_test_file("tests/test_vectors/first_log_entry_deactivated_error.jsonl");

    let first_log_entry: LogEntry =
        serde_json::from_str(&first_log_entry).expect("Failed to parse first log entry JSON");

    assert!(first_log_entry.parameters.validate(None).is_err());
}

#[test]
fn test_first_log_entry_verify_signature() {
    let first_log_entry = load_test_file("tests/test_vectors/first_log_entry_verify_full.jsonl");

    let first_log_entry: SignedDocument =
        serde_json::from_str(&first_log_entry).expect("Failed to parse first log entry JSON");

    assert!(verify_data(&first_log_entry).is_ok());
}

#[test]
fn test_first_log_entry_verify_signature_tampered() {
    let first_log_entry =
        load_test_file("tests/test_vectors/first_log_entry_verify_tampered.jsonl");

    let first_log_entry: SignedDocument =
        serde_json::from_str(&first_log_entry).expect("Failed to parse first log entry JSON");

    assert!(verify_data(&first_log_entry).is_err());
}

#[test]
fn test_first_log_entry_verify_full() {
    let first_log_entry = load_test_file("tests/test_vectors/first_log_entry_verify_full.jsonl");

    let first_log_entry: LogEntry =
        serde_json::from_str(&first_log_entry).expect("Failed to parse first log entry JSON");

    let result = first_log_entry.verify_log_entry(None, None, None);
    println!("{:#?}", result);
    assert!(result.is_ok());
}

#[test]
fn test_first_log_entry_verify_full_error() {
    let first_log_entry =
        load_test_file("tests/test_vectors/first_log_entry_verify_tampered.jsonl");

    let first_log_entry: LogEntry =
        serde_json::from_str(&first_log_entry).expect("Failed to parse first log entry JSON");

    assert!(first_log_entry.verify_log_entry(None, None, None).is_err());
}
