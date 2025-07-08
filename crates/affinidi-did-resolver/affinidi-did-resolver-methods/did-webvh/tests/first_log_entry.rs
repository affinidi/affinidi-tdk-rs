use affinidi_data_integrity::{DataIntegrityProof, verification_proof::verify_data};
use common::load_test_file;
use did_webvh::log_entry::LogEntry;

mod common;

#[test]
fn test_first_log_entry_good() {
    let first_log_entry = load_test_file("tests/test_vectors/first_log_entry_good.jsonl");

    let first_log_entry: LogEntry =
        serde_json::from_str(&first_log_entry).expect("Failed to parse first log entry JSON");

    assert!(first_log_entry.parameters.validate(None).is_ok());
}

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

    let mut first_log_entry =
        serde_json::to_value(&first_log_entry).expect("Failed to parse first log entry JSON");

    let proof: DataIntegrityProof = serde_json::from_value(
        first_log_entry
            .get("proof")
            .expect("Failed to get proof from first log entry")
            .clone(),
    )
    .expect("Couldn't extra proof");

    first_log_entry
        .as_object_mut()
        .expect("Failed to get object from first log entry")
        .remove("proof");

    assert!(verify_data(&first_log_entry, None, &proof).is_ok());
}

#[test]
fn test_first_log_entry_verify_signature_tampered() {
    let first_log_entry =
        load_test_file("tests/test_vectors/first_log_entry_verify_tampered.jsonl");

    let mut first_log_entry =
        serde_json::to_value(&first_log_entry).expect("Failed to parse first log entry JSON");

    let proof: DataIntegrityProof = serde_json::from_value(
        first_log_entry
            .get("proof")
            .expect("Failed to get proof from first log entry")
            .clone(),
    )
    .expect("Couldn't extra proof");

    first_log_entry
        .as_object_mut()
        .expect("Failed to get object from first log entry")
        .remove("proof");

    assert!(verify_data(&first_log_entry, None, &proof).is_err());
}

#[test]
fn test_first_log_entry_verify_full() {
    let first_log_entry = load_test_file("tests/test_vectors/first_log_entry_verify_full.jsonl");

    let first_log_entry: LogEntry =
        serde_json::from_str(&first_log_entry).expect("Failed to parse first log entry JSON");

    let result = first_log_entry.verify_log_entry(None, None, None);
    println!("{result:#?}",);
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
