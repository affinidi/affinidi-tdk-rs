//! TI7 — unit coverage for the shared `vectors` loader, against the sample
//! vectors under this crate's own `tests/vectors/sample/`.

use affinidi_tdk_test_support::vectors;

const DIR: &str = env!("CARGO_MANIFEST_DIR");

#[test]
fn load_json_parses_a_single_vector() {
    let v = vectors::load_json(DIR, "sample/one.json").expect("load one.json");
    assert_eq!(v["name"], "one");
    assert_eq!(v["value"], 1);
}

#[test]
fn load_str_returns_raw_text() {
    let text = vectors::load_str(DIR, "sample/note.txt").expect("load note.txt");
    assert!(text.starts_with("plain text vector"));
    assert!(text.contains("second line"));
}

#[test]
fn load_json_dir_returns_sorted_json_only() {
    let all = vectors::load_json_dir(DIR, "sample").expect("load sample dir");
    // Only the two .json files (note.txt is skipped), sorted by file stem.
    let names: Vec<&str> = all.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(names, vec!["one", "two"]);
    assert_eq!(all[0].1["value"], 1);
    assert_eq!(all[1].1["value"], 2);
}

#[test]
fn missing_vector_is_a_clean_error() {
    let err = vectors::load_json(DIR, "sample/does-not-exist.json").unwrap_err();
    assert!(
        matches!(err, vectors::VectorError::Read { .. }),
        "got {err:?}"
    );
}
