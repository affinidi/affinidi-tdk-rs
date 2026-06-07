//! Conformance KAT: the official **W3C `rdf-canon` (RDFC-1.0) test suite**.
//!
//! Each `testNNN-in.nq` is parsed to a dataset, canonicalized, and compared
//! byte-for-byte against the suite's expected `testNNN-rdfc10.nq`. Only the
//! SHA-256 (`rdfc10`) cases are vendored here; the single SHA-384 case is out
//! of scope for this ciphersuite.
//!
//! Source: `w3c/rdf-canon` `tests/rdfc10/`.

use affinidi_rdf_encoding::{nquads, rdfc1};

/// Known-failing cases. Empty — the full 63-case `rdfc10` suite passes
/// byte-for-byte, including the "poison – evil" symmetric graphs
/// (`test044`-`046`) and the deep `t-graph` (`test054`). Kept as a hook so a
/// future regression can be quarantined explicitly rather than silently.
const KNOWN_FAILING: &[&str] = &[];

#[test]
fn rdfc10_official_w3c_suite() {
    let dir = format!("{}/tests/fixtures/rdfc10", env!("CARGO_MANIFEST_DIR"));

    let mut inputs: Vec<String> = std::fs::read_dir(&dir)
        .expect("fixtures dir")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with("-in.nq"))
        .collect();
    inputs.sort();
    assert!(!inputs.is_empty(), "no rdfc10 fixtures found in {dir}");

    let mut ran = 0usize;
    let mut skipped: Vec<&str> = Vec::new();
    let mut failures: Vec<String> = Vec::new();

    for in_name in &inputs {
        let test_id = in_name.trim_end_matches("-in.nq");
        if KNOWN_FAILING.contains(&test_id) {
            skipped.push(test_id);
            continue;
        }
        let input = std::fs::read_to_string(format!("{dir}/{in_name}")).unwrap();
        let expected = std::fs::read_to_string(format!("{dir}/{test_id}-rdfc10.nq")).unwrap();

        match nquads::parse(&input).and_then(|ds| rdfc1::canonicalize(&ds)) {
            Ok(got) if got == expected => ran += 1,
            Ok(got) => failures.push(format!(
                "{test_id}: MISMATCH\n--- got ---\n{got}--- expected ---\n{expected}"
            )),
            Err(e) => failures.push(format!("{test_id}: ERROR {e}")),
        }
    }

    eprintln!(
        "rdfc10 W3C suite: {ran} passed, {} skipped (known-hard: {:?})",
        skipped.len(),
        skipped
    );
    assert!(
        failures.is_empty(),
        "{} RDFC-1.0 conformance failure(s):\n\n{}",
        failures.len(),
        failures.join("\n\n")
    );
}
