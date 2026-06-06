//! Known-answer test: JSON-LD → RDF → RDFC-1.0 canonical N-Quads must match the
//! official W3C vc-di-bbs test vector byte-for-byte.
//!
//! This locks the interop-critical pipeline (in particular the JSON-LD native
//! number conversion, whose canonical xsd:double / xsd:integer lexical forms the
//! RDFC-1.0 hashes — and therefore the canonical blank-node labels — depend on).
//!
//! Vector source: `w3c/vc-di-bbs` `TestVectors/{windDoc,addBaseDocCanon}.json`.

use affinidi_rdf_encoding::{jsonld, rdfc1};

fn fixture(name: &str) -> String {
    std::fs::read_to_string(format!(
        "{}/tests/fixtures/vc-di-bbs/{}",
        env!("CARGO_MANIFEST_DIR"),
        name
    ))
    .unwrap()
}

#[test]
fn windsurf_jsonld_canonicalizes_to_w3c_vector() {
    let doc: serde_json::Value = serde_json::from_str(&fixture("windDoc.json")).unwrap();
    // The vector is a JSON array of N-Quad lines (each already newline-terminated).
    let expected: String = serde_json::from_str::<Vec<String>>(&fixture("addBaseDocCanon.json"))
        .unwrap()
        .concat();

    let dataset = jsonld::expand_and_to_rdf(&doc).expect("expand to RDF");
    let canonical = rdfc1::canonicalize(&dataset).expect("RDFC-1.0 canonicalize");

    assert_eq!(
        canonical, expected,
        "canonical N-Quads diverge from the W3C vc-di-bbs vector"
    );
}
