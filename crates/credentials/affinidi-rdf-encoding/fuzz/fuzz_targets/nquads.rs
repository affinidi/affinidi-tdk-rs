//! Fuzz the N-Quads parser and feed whatever parses through RDFC-1.0
//! canonicalization and the serializer. Seeded with the W3C `rdfc10` suite
//! inputs.
#![no_main]

use affinidi_rdf_encoding::nquads::{parser, serializer};
use affinidi_rdf_encoding::rdfc1::{canonicalize_with_options, CanonicalizeOptions};
use libfuzzer_sys::fuzz_target;

/// Lower than the library default so one input cannot spend the whole run in
/// N-degree hashing; the bound itself is what is being exercised.
const MAX_NDEGREE_WORK: usize = 10_000;

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(dataset) = parser::parse(input) else {
        return;
    };
    let _ = serializer::serialize_dataset(&dataset.quads);
    let options = CanonicalizeOptions::default().with_max_ndegree_work(MAX_NDEGREE_WORK);
    let _ = canonicalize_with_options(&dataset, &options);
});
