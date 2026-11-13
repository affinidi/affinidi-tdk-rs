//! Fuzz JSON-LD expansion and conversion to RDF, in both the lenient and the
//! safe mode, then canonicalize the result. Contexts resolve from the bundled
//! set only, so nothing is fetched. Seeded with Verifiable Credential
//! documents.
#![no_main]

use affinidi_rdf_encoding::jsonld::{expand_and_to_rdf, expand_and_to_rdf_safe};
use affinidi_rdf_encoding::rdfc1::{canonicalize_with_options, CanonicalizeOptions};
use libfuzzer_sys::fuzz_target;

/// Lower than the library default so one input cannot spend the whole run in
/// N-degree hashing; the bound itself is what is being exercised.
const MAX_NDEGREE_WORK: usize = 10_000;

fuzz_target!(|data: &[u8]| {
    let Ok(document) = serde_json::from_slice::<serde_json::Value>(data) else {
        return;
    };
    let options = CanonicalizeOptions::default().with_max_ndegree_work(MAX_NDEGREE_WORK);
    if let Ok(dataset) = expand_and_to_rdf(&document) {
        let _ = canonicalize_with_options(&dataset, &options);
    }
    let _ = expand_and_to_rdf_safe(&document);
});
