//! Fuzz the remaining CESR entry points that read untrusted stream bytes:
//! format sniffing, the version-string reader, `Counter::from_qb64`,
//! `Indexer::from_qb64` and the qb64/qb2 transcoders. A value that decodes is
//! re-encoded, which must not panic.
#![no_main]

use affinidi_cesr::{codec, sniff, Counter, Indexer};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = sniff::sniff(data);
    let _ = sniff::has_version_string(data);
    let _ = sniff::version_string_size(data);
    let _ = codec::qb2_to_qb64(data);

    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let _ = codec::qb64_to_qb2(text);
    if let Ok(counter) = Counter::from_qb64(text) {
        let _ = counter.qb64();
        let _ = counter.full_size();
    }
    if let Ok(indexer) = Indexer::from_qb64(text) {
        let _ = indexer.qb64();
    }
});
