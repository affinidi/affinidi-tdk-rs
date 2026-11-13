//! Fuzz `Matter` decoding in both CESR domains: `from_qb64` on the input as
//! text and `from_qb2` on the raw bytes.
//!
//! Beyond "no panic", every value that decodes is re-encoded and decoded again,
//! and the second decode must equal the first. That round trip is asserted for
//! fixed-size codes only: variable-size codes have a known lead-size issue
//! (affinidi/affinidi-tdk-rs#1005) that makes them lossy today, so for those
//! the target checks only that encoding does not panic.
#![no_main]

use affinidi_cesr::Matter;
use libfuzzer_sys::fuzz_target;

fn check_round_trip(m: &Matter) {
    let fixed = m.sizage().fs > 0;

    let qb64 = m.qb64();
    let qb2 = m.qb2();
    if !fixed {
        return;
    }

    let qb64 = qb64.expect("a decoded fixed-size Matter re-encodes to qb64");
    let again = Matter::from_qb64(&qb64).expect("re-encoded qb64 decodes");
    assert_eq!(&again, m, "qb64 round trip changed the value");

    let qb2 = qb2.expect("a decoded fixed-size Matter re-encodes to qb2");
    let again = Matter::from_qb2(&qb2).expect("re-encoded qb2 decodes");
    assert_eq!(&again, m, "qb2 round trip changed the value");
}

fuzz_target!(|data: &[u8]| {
    if let Ok(m) = Matter::from_qb2(data) {
        check_round_trip(&m);
    }
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(m) = Matter::from_qb64(text) {
            check_round_trip(&m);
        }
    }
});
