//! Fuzz the X.509 readers applied to certificates taken from trust lists and
//! credential `x5chain` headers: `parse_certificate`, `is_self_signed` and
//! `extract_public_key`. Seeded with the crate's test certificate.
#![no_main]

use affinidi_trust_lists::x509::{extract_public_key, is_self_signed, parse_certificate};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = parse_certificate(data);
    let _ = is_self_signed(data);
    let _ = extract_public_key(data);
});
