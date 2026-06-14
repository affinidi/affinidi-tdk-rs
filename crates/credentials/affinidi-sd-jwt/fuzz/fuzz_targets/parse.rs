//! Fuzz the SD-JWT structural parser (JWS split, disclosure decode, digest
//! wiring) with raw bytes. No keys needed — `parse` is signature-agnostic.
#![no_main]

use affinidi_sd_jwt::{SdJwt, Sha256Hasher};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };
    let _ = SdJwt::parse(input, &Sha256Hasher);
});
