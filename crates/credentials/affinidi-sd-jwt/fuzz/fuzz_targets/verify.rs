//! Fuzz SD-JWT verification (signature + disclosure digests + claim resolution)
//! against the fixed HMAC verifier. Parses first, then verifies — seeded with
//! valid SD-JWTs so the verify body is reachable past the signature gate.
#![no_main]

use affinidi_sd_jwt::verifier::verify;
use affinidi_sd_jwt::{SdJwt, Sha256Hasher, VerificationOptions};
use affinidi_sd_jwt_fuzz::jwt_verifier;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };
    let hasher = Sha256Hasher;
    if let Ok(sd_jwt) = SdJwt::parse(input, &hasher) {
        let _ = verify(
            &sd_jwt,
            jwt_verifier(),
            &hasher,
            &VerificationOptions::default(),
            None,
        );
    }
});
