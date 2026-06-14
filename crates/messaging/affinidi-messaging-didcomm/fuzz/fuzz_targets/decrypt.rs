//! Fuzz the JWE decrypt path directly (header parse → ECDH → key-unwrap → AEAD)
//! against the fixed recipient/sender keys, bypassing format detection.
#![no_main]

use affinidi_messaging_didcomm::jwe::decrypt::decrypt;
use affinidi_messaging_didcomm_fuzz::{recipient, sender_public, RECIPIENT_KID};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };
    let _ = decrypt(input, RECIPIENT_KID, recipient(), Some(sender_public()));
});
