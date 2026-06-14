//! Fuzz the full DIDComm unpack entry point (format detect → decrypt / verify
//! → parse) against the fixed fuzz keys. Seeded with valid anoncrypt / authcrypt
//! / signed / plaintext envelopes so the fuzzer starts past the AEAD/signature
//! gates; mutation explores from there.
#![no_main]

use affinidi_messaging_didcomm::message::unpack::unpack;
use affinidi_messaging_didcomm_fuzz::{recipient, sender_public, signer, RECIPIENT_KID};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };
    let (_, signer_pub) = signer();
    // Supply every key the parser might need (recipient + authcrypt sender +
    // JWS signer) so all three protected paths are reachable, not just the
    // anoncrypt one. The result is discarded — we fuzz for panics / UB.
    let _ = unpack(
        input,
        Some(RECIPIENT_KID),
        Some(recipient()),
        Some(sender_public()),
        Some(&signer_pub),
    );
});
