//! Fuzz the full DIDComm unpack entry point (format detect → decrypt / verify
//! → parse) against the fixed fuzz keys. Seeded with valid anoncrypt / authcrypt
//! / signed / plaintext envelopes so the fuzzer starts past the AEAD/signature
//! gates; mutation explores from there.
#![no_main]

use affinidi_messaging_didcomm::message::unpack::unpack_bound;
use affinidi_messaging_didcomm::jws::verify::VerifyKey;
use affinidi_messaging_didcomm::{SenderKey, SignerKey};
use affinidi_messaging_didcomm_fuzz::{recipient, sender_public, signer, RECIPIENT_KID, SENDER_KID, SIGNER_KID};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };
    let (_, signer_pub) = signer();
    let signer_key = VerifyKey::Ed25519(signer_pub);
    // Supply every key the parser might need (recipient + authcrypt sender +
    // JWS signer) so all three protected paths are reachable, not just the
    // anoncrypt one. The result is discarded — we fuzz for panics / UB.
    let _ = unpack_bound(
        input,
        Some(RECIPIENT_KID),
        Some(recipient()),
        Some(SenderKey::new(SENDER_KID, sender_public())),
        Some(SignerKey::new(SIGNER_KID, &signer_key)),
    );
});
