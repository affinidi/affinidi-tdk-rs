//! Fuzz the plaintext DIDComm message parser with raw bytes.
#![no_main]

use affinidi_messaging_didcomm::Message;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = Message::from_json(data);
});
