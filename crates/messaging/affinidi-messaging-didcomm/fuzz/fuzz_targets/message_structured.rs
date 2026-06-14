//! Structure-aware fuzzing of the message parser: libFuzzer bytes become an
//! `Arbitrary`-built [`Message`] (via the didcomm `arbitrary` feature), which is
//! serialized and re-parsed. Reaches the serializer + parser with well-formed-ish
//! structures that raw byte mutation rarely produces.
#![no_main]

use affinidi_messaging_didcomm::Message;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|msg: Message| {
    if let Ok(bytes) = msg.to_json() {
        let _ = Message::from_json(&bytes);
    }
});
