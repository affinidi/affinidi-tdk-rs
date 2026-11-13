//! Fuzz the keys-free TSP readers a relay or mediator runs on unauthenticated
//! wire bytes: `is_tsp`, `MetaEnvelope::parse`, `Envelope::decode`, and the
//! control-payload decoder. Seeded with the specification's Appendix A
//! messages (qb2).
#![no_main]

use affinidi_tsp::message::control::ControlMessage;
use affinidi_tsp::message::envelope::Envelope;
use affinidi_tsp::{is_tsp, MetaEnvelope};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = is_tsp(data);
    let _ = MetaEnvelope::parse(data);
    if let Ok((_, consumed)) = Envelope::decode(data) {
        assert!(consumed <= data.len(), "envelope consumed past the input");
    }
    if let Ok(decoded) = Envelope::decode_full(data) {
        let _ = decoded.envelope.encode_fields();
    }
    let _ = ControlMessage::decode(data);
});
