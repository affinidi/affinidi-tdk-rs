//! Fuzz DIDComm v1 `unpack` (JSON, envelope detection, protected header,
//! recipient matching, CEK unwrap, content decryption, message decode) with a
//! fixed local identity and a fixed known peer. Seeds are well-formed
//! envelopes addressed to that identity, so recipient matching succeeds and
//! mutation reaches the key-unwrap step, plus plaintext and forward messages.
//! A message that comes out is also read as a forward.
#![no_main]

use std::sync::OnceLock;

use affinidi_messaging_didcomm_v1::protocols::forward;
use affinidi_messaging_didcomm_v1::{DIDCommV1Agent, PrivateIdentity};
use libfuzzer_sys::fuzz_target;

/// Fixed test keys. The seeds' recipient `kid`s are these identities' verkeys
/// (`[1; 32]` → `AKnL4NNf3DGWZJS6cPknBuEGnVsV4A4m5tgebLHaRSZ9`,
/// `[2; 32]` → `9hSR6S7WPtxmTojgo6GG3k4yDPecgJY292j7xrsUGWBu`).
fn agent() -> &'static DIDCommV1Agent {
    static AGENT: OnceLock<DIDCommV1Agent> = OnceLock::new();
    AGENT.get_or_init(|| {
        let local = PrivateIdentity::from_signing_key("did:example:local", &[1u8; 32])
            .expect("fixed local identity");
        let peer = PrivateIdentity::from_signing_key("did:example:peer", &[2u8; 32])
            .expect("fixed peer identity");
        let mut agent = DIDCommV1Agent::new();
        agent.add_peer(peer.to_resolved());
        agent.add_identity(local);
        agent
    })
}

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(result) = agent().unpack(input) {
        let message = result.message();
        if forward::is_forward(message) {
            let _ = forward::extract_payload(message);
            let _ = forward::destination(message);
        }
    }
});
