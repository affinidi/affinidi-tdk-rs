//! Fuzz the CBOR a reader receives before any session exists: the
//! `DeviceEngagement` array (QR code / NFC) and a bare `COSE_Key`. Values
//! that decode are re-encoded.
#![no_main]

use affinidi_mdoc::{CoseKey, DeviceEngagement};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(engagement) = DeviceEngagement::from_cbor_bytes(data) {
        let _ = engagement.to_cbor_bytes();
    }
    if let Ok(key) = CoseKey::from_cbor_bytes(data) {
        let _ = key.to_cbor_bytes();
    }
});
