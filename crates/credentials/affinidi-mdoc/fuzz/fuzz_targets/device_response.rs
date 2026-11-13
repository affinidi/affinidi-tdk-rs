//! Fuzz `DeviceResponse::from_cbor_bytes` (the structure a holder presents to
//! a reader, including `deviceSigned`) and the keys-free reads a verifier
//! makes next: disclosed-item digests, the `x5chain` header, the validity
//! window, disclosed names, and re-encoding.
#![no_main]

use affinidi_mdoc::DeviceResponse;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(response) = DeviceResponse::from_cbor_bytes(data) else {
        return;
    };
    let _ = response.verify_digests();
    let _ = response.x5chain();
    let _ = response.mso.validity_info.validate();
    for namespace in response.disclosed.keys() {
        let _ = response.disclosed_names(namespace);
    }
    let _ = response.to_cbor_bytes();
});
