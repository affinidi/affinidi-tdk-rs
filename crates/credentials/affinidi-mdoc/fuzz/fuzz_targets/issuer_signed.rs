//! Fuzz `IssuerSigned::from_cbor_bytes` (CBOR, COSE_Sign1, Tag24 MSO, issuer
//! signed items) and the keys-free reads a verifier makes next: item digests
//! against the MSO, the `x5chain` header, the validity window, attribute
//! lookup, and re-encoding.
#![no_main]

use affinidi_mdoc::IssuerSigned;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(issued) = IssuerSigned::from_cbor_bytes(data) else {
        return;
    };
    let _ = issued.verify_digests();
    let _ = issued.x5chain();
    let _ = issued.mso.validity_info.validate();
    for namespace in issued.namespaces.keys() {
        for name in issued.attribute_names(namespace) {
            let _ = issued.get_attribute(namespace, name);
        }
    }
    let _ = issued.to_cbor_bytes();
});
