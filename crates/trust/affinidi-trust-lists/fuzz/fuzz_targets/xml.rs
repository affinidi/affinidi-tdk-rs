//! Fuzz `parse_trust_list_xml` (ETSI TS 119 612 trust list / LoTL XML) and the
//! reads that follow it: the signature-element check, loading the list into a
//! registry at its own issue time, and certificate lookups against what was
//! indexed.
#![no_main]

use affinidi_trust_lists::{parse_trust_list_xml, TrustListRegistry};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(xml) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(unverified) = parse_trust_list_xml(xml) else {
        return;
    };
    let _ = unverified.has_signature_element();
    let list = unverified.assume_authenticated();
    let now = list.scheme_information.list_issue_date_time;
    let mut registry = TrustListRegistry::new();
    if registry.load_trust_list(&list, now).is_ok() {
        let anchors: Vec<Vec<u8>> = registry
            .certificate_anchors()
            .map(|(_, der)| der.to_vec())
            .collect();
        for der in &anchors {
            let _ = registry.lookup_by_certificate(der);
        }
    }
});
