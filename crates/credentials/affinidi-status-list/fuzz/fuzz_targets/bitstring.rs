//! Fuzz `BitstringStatusList::decode` (base64url, then GZIP inflation capped at
//! the declared size) and reads from the decoded list.
//!
//! Input layout: three bytes of declared size in bits (big-endian, capped at
//! 2^20 to bound the per-run allocation), one byte whose low bit picks the
//! purpose, then the encoded list as UTF-8.
#![no_main]

use affinidi_status_list::{BitstringStatusList, StatusPurpose};
use libfuzzer_sys::fuzz_target;

const MAX_SIZE_BITS: usize = 1 << 20;

fuzz_target!(|data: &[u8]| {
    let [a, b, c, flags, rest @ ..] = data else {
        return;
    };
    let declared = (usize::from(*a) << 16) | (usize::from(*b) << 8) | usize::from(*c);
    let size = declared % (MAX_SIZE_BITS + 1);
    let purpose = if flags & 1 == 0 {
        StatusPurpose::Revocation
    } else {
        StatusPurpose::Suspension
    };
    let Ok(encoded) = std::str::from_utf8(rest) else {
        return;
    };
    let Ok(list) = BitstringStatusList::decode(encoded, size, purpose) else {
        return;
    };
    assert_eq!(list.size(), size, "decoded list reports a different size");
    let _ = list.count_set();
    for index in [0, size / 2, size.saturating_sub(1), size, usize::MAX] {
        let _ = list.get(index);
    }
});
