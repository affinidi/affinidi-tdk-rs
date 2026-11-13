//! Fuzz `VerifiedStatusListToken::verify` past its signature callback: the
//! callback accepts any signature and returns the JWT's own payload, so
//! mutation reaches the claim checks and the ZLIB-inflated `status_list`.
//! Reads at several indexes follow. The input is also parsed as a Referenced
//! Token's claims with `StatusListReference::from_claims`.
#![no_main]

use affinidi_status_list::{token::VerifyOptions, StatusListReference, VerifiedStatusListToken};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use libfuzzer_sys::fuzz_target;
use serde_json::Value;

const URI: &str = "https://example.com/statuslists/1";
/// Fixed clock inside the seeds' validity windows.
const NOW: i64 = 1_800_000_000;
/// Below the library default so one input cannot inflate 16 MiB per run.
const MAX_LIST_BYTES: usize = 1 << 20;

fn payload_of(jwt: &str) -> Result<Value, String> {
    let segment = jwt.split('.').nth(1).ok_or("no payload segment")?;
    let bytes = URL_SAFE_NO_PAD.decode(segment).map_err(|e| e.to_string())?;
    serde_json::from_slice(&bytes).map_err(|e| e.to_string())
}

fuzz_target!(|data: &[u8]| {
    if let Ok(claims) = serde_json::from_slice::<Value>(data) {
        let _ = StatusListReference::from_claims(&claims);
    }

    let Ok(jwt) = std::str::from_utf8(data) else {
        return;
    };
    let reference = StatusListReference {
        idx: 0,
        uri: URI.to_string(),
    };
    let mut options = VerifyOptions::at(NOW);
    options.max_list_bytes = MAX_LIST_BYTES;
    let Ok(token) =
        VerifiedStatusListToken::verify(jwt, &reference, &options, |jwt, _header| payload_of(jwt))
    else {
        return;
    };
    let len = token.list().len() as u64;
    for idx in [0, len / 2, len.saturating_sub(1), len, u64::MAX] {
        let _ = token.status_of(&StatusListReference {
            idx,
            uri: URI.to_string(),
        });
    }
});
