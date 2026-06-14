//! Shared fixtures for the `affinidi-sd-jwt` fuzz targets (issue #477).
//!
//! A fixed HMAC key + verifier and a committed seed corpus of valid SD-JWTs, so
//! the `verify` target starts past the signature gate. The HMAC verifier is the
//! crate's own `_test-utils` helper — symmetric and test-only, never a
//! production path.
//!
//! The audit on #477 confirmed sd-jwt's `verify` is already synchronous and
//! trait-injected (`&dyn JwtVerifier` / `&dyn SdHasher`, no resolver, no I/O),
//! so it fuzzes with no tokio runtime.

use std::sync::OnceLock;

use affinidi_sd_jwt::signer::test_utils::{HmacSha256Signer, HmacSha256Verifier};
use affinidi_sd_jwt::{holder, issuer, Sha256Hasher};

/// Fixed HMAC key the seed corpus is signed with and the `verify` target checks
/// against. Any byte string works for HMAC; this one is a fixed constant.
pub const HMAC_KEY: &[u8] = b"affinidi-sd-jwt-fuzz-fixed-key!!";

/// Fixed verifier, cached so the hot fuzz loop never rebuilds it.
pub fn jwt_verifier() -> &'static HmacSha256Verifier {
    static V: OnceLock<HmacSha256Verifier> = OnceLock::new();
    V.get_or_init(|| HmacSha256Verifier::new(HMAC_KEY))
}

/// Build the committed seed corpus: serialized valid SD-JWTs (full issuance and
/// a zero-disclosure presentation) signed under [`HMAC_KEY`], one set per
/// claim/frame shape. Used by the `gen_corpus` binary.
pub fn seed_corpus() -> Vec<(String, Vec<u8>)> {
    let hasher = Sha256Hasher;
    let signer = HmacSha256Signer::new(HMAC_KEY);

    let cases = [
        (
            serde_json::json!({ "sub": "user123", "given_name": "John", "family_name": "Doe" }),
            serde_json::json!({ "_sd": ["given_name", "family_name"] }),
        ),
        (
            serde_json::json!({ "sub": "u2", "name": "Jane", "nested": { "a": [1, 2, 3] } }),
            serde_json::json!({ "_sd": ["name"] }),
        ),
    ];

    let mut out = Vec::new();
    for (i, (claims, frame)) in cases.iter().enumerate() {
        let sd = issuer::issue(claims, frame, &signer, &hasher, None).expect("issue sample");
        let full = sd.serialize().into_bytes();
        out.push((format!("parse/issued-{i}.sdjwt"), full.clone()));
        out.push((format!("verify/issued-{i}.sdjwt"), full));

        // A zero-disclosure presentation — valid, exercises the present path.
        let pres = holder::present(&sd, &[], None, &hasher).expect("present sample");
        let pres_bytes = pres.serialize().into_bytes();
        out.push((format!("parse/presentation-{i}.sdjwt"), pres_bytes.clone()));
        out.push((format!("verify/presentation-{i}.sdjwt"), pres_bytes));
    }
    out
}
