/*!
 * RFC 9901 §7.1 processing: what a Holder or Verifier MUST refuse, and the
 * recursive Disclosures it MUST accept (issue #962).
 *
 * Cases 3.c.ii.* to 5 sign their payload with the test HMAC key, so the
 * signature passes and only the disclosure processing is under test.
 */

use affinidi_sd_jwt::signer::test_utils::{HmacSha256Signer, HmacSha256Verifier};
use affinidi_sd_jwt::{
    Disclosure, JwtSigner, JwtVerifier, SdJwt, SdJwtError, Sha256Hasher, VerificationResult,
    holder, issuer, verifier,
};
use serde_json::{Value, json};

const KEY: &[u8] = b"rfc9901-processing-test-key-32b!";

fn sign(payload: Value) -> String {
    HmacSha256Signer::new(KEY)
        .sign_jwt(&json!({"alg": "HS256", "typ": "sd+jwt"}), &payload)
        .unwrap()
}

fn claim(salt: &str, name: &str, value: Value) -> Disclosure {
    Disclosure::new_claim_with_salt(salt, name, value, &Sha256Hasher).unwrap()
}

fn element(salt: &str, value: Value) -> Disclosure {
    Disclosure::new_array_element_with_salt(salt, value, &Sha256Hasher).unwrap()
}

fn verify(payload: Value, disclosures: Vec<Disclosure>) -> Result<VerificationResult, String> {
    let sd_jwt = SdJwt::new(sign(payload), disclosures, None);
    verifier::verify(
        &sd_jwt,
        &HmacSha256Verifier::new(KEY),
        &Sha256Hasher,
        &Default::default(),
        None,
    )
    .map_err(|e| e.to_string())
}

fn refused(payload: Value, disclosures: Vec<Disclosure>, why: &str) {
    match verify(payload, disclosures) {
        Ok(r) => panic!("accepted, claims {}", r.claims),
        Err(e) => assert!(e.contains(why), "refused for another reason: {e}"),
    }
}

// ── RFC 9901 Appendix A.2: recursive Disclosures ────────────────────────────

const RFC_A2_PRESENTATION: &str = concat!(
    "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImV4YW1wbGUrc2Qtand0In0.eyJfc2QiOiBbIi1hU3puSWQ5",
    "bVdNOG9jdVFvbENsbHN4VmdncTEtdkhXNE90bmhVdFZtV3ciLCAiSUticllObjN2QTdXRUZyeXN2YmRC",
    "SmpERFVfRXZRSXIwVzE4dlRScFVTZyIsICJvdGt4dVQxNG5CaXd6TkozTVBhT2l0T2w5cFZuWE9hRUhh",
    "bF94a3lOZktJIl0sICJpc3MiOiAiaHR0cHM6Ly9pc3N1ZXIuZXhhbXBsZS5jb20iLCAiaWF0IjogMTY4",
    "MzAwMDAwMCwgImV4cCI6IDE4ODMwMDAwMDAsICJ2ZXJpZmllZF9jbGFpbXMiOiB7InZlcmlmaWNhdGlv",
    "biI6IHsiX3NkIjogWyI3aDRVRTlxU2N2REtvZFhWQ3VvS2ZLQkpwVkJmWE1GX1RtQUdWYVplM1NjIiwg",
    "InZUd2UzcmFISUZZZ0ZBM3hhVUQyYU14Rno1b0RvOGlCdTA1cUtsT2c5THciXSwgInRydXN0X2ZyYW1l",
    "d29yayI6ICJkZV9hbWwiLCAiZXZpZGVuY2UiOiBbeyIuLi4iOiAidFlKMFREdWN5WlpDUk1iUk9HNHFS",
    "TzV2a1BTRlJ4RmhVRUxjMThDU2wzayJ9XX0sICJjbGFpbXMiOiB7Il9zZCI6IFsiUmlPaUNuNl93NVpI",
    "YWFka1FNcmNRSmYwSnRlNVJ3dXJSczU0MjMxRFRsbyIsICJTXzQ5OGJicEt6QjZFYW5mdHNzMHhjN2NP",
    "YW9uZVJyM3BLcjdOZFJtc01vIiwgIldOQS1VTks3Rl96aHNBYjlzeVdPNklJUTF1SGxUbU9VOHI4Q3ZK",
    "MGNJTWsiLCAiV3hoX3NWM2lSSDliZ3JUQkppLWFZSE5DTHQtdmpoWDFzZC1pZ09mXzlsayIsICJfTy13",
    "SmlIM2VuU0I0Uk9IbnRUb1FUOEptTHR6LW1oTzJmMWM4OVhvZXJRIiwgImh2RFhod21HY0pRc0JDQTJP",
    "dGp1TEFjd0FNcERzYVUwbmtvdmNLT3FXTkUiXX19LCAiX3NkX2FsZyI6ICJzaGEtMjU2In0.QoWYWtik",
    "m-AtjmPnNVshbGXQl5raEz15PByTmZwfTQg9W2O3oR6j2tMmysTZZawdo6mNLR_PsZSI25qrUpiNTg~W",
    "yIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgInRpbWUiLCAiMjAxMi0wNC0yM1QxODoyNVoiXQ~WyJQYz",
    "MzSk0yTGNoY1VfbEhnZ3ZfdWZRIiwgeyJfc2QiOiBbIjl3cGpWUFd1RDdQSzBuc1FETDhCMDZsbWRnVj",
    "NMVnliaEh5ZFFwVE55TEkiLCAiRzVFbmhPQU9vVTlYXzZRTU52ekZYanBFQV9SYy1BRXRtMWJHX3djYU",
    "tJayIsICJJaHdGcldVQjYzUmNacTl5dmdaMFhQYzdHb3doM08ya3FYZUJJc3dnMUI0IiwgIldweFE0SF",
    "NvRXRjVG1DQ0tPZURzbEJfZW11Y1lMejJvTzhvSE5yMWJFVlEiXX1d~WyJlSThaV205UW5LUHBOUGVOZ",
    "W5IZGhRIiwgIm1ldGhvZCIsICJwaXBwIl0~WyJHMDJOU3JRZmpGWFE3SW8wOXN5YWpBIiwgImdpdmVuX",
    "25hbWUiLCAiTWF4Il0~WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgImZhbWlseV9uYW1lIiwgIk1cd",
    "TAwZmNsbGVyIl0~WyJ5MXNWVTV3ZGZKYWhWZGd3UGdTN1JRIiwgImFkZHJlc3MiLCB7ImxvY2FsaXR5I",
    "jogIk1heHN0YWR0IiwgInBvc3RhbF9jb2RlIjogIjEyMzQ0IiwgImNvdW50cnkiOiAiREUiLCAic3RyZ",
    "WV0X2FkZHJlc3MiOiAiV2VpZGVuc3RyYVx1MDBkZmUgMjIifV0~",
);

/// Returns the JWS payload without checking its signature. The A.2 example is
/// signed ES256 under the RFC's Appendix A.5 key; what is tested here is the
/// disclosure processing after the signature.
struct SignatureNotChecked;

impl JwtVerifier for SignatureNotChecked {
    fn verify_jwt(&self, jws: &str) -> Result<Value, SdJwtError> {
        SdJwt::new(jws.to_string(), vec![], None).payload()
    }
}

/// The RFC's own example: the `evidence` element's Disclosure carries the
/// digests of four more. Verifies, and resolves to the RFC's published
/// processed payload.
#[test]
fn rfc9901_a2_recursive_disclosures_verify() {
    let sd_jwt = SdJwt::parse(RFC_A2_PRESENTATION, &Sha256Hasher).unwrap();
    assert_eq!(sd_jwt.disclosures.len(), 6);

    let opts = Default::default();
    let claims = verifier::verify(&sd_jwt, &SignatureNotChecked, &Sha256Hasher, &opts, None)
        .unwrap()
        .claims;
    assert_eq!(
        claims,
        holder::resolve_claims(&sd_jwt.payload().unwrap(), &sd_jwt.disclosures).unwrap()
    );
    assert_eq!(
        claims,
        json!({
            "iss": "https://issuer.example.com",
            "iat": 1683000000,
            "exp": 1883000000,
            "verified_claims": {
                "verification": {
                    "trust_framework": "de_aml",
                    "evidence": [{ "method": "pipp" }],
                    "time": "2012-04-23T18:25Z"
                },
                "claims": {
                    "given_name": "Max",
                    "family_name": "Müller",
                    "address": {
                        "locality": "Maxstadt",
                        "postal_code": "12344",
                        "country": "DE",
                        "street_address": "Weidenstraße 22"
                    }
                }
            }
        })
    );
}

/// This crate's own issuer, with a nested frame, puts the inner `_sd` inside
/// the outer Disclosure. Its verifier accepts that, with or without the inner
/// Disclosure.
#[test]
fn own_issuer_recursive_disclosures_verify() {
    let signer = HmacSha256Signer::new(KEY);
    let claims = json!({"sub": "user", "address": {"locality": "Anytown", "country": "DE"}});
    let frame = json!({"_sd": ["address"], "address": {"_sd": ["locality"]}});
    let sd_jwt = issuer::issue(&claims, &frame, &signer, &Sha256Hasher, None).unwrap();
    assert_eq!(sd_jwt.disclosures.len(), 2);

    let opts = Default::default();
    let jwt_verifier = HmacSha256Verifier::new(KEY);
    let all = verifier::verify(&sd_jwt, &jwt_verifier, &Sha256Hasher, &opts, None).unwrap();
    assert_eq!(
        all.claims["address"],
        json!({"locality": "Anytown", "country": "DE"})
    );

    let outer = sd_jwt
        .disclosures
        .iter()
        .find(|d| d.claim_name.as_deref() == Some("address"))
        .unwrap();
    let outer_only = SdJwt::new(sd_jwt.jws.clone(), vec![outer.clone()], None);
    let r = verifier::verify(&outer_only, &jwt_verifier, &Sha256Hasher, &opts, None).unwrap();
    assert_eq!(r.claims["address"], json!({"country": "DE"}));
}

/// The inner Disclosure without the one that references it is unreferenced
/// (step 5).
#[test]
fn inner_disclosure_without_its_parent_is_refused() {
    let inner = claim("s1", "locality", json!("Anytown"));
    let outer = claim("s2", "address", json!({"_sd": [inner.digest]}));
    refused(
        json!({"_sd": [outer.digest]}),
        vec![inner],
        "not found in payload",
    );
}

// ── RFC 9901 §7.1 step 3.c.ii: object claims ────────────────────────────────

/// 3.c.ii.3: a disclosed name already present at that level.
#[test]
fn disclosed_name_already_present_is_refused() {
    let d = claim("s1", "given_name", json!("Mallory"));
    refused(
        json!({"given_name": "Alice", "_sd": [d.digest]}),
        vec![d],
        "already exists",
    );
}

/// 3.c.ii.3: two Disclosures of the same name at one level.
#[test]
fn two_disclosures_of_one_name_are_refused() {
    let a = claim("s1", "given_name", json!("Alice"));
    let b = claim("s2", "given_name", json!("Mallory"));
    refused(
        json!({"_sd": [a.digest, b.digest]}),
        vec![a, b],
        "already exists",
    );
}

/// 3.c.ii.2: a Disclosure named `_sd` or `...`.
#[test]
fn reserved_disclosure_names_are_refused() {
    for name in ["_sd", "..."] {
        let d = claim("s1", name, json!(["injected"]));
        refused(
            json!({"nested": {"_sd": [d.digest]}}),
            vec![d],
            "reserved claim name",
        );
    }
}

/// 3.c.ii.1: an object `_sd` digest whose Disclosure has no claim name.
#[test]
fn array_element_disclosure_in_object_sd_is_refused() {
    let d = element("s1", json!("DE"));
    refused(
        json!({"_sd": [d.digest]}),
        vec![d],
        "array element disclosure",
    );
}

// ── RFC 9901 §7.1 step 3.c.iii: array elements ──────────────────────────────

/// 3.c.iii.1: an array `...` digest whose Disclosure has a claim name.
#[test]
fn object_claim_disclosure_in_array_is_refused() {
    let d = claim("s1", "nationality", json!("DE"));
    refused(
        json!({"nationalities": [{"...": d.digest}]}),
        vec![d],
        "object claim disclosure",
    );
}

/// An array element that is not disclosed is removed; one that is, replaced.
#[test]
fn array_elements_resolve() {
    let de = element("s1", json!("DE"));
    let fr = element("s2", json!("FR"));
    let r = verify(
        json!({"nationalities": [{"...": de.digest}, "US", {"...": fr.digest}]}),
        vec![de],
    )
    .unwrap();
    assert_eq!(r.claims["nationalities"], json!(["DE", "US"]));
}

// ── RFC 9901 §7.1 step 4: a digest at most once ─────────────────────────────

#[test]
fn digest_twice_in_one_sd_is_refused() {
    let d = claim("s1", "email", json!("a@example.com"));
    refused(
        json!({"_sd": [d.digest, d.digest]}),
        vec![d],
        "more than once",
    );
}

#[test]
fn digest_at_two_levels_is_refused() {
    let d = claim("s1", "email", json!("a@example.com"));
    refused(
        json!({"_sd": [d.digest], "other": {"_sd": [d.digest]}}),
        vec![d],
        "more than once",
    );
}

/// Counted even when its Disclosure is withheld.
#[test]
fn undisclosed_digest_twice_is_refused() {
    let d = claim("s1", "email", json!("a@example.com"));
    refused(
        json!({"_sd": [d.digest], "other": {"_sd": [d.digest]}}),
        vec![],
        "more than once",
    );
}

/// Counted through a Disclosure's value as well as the payload.
#[test]
fn digest_in_payload_and_in_a_disclosure_is_refused() {
    let inner = claim("s1", "locality", json!("Anytown"));
    let outer = claim("s2", "address", json!({"_sd": [inner.digest]}));
    refused(
        json!({"_sd": [outer.digest, inner.digest]}),
        vec![outer, inner],
        "more than once",
    );
}

// ── Well-formed input still resolves ────────────────────────────────────────

#[test]
fn flat_disclosure_resolves() {
    let d = claim("s1", "given_name", json!("Alice"));
    let r = verify(
        json!({"sub": "user", "_sd": [d.digest], "_sd_alg": "sha-256"}),
        vec![d],
    )
    .unwrap();
    assert_eq!(r.claims, json!({"sub": "user", "given_name": "Alice"}));
}
