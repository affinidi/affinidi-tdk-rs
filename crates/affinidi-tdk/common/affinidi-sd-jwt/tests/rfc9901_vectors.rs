/*!
 * RFC 9901 test vectors.
 *
 * These tests verify disclosure parsing and digest computation against
 * the exact values from RFC 9901 (Selective Disclosure for JWTs).
 *
 * Note: The RFC examples use JSON with spaces after separators
 * (e.g., `["salt", "name", "value"]`). Our library uses compact JSON
 * (e.g., `["salt","name","value"]`), producing different but equally
 * valid base64url strings. Tests here verify:
 * 1. Parsing the RFC's exact disclosure strings yields correct values
 * 2. Our own encoding is internally consistent (roundtrip)
 * 3. Digest computation against the RFC's exact strings matches
 *
 * Reference: https://www.rfc-editor.org/rfc/rfc9901.html
 */

use affinidi_sd_jwt::SdHasher;
use affinidi_sd_jwt::disclosure::Disclosure;
use affinidi_sd_jwt::hasher::Sha256Hasher;
use serde_json::{Value, json};

// ── RFC 9901 Section 5.1: Parse the spec's exact disclosure strings ─────────

/// RFC 9901 §5.1 — Parse the spec's disclosure for "given_name": "John"
/// Disclosure string: WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd
/// SHA-256 digest: jsu9yVulwQQlhFlM_3JlzMaSFzglhQG0DpfayQwLUK4
#[test]
fn rfc9901_parse_given_name() {
    let hasher = Sha256Hasher;
    let spec_str = "WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd";

    let d = Disclosure::parse(spec_str, &hasher).unwrap();
    assert_eq!(d.salt, "2GLC42sKQveCfGfryNRN9w");
    assert_eq!(d.claim_name.as_deref(), Some("given_name"));
    assert_eq!(d.claim_value, Value::String("John".into()));
    // Digest of the spec's exact string
    assert_eq!(d.digest, "jsu9yVulwQQlhFlM_3JlzMaSFzglhQG0DpfayQwLUK4");
}

/// RFC 9901 §5.1 — Parse the spec's disclosure for "family_name": "Doe"
/// Disclosure string: WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd
/// SHA-256 digest: TGf4oLbgwd5JQaHyKVQZU9UdGE0w5rtDsrZzfUaomLo
#[test]
fn rfc9901_parse_family_name() {
    let hasher = Sha256Hasher;
    let spec_str = "WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd";

    let d = Disclosure::parse(spec_str, &hasher).unwrap();
    assert_eq!(d.salt, "eluV5Og3gSNII8EYnsxA_A");
    assert_eq!(d.claim_name.as_deref(), Some("family_name"));
    assert_eq!(d.claim_value, Value::String("Doe".into()));
    assert_eq!(d.digest, "TGf4oLbgwd5JQaHyKVQZU9UdGE0w5rtDsrZzfUaomLo");
}

/// RFC 9901 §5.1 — Parse the spec's disclosure for "email": "johndoe@example.com"
#[test]
fn rfc9901_parse_email() {
    let hasher = Sha256Hasher;
    let spec_str = "WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgImVtYWlsIiwgImpvaG5kb2VAZXhhbXBsZS5jb20iXQ";

    let d = Disclosure::parse(spec_str, &hasher).unwrap();
    assert_eq!(d.salt, "6Ij7tM-a5iVPGboS5tmvVA");
    assert_eq!(d.claim_name.as_deref(), Some("email"));
    assert_eq!(d.claim_value, Value::String("johndoe@example.com".into()));
}

/// RFC 9901 §5.1 — Parse the spec's disclosure for "phone_number": "+1-202-555-0101"
#[test]
fn rfc9901_parse_phone_number() {
    let hasher = Sha256Hasher;
    let spec_str =
        "WyJlSThaV205UW5LUHBOUGVOZW5IZGhRIiwgInBob25lX251bWJlciIsICIrMS0yMDItNTU1LTAxMDEiXQ";

    let d = Disclosure::parse(spec_str, &hasher).unwrap();
    assert_eq!(d.salt, "eI8ZWm9QnKPpNPeNenHdhQ");
    assert_eq!(d.claim_name.as_deref(), Some("phone_number"));
    assert_eq!(d.claim_value, Value::String("+1-202-555-0101".into()));
}

/// RFC 9901 §5.1 — Parse the spec's disclosure for "phone_number_verified": true
#[test]
fn rfc9901_parse_phone_verified() {
    let hasher = Sha256Hasher;
    let spec_str = "WyJRZ19PNjR6cUF4ZTQxMmExMDhpcm9BIiwgInBob25lX251bWJlcl92ZXJpZmllZCIsIHRydWVd";

    let d = Disclosure::parse(spec_str, &hasher).unwrap();
    assert_eq!(d.salt, "Qg_O64zqAxe412a108iroA");
    assert_eq!(d.claim_name.as_deref(), Some("phone_number_verified"));
    assert_eq!(d.claim_value, Value::Bool(true));
}

/// RFC 9901 §5.1 — Parse the spec's disclosure for "birthdate": "1940-01-01"
#[test]
fn rfc9901_parse_birthdate() {
    let hasher = Sha256Hasher;
    let spec_str = "WyJQYzMzSk0yTGNoY1VfbEhnZ3ZfdWZRIiwgImJpcnRoZGF0ZSIsICIxOTQwLTAxLTAxIl0";

    let d = Disclosure::parse(spec_str, &hasher).unwrap();
    assert_eq!(d.salt, "Pc33JM2LchcU_lHggv_ufQ");
    assert_eq!(d.claim_name.as_deref(), Some("birthdate"));
    assert_eq!(d.claim_value, Value::String("1940-01-01".into()));
}

/// RFC 9901 §5.1 — Parse the spec's disclosure for "updated_at": 1570000000
#[test]
fn rfc9901_parse_updated_at() {
    let hasher = Sha256Hasher;
    let spec_str = "WyJHMDJOU3JRZmpGWFE3SW8wOXN5YWpBIiwgInVwZGF0ZWRfYXQiLCAxNTcwMDAwMDAwXQ";

    let d = Disclosure::parse(spec_str, &hasher).unwrap();
    assert_eq!(d.salt, "G02NSrQfjFXQ7Io09syajA");
    assert_eq!(d.claim_name.as_deref(), Some("updated_at"));
    assert_eq!(d.claim_value, json!(1570000000));
}

/// RFC 9901 §5.1 — Parse the spec's disclosure for "address" (complex object)
#[test]
fn rfc9901_parse_address() {
    let hasher = Sha256Hasher;
    let spec_str = "WyJBSngtMDk1VlBycFR0TjRRTU9xUk9BIiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjogIjEyMyBNYWluIFN0IiwgImxvY2FsaXR5IjogIkFueXRvd24iLCAicmVnaW9uIjogIkFueXN0YXRlIiwgImNvdW50cnkiOiAiVVMifV0";

    let d = Disclosure::parse(spec_str, &hasher).unwrap();
    assert_eq!(d.salt, "AJx-095VPrpTtN4QMOqROA");
    assert_eq!(d.claim_name.as_deref(), Some("address"));
    assert_eq!(d.claim_value["street_address"], "123 Main St");
    assert_eq!(d.claim_value["locality"], "Anytown");
    assert_eq!(d.claim_value["region"], "Anystate");
    assert_eq!(d.claim_value["country"], "US");
}

// ── RFC 9901 Section 5.1: Array element disclosures ─────────────────────────

/// RFC 9901 §5.1 — Parse array element disclosure for "US" (nationality)
/// Disclosure: WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIlVTIl0
/// SHA-256 digest: pFndjkZ_VCzmyTa6UjlZo3dh-ko8aIKQc9DlGzhaVYo
#[test]
fn rfc9901_parse_array_us() {
    let hasher = Sha256Hasher;
    let spec_str = "WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIlVTIl0";

    let d = Disclosure::parse(spec_str, &hasher).unwrap();
    assert_eq!(d.salt, "lklxF5jMYlGTPUovMNIvCA");
    assert!(d.claim_name.is_none()); // Array element
    assert_eq!(d.claim_value, Value::String("US".into()));
    assert_eq!(d.digest, "pFndjkZ_VCzmyTa6UjlZo3dh-ko8aIKQc9DlGzhaVYo");
}

/// RFC 9901 §5.1 — Parse array element disclosure for "DE" (nationality)
/// Disclosure: WyJuUHVvUW5rUkZxM0JJZUFtN0FuWEZBIiwgIkRFIl0
/// SHA-256 digest: 7Cf6JkPudry3lcbwHgeZ8khAv1U1OSlerP0VkBJrWZ0
#[test]
fn rfc9901_parse_array_de() {
    let hasher = Sha256Hasher;
    let spec_str = "WyJuUHVvUW5rUkZxM0JJZUFtN0FuWEZBIiwgIkRFIl0";

    let d = Disclosure::parse(spec_str, &hasher).unwrap();
    assert_eq!(d.salt, "nPuoQnkRFq3BIeAm7AnXFA");
    assert!(d.claim_name.is_none());
    assert_eq!(d.claim_value, Value::String("DE".into()));
    assert_eq!(d.digest, "7Cf6JkPudry3lcbwHgeZ8khAv1U1OSlerP0VkBJrWZ0");
}

// ── RFC 9901: Digest verification ───────────────────────────────────────────

/// Verify that the spec's disclosure digests match the _sd array from §5.1
#[test]
fn rfc9901_digests_in_sd_array() {
    let hasher = Sha256Hasher;

    // Expected _sd array digests from RFC 9901 §5.1 payload
    let expected_sd = [
        "CrQe7S5kqBAHt-nMYXgc6bdt2SH5aTY1sU_M-PgkjPI",
        "JzYaH4svliH0R3PyEMfeZu6Jt69u5qehZo7F7EPYlSE",
        "PorFbpKuVu6xymJagvkFsFXAbRoc2JGlAUA2BA4o7cI",
        "TGf4oLbgwd5JQaHyKVQZU9UdGE0w5rtDsrZzfUaomLo",
        "XQ_3kPKt1XyX7KANkqVR6yZ2Va5NrPIvPYbyMvRKBMM",
        "XzFrzwscM6GN6CJDc6vVK4BkMnfG8vOSKfpPIZdAfdE",
        "gbOsI4Edq2x2Kw-w5wPEzakob9hV1cRD0ATN3oQL9JM",
        "jsu9yVulwQQlhFlM_3JlzMaSFzglhQG0DpfayQwLUK4",
    ];

    // Parse the spec's given_name disclosure and verify its digest is in the _sd array
    let given_name_str = "WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd";
    let d = Disclosure::parse(given_name_str, &hasher).unwrap();
    assert!(
        expected_sd.contains(&d.digest.as_str()),
        "given_name digest {} not in _sd array",
        d.digest
    );

    // Parse family_name and verify
    let family_name_str = "WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd";
    let d = Disclosure::parse(family_name_str, &hasher).unwrap();
    assert!(
        expected_sd.contains(&d.digest.as_str()),
        "family_name digest {} not in _sd array",
        d.digest
    );
}

// ── RFC 9901: Holder key (cnf claim) ────────────────────────────────────────

/// RFC 9901 — Holder public key must not include private key 'd'
#[test]
fn rfc9901_holder_key_no_private() {
    let holder_jwk = json!({
        "kty": "EC",
        "crv": "P-256",
        "x": "TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc",
        "y": "ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ"
    });

    let cnf = json!({ "jwk": holder_jwk });
    assert_eq!(cnf["jwk"]["kty"], "EC");
    assert_eq!(cnf["jwk"]["crv"], "P-256");
    assert!(cnf["jwk"].get("d").is_none());
}

// ── RFC 9901: Data type coverage ────────────────────────────────────────────

/// Various JSON value types in disclosures
#[test]
fn rfc9901_data_type_coverage() {
    let hasher = Sha256Hasher;

    // null
    let d = Disclosure::new_claim("test_null", Value::Null, &hasher).unwrap();
    let parsed = Disclosure::parse(&d.serialized, &hasher).unwrap();
    assert_eq!(parsed.claim_value, Value::Null);

    // integer
    let d = Disclosure::new_claim("test_int", json!(42), &hasher).unwrap();
    let parsed = Disclosure::parse(&d.serialized, &hasher).unwrap();
    assert_eq!(parsed.claim_value, json!(42));

    // float
    let d = Disclosure::new_claim("test_float", json!(3.14), &hasher).unwrap();
    let parsed = Disclosure::parse(&d.serialized, &hasher).unwrap();
    assert_eq!(parsed.claim_value, json!(3.14));

    // string
    let d = Disclosure::new_claim("test_str", json!("foo"), &hasher).unwrap();
    let parsed = Disclosure::parse(&d.serialized, &hasher).unwrap();
    assert_eq!(parsed.claim_value, json!("foo"));

    // boolean
    let d = Disclosure::new_claim("test_bool", json!(true), &hasher).unwrap();
    let parsed = Disclosure::parse(&d.serialized, &hasher).unwrap();
    assert_eq!(parsed.claim_value, json!(true));

    // array
    let d = Disclosure::new_claim("test_arr", json!(["Test"]), &hasher).unwrap();
    let parsed = Disclosure::parse(&d.serialized, &hasher).unwrap();
    assert_eq!(parsed.claim_value, json!(["Test"]));

    // object
    let d = Disclosure::new_claim("test_object", json!({"foo": "bar"}), &hasher).unwrap();
    let parsed = Disclosure::parse(&d.serialized, &hasher).unwrap();
    assert_eq!(parsed.claim_value, json!({"foo": "bar"}));
}

// ── sd-jwt-python test cases ────────────────────────────────────────────────

/// array_of_scalars: partial disclosure of array elements
#[test]
fn python_testcase_array_of_scalars() {
    use affinidi_sd_jwt::holder;
    use affinidi_sd_jwt::issuer;
    use affinidi_sd_jwt::signer::test_utils::{HmacSha256Signer, HmacSha256Verifier};
    use affinidi_sd_jwt::verifier;

    let hasher = Sha256Hasher;
    let signer = HmacSha256Signer::new(b"python-test-key-at-least-32-by!");
    let jwt_verifier = HmacSha256Verifier::new(b"python-test-key-at-least-32-by!");

    let claims = json!({
        "nationalities": ["US", "CA", "DE"]
    });

    let frame = json!({
        "nationalities": {
            "_sd": ["0", "1"]
        }
    });

    let sd_jwt = issuer::issue(&claims, &frame, &signer, &hasher, None).unwrap();

    // Disclose only CA (index 1)
    let ca_disclosures: Vec<_> = sd_jwt
        .disclosures
        .iter()
        .filter(|d| d.claim_value == json!("CA"))
        .collect();

    let presentation = holder::present(&sd_jwt, &ca_disclosures, None, &hasher).unwrap();

    let result = verifier::verify(
        &presentation,
        &jwt_verifier,
        &hasher,
        &Default::default(),
        None,
    )
    .unwrap();

    assert!(result.is_verified());
    let nats = result.claims["nationalities"].as_array().unwrap();
    assert_eq!(nats.len(), 2);
    assert!(nats.contains(&json!("CA")));
    assert!(nats.contains(&json!("DE")));
    assert!(!nats.contains(&json!("US")));
}

/// array_in_sd: entire array as a single SD claim
#[test]
fn python_testcase_array_in_sd() {
    use affinidi_sd_jwt::holder;
    use affinidi_sd_jwt::issuer;
    use affinidi_sd_jwt::signer::test_utils::{HmacSha256Signer, HmacSha256Verifier};
    use affinidi_sd_jwt::verifier;

    let hasher = Sha256Hasher;
    let signer = HmacSha256Signer::new(b"python-test-key-at-least-32-by!");
    let jwt_verifier = HmacSha256Verifier::new(b"python-test-key-at-least-32-by!");

    let claims = json!({ "sd_array": [32, 23] });
    let frame = json!({ "_sd": ["sd_array"] });

    let sd_jwt = issuer::issue(&claims, &frame, &signer, &hasher, None).unwrap();
    assert_eq!(sd_jwt.disclosures.len(), 1);

    let all_refs: Vec<_> = sd_jwt.disclosures.iter().collect();
    let presentation = holder::present(&sd_jwt, &all_refs, None, &hasher).unwrap();

    let result = verifier::verify(
        &presentation,
        &jwt_verifier,
        &hasher,
        &Default::default(),
        None,
    )
    .unwrap();

    assert!(result.is_verified());
    assert_eq!(result.claims["sd_array"], json!([32, 23]));
}

/// Verification error: disclosure digest not found in payload
#[test]
fn error_disclosure_digest_not_in_payload() {
    use affinidi_sd_jwt::SdJwt;
    use affinidi_sd_jwt::issuer;
    use affinidi_sd_jwt::signer::test_utils::{HmacSha256Signer, HmacSha256Verifier};
    use affinidi_sd_jwt::verifier;

    let hasher = Sha256Hasher;
    let signer = HmacSha256Signer::new(b"python-test-key-at-least-32-by!");
    let jwt_verifier = HmacSha256Verifier::new(b"python-test-key-at-least-32-by!");

    let claims = json!({"sub": "user", "name": "Alice"});
    let frame = json!({"_sd": ["name"]});

    let sd_jwt = issuer::issue(&claims, &frame, &signer, &hasher, None).unwrap();

    let fake_disclosure =
        affinidi_sd_jwt::Disclosure::new_claim("fake_claim", json!("fake"), &hasher).unwrap();

    let tampered = SdJwt {
        jws: sd_jwt.jws.clone(),
        disclosures: vec![sd_jwt.disclosures[0].clone(), fake_disclosure],
        kb_jwt: None,
    };

    let result = verifier::verify(&tampered, &jwt_verifier, &hasher, &Default::default(), None);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("disclosure digest not found")
    );
}

/// Verification error: _sd_alg mismatch
#[test]
fn error_sd_alg_mismatch() {
    use affinidi_sd_jwt::hasher::Sha384Hasher;
    use affinidi_sd_jwt::issuer;
    use affinidi_sd_jwt::signer::test_utils::{HmacSha256Signer, HmacSha256Verifier};
    use affinidi_sd_jwt::verifier;

    let signer = HmacSha256Signer::new(b"python-test-key-at-least-32-by!");
    let jwt_verifier = HmacSha256Verifier::new(b"python-test-key-at-least-32-by!");

    let claims = json!({"sub": "user", "name": "Alice"});
    let frame = json!({"_sd": ["name"]});

    let sd_jwt = issuer::issue(&claims, &frame, &signer, &Sha256Hasher, None).unwrap();

    let result = verifier::verify(
        &sd_jwt,
        &jwt_verifier,
        &Sha384Hasher,
        &Default::default(),
        None,
    );
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("_sd_alg mismatch"));
}

/// KB-JWT: verify sd_hash computation
#[test]
fn rfc9901_kb_jwt_sd_hash() {
    use affinidi_sd_jwt::Disclosure;
    use affinidi_sd_jwt::holder::{self, KbJwtInput};
    use affinidi_sd_jwt::issuer;
    use affinidi_sd_jwt::signer::test_utils::HmacSha256Signer;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

    let hasher = Sha256Hasher;
    let signer = HmacSha256Signer::new(b"rfc9901-test-key-32-bytes-long!");
    let holder_signer = HmacSha256Signer::new(b"holder-test-key-32-bytes-long!!");

    let holder_jwk = json!({
        "kty": "EC",
        "crv": "P-256",
        "x": "TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc",
        "y": "ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ"
    });

    let claims = json!({"sub": "user_42", "given_name": "John"});
    let frame = json!({"_sd": ["given_name"]});

    let sd_jwt = issuer::issue(&claims, &frame, &signer, &hasher, Some(&holder_jwk)).unwrap();

    let all_refs: Vec<&Disclosure> = sd_jwt.disclosures.iter().collect();
    let kb_input = KbJwtInput {
        audience: "https://verifier.example.org",
        nonce: "1234567890",
        signer: &holder_signer,
        iat: 1683000000,
    };

    let presentation = holder::present(&sd_jwt, &all_refs, Some(&kb_input), &hasher).unwrap();

    // Compute expected sd_hash
    let presentation_without_kb = {
        let mut parts = vec![sd_jwt.jws.clone()];
        for d in &sd_jwt.disclosures {
            parts.push(d.serialized.clone());
        }
        parts.join("~") + "~"
    };
    let expected_sd_hash = hasher.hash_b64(presentation_without_kb.as_bytes());

    // Extract sd_hash from KB-JWT payload
    let kb_jwt_str = presentation.kb_jwt.as_ref().unwrap();
    let payload_b64 = kb_jwt_str.split('.').nth(1).unwrap();
    let payload_bytes = URL_SAFE_NO_PAD.decode(payload_b64).unwrap();
    let kb_payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();

    assert_eq!(kb_payload["sd_hash"].as_str().unwrap(), expected_sd_hash);
    assert_eq!(kb_payload["aud"], "https://verifier.example.org");
    assert_eq!(kb_payload["nonce"], "1234567890");
    assert_eq!(kb_payload["iat"], 1683000000);
}

/// Our encoding: roundtrip consistency (create -> serialize -> parse -> same values)
#[test]
fn encoding_roundtrip_consistency() {
    let hasher = Sha256Hasher;

    let claims = [
        ("given_name", json!("John")),
        ("family_name", json!("Doe")),
        ("email", json!("johndoe@example.com")),
        ("age", json!(42)),
        ("verified", json!(true)),
        ("address", json!({"street": "123 Main", "city": "Town"})),
    ];

    for (name, value) in &claims {
        let d = Disclosure::new_claim(name, value.clone(), &hasher).unwrap();
        let parsed = Disclosure::parse(&d.serialized, &hasher).unwrap();

        assert_eq!(parsed.salt, d.salt);
        assert_eq!(parsed.claim_name, d.claim_name);
        assert_eq!(parsed.claim_value, d.claim_value);
        assert_eq!(parsed.digest, d.digest);
    }
}
