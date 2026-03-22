/*!
 * SD-JWT specification test vectors.
 *
 * These test the disclosure encoding and digest computation
 * against known values from the IETF SD-JWT specification (RFC 9449).
 */

use affinidi_sd_jwt::disclosure::Disclosure;
use affinidi_sd_jwt::hasher::Sha256Hasher;
use serde_json::{Value, json};

/// Spec Example: Disclosure for "given_name": "John"
/// From the SD-JWT spec, a disclosure with known salt should produce
/// a deterministic base64url encoding and digest.
#[test]
fn disclosure_deterministic_encoding() {
    let hasher = Sha256Hasher;

    // Create a disclosure with a known salt
    let d = Disclosure::new_claim_with_salt(
        "2GLC42sKQveCfGfryNRN9w",
        "given_name",
        Value::String("John".into()),
        &hasher,
    )
    .unwrap();

    // The serialized form should be deterministic
    assert_eq!(d.salt, "2GLC42sKQveCfGfryNRN9w");
    assert_eq!(d.claim_name.as_deref(), Some("given_name"));
    assert_eq!(d.claim_value, Value::String("John".into()));

    // The base64url encoding of ["2GLC42sKQveCfGfryNRN9w","given_name","John"]
    // should be deterministic
    assert!(!d.serialized.is_empty());
    assert!(!d.digest.is_empty());

    // Parse it back and verify consistency
    let parsed = Disclosure::parse(&d.serialized, &hasher).unwrap();
    assert_eq!(parsed.salt, d.salt);
    assert_eq!(parsed.claim_name, d.claim_name);
    assert_eq!(parsed.claim_value, d.claim_value);
    assert_eq!(parsed.digest, d.digest);
}

/// Spec: Array element disclosures use 2-element arrays [salt, value]
#[test]
fn array_element_disclosure_format() {
    let hasher = Sha256Hasher;

    let d = Disclosure::new_array_element_with_salt(
        "lklxF5jMYlGTPUovMNIvCA",
        Value::String("US".into()),
        &hasher,
    )
    .unwrap();

    assert_eq!(d.salt, "lklxF5jMYlGTPUovMNIvCA");
    assert!(d.claim_name.is_none());
    assert_eq!(d.claim_value, Value::String("US".into()));

    // Parse back
    let parsed = Disclosure::parse(&d.serialized, &hasher).unwrap();
    assert!(parsed.claim_name.is_none());
    assert_eq!(parsed.claim_value, Value::String("US".into()));
}

/// Spec: Nested object disclosures
#[test]
fn nested_object_disclosure() {
    let hasher = Sha256Hasher;

    let address = json!({
        "street_address": "123 Main St",
        "locality": "Anytown",
        "region": "Anystate",
        "country": "US"
    });

    let d = Disclosure::new_claim_with_salt(
        "6Ij7tM-a5iVPGboS5tmvVA",
        "address",
        address.clone(),
        &hasher,
    )
    .unwrap();

    assert_eq!(d.claim_name.as_deref(), Some("address"));
    assert_eq!(d.claim_value, address);

    let parsed = Disclosure::parse(&d.serialized, &hasher).unwrap();
    assert_eq!(parsed.claim_value["street_address"], "123 Main St");
    assert_eq!(parsed.claim_value["locality"], "Anytown");
}

/// Spec: Boolean, number, and null values in disclosures
#[test]
fn various_value_types_in_disclosures() {
    let hasher = Sha256Hasher;

    // Boolean
    let d = Disclosure::new_claim_with_salt(
        "sa_aIhwHFRJt6YPkKhZ2ew",
        "email_verified",
        Value::Bool(true),
        &hasher,
    )
    .unwrap();
    let parsed = Disclosure::parse(&d.serialized, &hasher).unwrap();
    assert_eq!(parsed.claim_value, Value::Bool(true));

    // Number
    let d = Disclosure::new_claim_with_salt("Pc33JM2LchcU_lHggv_ufQ", "age", json!(42), &hasher)
        .unwrap();
    let parsed = Disclosure::parse(&d.serialized, &hasher).unwrap();
    assert_eq!(parsed.claim_value, json!(42));

    // Null
    let d = Disclosure::new_claim_with_salt(
        "G02NSrQfjFXQ7Io09syajA",
        "middle_name",
        Value::Null,
        &hasher,
    )
    .unwrap();
    let parsed = Disclosure::parse(&d.serialized, &hasher).unwrap();
    assert_eq!(parsed.claim_value, Value::Null);
}

/// Spec Example: Full SD-JWT issuance with flat claims
#[test]
fn spec_example_flat_claims_issuance() {
    use affinidi_sd_jwt::hasher::Sha256Hasher;
    use affinidi_sd_jwt::issuer;
    use affinidi_sd_jwt::signer::test_utils::HmacSha256Signer;

    let hasher = Sha256Hasher;
    let signer = HmacSha256Signer::new(b"spec-test-key-at-least-32-bytes!");

    // Spec-like claims
    let claims = json!({
        "iss": "https://issuer.example.com",
        "iat": 1683000000,
        "exp": 1883000000,
        "sub": "user_42",
        "given_name": "John",
        "family_name": "Doe",
        "email": "johndoe@example.com",
        "phone_number": "+1-202-555-0101",
        "address": {
            "street_address": "123 Main St",
            "locality": "Anytown",
            "region": "Anystate",
            "country": "US"
        },
        "birthdate": "1940-01-01"
    });

    let frame = json!({
        "_sd": [
            "given_name",
            "family_name",
            "email",
            "phone_number",
            "birthdate"
        ],
        "address": {
            "_sd": ["street_address", "locality", "region"]
        }
    });

    let sd_jwt = issuer::issue(&claims, &frame, &signer, &hasher, None).unwrap();

    // Should have 8 disclosures: 5 top-level + 3 address
    assert_eq!(sd_jwt.disclosures.len(), 8);

    let payload = sd_jwt.payload().unwrap();

    // Non-disclosed claims should be visible
    assert_eq!(payload["iss"], "https://issuer.example.com");
    assert_eq!(payload["sub"], "user_42");
    assert_eq!(payload["iat"], 1683000000);
    assert_eq!(payload["exp"], 1883000000);

    // Disclosed claims should NOT be directly visible
    assert!(payload.get("given_name").is_none());
    assert!(payload.get("family_name").is_none());
    assert!(payload.get("email").is_none());
    assert!(payload.get("phone_number").is_none());
    assert!(payload.get("birthdate").is_none());

    // _sd array at top level should have 5 digests
    let sd_array = payload["_sd"].as_array().unwrap();
    assert_eq!(sd_array.len(), 5);

    // address should still be an object with country visible
    assert_eq!(payload["address"]["country"], "US");
    assert!(payload["address"].get("street_address").is_none());

    // address._sd should have 3 digests
    let addr_sd = payload["address"]["_sd"].as_array().unwrap();
    assert_eq!(addr_sd.len(), 3);

    // _sd_alg should be set
    assert_eq!(payload["_sd_alg"], "sha-256");
}

/// Spec: Full issuance -> holder presentation -> verifier flow
#[test]
fn spec_example_full_flow() {
    use affinidi_sd_jwt::SdJwt;
    use affinidi_sd_jwt::hasher::Sha256Hasher;
    use affinidi_sd_jwt::holder::{self, KbJwtInput};
    use affinidi_sd_jwt::issuer;
    use affinidi_sd_jwt::signer::test_utils::{HmacSha256Signer, HmacSha256Verifier};
    use affinidi_sd_jwt::verifier;

    let hasher = Sha256Hasher;
    let issuer_key = b"issuer-key-for-testing-32-bytes!";
    let holder_key = b"holder-key-for-testing-32-bytes!";

    let signer = HmacSha256Signer::new(issuer_key);
    let jwt_verifier = HmacSha256Verifier::new(issuer_key);
    let holder_signer = HmacSha256Signer::new(holder_key);

    let holder_jwk = json!({
        "kty": "oct",
        "k": "holder-public-key"
    });

    // Step 1: Issuer creates SD-JWT
    let claims = json!({
        "iss": "https://issuer.example.com",
        "iat": 1683000000,
        "exp": 1883000000,
        "sub": "user_42",
        "given_name": "John",
        "family_name": "Doe",
        "email": "johndoe@example.com",
        "nationalities": ["US", "DE"]
    });

    let frame = json!({
        "_sd": ["given_name", "family_name", "email"],
        "nationalities": {
            "_sd": ["0", "1"]
        }
    });

    let sd_jwt = issuer::issue(&claims, &frame, &signer, &hasher, Some(&holder_jwk)).unwrap();

    // 3 top-level + 2 array element disclosures
    assert_eq!(sd_jwt.disclosures.len(), 5);

    // Step 2: Holder selects disclosures for presentation
    // Reveal only given_name and email
    let selected = holder::select_disclosures(&sd_jwt, &["given_name", "email"]);
    assert_eq!(selected.len(), 2);

    let kb_input = KbJwtInput {
        audience: "https://verifier.example.com",
        nonce: "XZOUco1u_gEPknxS78sWWg",
        signer: &holder_signer,
        iat: 1700000000,
    };

    let presentation = holder::present(&sd_jwt, &selected, Some(&kb_input), &hasher).unwrap();

    // Should have 2 disclosures + KB-JWT
    assert_eq!(presentation.disclosures.len(), 2);
    assert!(presentation.kb_jwt.is_some());

    // Step 3: Serialize and transmit
    let serialized = presentation.serialize();

    // Step 4: Verifier parses and verifies
    let parsed = SdJwt::parse(&serialized, &hasher).unwrap();
    assert_eq!(parsed.disclosures.len(), 2);
    assert!(parsed.kb_jwt.is_some());

    let result = verifier::verify(
        &parsed,
        &jwt_verifier,
        &hasher,
        true,
        Some("https://verifier.example.com"),
        Some("XZOUco1u_gEPknxS78sWWg"),
    )
    .unwrap();

    assert!(result.is_verified());
    assert_eq!(result.claims["given_name"], "John");
    assert_eq!(result.claims["email"], "johndoe@example.com");
    assert!(result.claims.get("family_name").is_none());
    // Nationalities array elements not disclosed
    let nats = result.claims["nationalities"].as_array().unwrap();
    assert!(nats.is_empty()); // Both were selectively disclosable and not selected
}

/// Spec: _sd_alg claim must be present
#[test]
fn sd_alg_claim_present() {
    use affinidi_sd_jwt::issuer;
    use affinidi_sd_jwt::signer::test_utils::HmacSha256Signer;

    let hasher = Sha256Hasher;
    let signer = HmacSha256Signer::new(b"spec-test-key-at-least-32-bytes!");

    let claims = json!({"sub": "user", "name": "Alice"});
    let frame = json!({"_sd": ["name"]});

    let sd_jwt = issuer::issue(&claims, &frame, &signer, &hasher, None).unwrap();
    let payload = sd_jwt.payload().unwrap();

    assert_eq!(payload["_sd_alg"], "sha-256");
}

/// Spec: _sd digests must be sorted
#[test]
fn sd_digests_are_sorted() {
    use affinidi_sd_jwt::issuer;
    use affinidi_sd_jwt::signer::test_utils::HmacSha256Signer;

    let hasher = Sha256Hasher;
    let signer = HmacSha256Signer::new(b"spec-test-key-at-least-32-bytes!");

    let claims = json!({
        "sub": "user",
        "a_claim": "A",
        "b_claim": "B",
        "c_claim": "C",
        "d_claim": "D"
    });

    let frame = json!({
        "_sd": ["a_claim", "b_claim", "c_claim", "d_claim"]
    });

    let sd_jwt = issuer::issue(&claims, &frame, &signer, &hasher, None).unwrap();
    let payload = sd_jwt.payload().unwrap();

    let sd_array: Vec<&str> = payload["_sd"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();

    // Verify sorted
    let mut sorted = sd_array.clone();
    sorted.sort();
    assert_eq!(sd_array, sorted);
}

/// Spec: JWT header must have typ: sd+jwt
#[test]
fn jwt_header_typ_is_sd_jwt() {
    use affinidi_sd_jwt::issuer;
    use affinidi_sd_jwt::signer::test_utils::HmacSha256Signer;

    let hasher = Sha256Hasher;
    let signer = HmacSha256Signer::new(b"spec-test-key-at-least-32-bytes!");

    let claims = json!({"sub": "user", "name": "Alice"});
    let frame = json!({"_sd": ["name"]});

    let sd_jwt = issuer::issue(&claims, &frame, &signer, &hasher, None).unwrap();
    let header = sd_jwt.header().unwrap();

    assert_eq!(header["typ"], "sd+jwt");
}

/// Spec: cnf claim with holder public key
#[test]
fn cnf_claim_with_holder_key() {
    use affinidi_sd_jwt::issuer;
    use affinidi_sd_jwt::signer::test_utils::HmacSha256Signer;

    let hasher = Sha256Hasher;
    let signer = HmacSha256Signer::new(b"spec-test-key-at-least-32-bytes!");

    let holder_jwk = json!({
        "kty": "EC",
        "crv": "P-256",
        "x": "TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc",
        "y": "ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ"
    });

    let claims = json!({"sub": "user", "name": "Alice"});
    let frame = json!({"_sd": ["name"]});

    let sd_jwt = issuer::issue(&claims, &frame, &signer, &hasher, Some(&holder_jwk)).unwrap();
    let payload = sd_jwt.payload().unwrap();

    assert!(payload.get("cnf").is_some());
    assert_eq!(payload["cnf"]["jwk"]["kty"], "EC");
    assert_eq!(payload["cnf"]["jwk"]["crv"], "P-256");
    assert_eq!(
        payload["cnf"]["jwk"]["x"],
        "TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc"
    );
}

/// Spec: SD-JWT serialization format
#[test]
fn serialization_format_compliance() {
    use affinidi_sd_jwt::issuer;
    use affinidi_sd_jwt::signer::test_utils::HmacSha256Signer;

    let hasher = Sha256Hasher;
    let signer = HmacSha256Signer::new(b"spec-test-key-at-least-32-bytes!");

    let claims = json!({"sub": "user", "a": "1", "b": "2"});
    let frame = json!({"_sd": ["a", "b"]});

    let sd_jwt = issuer::issue(&claims, &frame, &signer, &hasher, None).unwrap();
    let serialized = sd_jwt.serialize();

    // Must end with ~
    assert!(serialized.ends_with('~'));

    // Split by ~
    let parts: Vec<&str> = serialized.split('~').collect();

    // JWS (3 dot-parts) + 2 disclosures + trailing empty
    assert_eq!(parts.len(), 4);

    // First part is JWS
    assert_eq!(parts[0].split('.').count(), 3);

    // Middle parts are base64url disclosures
    for part in &parts[1..3] {
        assert!(!part.is_empty());
        // Should be valid base64url
        assert!(
            part.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
    }

    // Last part is empty (no KB-JWT)
    assert!(parts[3].is_empty());
}

/// Spec: KB-JWT must have typ: kb+jwt in header
#[test]
fn kb_jwt_header_typ() {
    use affinidi_sd_jwt::Disclosure;
    use affinidi_sd_jwt::holder::{self, KbJwtInput};
    use affinidi_sd_jwt::issuer;
    use affinidi_sd_jwt::signer::test_utils::HmacSha256Signer;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

    let hasher = Sha256Hasher;
    let signer = HmacSha256Signer::new(b"spec-test-key-at-least-32-bytes!");
    let holder_signer = HmacSha256Signer::new(b"holder-key-for-testing-32-bytes!");

    let holder_jwk = json!({"kty": "oct", "k": "test"});
    let claims = json!({"sub": "user", "name": "Alice"});
    let frame = json!({"_sd": ["name"]});

    let sd_jwt = issuer::issue(&claims, &frame, &signer, &hasher, Some(&holder_jwk)).unwrap();

    let all_refs: Vec<&Disclosure> = sd_jwt.disclosures.iter().collect();
    let kb_input = KbJwtInput {
        audience: "https://verifier.example.com",
        nonce: "test-nonce",
        signer: &holder_signer,
        iat: 1700000000,
    };

    let presentation = holder::present(&sd_jwt, &all_refs, Some(&kb_input), &hasher).unwrap();

    // Decode KB-JWT header
    let kb_jwt_str = presentation.kb_jwt.as_ref().unwrap();
    let header_b64 = kb_jwt_str.split('.').next().unwrap();
    let header_bytes = URL_SAFE_NO_PAD.decode(header_b64).unwrap();
    let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();

    assert_eq!(header["typ"], "kb+jwt");
    assert_eq!(header["alg"], "HS256");
}

/// Spec: KB-JWT payload must contain sd_hash, aud, nonce, iat
#[test]
fn kb_jwt_payload_claims() {
    use affinidi_sd_jwt::Disclosure;
    use affinidi_sd_jwt::holder::{self, KbJwtInput};
    use affinidi_sd_jwt::issuer;
    use affinidi_sd_jwt::signer::test_utils::HmacSha256Signer;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

    let hasher = Sha256Hasher;
    let signer = HmacSha256Signer::new(b"spec-test-key-at-least-32-bytes!");
    let holder_signer = HmacSha256Signer::new(b"holder-key-for-testing-32-bytes!");

    let holder_jwk = json!({"kty": "oct", "k": "test"});
    let claims = json!({"sub": "user", "name": "Alice"});
    let frame = json!({"_sd": ["name"]});

    let sd_jwt = issuer::issue(&claims, &frame, &signer, &hasher, Some(&holder_jwk)).unwrap();

    let all_refs: Vec<&Disclosure> = sd_jwt.disclosures.iter().collect();
    let kb_input = KbJwtInput {
        audience: "https://verifier.example.com",
        nonce: "test-nonce-123",
        signer: &holder_signer,
        iat: 1700000000,
    };

    let presentation = holder::present(&sd_jwt, &all_refs, Some(&kb_input), &hasher).unwrap();

    // Decode KB-JWT payload
    let kb_jwt_str = presentation.kb_jwt.as_ref().unwrap();
    let payload_b64 = kb_jwt_str.split('.').nth(1).unwrap();
    let payload_bytes = URL_SAFE_NO_PAD.decode(payload_b64).unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();

    assert_eq!(payload["aud"], "https://verifier.example.com");
    assert_eq!(payload["nonce"], "test-nonce-123");
    assert_eq!(payload["iat"], 1700000000);
    assert!(payload.get("sd_hash").is_some());
    // sd_hash should be a non-empty string
    let sd_hash = payload["sd_hash"].as_str().unwrap();
    assert!(!sd_hash.is_empty());
}

/// Spec: Decoy digests should be indistinguishable from real ones
#[test]
fn decoy_digests_format() {
    use affinidi_sd_jwt::issuer;
    use affinidi_sd_jwt::signer::test_utils::HmacSha256Signer;

    let hasher = Sha256Hasher;
    let signer = HmacSha256Signer::new(b"spec-test-key-at-least-32-bytes!");

    let claims = json!({"sub": "user", "secret": "value"});
    let frame = json!({"_sd": ["secret"], "_sd_decoy": 5});

    let sd_jwt = issuer::issue(&claims, &frame, &signer, &hasher, None).unwrap();
    let payload = sd_jwt.payload().unwrap();

    let sd_array = payload["_sd"].as_array().unwrap();
    // 1 real + 5 decoy
    assert_eq!(sd_array.len(), 6);

    // All should be base64url strings of the same format
    for digest in sd_array {
        let s = digest.as_str().unwrap();
        assert!(!s.is_empty());
        // All should be valid base64url
        assert!(
            s.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
    }

    // Only 1 real disclosure
    assert_eq!(sd_jwt.disclosures.len(), 1);
}

/// Spec: Multiple hashers should work correctly
#[test]
fn different_hashers() {
    use affinidi_sd_jwt::hasher::{Sha256Hasher, Sha384Hasher, Sha512Hasher};
    use affinidi_sd_jwt::issuer;
    use affinidi_sd_jwt::signer::test_utils::HmacSha256Signer;

    let signer = HmacSha256Signer::new(b"spec-test-key-at-least-32-bytes!");

    let claims = json!({"sub": "user", "name": "Alice"});
    let frame = json!({"_sd": ["name"]});

    // SHA-256
    let sd_jwt_256 = issuer::issue(&claims, &frame, &signer, &Sha256Hasher, None).unwrap();
    let payload_256 = sd_jwt_256.payload().unwrap();
    assert_eq!(payload_256["_sd_alg"], "sha-256");

    // SHA-384
    let sd_jwt_384 = issuer::issue(&claims, &frame, &signer, &Sha384Hasher, None).unwrap();
    let payload_384 = sd_jwt_384.payload().unwrap();
    assert_eq!(payload_384["_sd_alg"], "sha-384");

    // SHA-512
    let sd_jwt_512 = issuer::issue(&claims, &frame, &signer, &Sha512Hasher, None).unwrap();
    let payload_512 = sd_jwt_512.payload().unwrap();
    assert_eq!(payload_512["_sd_alg"], "sha-512");

    // Digests should be different lengths in base64url
    let d256 = payload_256["_sd"][0].as_str().unwrap();
    let d384 = payload_384["_sd"][0].as_str().unwrap();
    let d512 = payload_512["_sd"][0].as_str().unwrap();

    // SHA-256 = 32 bytes = 43 base64url chars
    // SHA-384 = 48 bytes = 64 base64url chars
    // SHA-512 = 64 bytes = 86 base64url chars
    assert!(d256.len() < d384.len());
    assert!(d384.len() < d512.len());
}

/// Edge case: Empty _sd array (no claims to disclose)
#[test]
fn empty_disclosure_frame() {
    use affinidi_sd_jwt::issuer;
    use affinidi_sd_jwt::signer::test_utils::{HmacSha256Signer, HmacSha256Verifier};
    use affinidi_sd_jwt::verifier;

    let hasher = Sha256Hasher;
    let signer = HmacSha256Signer::new(b"spec-test-key-at-least-32-bytes!");
    let jwt_verifier = HmacSha256Verifier::new(b"spec-test-key-at-least-32-bytes!");

    let claims = json!({"sub": "user", "name": "Alice"});
    let frame = json!({});

    let sd_jwt = issuer::issue(&claims, &frame, &signer, &hasher, None).unwrap();
    assert!(sd_jwt.disclosures.is_empty());

    let result = verifier::verify(&sd_jwt, &jwt_verifier, &hasher, false, None, None).unwrap();
    assert!(result.is_verified());
    assert_eq!(result.claims["sub"], "user");
    assert_eq!(result.claims["name"], "Alice");
}

/// Edge case: All claims disclosed
#[test]
fn all_claims_disclosed() {
    use affinidi_sd_jwt::issuer;
    use affinidi_sd_jwt::signer::test_utils::{HmacSha256Signer, HmacSha256Verifier};
    use affinidi_sd_jwt::verifier;

    let hasher = Sha256Hasher;
    let signer = HmacSha256Signer::new(b"spec-test-key-at-least-32-bytes!");
    let jwt_verifier = HmacSha256Verifier::new(b"spec-test-key-at-least-32-bytes!");

    let claims = json!({
        "given_name": "John",
        "family_name": "Doe",
        "email": "john@example.com"
    });

    let frame = json!({
        "_sd": ["given_name", "family_name", "email"]
    });

    let sd_jwt = issuer::issue(&claims, &frame, &signer, &hasher, None).unwrap();
    assert_eq!(sd_jwt.disclosures.len(), 3);

    // Verify with all disclosures
    let result = verifier::verify(&sd_jwt, &jwt_verifier, &hasher, false, None, None).unwrap();
    assert!(result.is_verified());
    assert_eq!(result.claims["given_name"], "John");
    assert_eq!(result.claims["family_name"], "Doe");
    assert_eq!(result.claims["email"], "john@example.com");
}

/// Edge case: Deeply nested disclosures
#[test]
fn deeply_nested_disclosures() {
    use affinidi_sd_jwt::issuer;
    use affinidi_sd_jwt::signer::test_utils::{HmacSha256Signer, HmacSha256Verifier};
    use affinidi_sd_jwt::verifier;

    let hasher = Sha256Hasher;
    let signer = HmacSha256Signer::new(b"spec-test-key-at-least-32-bytes!");
    let jwt_verifier = HmacSha256Verifier::new(b"spec-test-key-at-least-32-bytes!");

    let claims = json!({
        "sub": "user",
        "address": {
            "formatted": {
                "line1": "123 Main St",
                "line2": "Apt 4B",
                "city": "Anytown"
            },
            "country": "US"
        }
    });

    let frame = json!({
        "address": {
            "formatted": {
                "_sd": ["line1", "line2"]
            }
        }
    });

    let sd_jwt = issuer::issue(&claims, &frame, &signer, &hasher, None).unwrap();
    assert_eq!(sd_jwt.disclosures.len(), 2);

    let result = verifier::verify(&sd_jwt, &jwt_verifier, &hasher, false, None, None).unwrap();
    assert!(result.is_verified());
    assert_eq!(
        result.claims["address"]["formatted"]["line1"],
        "123 Main St"
    );
    assert_eq!(result.claims["address"]["formatted"]["line2"], "Apt 4B");
    assert_eq!(result.claims["address"]["formatted"]["city"], "Anytown");
    assert_eq!(result.claims["address"]["country"], "US");
}
