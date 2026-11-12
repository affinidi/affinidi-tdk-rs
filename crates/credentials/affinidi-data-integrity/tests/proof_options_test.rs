//! The optional proof members of VC Data Integrity 1.0 §2.1 — `expires`,
//! `domain`, `challenge`, `id`, `previousProof` — are signed, survive a JSON
//! round trip, and are covered by the signature for every cryptosuite, and
//! `expires` is enforced on verify.

use affinidi_data_integrity::crypto_suites::CryptoSuite;
use affinidi_data_integrity::signer::Signer;
use affinidi_data_integrity::{
    DataIntegrityError, DataIntegrityProof, SignOptions, StringOrList, VerifyOptions,
    prepare_sign_input, verify_conformance,
};
use affinidi_secrets_resolver::secrets::Secret;
use chrono::{DateTime, TimeDelta, TimeZone, Utc};
use multibase::Base;
use serde_json::{Value, json};

const VERIFICATION_METHOD: &str = "did:example:issuer#key-1";

fn document() -> Value {
    json!({
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "id": "urn:uuid:5a8b2f7e-4c63-4b0a-9d0e-3f1c2b7a6e10",
        "type": ["VerifiableCredential"],
        "issuer": "did:example:issuer",
        "validFrom": "2026-01-01T00:00:00Z",
        "credentialSubject": { "id": "did:example:subject" }
    })
}

fn created() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 3, 1, 12, 0, 0).unwrap()
}

fn expires() -> DateTime<Utc> {
    created() + TimeDelta::hours(1)
}

/// One signer and suite per cryptosuite family this crate signs with.
fn cases() -> Vec<(Secret, CryptoSuite)> {
    let ed25519 = Secret::generate_ed25519(Some(VERIFICATION_METHOD), Some(&[7u8; 32]));
    let p256 = Secret::generate_p256(Some(VERIFICATION_METHOD), None).expect("P-256 key");
    let ml_dsa = Secret::generate_ml_dsa_44(Some(VERIFICATION_METHOD), Some(&[9u8; 32]));
    vec![
        (ed25519.clone(), CryptoSuite::EddsaJcs2022),
        (ed25519, CryptoSuite::EddsaRdfc2022),
        (p256, CryptoSuite::EcdsaJcs2019),
        (ml_dsa.clone(), CryptoSuite::MlDsa44Jcs2024),
        (ml_dsa, CryptoSuite::MlDsa44Rdfc2024),
        #[cfg(feature = "slh-dsa")]
        (
            Secret::generate_slh_dsa_sha2_128s(Some(VERIFICATION_METHOD)),
            CryptoSuite::SlhDsa128Jcs2024,
        ),
        #[cfg(feature = "slh-dsa")]
        (
            Secret::generate_slh_dsa_sha2_128s(Some(VERIFICATION_METHOD)),
            CryptoSuite::SlhDsa128Rdfc2024,
        ),
    ]
}

fn sign_options(suite: CryptoSuite) -> SignOptions {
    SignOptions::new()
        .with_cryptosuite(suite)
        .with_created(created())
        .with_expires(expires())
        .with_domain(vec![
            "https://verifier.example".to_string(),
            "https://other.example".to_string(),
        ])
        .with_challenge("1f44d55f-f161-4938-a659-f8026467f126")
        .with_nonce("c6a1b0d2")
        .with_id("urn:uuid:7d3e6b9c-1a2f-4e58-8c0b-5f4d3a2e1b0c")
        .with_previous_proof("urn:uuid:0e5c1d2b-3a4f-4b6e-9d7c-8a1b2c3d4e5f")
}

/// What a verifier holds: the proof as parsed from JSON.
fn reparse(proof: &DataIntegrityProof) -> DataIntegrityProof {
    serde_json::from_value(serde_json::to_value(proof).unwrap()).expect("proof parses")
}

fn at(time: DateTime<Utc>) -> VerifyOptions {
    VerifyOptions::new().with_verification_time(time)
}

#[tokio::test]
async fn every_optional_member_round_trips_through_json() {
    for (secret, suite) in cases() {
        let proof = DataIntegrityProof::sign(&document(), &secret, sign_options(suite))
            .await
            .unwrap_or_else(|error| panic!("{suite}: sign: {error}"));
        let json = serde_json::to_value(&proof).unwrap();
        assert_eq!(json["expires"], "2026-03-01T13:00:00Z", "{suite}");
        assert_eq!(
            json["domain"],
            json!(["https://verifier.example", "https://other.example"]),
            "{suite}"
        );
        assert_eq!(
            json["challenge"], "1f44d55f-f161-4938-a659-f8026467f126",
            "{suite}"
        );
        assert_eq!(json["nonce"], "c6a1b0d2", "{suite}");
        assert_eq!(
            json["id"], "urn:uuid:7d3e6b9c-1a2f-4e58-8c0b-5f4d3a2e1b0c",
            "{suite}"
        );
        assert_eq!(
            json["previousProof"], "urn:uuid:0e5c1d2b-3a4f-4b6e-9d7c-8a1b2c3d4e5f",
            "{suite}"
        );
        assert_eq!(
            serde_json::to_value(reparse(&proof)).unwrap(),
            json,
            "{suite}: parse then serialize must reproduce the proof"
        );
    }
}

#[tokio::test]
async fn a_proof_with_expires_verifies_before_it_and_is_refused_after() {
    for (secret, suite) in cases() {
        let proof = reparse(
            &DataIntegrityProof::sign(&document(), &secret, sign_options(suite))
                .await
                .unwrap_or_else(|error| panic!("{suite}: sign: {error}")),
        );
        let public_key = secret.get_public_bytes();

        proof
            .verify_with_public_key(&document(), public_key, at(created()))
            .unwrap_or_else(|error| panic!("{suite}: at creation: {error}"));
        let one_second = TimeDelta::seconds(1);
        proof
            .verify_with_public_key(&document(), public_key, at(expires() - one_second))
            .unwrap_or_else(|error| panic!("{suite}: just before expiry: {error}"));

        // Inclusive bound, no skew by default: expired at the instant itself.
        for time in [expires(), expires() + one_second] {
            let result = proof.verify_with_public_key(&document(), public_key, at(time));
            assert!(
                matches!(result, Err(DataIntegrityError::ProofExpired { ref expires })
                    if expires == "2026-03-01T13:00:00Z"),
                "{suite}: at {time} must be ProofExpired, got {result:?}"
            );
        }

        // The `created` skew does not stretch `expires`.
        let result = proof.verify_with_public_key(
            &document(),
            public_key,
            at(expires()).with_clock_skew(TimeDelta::hours(1)),
        );
        assert!(
            matches!(result, Err(DataIntegrityError::ProofExpired { .. })),
            "{suite}: got {result:?}"
        );

        let tolerant = || at(expires()).with_expiry_clock_skew(TimeDelta::seconds(60));
        proof
            .verify_with_public_key(&document(), public_key, tolerant())
            .unwrap_or_else(|error| panic!("{suite}: within the expiry skew: {error}"));
        let result = proof.verify_with_public_key(
            &document(),
            public_key,
            tolerant().with_verification_time(expires() + TimeDelta::seconds(60)),
        );
        assert!(
            matches!(result, Err(DataIntegrityError::ProofExpired { .. })),
            "{suite}: at the end of the expiry skew must be ProofExpired, got {result:?}"
        );
    }
}

#[tokio::test]
async fn an_expired_proof_is_refused_at_the_current_time() {
    let secret = Secret::generate_ed25519(Some(VERIFICATION_METHOD), Some(&[7u8; 32]));
    let options = SignOptions::new()
        .with_created(Utc::now() - TimeDelta::hours(2))
        .with_expires(Utc::now() - TimeDelta::hours(1));
    let proof = DataIntegrityProof::sign(&document(), &secret, options)
        .await
        .unwrap();

    let result =
        proof.verify_with_public_key(&document(), secret.get_public_bytes(), VerifyOptions::new());
    assert!(
        matches!(result, Err(DataIntegrityError::ProofExpired { .. })),
        "got {result:?}"
    );
    let conformance = verify_conformance(&proof, CryptoSuite::EddsaJcs2022);
    assert!(
        matches!(conformance, Err(DataIntegrityError::ProofExpired { .. })),
        "got {conformance:?}"
    );
}

#[tokio::test]
async fn every_optional_member_is_covered_by_the_signature() {
    type Change = fn(&mut Value);
    let changes: [(&str, Change); 10] = [
        ("expires later", |proof| {
            proof["expires"] = json!("2027-03-01T13:00:00Z")
        }),
        ("expires removed", |proof| {
            proof.as_object_mut().unwrap().remove("expires");
        }),
        ("domain changed", |proof| {
            proof["domain"] = json!("https://verifier.example")
        }),
        ("domain removed", |proof| {
            proof.as_object_mut().unwrap().remove("domain");
        }),
        ("challenge changed", |proof| {
            proof["challenge"] = json!("other")
        }),
        ("challenge removed", |proof| {
            proof.as_object_mut().unwrap().remove("challenge");
        }),
        ("id changed", |proof| {
            proof["id"] = json!("urn:uuid:00000000-0000-4000-8000-000000000000")
        }),
        ("id removed", |proof| {
            proof.as_object_mut().unwrap().remove("id");
        }),
        ("previousProof changed", |proof| {
            proof["previousProof"] = json!(["urn:uuid:00000000-0000-4000-8000-000000000000"])
        }),
        ("previousProof removed", |proof| {
            proof.as_object_mut().unwrap().remove("previousProof");
        }),
    ];

    for (secret, suite) in cases() {
        let signed = DataIntegrityProof::sign(&document(), &secret, sign_options(suite))
            .await
            .unwrap();
        let signed = serde_json::to_value(&signed).unwrap();
        for (name, change) in &changes {
            let mut altered = signed.clone();
            change(&mut altered);
            let proof: DataIntegrityProof = serde_json::from_value(altered).unwrap();
            let result =
                proof.verify_with_public_key(&document(), secret.get_public_bytes(), at(created()));
            assert!(
                matches!(result, Err(DataIntegrityError::InvalidSignature { .. })),
                "{suite}: {name}: must not verify, got {result:?}"
            );
        }
    }
}

#[tokio::test]
async fn a_malformed_expires_is_refused() {
    let secret = Secret::generate_ed25519(Some(VERIFICATION_METHOD), Some(&[7u8; 32]));
    let signed = DataIntegrityProof::sign(
        &document(),
        &secret,
        SignOptions::new()
            .with_created(created())
            .with_expires(expires()),
    )
    .await
    .unwrap();

    for malformed in [
        "",
        "tomorrow",
        "2026-03-01",
        "2026-03-01T13:00:00",
        "2026-03-01 13:00:00Z",
        "2026-03-01t13:00:00z",
        "2026-13-01T13:00:00Z",
        "2026-02-30T13:00:00Z",
        "2026-03-01T24:00:00Z",
        "2026-03-01T13:60:00Z",
        "2026-03-01T13:00:60Z",
        "2026-03-01T13:00:00+14:30",
        "2026-03-01T13:00:00+15:00",
    ] {
        let mut proof = signed.clone();
        proof.expires = Some(malformed.to_string());
        let result =
            proof.verify_with_public_key(&document(), secret.get_public_bytes(), at(created()));
        assert!(
            matches!(result, Err(DataIntegrityError::MalformedProof(_))),
            "{malformed:?} must be refused as malformed, got {result:?}"
        );
    }
}

/// A producer that writes `expires` with a time-zone offset rather than `Z`.
#[tokio::test]
async fn an_expires_with_an_offset_is_compared_in_utc() {
    let secret = Secret::generate_ed25519(Some(VERIFICATION_METHOD), Some(&[7u8; 32]));
    let suite = CryptoSuite::EddsaRdfc2022;
    let mut proof = DataIntegrityProof::new(
        suite,
        VERIFICATION_METHOD.to_string(),
        "assertionMethod".to_string(),
        None,
        Some("2026-03-01T12:00:00Z".to_string()),
        Some(vec!["https://www.w3.org/ns/credentials/v2".to_string()]),
    );
    // 15:00 at +02:00 is 13:00 UTC.
    proof.expires = Some("2026-03-01T15:00:00+02:00".to_string());
    proof.domain = Some(StringOrList::from("https://verifier.example"));
    let input = prepare_sign_input(&document(), &proof, suite).unwrap();
    let signature = secret.sign(&input).await.unwrap();
    proof.proof_value = Some(multibase::encode(Base::Base58Btc, signature));
    let proof = reparse(&proof);

    let public_key = secret.get_public_bytes();
    proof
        .verify_with_public_key(
            &document(),
            public_key,
            at(expires() - TimeDelta::seconds(1)),
        )
        .expect("one second before 13:00 UTC verifies");
    let result = proof.verify_with_public_key(&document(), public_key, at(expires()));
    assert!(
        matches!(result, Err(DataIntegrityError::ProofExpired { .. })),
        "got {result:?}"
    );
}

#[tokio::test]
async fn expected_domain_and_challenge_are_checked_when_set() {
    let secret = Secret::generate_ed25519(Some(VERIFICATION_METHOD), Some(&[7u8; 32]));
    let public_key = secret.get_public_bytes();
    let proof = DataIntegrityProof::sign(
        &document(),
        &secret,
        sign_options(CryptoSuite::EddsaJcs2022),
    )
    .await
    .unwrap();

    proof
        .verify_with_public_key(
            &document(),
            public_key,
            at(created())
                .with_expected_domain("https://other.example")
                .with_expected_challenge("1f44d55f-f161-4938-a659-f8026467f126"),
        )
        .expect("a listed domain and the issued challenge verify");

    let wrong_domain = proof.verify_with_public_key(
        &document(),
        public_key,
        at(created()).with_expected_domain("https://elsewhere.example"),
    );
    assert!(
        matches!(wrong_domain, Err(DataIntegrityError::Conformance(_))),
        "got {wrong_domain:?}"
    );
    let wrong_challenge = proof.verify_with_public_key(
        &document(),
        public_key,
        at(created()).with_expected_challenge("another"),
    );
    assert!(
        matches!(wrong_challenge, Err(DataIntegrityError::Conformance(_))),
        "got {wrong_challenge:?}"
    );

    let bare = DataIntegrityProof::sign(&document(), &secret, SignOptions::new())
        .await
        .unwrap();
    for options in [
        VerifyOptions::new().with_expected_domain("https://verifier.example"),
        VerifyOptions::new().with_expected_challenge("1f44d55f-f161-4938-a659-f8026467f126"),
    ] {
        let result = bare.verify_with_public_key(&document(), public_key, options);
        assert!(
            matches!(result, Err(DataIntegrityError::Conformance(_))),
            "a proof without the member must be refused when one is expected, got {result:?}"
        );
    }
}

#[tokio::test]
async fn a_relative_id_or_previous_proof_is_refused() {
    let secret = Secret::generate_ed25519(Some(VERIFICATION_METHOD), Some(&[7u8; 32]));
    let relative = [
        "#proof-1",
        "proof-0",
        "",
        "1urn:x",
        "urn:has space",
        "//host/path",
    ];

    for value in relative {
        for options in [
            SignOptions::new().with_id(value),
            SignOptions::new().with_previous_proof(value),
            SignOptions::new().with_previous_proof(vec![
                "urn:uuid:0e5c1d2b-3a4f-4b6e-9d7c-8a1b2c3d4e5f".to_string(),
                value.to_string(),
            ]),
        ] {
            let result = DataIntegrityProof::sign(&document(), &secret, options).await;
            assert!(
                matches!(result, Err(DataIntegrityError::MalformedProof(_))),
                "signing with {value:?} must be refused, got {result:?}"
            );
        }
    }

    for suite in [CryptoSuite::EddsaJcs2022, CryptoSuite::EddsaRdfc2022] {
        let signed = DataIntegrityProof::sign(
            &document(),
            &secret,
            SignOptions::new()
                .with_cryptosuite(suite)
                .with_created(created()),
        )
        .await
        .unwrap();
        for value in relative {
            let mut with_id = signed.clone();
            with_id.id = Some(value.to_string());
            let mut with_previous = signed.clone();
            with_previous.previous_proof = Some(StringOrList::from(value));
            for proof in [with_id, with_previous] {
                let result = proof.verify_with_public_key(
                    &document(),
                    secret.get_public_bytes(),
                    at(created()),
                );
                assert!(
                    matches!(result, Err(DataIntegrityError::MalformedProof(_))),
                    "{suite}: {value:?} must be refused, got {result:?}"
                );
            }
        }
    }
}

#[tokio::test]
async fn expires_before_created_is_refused() {
    let secret = Secret::generate_ed25519(Some(VERIFICATION_METHOD), Some(&[7u8; 32]));
    let result = DataIntegrityProof::sign(
        &document(),
        &secret,
        SignOptions::new()
            .with_created(created())
            .with_expires(created() - TimeDelta::seconds(1)),
    )
    .await;
    assert!(
        matches!(result, Err(DataIntegrityError::MalformedProof(_))),
        "got {result:?}"
    );

    let mut proof = DataIntegrityProof::sign(
        &document(),
        &secret,
        SignOptions::new()
            .with_created(created())
            .with_expires(expires()),
    )
    .await
    .unwrap();
    proof.expires = Some("2026-03-01T11:59:59Z".to_string());
    let result =
        proof.verify_with_public_key(&document(), secret.get_public_bytes(), at(created()));
    assert!(
        matches!(result, Err(DataIntegrityError::MalformedProof(_))),
        "got {result:?}"
    );
}

#[tokio::test]
async fn a_malformed_created_is_refused() {
    let secret = Secret::generate_ed25519(Some(VERIFICATION_METHOD), Some(&[7u8; 32]));
    let signed = DataIntegrityProof::sign(&document(), &secret, SignOptions::new())
        .await
        .unwrap();
    for malformed in [
        "2026-03-01T12:00:00",
        "2026-03-01 12:00:00Z",
        "2026-03-01t12:00:00z",
        "2026-02-30T12:00:00Z",
        "2026-03-01T12:00:60Z",
        "2026-03-01T12:00:00+15:00",
    ] {
        let mut proof = signed.clone();
        proof.created = Some(malformed.to_string());
        let result = proof.verify_with_public_key(
            &document(),
            secret.get_public_bytes(),
            VerifyOptions::new(),
        );
        assert!(
            matches!(result, Err(DataIntegrityError::MalformedProof(_))),
            "{malformed:?} must be refused as malformed, got {result:?}"
        );
    }
}
