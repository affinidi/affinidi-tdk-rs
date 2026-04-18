//! Regression tests for deterministic sign output.
//!
//! Each fixture under `tests/fixtures/*.json` describes a sign input
//! (seed, document, created, proof_purpose, suite) and the expected
//! output (the full `DataIntegrityProof`). We re-sign with the stored
//! inputs and assert byte-for-byte equality.
//!
//! Set `AFFINIDI_DATA_INTEGRITY_REGEN_FIXTURES=1` to regenerate each
//! fixture with the current code's output.

use std::path::{Path, PathBuf};

use affinidi_data_integrity::{
    DataIntegrityProof, SignOptions, VerifyOptions, crypto_suites::CryptoSuite,
};
use affinidi_secrets_resolver::secrets::Secret;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Serialize, Deserialize)]
struct Fixture {
    suite: String,
    seed_hex: String,
    kid: String,
    document: Value,
    created: String,
    #[serde(default)]
    proof_purpose: Option<String>,
    /// Expected sign output. Absent when regenerating.
    #[serde(default)]
    expected_proof: Option<DataIntegrityProof>,
}

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn hex_to_seed(hex: &str) -> [u8; 32] {
    assert_eq!(hex.len(), 64, "seed hex must be 32 bytes");
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

/// Builds the signing Secret for a fixture, or returns `None` if the
/// fixture's suite requires a Cargo feature that isn't compiled in.
/// Lets the default-features test run pass over PQC fixtures.
async fn build_secret(fixture: &Fixture) -> Option<Secret> {
    let seed = hex_to_seed(&fixture.seed_hex);
    let kid = Some(fixture.kid.as_str());
    match fixture.suite.as_str() {
        "eddsa-jcs-2022" | "eddsa-rdfc-2022" => Some(Secret::generate_ed25519(kid, Some(&seed))),
        #[cfg(feature = "ml-dsa")]
        "mldsa44-jcs-2024" | "mldsa44-rdfc-2024" => {
            Some(Secret::generate_ml_dsa_44(kid, Some(&seed)))
        }
        _ => None,
    }
}

async fn sign_fixture(fixture: &Fixture, secret: &Secret) -> DataIntegrityProof {
    let created = fixture.created.parse::<DateTime<Utc>>().expect("created");
    let mut opts = SignOptions::new()
        .with_cryptosuite(CryptoSuite::try_from(fixture.suite.as_str()).unwrap())
        .with_created(created);
    if let Some(pp) = &fixture.proof_purpose {
        opts = opts.with_proof_purpose(pp.clone());
    }
    DataIntegrityProof::sign(&fixture.document, secret, opts)
        .await
        .expect("sign")
}

fn should_regen() -> bool {
    std::env::var("AFFINIDI_DATA_INTEGRITY_REGEN_FIXTURES").is_ok()
}

async fn run_fixture(path: &Path) {
    let raw =
        std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    // Peek at the suite name first without deserializing the whole
    // fixture — some fixtures use PQC cryptosuite variants that aren't
    // present in the CryptoSuite enum under default features.
    let peek: serde_json::Value = serde_json::from_str(&raw).expect("fixture JSON");
    let suite_name = peek
        .get("suite")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let suite_supported = matches!(
        suite_name,
        "eddsa-jcs-2022" | "eddsa-rdfc-2022" | "bbs-2023"
    ) || (cfg!(feature = "ml-dsa")
        && matches!(suite_name, "mldsa44-jcs-2024" | "mldsa44-rdfc-2024"))
        || (cfg!(feature = "slh-dsa")
            && matches!(suite_name, "slhdsa128-jcs-2024" | "slhdsa128-rdfc-2024"));
    if !suite_supported {
        eprintln!(
            "skipping fixture {} — suite {} needs a feature that isn't compiled",
            path.display(),
            suite_name
        );
        return;
    }

    let mut fixture: Fixture = serde_json::from_str(&raw).expect("parse fixture");
    let Some(secret) = build_secret(&fixture).await else {
        eprintln!(
            "skipping fixture {} — no secret generator for suite",
            path.display()
        );
        return;
    };
    let actual = sign_fixture(&fixture, &secret).await;

    // Always verify the signature — fixtures must always be round-trippable.
    actual
        .verify_with_public_key(
            &fixture.document,
            secret.get_public_bytes(),
            VerifyOptions::new(),
        )
        .expect("verify fixture proof");

    if should_regen() {
        fixture.expected_proof = Some(actual);
        let json = serde_json::to_string_pretty(&fixture).unwrap();
        std::fs::write(path, json).expect("regen write");
        return;
    }

    match &fixture.expected_proof {
        Some(expected) => {
            // Pin on the serialised form so we catch field-ordering
            // differences too.
            let expected_json = serde_json::to_string(expected).unwrap();
            let actual_json = serde_json::to_string(&actual).unwrap();
            assert_eq!(
                actual_json,
                expected_json,
                "fixture {} drifted — run with AFFINIDI_DATA_INTEGRITY_REGEN_FIXTURES=1 and commit after reviewing",
                path.display()
            );
        }
        None => panic!(
            "fixture {} has no expected_proof; regenerate with AFFINIDI_DATA_INTEGRITY_REGEN_FIXTURES=1",
            path.display()
        ),
    }
}

#[tokio::test]
async fn all_fixtures_round_trip() {
    let dir = fixture_dir();
    let mut any = false;
    for entry in std::fs::read_dir(&dir).expect("read fixtures dir") {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("json") {
            any = true;
            run_fixture(&path).await;
        }
    }
    // At least one .json file must exist — skip-vs-run is a matter of
    // which features are enabled at test time.
    assert!(any, "no JSON fixtures found in {}", dir.display());
}
