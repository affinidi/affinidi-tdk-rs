use affinidi_data_integrity::{
    DataIntegrityProof, verification_proof::verify_data_with_public_key,
};
use affinidi_secrets_resolver::secrets::Secret;
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use serde_json::json;

/// W3C vc-di-eddsa B.1 Alumni Credential — used by both JCS and RDFC benchmarks.
fn b1_credential() -> serde_json::Value {
    json!({
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://www.w3.org/ns/credentials/examples/v2"
        ],
        "id": "urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33",
        "type": ["VerifiableCredential", "AlumniCredential"],
        "name": "Alumni Credential",
        "description": "A minimum viable example of an Alumni Credential.",
        "issuer": "https://vc.example/issuers/5678",
        "validFrom": "2023-01-01T00:00:00Z",
        "credentialSubject": {
            "id": "did:example:abcdefgh",
            "alumniOf": "The School of Examples"
        }
    })
}

fn test_secret() -> Secret {
    let pub_key = "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2";
    let pri_key = "z3u2en7t5LR2WtQH5PfFqMqwVHBeXouLzo6haApm8XHqvjxq";
    Secret::from_multibase(pri_key, Some(&format!("did:key:{pub_key}#{pub_key}")))
        .expect("Invalid key")
}

fn context_from_doc(doc: &serde_json::Value) -> Vec<String> {
    doc.get("@context")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e.as_str().unwrap().to_string())
        .collect()
}

// ─── Signing benchmarks ───────────────────────────────────────────────

fn bench_sign_jcs(c: &mut Criterion) {
    let doc = b1_credential();
    let context = context_from_doc(&doc);
    let secret = test_secret();

    c.bench_function("sign_jcs", |b| {
        b.iter(|| {
            DataIntegrityProof::sign_jcs_data(
                &doc,
                Some(context.clone()),
                &secret,
                Some("2023-02-24T23:36:38Z".to_string()),
            )
            .unwrap()
        })
    });
}

fn bench_sign_rdfc(c: &mut Criterion) {
    let doc = b1_credential();
    let context = context_from_doc(&doc);
    let secret = test_secret();

    c.bench_function("sign_rdfc", |b| {
        b.iter(|| {
            DataIntegrityProof::sign_rdfc_data(
                &doc,
                Some(context.clone()),
                &secret,
                Some("2023-02-24T23:36:38Z".to_string()),
            )
            .unwrap()
        })
    });
}

// ─── Verification benchmarks ──────────────────────────────────────────

fn bench_verify_jcs(c: &mut Criterion) {
    let doc = b1_credential();
    let context = context_from_doc(&doc);
    let secret = test_secret();

    let proof = DataIntegrityProof::sign_jcs_data(
        &doc,
        Some(context.clone()),
        &secret,
        Some("2023-02-24T23:36:38Z".to_string()),
    )
    .unwrap();

    let public_key_bytes = secret.get_public_bytes().to_vec();

    c.bench_function("verify_jcs", |b| {
        b.iter(|| {
            verify_data_with_public_key(
                &doc,
                Some(context.clone()),
                &proof,
                public_key_bytes.as_slice(),
            )
            .unwrap()
        })
    });
}

fn bench_verify_rdfc(c: &mut Criterion) {
    let doc = b1_credential();
    let context = context_from_doc(&doc);
    let secret = test_secret();

    let proof = DataIntegrityProof::sign_rdfc_data(
        &doc,
        Some(context.clone()),
        &secret,
        Some("2023-02-24T23:36:38Z".to_string()),
    )
    .unwrap();

    let public_key_bytes = secret.get_public_bytes().to_vec();

    c.bench_function("verify_rdfc", |b| {
        b.iter(|| {
            verify_data_with_public_key(
                &doc,
                Some(context.clone()),
                &proof,
                public_key_bytes.as_slice(),
            )
            .unwrap()
        })
    });
}

// ─── Side-by-side comparison group ────────────────────────────────────

fn bench_sign_comparison(c: &mut Criterion) {
    let doc = b1_credential();
    let context = context_from_doc(&doc);
    let secret = test_secret();

    let mut group = c.benchmark_group("sign");
    for suite in ["jcs", "rdfc"] {
        group.bench_with_input(BenchmarkId::from_parameter(suite), &suite, |b, suite| {
            b.iter(|| match *suite {
                "jcs" => {
                    DataIntegrityProof::sign_jcs_data(
                        &doc,
                        Some(context.clone()),
                        &secret,
                        Some("2023-02-24T23:36:38Z".to_string()),
                    )
                    .unwrap();
                }
                "rdfc" => {
                    DataIntegrityProof::sign_rdfc_data(
                        &doc,
                        Some(context.clone()),
                        &secret,
                        Some("2023-02-24T23:36:38Z".to_string()),
                    )
                    .unwrap();
                }
                _ => unreachable!(),
            })
        });
    }
    group.finish();
}

fn bench_verify_comparison(c: &mut Criterion) {
    let doc = b1_credential();
    let context = context_from_doc(&doc);
    let secret = test_secret();

    let jcs_proof = DataIntegrityProof::sign_jcs_data(
        &doc,
        Some(context.clone()),
        &secret,
        Some("2023-02-24T23:36:38Z".to_string()),
    )
    .unwrap();

    let rdfc_proof = DataIntegrityProof::sign_rdfc_data(
        &doc,
        Some(context.clone()),
        &secret,
        Some("2023-02-24T23:36:38Z".to_string()),
    )
    .unwrap();

    let public_key_bytes = secret.get_public_bytes().to_vec();

    let mut group = c.benchmark_group("verify");
    for suite in ["jcs", "rdfc"] {
        group.bench_with_input(BenchmarkId::from_parameter(suite), &suite, |b, suite| {
            let proof = match *suite {
                "jcs" => &jcs_proof,
                "rdfc" => &rdfc_proof,
                _ => unreachable!(),
            };
            b.iter(|| {
                verify_data_with_public_key(
                    &doc,
                    Some(context.clone()),
                    proof,
                    public_key_bytes.as_slice(),
                )
                .unwrap()
            })
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_sign_jcs,
    bench_sign_rdfc,
    bench_verify_jcs,
    bench_verify_rdfc,
    bench_sign_comparison,
    bench_verify_comparison,
);
criterion_main!(benches);
