//! Per-suite sign / verify / roundtrip benchmarks.
//!
//! Run with: `cargo bench -p affinidi-data-integrity --features post-quantum`
//!
//! Produces Criterion HTML reports under `target/criterion/`. Numbers
//! are documented in the crate README.

use affinidi_data_integrity::{
    DataIntegrityProof, SignOptions, VerifyOptions, crypto_suites::CryptoSuite,
};
use affinidi_secrets_resolver::secrets::Secret;
use chrono::TimeZone;
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use serde_json::json;

/// W3C vc-di-eddsa B.1 Alumni Credential.
fn sample_doc() -> serde_json::Value {
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

fn fixed_created() -> chrono::DateTime<chrono::Utc> {
    chrono::Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()
}

/// One signer per suite, keyed on the suite name.
fn make_signer(suite: CryptoSuite) -> Secret {
    match suite {
        CryptoSuite::EddsaJcs2022 | CryptoSuite::EddsaRdfc2022 => {
            Secret::generate_ed25519(Some("did:key:bench#bench"), Some(&[1u8; 32]))
        }
        #[cfg(feature = "ml-dsa")]
        CryptoSuite::MlDsa44Jcs2024 | CryptoSuite::MlDsa44Rdfc2024 => {
            Secret::generate_ml_dsa_44(Some("did:key:bench#bench"), Some(&[2u8; 32]))
        }
        #[cfg(feature = "slh-dsa")]
        CryptoSuite::SlhDsa128Jcs2024 | CryptoSuite::SlhDsa128Rdfc2024 => {
            Secret::generate_slh_dsa_sha2_128s(Some("did:key:bench#bench"))
        }
        _ => panic!("bench: unsupported suite {suite:?}"),
    }
}

fn suites_enabled() -> Vec<(CryptoSuite, &'static str)> {
    let mut out: Vec<(CryptoSuite, &'static str)> = vec![
        (CryptoSuite::EddsaJcs2022, "eddsa-jcs-2022"),
        (CryptoSuite::EddsaRdfc2022, "eddsa-rdfc-2022"),
    ];
    #[cfg(feature = "ml-dsa")]
    {
        out.push((CryptoSuite::MlDsa44Jcs2024, "mldsa44-jcs-2024"));
        out.push((CryptoSuite::MlDsa44Rdfc2024, "mldsa44-rdfc-2024"));
    }
    #[cfg(feature = "slh-dsa")]
    {
        out.push((CryptoSuite::SlhDsa128Jcs2024, "slhdsa128-jcs-2024"));
        // slhdsa128-rdfc-2024 sign is dominated by the SLH-DSA signature
        // (~117 ms on Apple M4 Pro) plus the RDFC expansion. With the
        // default criterion sample_size=100 the bench group would take
        // ~15 minutes — skip by default. Uncomment the push below for
        // local deep-dive runs.
        // out.push((CryptoSuite::SlhDsa128Rdfc2024, "slhdsa128-rdfc-2024"));
    }
    out
}

fn sign_once(
    rt: &tokio::runtime::Runtime,
    doc: &serde_json::Value,
    signer: &Secret,
    suite: CryptoSuite,
) -> DataIntegrityProof {
    rt.block_on(DataIntegrityProof::sign(
        doc,
        signer,
        SignOptions::new()
            .with_cryptosuite(suite)
            .with_created(fixed_created()),
    ))
    .expect("sign")
}

fn bench_sign(c: &mut Criterion) {
    let doc = sample_doc();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("sign");

    for (suite, name) in suites_enabled() {
        let signer = make_signer(suite);
        group.bench_with_input(BenchmarkId::from_parameter(name), &name, |b, _| {
            b.iter(|| sign_once(&rt, &doc, &signer, suite))
        });
    }
    group.finish();
}

fn bench_verify(c: &mut Criterion) {
    let doc = sample_doc();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("verify");

    for (suite, name) in suites_enabled() {
        let signer = make_signer(suite);
        let proof = sign_once(&rt, &doc, &signer, suite);
        let pk = signer.get_public_bytes().to_vec();
        group.bench_with_input(BenchmarkId::from_parameter(name), &name, |b, _| {
            b.iter(|| {
                proof
                    .verify_with_public_key(&doc, &pk, VerifyOptions::new())
                    .unwrap()
            })
        });
    }
    group.finish();
}

fn bench_roundtrip(c: &mut Criterion) {
    let doc = sample_doc();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("roundtrip_sign_serialize_deserialize_verify");

    for (suite, name) in suites_enabled() {
        let signer = make_signer(suite);
        let pk = signer.get_public_bytes().to_vec();
        group.bench_with_input(BenchmarkId::from_parameter(name), &name, |b, _| {
            b.iter(|| {
                let proof = sign_once(&rt, &doc, &signer, suite);
                let json = serde_json::to_string(&proof).unwrap();
                let parsed: DataIntegrityProof = serde_json::from_str(&json).unwrap();
                parsed
                    .verify_with_public_key(&doc, &pk, VerifyOptions::new())
                    .unwrap();
            })
        });
    }
    group.finish();
}

#[cfg(feature = "ml-dsa")]
fn bench_ml_dsa_caching(c: &mut Criterion) {
    use affinidi_data_integrity::{CachingSigner, signer::Signer};
    let rt = tokio::runtime::Runtime::new().unwrap();
    let _ = sample_doc();
    let plain = Secret::generate_ml_dsa_44(Some("did:key:bench#bench"), Some(&[2u8; 32]));
    let cached = CachingSigner::new(plain.clone());

    let mut group = c.benchmark_group("ml_dsa_44_sign_cache");
    group.bench_function("uncached", |b| {
        b.iter(|| rt.block_on(plain.sign(b"hot-path")).unwrap())
    });
    group.bench_function("cached", |b| {
        b.iter(|| rt.block_on(cached.sign(b"hot-path")).unwrap())
    });
    group.finish();
}

#[cfg(not(feature = "ml-dsa"))]
fn bench_ml_dsa_caching(_c: &mut Criterion) {}

/// Static size assertions — emitted at bench startup so the README can
/// quote the numbers without re-measuring.
fn emit_sizes() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let doc = sample_doc();
    eprintln!("signature sizes (multibase-encoded proofValue):");
    for (suite, name) in suites_enabled() {
        let signer = make_signer(suite);
        let proof = sign_once(&rt, &doc, &signer, suite);
        let pv_len = proof.proof_value.as_ref().map(String::len).unwrap_or(0);
        eprintln!("  {name}: {pv_len} bytes");
    }
}

fn bench_emit_sizes(c: &mut Criterion) {
    emit_sizes();
    // Criterion expects at least one measurement per benchmark fn,
    // so do a trivial one so the harness is happy.
    c.bench_function("emit_sizes", |b| b.iter(|| ()));
}

criterion_group!(
    benches,
    bench_sign,
    bench_verify,
    bench_roundtrip,
    bench_ml_dsa_caching,
    bench_emit_sizes,
);
criterion_main!(benches);
