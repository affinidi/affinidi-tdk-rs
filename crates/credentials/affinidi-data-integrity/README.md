# affinidi-data-integrity

[![Crates.io](https://img.shields.io/crates/v/affinidi-data-integrity.svg)](https://crates.io/crates/affinidi-data-integrity)
[![Documentation](https://docs.rs/affinidi-data-integrity/badge.svg)](https://docs.rs/affinidi-data-integrity)
[![Rust](https://img.shields.io/badge/rust-1.94%2B-blue.svg?maxAge=3600)](https://github.com/affinidi/affinidi-tdk-rs)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)

A production-grade implementation of the
[W3C Data Integrity](https://www.w3.org/TR/vc-data-integrity/) specification
for the Affinidi Trust Development Kit. Sign and verify cryptographic
proofs over JSON and JSON-LD documents using classical (Ed25519) and
post-quantum (ML-DSA, SLH-DSA) algorithms.

- **Unified API** — one `sign()` / `verify_with_public_key()` / `verify()` entry point.
- **Post-quantum ready** — ML-DSA-44 and SLH-DSA-SHA2-128s behind the `post-quantum` feature flag (W3C `di-quantum-safe` v0.3, experimental).
- **First-class remote signers** — KMS / HSM backends implement the same `Signer` trait, with a `prepare_sign_input` helper for protocols that hash out-of-band.
- **Hybrid / multi-proof** — `sign_multi` and `verify_multi` with `VerifyPolicy::{RequireAll, RequireAny, RequireThreshold(n)}` for witness schemes and gradual PQC migration.
- **Spec-shape validation** — `verify_conformance` catches malformed-but-cryptographically-valid proofs separately from signature verification.

## Cryptosuites

| Cryptosuite | Alg | Canonicalization | Feature | Status |
|---|---|---|---|---|
| `eddsa-jcs-2022` | Ed25519 | JCS (RFC 8785) | (default) | W3C Rec |
| `eddsa-rdfc-2022` | Ed25519 | RDFC-1.0 (URDNA2015) | (default) | W3C Rec |
| `bbs-2023` | BBS+ / BLS12-381 | JCS (selective disclosure) | `bbs-2023` | W3C WD |
| `mldsa44-jcs-2024` | ML-DSA-44 (FIPS 204) | JCS | `ml-dsa` / `post-quantum` | Experimental |
| `mldsa44-rdfc-2024` | ML-DSA-44 | RDFC-1.0 | `ml-dsa` / `post-quantum` | Experimental |
| `slhdsa128-jcs-2024` | SLH-DSA-SHA2-128s (FIPS 205) | JCS | `slh-dsa` / `post-quantum` | Experimental |
| `slhdsa128-rdfc-2024` | SLH-DSA-SHA2-128s | RDFC-1.0 | `slh-dsa` / `post-quantum` | Experimental |

**Default choice**: `eddsa-jcs-2022` — it is produced automatically for any Ed25519 `Signer` unless overridden via `SignOptions::with_cryptosuite(...)`. Prefer JCS over RDFC for new designs; RDFC is ~4× slower and mainly needed for JSON-LD interop.

## Feature flags

| Feature | Default | Enables |
|---|---|---|
| `bbs-2023` | off | `bbs-2023` cryptosuite (BLS12-381 selective disclosure) |
| `ml-dsa` | off | ML-DSA (FIPS 204) primitives + `mldsa44-*-2024` cryptosuites |
| `slh-dsa` | off | SLH-DSA-SHA2-128s (FIPS 205) primitives + `slhdsa128-*-2024` cryptosuites |
| `post-quantum` | off | umbrella — enables both `ml-dsa` and `slh-dsa` |

**For verifiers**: enable broadly. You don't pick what you're asked to verify, so you want the largest compatible surface.

**For signers**: enable narrowly. Pick the exact suites you produce, to reduce binary size and auditable attack surface.

## Installation

```toml
[dependencies]
affinidi-data-integrity = "0.5"

# With post-quantum cryptosuites:
# affinidi-data-integrity = { version = "0.5", features = ["post-quantum"] }
```

## Quickstart

```rust
use affinidi_data_integrity::{DataIntegrityProof, SignOptions, VerifyOptions};
use affinidi_secrets_resolver::secrets::Secret;
use serde_json::json;

# async fn demo() -> Result<(), affinidi_data_integrity::DataIntegrityError> {
let secret = Secret::generate_ed25519(Some("did:key:z6Mk...#key-0"), None);
let doc = json!({ "name": "Alice" });

// Sign — the library auto-picks `eddsa-jcs-2022` for Ed25519 keys.
let proof = DataIntegrityProof::sign(&doc, &secret, SignOptions::new()).await?;

// Verify — pass the public-key bytes directly.
proof.verify_with_public_key(&doc, secret.get_public_bytes(), VerifyOptions::new())?;
# Ok(()) }
```

### Post-quantum — same API, ML-DSA key

```rust
# #[cfg(feature = "ml-dsa")]
# async fn pqc() -> Result<(), affinidi_data_integrity::DataIntegrityError> {
use affinidi_data_integrity::{DataIntegrityProof, SignOptions};
use affinidi_secrets_resolver::secrets::Secret;
use serde_json::json;

let secret = Secret::generate_ml_dsa_44(Some("did:key:zMl...#k"), None);
// Signer::cryptosuite() auto-selects mldsa44-jcs-2024 from the key type.
let proof = DataIntegrityProof::sign(&json!({"pqc": true}), &secret, SignOptions::new()).await?;
# Ok(()) }
```

### Resolving the public key via DID

```rust
# async fn verify_via_did() -> Result<(), affinidi_data_integrity::DataIntegrityError> {
use affinidi_data_integrity::{DidKeyResolver, VerifyOptions};
# let proof: affinidi_data_integrity::DataIntegrityProof = todo!();
# let doc = serde_json::json!({});

// Works for did:key out-of-the-box; plug in a custom resolver for did:web / did:webvh.
proof.verify(&doc, &DidKeyResolver, VerifyOptions::new()).await?;
# Ok(()) }
```

### Remote signer (KMS / HSM)

Implement the `Signer` trait — exactly the same trait that local keys use. See `examples/remote_signer_ed25519.rs` and `examples/remote_signer_ml_dsa.rs` for full worked examples with a mock signing service. For protocols that hash out-of-band, `prepare_sign_input()` returns the exact bytes the remote side must sign.

### Multi-proof (hybrid migration, witness threshold)

```rust
# #[cfg(feature = "ml-dsa")]
# async fn multi() -> Result<(), affinidi_data_integrity::DataIntegrityError> {
use affinidi_data_integrity::{
    DataIntegrityProof, DidKeyResolver, SignOptions, VerifyOptions,
    VerifyPolicy, verify_multi,
};
use affinidi_data_integrity::signer::Signer;
# let classical: affinidi_secrets_resolver::secrets::Secret = todo!();
# let pqc: affinidi_secrets_resolver::secrets::Secret = todo!();
# let doc = serde_json::json!({});

// Ed25519 + ML-DSA proofs on the same credential.
let signers: Vec<&dyn Signer> = vec![&classical, &pqc];
let proofs = DataIntegrityProof::sign_multi(&doc, &signers, SignOptions::new()).await?;

// Accept the credential if at least one proof verifies — tolerates a
// verifier that only understands one of the two suites.
let result = verify_multi(&proofs, &doc, &DidKeyResolver, VerifyOptions::new(), VerifyPolicy::RequireAny).await;
result.into_result()?;
# Ok(()) }
```

### Caching ML-DSA for issuer-scale workloads

ML-DSA signing expands the FIPS 204 matrix on every call (~80–100 µs for ML-DSA-44). For issuers signing thousands of credentials with the same key, wrap in `CachingSigner`:

```rust,ignore
use affinidi_data_integrity::CachingSigner;
let signer = CachingSigner::new(secret);
// First sign expands and caches; subsequent signs reuse the expanded key.
```

Benchmarks show ~33% latency reduction per sign for ML-DSA-44 on cached paths.

## Performance

Apple M4 Pro, `--release`, `cargo bench -p affinidi-data-integrity --features post-quantum`:

| Cryptosuite | Sign | Sign (CachingSigner) | Proof size |
|---|---:|---:|---:|
| `eddsa-jcs-2022` | 46 µs | — | 89 B |
| `eddsa-rdfc-2022` | 198 µs | — | 89 B |
| `mldsa44-jcs-2024` | 373 µs | **248 µs** (‑33%) | ~3306 B |
| `mldsa44-rdfc-2024` | ~500 µs | **~375 µs** (‑25%) | ~3306 B |
| `slhdsa128-jcs-2024` | 117 ms | — | ~10730 B |

`CachingSigner<S>` caches the expanded ML-DSA matrix after the first sign. Subsequent signs skip the ~80–100 µs re-expansion. Ed25519 and SLH-DSA don't have expansion-cacheable state.

SLH-DSA trades signature speed for tiny keys (32 B public, 64 B private) and stateless-hash security — use it when signing rarely and long-term unforgeability matters more than throughput.

## Migration from ≤0.5.3 to 0.5.4

0.5.4 introduces a unified sign/verify API. The old entry points remain as `#[deprecated]` thin wrappers for one minor version (planned removal in 0.6.0). Breaking changes stay within pre-1.0 minor-version semantics and don't require downstream crate republishes that pin `^0.5`.

| Old (0.5) | New (0.6) |
|---|---|
| `DataIntegrityProof::sign_jcs_data(&doc, ctx, &signer, created)` | `DataIntegrityProof::sign(&doc, &signer, SignOptions::new().with_context(ctx).with_created(ts))` |
| `sign_jcs_data_with_suite(suite, ...)` | `DataIntegrityProof::sign(..., SignOptions::new().with_cryptosuite(suite))` |
| `sign_rdfc_data(...)` | same as `sign` — RDFC is derived from the suite |
| `verify_data_with_public_key(...)` | `proof.verify_with_public_key(&doc, &pk, VerifyOptions::new())` |

Also: `DataIntegrityError` gained structured variants (`KeyTypeMismatch`, `InvalidSignature`, etc.). The old `InputDataError(String)` / `CryptoError(String)` / `VerificationError(String)` / `SecretsError(String)` / `RdfEncodingError(String)` variants are kept as `#[deprecated]` for the same deprecation window.

See [CHANGELOG.md](CHANGELOG.md) for the full breaking-change list.

## Security considerations

- **Post-quantum suites are experimental.** W3C `di-quantum-safe` is v0.3 and explicitly "do not use in production"; NIST FIPS 204 / 205 are final, but the Data Integrity profile on top is still moving. Classical Ed25519 is the only option currently recommended for production-grade VCs.
- **Deterministic signing.** All supported suites (Ed25519, ML-DSA, SLH-DSA) sign deterministically in this crate — the same input produces the same signature. This is required for W3C interop and for reproducible test vectors. If you need randomised signatures for side-channel reasons, drop to the underlying primitive crates directly.
- **Zeroize coverage.** Private key bytes held by `Secret` are zeroized on drop via its `ZeroizeOnDrop` derive. The ML-DSA crate zeroizes its expanded matrix (we enable its `zeroize` feature). Intermediate stack copies inside this crate are wrapped in `Zeroizing`. Your own `Signer` implementations should match this.
- **Timing channels.** Ed25519 and ML-DSA signing are constant-time in the underlying RustCrypto crates. SLH-DSA has branching tied to public material only. BBS-2023 has selective-disclosure-specific side-channel considerations — see its spec.
- See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## Out of scope

- **JOSE / JWS / JWT post-quantum.** Waiting for IETF draft stability. When those standards land they will live in sibling crates (`affinidi-data-integrity-jose`, etc.), not this crate.
- **COSE / mdoc post-quantum.** Same — waiting on IETF.
- **FALCON, SQIsign, HAWK, Kyber/ML-KEM.** Either not NIST-finalised or not in the current `di-quantum-safe` cryptosuite set.

## Related crates

- [`affinidi-crypto`](../../core/affinidi-crypto/) — classical and post-quantum primitives.
- [`affinidi-encoding`](../../core/affinidi-encoding/) — multicodec / multibase.
- [`affinidi-secrets-resolver`](../../core/affinidi-secrets-resolver/) — key material and multikey codec.
- [`affinidi-rdf-encoding`](../affinidi-rdf-encoding/) — RDFC-1.0 canonicalization.

## License

[Apache-2.0](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)
