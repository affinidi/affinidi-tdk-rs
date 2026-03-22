# affinidi-data-integrity

[![Crates.io](https://img.shields.io/crates/v/affinidi-data-integrity.svg)](https://crates.io/crates/affinidi-data-integrity)
[![Documentation](https://docs.rs/affinidi-data-integrity/badge.svg)](https://docs.rs/affinidi-data-integrity)
[![Rust](https://img.shields.io/badge/rust-1.90.0%2B-blue.svg?maxAge=3600)](https://github.com/affinidi/affinidi-tdk-rs/tree/main/crates/affinidi-tdk/common/affinidi-data-integrity)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)

An implementation of the
[W3C Data Integrity](https://www.w3.org/TR/vc-data-integrity/) specification,
integrated with the Affinidi Trust Development Kit. Create and verify
cryptographic proofs over JSON and JSON-LD documents using Ed25519.

## Supported Cryptosuites

| Cryptosuite | Canonicalization | Use Case |
|---|---|---|
| `eddsa-jcs-2022` | JSON Canonicalization Scheme (JCS) | General JSON documents |
| `eddsa-rdfc-2022` | RDF Dataset Canonicalization (RDFC-1.0) | JSON-LD / Verifiable Credentials |

**Prefer JCS unless you specifically need RDFC.** JCS is ~4x faster as it
canonicalizes JSON directly, while RDFC must expand JSON-LD into RDF.

## Installation

```toml
[dependencies]
affinidi-data-integrity = "0.5"
```

## Usage

### Sign a JSON Document (JCS)

Signing methods are `async` and accept any implementation of the `Signer` trait.
The `Secret` type implements `Signer` directly, so existing code only needs to add `.await`:

```rust
use affinidi_data_integrity::DataIntegrityProof;
use affinidi_secrets_resolver::secrets::Secret;
use serde_json::json;

let document = json!({
    "id": "urn:uuid:example-123",
    "type": "ExampleDocument",
    "data": "Hello, world!"
});

let secret = Secret::from_multibase(
    "z3u2en7t5LR2WtQH5PfFqMqwVHBeXouLzo6haApm8XHqvjxq",
    Some("did:key:z6Mkr...#z6Mkr..."),
).expect("Invalid key");

let proof = DataIntegrityProof::sign_jcs_data(
    &document, None, &secret, None,
).await.expect("Signing failed");
```

### Sign a Verifiable Credential (RDFC)

```rust
let credential = json!({
    "@context": [
        "https://www.w3.org/ns/credentials/v2",
        "https://www.w3.org/ns/credentials/examples/v2"
    ],
    "type": ["VerifiableCredential", "AlumniCredential"],
    "issuer": "https://vc.example/issuers/5678",
    "credentialSubject": {
        "id": "did:example:abcdefgh",
        "alumniOf": "The School of Examples"
    }
});

let proof = DataIntegrityProof::sign_rdfc_data(
    &credential, None, &secret, None,
).await.expect("Signing failed");
```

### Custom Signer (KMS/HSM)

Implement the `Signer` trait to use external signing backends:

```rust
use affinidi_data_integrity::signer::Signer;
use affinidi_secrets_resolver::secrets::KeyType;
use async_trait::async_trait;

struct MyKmsSigner { /* ... */ }

#[async_trait]
impl Signer for MyKmsSigner {
    fn key_type(&self) -> KeyType { KeyType::Ed25519 }
    fn verification_method(&self) -> &str { "did:key:z6Mk...#z6Mk..." }

    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, DataIntegrityError> {
        // Call your KMS/HSM service here
        todo!()
    }
}

let proof = DataIntegrityProof::sign_jcs_data(
    &document, None, &my_kms_signer, None,
).await.expect("Signing failed");
```

### Verify a Proof

Verification auto-dispatches based on the `cryptosuite` field:

```rust
use affinidi_data_integrity::verification_proof::verify_data_with_public_key;

let public_key_bytes = Secret::decode_multikey("z6Mkr...").expect("Invalid multikey");

let result = verify_data_with_public_key(
    &document, context, &proof, public_key_bytes.as_slice(),
).expect("Verification failed");

assert!(result.verified);
```

## Performance

Benchmarks on the W3C vc-di-eddsa B.1 Alumni Credential (Apple M4 Pro, `--release`):

| Operation | JCS | RDFC | Ratio |
|---|---|---|---|
| **Sign** | ~46 us | ~199 us | ~4.3x slower |
| **Verify** | ~61 us | ~212 us | ~3.5x slower |

Run benchmarks:

```bash
cargo bench -p affinidi-data-integrity --bench proof_benchmarks
```

## Related Crates

- [`affinidi-crypto`](../affinidi-crypto/) — Cryptographic primitives (dependency)
- [`affinidi-rdf-encoding`](../affinidi-rdf-encoding/) — RDFC-1.0 canonicalization (dependency)
- [`affinidi-secrets-resolver`](../affinidi-secrets-resolver/) — Secret management (dependency)

## License

[Apache-2.0](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)
