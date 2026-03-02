# Affinidi Data Integrity Library

[![Crates.io](https://img.shields.io/crates/v/affinidi-data-integrity.svg)](https://crates.io/crates/affinidi-data-integrity)
[![Documentation](https://docs.rs/affinidi-data-integrity/badge.svg)](https://docs.rs/affinidi-data-integrity)
[![Rust](https://img.shields.io/badge/rust-1.90.0%2B-blue.svg?maxAge=3600)](https://github.com/affinidi/affinidi-tdk-rs/tree/main/crates/affinidi-tdk/common/affinidi-data-integrity)

**IMPORTANT:**

> affinidi-data-integrity crate is provided "as is" without any warranties or
> guarantees, and by using this framework, users agree to assume all risks
> associated with its deployment and use including implementing security, and
> privacy measures in their applications. Affinidi assumes no liability for any
> issues arising from the use or modification of the project.

## Overview

An implementation of the [W3C Data Integrity](https://www.w3.org/TR/vc-data-integrity/)
specification that is integrated with the Affinidi Trust Development Kit (TDK) framework.

## Supported Cryptosuites

This crate supports the following [W3C vc-di-eddsa](https://www.w3.org/TR/vc-di-eddsa/)
cryptosuites, both using Ed25519 for signing and verification:

| Cryptosuite | Canonicalization | Use Case |
|---|---|---|
| `eddsa-jcs-2022` | JSON Canonicalization Scheme (JCS) | General JSON documents |
| `eddsa-rdfc-2022` | RDF Dataset Canonicalization (RDFC-1.0) | JSON-LD / Verifiable Credentials |

**JCS** canonicalizes raw JSON using [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785)
and works with any serializable data structure.

**RDFC** expands JSON-LD documents into RDF, canonicalizes via
[RDFC-1.0](https://www.w3.org/TR/rdf-canon/), and produces order-independent
canonical N-Quads. Documents **must** contain an `@context` field. Use this for
W3C Verifiable Credentials.

## Usage

### Creating a Proof (JCS)

Use `sign_jcs_data()` for general JSON documents:

```rust
use affinidi_data_integrity::DataIntegrityProof;
use affinidi_secrets_resolver::secrets::Secret;
use serde_json::json;

let document = json!({
    "id": "urn:uuid:example-123",
    "type": "ExampleDocument",
    "data": "Hello, world!"
});

// Load your Ed25519 signing key
let secret = Secret::from_multibase(
    "z3u2en7t5LR2WtQH5PfFqMqwVHBeXouLzo6haApm8XHqvjxq",
    Some("did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2#z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2"),
).expect("Invalid key");

let proof = DataIntegrityProof::sign_jcs_data(
    &document,
    None,       // optional @context for the proof
    &secret,
    None,       // auto-generates created timestamp
).expect("Signing failed");

println!("Proof value: {}", proof.proof_value.as_ref().unwrap());
```

### Creating a Proof (RDFC)

Use `sign_rdfc_data()` for JSON-LD documents such as Verifiable Credentials.
The document **must** contain an `@context` field:

```rust
use affinidi_data_integrity::DataIntegrityProof;
use affinidi_secrets_resolver::secrets::Secret;
use serde_json::json;

let credential = json!({
    "@context": [
        "https://www.w3.org/ns/credentials/v2",
        "https://www.w3.org/ns/credentials/examples/v2"
    ],
    "id": "urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33",
    "type": ["VerifiableCredential", "AlumniCredential"],
    "issuer": "https://vc.example/issuers/5678",
    "validFrom": "2023-01-01T00:00:00Z",
    "credentialSubject": {
        "id": "did:example:abcdefgh",
        "alumniOf": "The School of Examples"
    }
});

let secret = Secret::from_multibase(
    "z3u2en7t5LR2WtQH5PfFqMqwVHBeXouLzo6haApm8XHqvjxq",
    Some("did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2#z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2"),
).expect("Invalid key");

let proof = DataIntegrityProof::sign_rdfc_data(
    &credential,
    None,       // uses document's @context by default
    &secret,
    None,       // auto-generates created timestamp
).expect("Signing failed");

println!("Proof value: {}", proof.proof_value.as_ref().unwrap());
```

### Verifying a Proof

Verification auto-dispatches based on the `cryptosuite` field in the proof,
so the same function works for both JCS and RDFC proofs:

```rust
use affinidi_data_integrity::verification_proof::verify_data_with_public_key;
use affinidi_secrets_resolver::secrets::Secret;

// `document` is the original data (without the proof attached)
// `proof` is the DataIntegrityProof from signing
// `context` must match the @context used during signing (if any)

let public_key_bytes = Secret::decode_multikey(
    "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2"
).expect("Invalid multikey");

let result = verify_data_with_public_key(
    &document,
    context,                // Option<Vec<String>>
    &proof,
    public_key_bytes.as_slice(),
).expect("Verification failed");

assert!(result.verified);
```

## Choosing a Cryptosuite

**Prefer `eddsa-jcs-2022` (JCS) unless you specifically need RDFC.** JCS is
significantly faster because it canonicalizes JSON directly, while RDFC must
expand JSON-LD into RDF and run the full RDFC-1.0 canonicalization algorithm.
Both produce equally valid W3C Data Integrity proofs with the same Ed25519
security.

Use `eddsa-rdfc-2022` (RDFC) when:
- Interoperating with systems that require RDFC proofs
- Working with JSON-LD documents where semantic equivalence across different
  JSON serializations matters (e.g. key ordering, `@context` aliasing)
- A specification or verifier explicitly mandates RDFC

## Performance

Benchmarks run on the W3C vc-di-eddsa B.1 Alumni Credential (Apple M4 Pro,
Rust 1.90, `--release`):

| Operation | JCS | RDFC | Ratio |
|---|---|---|---|
| **Sign** | ~46 µs | ~330 µs | ~7x slower |
| **Verify** | ~61 µs | ~350 µs | ~6x slower |

The Ed25519 cryptographic operations are identical for both suites. The
performance difference is entirely in the transformation step — JCS runs a
single-pass JSON canonicalization, while RDFC performs JSON-LD expansion, RDF
conversion, and RDFC-1.0 dataset canonicalization.

To reproduce these benchmarks:

```sh
cargo bench -p affinidi-data-integrity --bench proof_benchmarks
```

HTML reports are generated in `target/criterion/` for detailed analysis.

## Support & Feedback

If you face any issues or have suggestions, please don't hesitate to contact us
using [this link](https://www.affinidi.com/get-in-touch).

### Reporting Technical Issues

If you have a technical issue with the Affinidi Data Integrity Library GitHub
repo, you can also create an issue directly in GitHub.

If you're unable to find an open issue addressing the problem, [open a new one](https://github.com/affinidi/affinidi-tdk-rs/issues/new).
Be sure to include a **title and clear description**, as much relevant information
as possible, and a **code sample** or an **executable test case** demonstrating
the expected behavior that is not occurring.
