# affinidi-bbs

[![Crates.io](https://img.shields.io/crates/v/affinidi-bbs.svg)](https://crates.io/crates/affinidi-bbs)
[![Documentation](https://docs.rs/affinidi-bbs/badge.svg)](https://docs.rs/affinidi-bbs)
[![Rust](https://img.shields.io/badge/rust-1.90.0%2B-blue.svg?maxAge=3600)](https://github.com/affinidi/affinidi-tdk-rs/tree/main/crates/core/affinidi-bbs)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)

BBS Signatures implementation per
[IETF draft-irtf-cfrg-bbs-signatures](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/)
over the BLS12-381 pairing-friendly curve.

## Features

- **KeyGen**: Generate BBS key pairs (32-byte secret key, 96-byte public key)
- **Sign/Verify**: Sign multiple messages, verify with public key
- **ProofGen/ProofVerify**: Zero-knowledge selective disclosure proofs
- **Two ciphersuites**: SHA-256 (XMD) and SHAKE-256 (XOF)
- **Unlinkability**: Each proof is cryptographically independent
- **Pure Rust**: Built on `bls12_381_plus` (no C/FFI dependencies)

## Security Properties

- **Selective disclosure**: Prove possession of a subset of signed messages
  without revealing the others
- **Unlinkability**: Multiple proofs from the same signature cannot be correlated
- **Unforgeability**: Cannot forge signatures without the secret key
- **Zero-knowledge**: Proofs reveal nothing about undisclosed messages

## eIDAS 2.0 Compliance

Addresses ARF ZKP requirements:
- **ZKP_01**: Unlinkable selective disclosure
- **ZKP_02**: Verifier cannot see undisclosed attributes
- **ZKP_03**: Cross-presentation unlinkability
- **ZKP_06**: Holder binding via presentation header

## Installation

```toml
[dependencies]
affinidi-bbs = "0.1"
```

## Quick Start

```rust,ignore
use affinidi_bbs::{keygen, sk_to_pk, sign, verify, proof_gen, proof_verify};

// Generate keys
let sk = keygen(b"seed-material-at-least-32-bytes!", b"")?;
let pk = sk_to_pk(&sk);

// Sign 3 messages
let messages = [b"msg1".as_ref(), b"msg2", b"msg3"];
let signature = sign(&sk, &pk, b"header", &messages)?;

// Verify
assert!(verify(&pk, &signature, b"header", &messages)?);

// Selective disclosure: reveal only message 0
let proof = proof_gen(&pk, &signature, b"header", b"ph", &messages, &[0])?;

// Verifier checks proof with only the disclosed message
assert!(proof_verify(&pk, &proof, b"header", b"ph", &[b"msg1".as_ref()], &[0])?);
```

## Related Crates

- [`affinidi-data-integrity`](../../credentials/affinidi-data-integrity/) — bbs-2023 cryptosuite for VCs
- [`affinidi-crypto`](../affinidi-crypto/) — Other cryptographic primitives

## License

[Apache-2.0](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)
