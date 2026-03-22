# affinidi-crypto

[![Crates.io](https://img.shields.io/crates/v/affinidi-crypto.svg)](https://crates.io/crates/affinidi-crypto)
[![Documentation](https://docs.rs/affinidi-crypto/badge.svg)](https://docs.rs/affinidi-crypto)
[![Rust](https://img.shields.io/badge/rust-1.90.0%2B-blue.svg?maxAge=3600)](https://github.com/affinidi/affinidi-tdk-rs/tree/main/crates/affinidi-tdk/common/affinidi-crypto)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)

Cryptographic primitives and JWK types for the Affinidi Trust Development Kit.
Provides key generation, encoding, and conversion utilities across multiple
elliptic curve families.

## Supported Algorithms

| Algorithm | Feature Flag | Curve |
|---|---|---|
| Ed25519 / X25519 | `ed25519` | Curve25519 |
| P-256 (secp256r1) | `p256` | NIST P-256 |
| P-384 | `p384` | NIST P-384 |
| secp256k1 | `k256` | secp256k1 |

All features are enabled by default.

## Installation

```toml
[dependencies]
affinidi-crypto = "0.1"
```

Or with only specific curves:

```toml
[dependencies]
affinidi-crypto = { version = "0.1", default-features = false, features = ["ed25519", "p256"] }
```

## WASM Support

This crate supports `wasm32` targets with the `getrandom/js` feature
automatically enabled.

## Related Crates

- [`affinidi-encoding`](../affinidi-encoding/) — Multibase/multicodec encoding (dependency)
- [`affinidi-secrets-resolver`](../affinidi-secrets-resolver/) — Secret management built on this crate
- [`affinidi-data-integrity`](../affinidi-data-integrity/) — W3C Data Integrity proofs

## License

[Apache-2.0](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)
