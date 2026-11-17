# affinidi-secrets-resolver

[![Crates.io](https://img.shields.io/crates/v/affinidi-secrets-resolver.svg)](https://crates.io/crates/affinidi-secrets-resolver)
[![Documentation](https://docs.rs/affinidi-secrets-resolver/badge.svg)](https://docs.rs/affinidi-secrets-resolver)
[![Rust](https://img.shields.io/badge/rust-1.95.0%2B-blue.svg?maxAge=3600)](https://github.com/affinidi/affinidi-tdk-rs/tree/main/crates/core/affinidi-secrets-resolver/)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)

DID secret management for the Affinidi Trust Development Kit. Handles storage,
resolution, and cryptographic operations for DID-associated private keys.

## Installation

```toml
[dependencies]
affinidi-secrets-resolver = "0.6"
```

## Feature Flags

| Feature | Default | Description |
|---|---|---|
| `ed25519` | Yes | Ed25519 and X25519 key support |
| `p256` | Yes | P-256 (secp256r1) key support |
| `p384` | Yes | P-384 key support |
| `k256` | Yes | secp256k1 key support |

## WASM Support

This crate supports `wasm32` targets with the `getrandom/wasm_js` feature
automatically enabled.

## Related Crates

- [`affinidi-crypto`](https://github.com/affinidi/affinidi-tdk-rs/tree/main/crates/core/affinidi-crypto/) — Cryptographic primitives (dependency)
- [`affinidi-encoding`](https://github.com/affinidi/affinidi-tdk-rs/tree/main/crates/core/affinidi-encoding/) — Multibase encoding (dependency)
- [`affinidi-did-authentication`](https://github.com/affinidi/affinidi-tdk-rs/tree/main/crates/identity/affinidi-did-authentication/) — DID authentication built on this crate

## License

[Apache-2.0](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)
