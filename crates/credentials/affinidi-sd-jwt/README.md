# affinidi-sd-jwt

[![Crates.io](https://img.shields.io/crates/v/affinidi-sd-jwt.svg)](https://crates.io/crates/affinidi-sd-jwt)
[![Documentation](https://docs.rs/affinidi-sd-jwt/badge.svg)](https://docs.rs/affinidi-sd-jwt)
[![Rust](https://img.shields.io/badge/rust-1.90.0%2B-blue.svg?maxAge=3600)](https://github.com/affinidi/affinidi-tdk-rs/tree/main/crates/affinidi-tdk/common/affinidi-sd-jwt)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)

SD-JWT (Selective Disclosure JWT) implementation following the
[IETF SD-JWT specification](https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/).

## Installation

```toml
[dependencies]
affinidi-sd-jwt = "0.1"
```

## Features

- **Issuance**: Create SD-JWTs with selectively disclosable claims (flat, nested, array elements)
- **Presentation**: Filter disclosures to reveal only chosen claims, with optional Key Binding JWT
- **Verification**: Verify issuer signature, reconstruct disclosed claims, verify KB-JWT
- **Decoy digests**: Add fake hashes to obscure the number of disclosable claims
- **Pluggable hashing**: SHA-256 (default), SHA-384, SHA-512, or custom hashers
- **Pluggable signing**: Abstract `Signer` and `Verifier` traits for any algorithm

## Related Crates

- [`affinidi-tdk`](../../affinidi-tdk/) — Unified TDK entry point
- [`affinidi-data-integrity`](../affinidi-data-integrity/) — W3C Data Integrity proofs
- [`affinidi-crypto`](../affinidi-crypto/) — Cryptographic primitives

## License

[Apache-2.0](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)
