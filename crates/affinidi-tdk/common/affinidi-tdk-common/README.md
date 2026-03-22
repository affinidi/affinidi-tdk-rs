# affinidi-tdk-common

[![Crates.io](https://img.shields.io/crates/v/affinidi-tdk-common.svg)](https://crates.io/crates/affinidi-tdk-common)
[![Documentation](https://docs.rs/affinidi-tdk-common/badge.svg)](https://docs.rs/affinidi-tdk-common)
[![Rust](https://img.shields.io/badge/rust-1.90.0%2B-blue.svg?maxAge=3600)](https://github.com/affinidi/affinidi-tdk-rs/tree/main/crates/affinidi-tdk/common/affinidi-tdk-common)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)

Shared structs and utilities used across the Affinidi Trust Development Kit.
Provides common configuration, TLS setup, caching, keyring integration, and
cross-crate types.

## Installation

```toml
[dependencies]
affinidi-tdk-common = "0.5"
```

## Feature Flags

| Feature | Default | Description |
|---|---|---|
| `messaging` | Yes | Includes messaging-related types |

## Key Dependencies

This crate aggregates several TDK libraries:

- [`affinidi-did-resolver-cache-sdk`](../../../affinidi-did-resolver/affinidi-did-resolver-cache-sdk/) — DID resolution
- [`affinidi-did-authentication`](../affinidi-did-authentication/) — DID authentication
- [`affinidi-data-integrity`](../affinidi-data-integrity/) — Data integrity proofs
- [`affinidi-secrets-resolver`](../affinidi-secrets-resolver/) — Secret management

## Related Crates

- [`affinidi-tdk`](../../affinidi-tdk/) — Unified TDK entry point
- [`affinidi-meeting-place`](../../../affinidi-meeting-place/) — Meeting Place SDK

## License

[Apache-2.0](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)
