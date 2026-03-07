# affinidi-messaging-didcomm

[![Crates.io](https://img.shields.io/crates/v/affinidi-messaging-didcomm.svg)](https://crates.io/crates/affinidi-messaging-didcomm)
[![Documentation](https://docs.rs/affinidi-messaging-didcomm/badge.svg)](https://docs.rs/affinidi-messaging-didcomm)
[![Rust](https://img.shields.io/badge/rust-1.90.0%2B-blue.svg?maxAge=3600)](https://github.com/affinidi/affinidi-tdk-rs/tree/main/crates/affinidi-messaging/affinidi-messaging-didcomm)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)

DIDComm v2 protocol implementation for Rust, integrated with the Affinidi
Messaging framework. A modified and extended version of
[didcomm-rust](https://github.com/sicpa-dlab/didcomm-rust).

Provides message packing (encryption, signing) and unpacking (decryption,
verification) following the
[DIDComm Messaging](https://identity.foundation/didcomm-messaging/spec/)
specification.

## Installation

```toml
[dependencies]
affinidi-messaging-didcomm = "0.12"
```

## Feature Flags

| Feature | Default | Description |
|---|---|---|
| `testvectors` | No | Enable DIDComm test vectors |

## Related Crates

- [`affinidi-messaging-sdk`](../affinidi-messaging-sdk/) — High-level messaging SDK (depends on this)
- [`affinidi-crypto`](../../affinidi-tdk/common/affinidi-crypto/) — Cryptographic primitives (dependency)
- [`affinidi-secrets-resolver`](../../affinidi-tdk/common/affinidi-secrets-resolver/) — Secret management (dependency)
- [`affinidi-did-resolver-cache-sdk`](../../affinidi-did-resolver/affinidi-did-resolver-cache-sdk/) — DID resolution (dependency)

## License

[Apache-2.0](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)
