# affinidi-tdk

[![Crates.io](https://img.shields.io/crates/v/affinidi-tdk.svg)](https://crates.io/crates/affinidi-tdk)
[![Documentation](https://docs.rs/affinidi-tdk/badge.svg)](https://docs.rs/affinidi-tdk)
[![Rust](https://img.shields.io/badge/rust-1.90.0%2B-blue.svg?maxAge=3600)](https://github.com/affinidi/affinidi-tdk-rs/tree/main/crates/affinidi-tdk/affinidi-tdk)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)

The unified entry point for the Affinidi Trust Development Kit. Depend on this
single crate and enable feature flags to pull in only the libraries you need.

> **Disclaimer:** This project is provided "as is" without warranties or
> guarantees. Users assume all risks associated with its deployment and use.

## Installation

```toml
[dependencies]
affinidi-tdk = "0.6"
```

## Feature Flags

| Feature | Default | Description |
|---|---|---|
| `messaging` | Yes | Affinidi Messaging SDK |
| `meeting-place` | Yes | Affinidi Meeting Place SDK |
| `did-peer` | Yes | Peer DID method support |
| `data-integrity` | Yes | W3C Data Integrity proof support |

Disable defaults with `default-features = false` in your `Cargo.toml` or
`--no-default-features` on the command line, then enable only what you need:

```toml
[dependencies]
affinidi-tdk = { version = "0.5", default-features = false, features = ["data-integrity"] }
```

## Re-exported Crates

This crate re-exports the following libraries:

- [`affinidi-did-resolver-cache-sdk`](../../../affinidi-did-resolver/affinidi-did-resolver-cache-sdk/) — DID resolution and caching
- [`affinidi-did-common`](../../../affinidi-did-resolver/affinidi-did-common/) — DID Document types
- [`affinidi-messaging-didcomm`](../../../affinidi-messaging/affinidi-messaging-didcomm/) — DIDComm protocol
- [`affinidi-messaging-sdk`](../../../affinidi-messaging/affinidi-messaging-sdk/) — Messaging SDK *(feature: `messaging`)*
- [`affinidi-meeting-place`](../../../affinidi-meeting-place/) — Meeting Place SDK *(feature: `meeting-place`)*
- [`affinidi-data-integrity`](../common/affinidi-data-integrity/) — Data Integrity proofs *(feature: `data-integrity`)*
- [`affinidi-did-authentication`](../common/affinidi-did-authentication/) — DID authentication
- [`affinidi-tdk-common`](../common/affinidi-tdk-common/) — Shared utilities
- [`affinidi-secrets-resolver`](../common/affinidi-secrets-resolver/) — Secret management
- [`affinidi-crypto`](../common/affinidi-crypto/) — Cryptographic primitives

## Related Crates

- [`affinidi-messaging`](../../../affinidi-messaging/) — Full messaging framework
- [`affinidi-did-resolver`](../../../affinidi-did-resolver/) — DID resolution

## License

[Apache-2.0](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)
