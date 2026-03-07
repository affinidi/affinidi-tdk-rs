# did-scid

[![Crates.io](https://img.shields.io/crates/v/did-scid.svg)](https://crates.io/crates/did-scid)
[![Documentation](https://docs.rs/did-scid/badge.svg)](https://docs.rs/did-scid)
[![Rust](https://img.shields.io/badge/rust-1.90.0%2B-blue.svg?maxAge=3600)](https://github.com/affinidi/affinidi-tdk-rs/tree/main/crates/affinidi-did-resolver/affinidi-did-resolver-methods/did-scid)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)

Rust implementation of the `did:scid` (Self-Certifying Identifier) DID method.

A Self-Certifying Identifier (SCID) is a subclass of verifiable identifier that
is cryptographically verifiable without relying on any third party, because the
identifier is cryptographically bound to the keys from which it was generated.

## Installation

```toml
[dependencies]
did-scid = "0.1"
```

## Feature Flags

| Feature | Default | Description |
|---|---|---|
| `did-webvh` | Yes | Verifiable History via WebVH |
| `did-cheqd` | Yes | Verifiable History via Cheqd |

## Capabilities

- `did:scid:vh` — Verifiable History support
  - WebVH backend
  - Cheqd backend
- Peer-level `did:scid` implementations

## Specification

[DID SCID Method Specification](https://lf-toip.atlassian.net/wiki/spaces/HOME/pages/88572360/DID+SCID+Method+Specification)

## Related Crates

- [`affinidi-did-common`](../../affinidi-did-common/) — DID Document types (dependency)
- [`affinidi-did-resolver-cache-sdk`](../../affinidi-did-resolver-cache-sdk/) — Resolver SDK (uses this via feature flag)

## Contributing

Head over to our
[CONTRIBUTING](https://github.com/affinidi/affinidi-tdk-rs/blob/main/CONTRIBUTING.md)
guidelines.

## License

[Apache-2.0](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)
