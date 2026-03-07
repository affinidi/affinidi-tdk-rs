# did-example

[![Crates.io](https://img.shields.io/crates/v/did-example.svg)](https://crates.io/crates/did-example)
[![Documentation](https://docs.rs/did-example/badge.svg)](https://docs.rs/did-example)
[![Rust](https://img.shields.io/badge/rust-1.90.0%2B-blue.svg?maxAge=3600)](https://github.com/affinidi/affinidi-tdk-rs/tree/main/crates/affinidi-did-resolver/affinidi-did-resolver-methods/did-example)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)

A `did:example` implementation for testing and development. Creates
non-deterministic example DID Documents that must be manually loaded into the
resolver.

## Installation

```toml
[dependencies]
did-example = "0.5"
```

## Usage

Unlike deterministic DID methods (e.g., `did:key`), `did:example` documents
cannot be auto-resolved. You must manually add documents to the resolver:

```rust
// Documents must be registered before they can be resolved
resolver.add_example_document(did, document);
```

Enable in the resolver SDK with the `did_example` feature flag:

```toml
[dependencies]
affinidi-did-resolver-cache-sdk = { version = "0.8", features = ["did_example"] }
```

## Related Crates

- [`affinidi-did-common`](../../affinidi-did-common/) — DID Document types (dependency)
- [`affinidi-did-resolver-cache-sdk`](../../affinidi-did-resolver-cache-sdk/) — Resolver SDK

## License

[Apache-2.0](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)
