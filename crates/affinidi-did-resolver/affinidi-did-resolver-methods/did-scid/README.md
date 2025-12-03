# did-scid Rust implementation

[![Crates.io](https://img.shields.io/crates/v/did-scid.svg)](https://crates.io/crates/did-scid)
[![Documentation](https://docs.rs/did-scid/badge.svg)](https://docs.rs/did-scid)
[![Rust](https://img.shields.io/badge/rust-1.88.0%2B-blue.svg?maxAge=3600)](https://github.com/affinidi/affinidi-tdk-rs/tree/main/crates/affinidi-did-resolver/affinidi-did-resolver-methods/did-scid)

## Self Certifying Identifiers (SCID)

_A subclass of verifiable identifier (VID) that is cryptographically verifiable
without the need to rely on any third party for verification because the identifier
is cryptographically bound to the cryptographic keys from which it was generated._

## did:scid method specification

[DID SCID Method Specification](https://lf-toip.atlassian.net/wiki/spaces/HOME/pages/88572360/DID+SCID+Method+Specification)

## Features

- [x] `did:scid:vh`: Support Verifiable History
  - [x] `did:scid:vh`: Supports WebVH
  - [x] `did:scid:vh`: Supports Cheqd
- [x] Supports peer level did:scid implementations

## Contributing

Want to contribute?

Head over to our [CONTRIBUTING](https://github.com/affinidi/affinidi-tdk-rs/blob/main/CONTRIBUTING.md)
guidelines.
