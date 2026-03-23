# affinidi-status-list

[![Crates.io](https://img.shields.io/crates/v/affinidi-status-list.svg)](https://crates.io/crates/affinidi-status-list)
[![Documentation](https://docs.rs/affinidi-status-list/badge.svg)](https://docs.rs/affinidi-status-list)
[![Rust](https://img.shields.io/badge/rust-1.90.0%2B-blue.svg?maxAge=3600)](https://github.com/affinidi/affinidi-tdk-rs/tree/main/crates/credentials/affinidi-status-list)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)

Credential status and revocation management implementing:
- [W3C Bitstring Status List v1.0](https://www.w3.org/TR/vc-bitstring-status-list/)
- eIDAS 2.0 Attestation Status List (ASL)
- eIDAS 2.0 Attestation Revocation List (ARL)

## Installation

```toml
[dependencies]
affinidi-status-list = "0.1"
```

## Features

- **Status List**: Compressed bitstring with O(1) lookup by index
- **Revocation List**: Set of revoked credential identifiers
- **Privacy**: Random index assignment, decoy entries, herd privacy
- **Multiple purposes**: Revocation, suspension (separate lists per purpose)
- **Compression**: GZIP compression per W3C Bitstring Status List spec

## License

[Apache-2.0](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)
