# affinidi-encoding

[![Crates.io](https://img.shields.io/crates/v/affinidi-encoding.svg)](https://crates.io/crates/affinidi-encoding)
[![Documentation](https://docs.rs/affinidi-encoding/badge.svg)](https://docs.rs/affinidi-encoding)
[![Rust](https://img.shields.io/badge/rust-1.90.0%2B-blue.svg?maxAge=3600)](https://github.com/affinidi/affinidi-tdk-rs/tree/main/crates/affinidi-tdk/common/affinidi-encoding)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)

Multibase and multicodec encoding utilities for the Affinidi Trust Development
Kit. Provides encoding and decoding of cryptographic key material using the
[Multibase](https://github.com/multiformats/multibase) and
[Multicodec](https://github.com/multiformats/multicodec) specifications.

## Installation

```toml
[dependencies]
affinidi-encoding = "0.1"
```

## Features

- Multibase encoding/decoding (Base58-BTC)
- Multicodec prefix handling for key type identification
- Zeroize support for sensitive key material

## Related Crates

- [`affinidi-crypto`](../affinidi-crypto/) — Cryptographic primitives built on this crate
- [`affinidi-secrets-resolver`](../affinidi-secrets-resolver/) — Secret management

## License

[Apache-2.0](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)
