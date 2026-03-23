# affinidi-openid4vp

[![Crates.io](https://img.shields.io/crates/v/affinidi-openid4vp.svg)](https://crates.io/crates/affinidi-openid4vp)
[![Documentation](https://docs.rs/affinidi-openid4vp/badge.svg)](https://docs.rs/affinidi-openid4vp)
[![Rust](https://img.shields.io/badge/rust-1.90.0%2B-blue.svg?maxAge=3600)](https://github.com/affinidi/affinidi-tdk-rs/tree/main/crates/protocols/affinidi-openid4vp)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)

OpenID for Verifiable Presentations (OpenID4VP) implementation per
[OpenID4VP 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html).

Includes Presentation Exchange v2 types for credential matching.

## Installation

```toml
[dependencies]
affinidi-openid4vp = "0.1"
```

## Features

- **Authorization request/response**: Verifier-initiated presentation requests
- **Presentation Exchange v2**: Input descriptors and submission matching
- **VP Token**: Verifiable Presentation token construction and parsing
- **Same-device and cross-device flows**: QR code, deep link, redirect

## License

[Apache-2.0](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)
