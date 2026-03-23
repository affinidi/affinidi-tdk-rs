# affinidi-openid4vci

[![Crates.io](https://img.shields.io/crates/v/affinidi-openid4vci.svg)](https://crates.io/crates/affinidi-openid4vci)
[![Documentation](https://docs.rs/affinidi-openid4vci/badge.svg)](https://docs.rs/affinidi-openid4vci)
[![Rust](https://img.shields.io/badge/rust-1.90.0%2B-blue.svg?maxAge=3600)](https://github.com/affinidi/affinidi-tdk-rs/tree/main/crates/protocols/affinidi-openid4vci)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)

OpenID for Verifiable Credential Issuance (OpenID4VCI) implementation per
[OpenID4VCI 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html).

## Installation

```toml
[dependencies]
affinidi-openid4vci = "0.1"
```

## Features

- **Issuer metadata**: `CredentialIssuerMetadata` for `/.well-known/openid-credential-issuer`
- **Credential offer**: QR code and deep link payloads for initiating issuance
- **Authorization flows**: Authorization code and pre-authorized code
- **Credential request/response**: Standard credential endpoint types
- **Proof of possession**: JWT key proof for device binding
- **Batch and deferred**: Batch credential issuance and deferred retrieval

## License

[Apache-2.0](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)
