# affinidi-sd-jwt-vc

[![Crates.io](https://img.shields.io/crates/v/affinidi-sd-jwt-vc.svg)](https://crates.io/crates/affinidi-sd-jwt-vc)
[![Documentation](https://docs.rs/affinidi-sd-jwt-vc/badge.svg)](https://docs.rs/affinidi-sd-jwt-vc)
[![Rust](https://img.shields.io/badge/rust-1.90.0%2B-blue.svg?maxAge=3600)](https://github.com/affinidi/affinidi-tdk-rs/tree/main/crates/credentials/affinidi-sd-jwt-vc)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)

SD-JWT-based Verifiable Credentials per
[IETF SD-JWT VC](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/).

Layers VC semantics (credential type, issuer metadata, temporal claims) on top of
the base [SD-JWT (RFC 9901)](https://www.rfc-editor.org/rfc/rfc9901.html) format.

## Installation

```toml
[dependencies]
affinidi-sd-jwt-vc = "0.1"
```

## Features

- `vct` (Verifiable Credential Type) claim enforcement
- Issuer metadata (`iss`) and temporal claims (`iat`, `exp`, `nbf`)
- Status integration (`status` claim for revocation/suspension)
- Key binding via `cnf.jwk` (holder proof of possession)
- Built on `affinidi-sd-jwt` for selective disclosure

## Related Crates

- [`affinidi-sd-jwt`](../affinidi-sd-jwt/) — Base SD-JWT (RFC 9901)
- [`affinidi-vc`](../affinidi-vc/) — W3C VC Data Model types
- [`affinidi-status-list`](../affinidi-status-list/) — Credential status/revocation

## License

[Apache-2.0](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)
