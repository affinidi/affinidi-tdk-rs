# affinidi-vc

[![Crates.io](https://img.shields.io/crates/v/affinidi-vc.svg)](https://crates.io/crates/affinidi-vc)
[![Documentation](https://docs.rs/affinidi-vc/badge.svg)](https://docs.rs/affinidi-vc)
[![Rust](https://img.shields.io/badge/rust-1.90.0%2B-blue.svg?maxAge=3600)](https://github.com/affinidi/affinidi-tdk-rs/tree/main/crates/credentials/affinidi-vc)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)

W3C Verifiable Credentials Data Model implementation supporting both
[v1.1](https://www.w3.org/TR/vc-data-model/) and
[v2.0](https://www.w3.org/TR/vc-data-model-2.0/).

## Installation

```toml
[dependencies]
affinidi-vc = "0.2"
```

## Features

- `VerifiableCredential` type supporting both VCDM 1.1 and 2.0
- `VerifiablePresentation` for submitting credentials to verifiers
- Builder pattern for ergonomic credential construction
- Proof-format agnostic (works with Data Integrity, JWT, SD-JWT-VC, COSE)
- JSON-LD context validation
- Credential status integration point
- `sd_jwt_vc` module — SD-JWT VC issuance and verification (merged in from the
  former `affinidi-sd-jwt-vc` crate)

## Related Crates

- [`affinidi-sd-jwt`](../affinidi-sd-jwt/) - Base SD-JWT (RFC 9901), backs `sd_jwt_vc`
- [`affinidi-data-integrity`](../affinidi-data-integrity/) - W3C Data Integrity proofs
- [`affinidi-status-list`](../affinidi-status-list/) - Credential status/revocation

## License

[Apache-2.0](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)
