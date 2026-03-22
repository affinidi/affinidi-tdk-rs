# affinidi-mdoc

[![Crates.io](https://img.shields.io/crates/v/affinidi-mdoc.svg)](https://crates.io/crates/affinidi-mdoc)
[![Documentation](https://docs.rs/affinidi-mdoc/badge.svg)](https://docs.rs/affinidi-mdoc)
[![Rust](https://img.shields.io/badge/rust-1.90.0%2B-blue.svg?maxAge=3600)](https://github.com/affinidi/affinidi-tdk-rs/tree/main/crates/credentials/affinidi-mdoc)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)

ISO/IEC 18013-5 mdoc (Mobile Document) implementation for mobile driving
licences (mDL) and eIDAS 2.0 attestations.

## Installation

```toml
[dependencies]
affinidi-mdoc = "0.1"
```

## Features

- **CBOR encoding**: Full CBOR serialization/deserialization via `ciborium`
- **COSE signatures**: COSE_Sign1 signing and verification via `coset`
- **Mobile Security Object (MSO)**: Issuer-signed digests of attribute values
- **Namespace-based attributes**: Organized by doc type and namespace
- **IssuerSigned / DeviceResponse**: Full credential and presentation structures
- **Selective disclosure**: Holder reveals only chosen attributes per namespace

## eIDAS PID Namespace

The eIDAS PID namespace `eu.europa.ec.eudi.pid.1` defines standard attributes:
`family_name`, `given_name`, `birth_date`, `age_over_18`, `nationality`, etc.

## Related Crates

- [`affinidi-sd-jwt-vc`](../affinidi-sd-jwt-vc/) — SD-JWT VC format (the other eIDAS mandatory format)
- [`affinidi-vc`](../affinidi-vc/) — W3C VC Data Model types
- [`affinidi-status-list`](../affinidi-status-list/) — Credential status/revocation

## License

[Apache-2.0](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)
