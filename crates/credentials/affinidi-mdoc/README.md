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
affinidi-mdoc = "0.6"
```

## Features

- **CBOR encoding**: Full CBOR serialization/deserialization via `ciborium`
- **COSE signatures**: COSE_Sign1 signing and verification via `coset`
- **Mobile Security Object (MSO)**: Issuer-signed digests of attribute values
- **Namespace-based attributes**: Organized by doc type and namespace
- **IssuerSigned / DeviceResponse**: Full credential and presentation structures
- **Issuance**: `MdocBuilder` requires the holder's device key and the
  validity window; `build()` returns an error if either is missing or malformed
- **Selective disclosure**: Holder reveals only chosen attributes per namespace
- **Proximity session encryption**: `SessionKeys` derives `SKDevice` /
  `SKReader` as ISO/IEC 18013-5 §9.1.1.5 specifies, and `SessionEncryption`
  builds the AES-256-GCM IVs and keeps the message counters
- **Reader verification**: `DeviceResponse::verify` checks the `issuerAuth`
  algorithm and signature (issuer key from a caller-supplied verifier, or from
  a resolver handed the `x5chain`), docType, validity, item digests over the
  bytes as received, and the device signature against the device key in the
  signed MSO. Validating the `x5chain` against trust anchors is the resolver's
  job; this crate does not do X.509 path validation.

## eIDAS PID Namespace

The eIDAS PID namespace `eu.europa.ec.eudi.pid.1` defines standard attributes:
`family_name`, `given_name`, `birth_date`, `age_over_18`, `nationality`, etc.

## Related Crates

- [`affinidi-vc`](../affinidi-vc/) — SD-JWT VC (`affinidi_vc::sd_jwt_vc`, the other eIDAS mandatory format)
- [`affinidi-vc`](../affinidi-vc/) — W3C VC Data Model types
- [`affinidi-status-list`](../affinidi-status-list/) — Credential status/revocation

## License

[Apache-2.0](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)
