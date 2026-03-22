# affinidi-trust-lists

[![Crates.io](https://img.shields.io/crates/v/affinidi-trust-lists.svg)](https://crates.io/crates/affinidi-trust-lists)
[![Documentation](https://docs.rs/affinidi-trust-lists/badge.svg)](https://docs.rs/affinidi-trust-lists)
[![Rust](https://img.shields.io/badge/rust-1.90.0%2B-blue.svg?maxAge=3600)](https://github.com/affinidi/affinidi-tdk-rs/tree/main/crates/trust/affinidi-trust-lists)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)

EU Trusted Lists implementation per [ETSI TS 119 612](https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/)
for eIDAS 2.0 trust infrastructure.

## Installation

```toml
[dependencies]
affinidi-trust-lists = "0.1"
```

## Features

- **Trust List parsing**: Parse XML Trusted Lists (ETSI TS 119 612)
- **Trust List Registry**: In-memory indexed store for fast lookups
- **Issuer lookup**: Match credential issuers by X.509 certificate, Subject Key Identifier, or public key
- **Service types**: All 34+ ETSI service types including eIDAS 2.0 (PID, QEAA, Wallet Provider, etc.)
- **Service status**: Granted, Withdrawn, Supervision states
- **LoTL resolution**: Follow List of Trusted Lists pointers to national TLs
- **Service history**: Track status transitions over time

## eIDAS 2.0 Entity Types

Supports all 7 entity types required by the Architecture Reference Framework:
1. Wallet Providers
2. PID Providers
3. QEAA Providers
4. PuB-EAA Providers
5. QESRC Providers
6. Access Certificate Authorities
7. Registration Certificate Providers

## Quick Start

```rust,ignore
use affinidi_trust_lists::{TrustListRegistry, ServiceType, ServiceStatus};

// Create a registry and add trust anchors
let mut registry = TrustListRegistry::new();

// Add a PID provider
registry.add_provider(
    "DE",
    "German Federal Identity Office",
    ServiceType::Pid,
    ServiceStatus::Granted,
    b"<issuer-certificate-bytes>",
);

// Look up an issuer by certificate
if let Some(entry) = registry.lookup_by_certificate(issuer_cert) {
    assert_eq!(entry.status, ServiceStatus::Granted);
}
```

## Related Crates

- [`affinidi-sd-jwt-vc`](../../credentials/affinidi-sd-jwt-vc/) — SD-JWT VC format (issuer trust validation)
- [`affinidi-mdoc`](../../credentials/affinidi-mdoc/) — mdoc format (IACA cert trust validation)
- [`affinidi-tdk`](../../tdk/affinidi-tdk/) — Unified TDK entry point

## License

[Apache-2.0](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)
