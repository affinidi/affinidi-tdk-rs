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
affinidi-trust-lists = "0.2"
```

## Features

- **Trust List parsing**: Parse XML Trusted Lists (ETSI TS 119 612), including
  `ListIssueDateTime` / `NextUpdate`, every digital identity of a service, and
  service history
- **Trust List Registry**: In-memory indexed store for fast lookups. Loading
  refuses a stale or closed list, and loaded entries stop being trusted once
  their list passes `NextUpdate`. Lookups and chain validation at a given time
  use the service status in force at that time; the `find_*` / `*_providers`
  listings use the current status and do not check list freshness
- **X.509 path validation**: Verifies each certificate signature up to a trust
  anchor of the service types you accept, with CA, key-usage, path-length and
  validity checks (no revocation checking; ECDSA on P-256 / P-384, RSA and
  Ed25519 only, so P-521 and brainpool certificates do not validate)
- **Issuer lookup**: Match credential issuers by X.509 certificate, Subject Key Identifier, or public key
- **Service types**: All 34+ ETSI service types including eIDAS 2.0 (PID, QEAA, Wallet Provider, etc.)
- **Service status**: Granted, Withdrawn, Supervision states
- **LoTL pointers**: Parse List of Trusted Lists pointers to national TLs (fetching them is up to you)
- **Service history**: Track status transitions over time

## Trust list signatures are not verified

This crate does **not** verify the XAdES signature of an XML trusted list.
`parse_trust_list_xml` returns an `UnverifiedTrustList`; authenticate the
list's bytes yourself (for example, verify the XAdES signature against the
signing certificates the LoTL publishes for that territory) and only then call
`assume_authenticated()` and load it into a registry.

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
use affinidi_trust_lists::{
    LookupResult, ServiceStatus, ServiceType, TrustListRegistry, validate_x5chain_at,
};

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
if let LookupResult::Trusted(entry) = registry.lookup_by_certificate(issuer_cert) {
    println!("trusted: {}", entry.provider_name);
}

// Validate an mdoc x5chain (leaf first) to an active anchor
let result = validate_x5chain_at(&x5chain, &registry, &[ServiceType::Pid], chrono::Utc::now())?;
if result.valid {
    // the leaf chains to a usable `result.trust_anchor`; now verify the COSE signature
    // with the leaf's key
}
```

## Related Crates

- [`affinidi-sd-jwt-vc`](../../credentials/affinidi-sd-jwt-vc/) — SD-JWT VC format (issuer trust validation)
- [`affinidi-mdoc`](../../credentials/affinidi-mdoc/) — mdoc format (IACA cert trust validation)
- [`affinidi-tdk`](../../tdk/affinidi-tdk/) — Unified TDK entry point

## License

[Apache-2.0](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)
