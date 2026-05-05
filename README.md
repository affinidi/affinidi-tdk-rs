# Affinidi Trust Development Kit (TDK) for Rust

[![Rust](https://img.shields.io/badge/rust-1.90.0%2B-blue.svg?maxAge=3600)](https://github.com/affinidi/affinidi-tdk-rs)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](LICENSE)
[![GitHub Issues](https://img.shields.io/github/issues/affinidi/affinidi-tdk-rs)](https://github.com/affinidi/affinidi-tdk-rs/issues)

A Rust workspace for building secure, privacy-preserving applications using
decentralised identity technologies. The TDK provides libraries and tools for
DID resolution, DIDComm messaging, data integrity proofs, cryptographic
primitives, and more.

> **Disclaimer:** This project is provided "as is" without warranties or
> guarantees. By using this framework, users agree to assume all risks
> associated with its deployment and use, including implementing security and
> privacy measures in their applications. Affinidi assumes no liability for any
> issues arising from the use or modification of the project.

## Workspace Overview

```mermaid
graph TD
    TDK["affinidi-tdk<br/><i>Unified entry point</i>"]

    subgraph Messaging["Affinidi Messaging"]
        SDK["messaging-sdk"]
        DIDCOMM["messaging-didcomm"]
        CORE["messaging-core"]
        TSP["affinidi-tsp"]
        MEDIATOR["messaging-mediator"]
        HELPERS["messaging-helpers"]
        TEXTCLIENT["messaging-text-client"]
    end

    subgraph Resolver["Affinidi DID Resolver"]
        CACHESDK["resolver-cache-sdk"]
        CACHESERVER["resolver-cache-server"]
        COMMON["did-common"]
        TRAITS["resolver-traits"]
        DIDSCID["did-scid"]
        DIDEXAMPLE["did-example"]
    end

    subgraph Common["TDK Common Libraries"]
        CRYPTO["affinidi-crypto"]
        ENCODING["affinidi-encoding"]
        SECRETS["secrets-resolver"]
        AUTH["did-authentication"]
        TDKCOMMON["tdk-common"]
        DI["data-integrity"]
        RDF["rdf-encoding"]
    end

    MP["affinidi-meeting-place"]

    TDK --> SDK
    TDK --> MP
    TDK --> DI
    TDK --> CACHESDK
    TDK --> DIDCOMM
    TDK --> AUTH
    TDK --> SECRETS
    TDK --> CRYPTO
    TDK --> TDKCOMMON
    TDK --> COMMON

    SDK --> DIDCOMM
    SDK --> CACHESDK
    DIDCOMM --> CORE
    TSP --> CORE
    MEDIATOR --> SDK
    MEDIATOR --> TSP
    HELPERS --> SDK
    HELPERS --> TSP
    TEXTCLIENT --> SDK
    MP --> AUTH
    MP --> TDKCOMMON

    CACHESDK --> COMMON
    CACHESDK --> TRAITS
    CACHESERVER --> CACHESDK
    DI --> CRYPTO
    DI --> RDF
    SECRETS --> CRYPTO
    SECRETS --> ENCODING
    AUTH --> SECRETS
    TDKCOMMON --> AUTH
    TDKCOMMON --> DI
```

## Crate Index

### [`affinidi-tdk`](./crates/affinidi-tdk/affinidi-tdk/) — Unified Entry Point

A single crate that re-exports the core TDK libraries with feature flags so you
can depend on one crate and enable only what you need.

### [Affinidi Messaging](./crates/affinidi-messaging/)

Secure, private messaging built on [DIDComm v2](https://identity.foundation/didcomm-messaging/spec/) and [TSP](https://trustoverip.github.io/tswg-tsp-specification/).

| Crate | Description |
|---|---|
| [`affinidi-messaging-sdk`](./crates/affinidi-messaging/affinidi-messaging-sdk/) | SDK for integrating Affinidi Messaging into your application |
| [`affinidi-messaging-didcomm`](./crates/affinidi-messaging/affinidi-messaging-didcomm/) | DIDComm v2.1 protocol implementation for Rust |
| [`affinidi-messaging-core`](./crates/affinidi-messaging/affinidi-messaging-core/) | Protocol-agnostic messaging traits |
| [`affinidi-messaging-mediator`](./crates/affinidi-messaging/affinidi-messaging-mediator/) | Mediator & relay service (DIDComm and TSP via feature flags) |
| [`affinidi-messaging-test-mediator`](./crates/affinidi-messaging/affinidi-messaging-test-mediator/) | Embedded mediator fixture for integration tests |
| [`affinidi-messaging-helpers`](./crates/affinidi-messaging/affinidi-messaging-helpers/) | Setup tools, environment config, and examples |
| [`affinidi-messaging-text-client`](./crates/affinidi-messaging/affinidi-messaging-text-client/) | Terminal-based DIDComm chat client |

### [Trust Spanning Protocol](./crates/affinidi-messaging/affinidi-tsp/)

| Crate | Description |
|---|---|
| [`affinidi-tsp`](./crates/affinidi-messaging/affinidi-tsp/) | TSP implementation with HPKE-Auth encryption and CESR encoding |
| [`affinidi-cesr`](./crates/affinidi-tdk/common/affinidi-cesr/) | CESR codec for binary message encoding |

### [Affinidi DID Resolver](./crates/affinidi-did-resolver/)

High-performance DID resolution with local and network caching (250k+ resolutions/sec cached).

| Crate | Description |
|---|---|
| [`affinidi-did-resolver-cache-sdk`](./crates/affinidi-did-resolver/affinidi-did-resolver-cache-sdk/) | SDK for local and network DID resolution with caching |
| [`affinidi-did-resolver-cache-server`](./crates/affinidi-did-resolver/affinidi-did-resolver-cache-server/) | Standalone network DID resolution server |
| [`affinidi-did-common`](./crates/affinidi-did-resolver/affinidi-did-common/) | DID Document types, builders, and common utilities |
| [`affinidi-did-resolver-traits`](./crates/affinidi-did-resolver/affinidi-did-resolver-traits/) | Pluggable resolver traits for custom DID methods |
| [`did-scid`](./crates/affinidi-did-resolver/affinidi-did-resolver-methods/did-scid/) | Self-Certifying Identifier DID method |
| [`did-example`](./crates/affinidi-did-resolver/affinidi-did-resolver-methods/did-example/) | Example DID method for testing |

### [TDK Common Libraries](./crates/affinidi-tdk/common/)

Shared building blocks used across the workspace.

| Crate | Description |
|---|---|
| [`affinidi-crypto`](./crates/affinidi-tdk/common/affinidi-crypto/) | Cryptographic primitives — key generation, JWK, Ed25519, P-256, secp256k1 |
| [`affinidi-encoding`](./crates/affinidi-tdk/common/affinidi-encoding/) | Multibase and multicodec encoding utilities |
| [`affinidi-secrets-resolver`](./crates/affinidi-tdk/common/affinidi-secrets-resolver/) | DID secret management and key resolution |
| [`affinidi-did-authentication`](./crates/affinidi-tdk/common/affinidi-did-authentication/) | Authentication via DID ownership proofs |
| [`affinidi-tdk-common`](./crates/affinidi-tdk/common/affinidi-tdk-common/) | Shared structs, TLS config, and cross-crate utilities |
| [`affinidi-data-integrity`](./crates/affinidi-tdk/common/affinidi-data-integrity/) | W3C Data Integrity proofs (eddsa-jcs-2022, eddsa-rdfc-2022) |
| [`affinidi-rdf-encoding`](./crates/affinidi-tdk/common/affinidi-rdf-encoding/) | RDFC-1.0 canonicalization and JSON-LD expansion |

### [Affinidi Meeting Place](./crates/affinidi-meeting-place/)

Discover and connect with others using DIDs and DIDComm in a secure and private way.

## Requirements

- **Rust** 1.90.0+ (2024 Edition)
- **Redis** 8.0+ (required for the messaging mediator)
- **Docker** (recommended for running Redis)

## Quick Start

Add the unified TDK crate to your project:

```toml
[dependencies]
affinidi-tdk = "0.5"
```

Or depend on individual crates for finer control:

```toml
[dependencies]
affinidi-did-resolver-cache-sdk = "0.8"
affinidi-messaging-sdk = "0.15"
affinidi-data-integrity = "0.4"
```

### Resolve a DID

```rust
use affinidi_did_resolver_cache_sdk::{config::ClientConfigBuilder, DIDCacheClient};

let config = ClientConfigBuilder::default().build();
let resolver = DIDCacheClient::new(config).await?;
let result = resolver.resolve("did:key:z6Mkr...").await?;
println!("DID Document: {:#?}", result.doc);
```

### Send a DIDComm Message

```rust
use affinidi_messaging_sdk::{ATM, config::Config};

let config = Config::builder()
    .with_my_did("did:peer:2...")
    .with_atm_did("did:peer:2...")
    .build()?;
let mut atm = ATM::new(config, vec![]).await?;
atm.send_ping("did:peer:2...", true, true).await?;
```

## Using affinidi-* crates from outside this workspace

This workspace's root `Cargo.toml` defines a non-trivial
[`[patch.crates-io]` table](./Cargo.toml#L85). Cargo's patch tables
are only honoured by the workspace that *defines* them — when an
external repository depends on any affinidi-* crate via a git rev or
local path, that consumer must replicate the same patch table
verbatim, or different parts of the dependency closure will end up
resolving the affinidi-* crates from a mix of crates.io and the
git/path source. Type-graph divergence shows up as confusing trait
mismatches at compile time (`expected MediatorACLSet, found
MediatorACLSet`).

This is a known cargo limitation — see
[rust-lang/cargo#4452](https://github.com/rust-lang/cargo/issues/4452).

### Recommended path: depend on crates.io releases

The simplest approach is to depend on published versions only:

```toml
[dependencies]
affinidi-tdk = "0.7"
affinidi-messaging-sdk = "0.17"

[dev-dependencies]
affinidi-messaging-test-mediator = "0.1"
```

No patch table is needed — cargo resolves a single version of each
affinidi-* crate from crates.io and the type graph is unified by
construction.

### When you must use a git rev (unreleased fixes)

If you need a patch that hasn't reached crates.io yet, pin the
relevant affinidi-* crates to the same git rev, *and* mirror the
workspace's patch table so transitive deps go through the same rev:

```toml
[patch.crates-io]
# Pick a single rev that all affinidi-* deps resolve through.
# Bump this when you bump any affinidi-* dep above.
affinidi-secrets-resolver = { git = "https://github.com/affinidi/affinidi-tdk-rs", rev = "<rev>" }
affinidi-did-resolver-cache-sdk = { git = "https://github.com/affinidi/affinidi-tdk-rs", rev = "<rev>" }
affinidi-did-common = { git = "https://github.com/affinidi/affinidi-tdk-rs", rev = "<rev>" }
affinidi-crypto = { git = "https://github.com/affinidi/affinidi-tdk-rs", rev = "<rev>" }
affinidi-encoding = { git = "https://github.com/affinidi/affinidi-tdk-rs", rev = "<rev>" }
affinidi-data-integrity = { git = "https://github.com/affinidi/affinidi-tdk-rs", rev = "<rev>" }
affinidi-messaging-didcomm = { git = "https://github.com/affinidi/affinidi-tdk-rs", rev = "<rev>" }
affinidi-messaging-sdk = { git = "https://github.com/affinidi/affinidi-tdk-rs", rev = "<rev>" }
affinidi-messaging-mediator = { git = "https://github.com/affinidi/affinidi-tdk-rs", rev = "<rev>" }
affinidi-messaging-mediator-common = { git = "https://github.com/affinidi/affinidi-tdk-rs", rev = "<rev>" }
affinidi-did-authentication = { git = "https://github.com/affinidi/affinidi-tdk-rs", rev = "<rev>" }
affinidi-tdk-common = { git = "https://github.com/affinidi/affinidi-tdk-rs", rev = "<rev>" }
affinidi-tdk = { git = "https://github.com/affinidi/affinidi-tdk-rs", rev = "<rev>" }
affinidi-meeting-place = { git = "https://github.com/affinidi/affinidi-tdk-rs", rev = "<rev>" }
affinidi-tsp = { git = "https://github.com/affinidi/affinidi-tdk-rs", rev = "<rev>" }
affinidi-did-web = { git = "https://github.com/affinidi/affinidi-tdk-rs", rev = "<rev>" }
did-scid = { git = "https://github.com/affinidi/affinidi-tdk-rs", rev = "<rev>" }
```

The rev must match — and stay matched — to the version constraints
in your own `[dependencies]`. If you bump `affinidi-tdk` above, bump
the rev too; otherwise cargo may fall back to crates.io for crates
not in the patch table.

A regenerator helper is provided to emit the patch block for a
specific commit on this repo:

```bash
./tools/generate-consumer-patch.sh <git-rev>
```

## Support & Feedback

If you face any issues or have suggestions, please don't hesitate to contact us
using [this link](https://share.hsforms.com/1i-4HKZRXSsmENzXtPdIG4g8oa2v).

### Reporting Technical Issues

If you have a technical issue, you can
[open an issue](https://github.com/affinidi/affinidi-tdk-rs/issues/new) directly
in GitHub. Please include a **title and clear description**, as much relevant
information as possible, and a **code sample** or **executable test case**
demonstrating the expected behaviour.

## Contributing

Want to contribute? Head over to our
[CONTRIBUTING](https://github.com/affinidi/affinidi-tdk-rs/blob/main/CONTRIBUTING.md)
guidelines.

## License

This project is licensed under the [Apache-2.0](LICENSE) license.
