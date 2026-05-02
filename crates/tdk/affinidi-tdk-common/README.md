# affinidi-tdk-common

[![Crates.io](https://img.shields.io/crates/v/affinidi-tdk-common.svg)](https://crates.io/crates/affinidi-tdk-common)
[![Documentation](https://docs.rs/affinidi-tdk-common/badge.svg)](https://docs.rs/affinidi-tdk-common)
[![Rust](https://img.shields.io/badge/rust-1.94.0%2B-blue.svg?maxAge=3600)](https://github.com/affinidi/affinidi-tdk-rs/tree/main/crates/tdk/affinidi-tdk-common)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)

Shared building blocks for Affinidi Trust Development Kit (TDK) crates.

## Overview

The crate is organised around four core concepts:

| Module | Purpose |
|---|---|
| [`config`] | `TDKConfig` + `TDKConfigBuilder` — typed configuration, owns optional DID resolver / secrets resolver / environment-file path / custom auth handlers. |
| [`TDKSharedState`] (lib.rs) | Runtime container exposing the DID resolver, secrets resolver, HTTPS client, and `AuthenticationCache` via accessor methods. Cheap to clone. |
| [`profiles`] + [`environments`] | Serialisable identity profiles + on-disk grouping (`environments.json`). |
| [`secrets`] | `KeyringStore` — handle into the OS native credential store (macOS Keychain, Windows Credential Manager, freedesktop Secret Service). |
| [`tasks::authentication`] | `AuthenticationCache` — shared, channel-driven cache for DID Auth tokens. |

[`TDKError`] is the single error funnel; consumers convert it to their own
error types via `From<TDKError>` impls.

## Installation

```toml
[dependencies]
affinidi-tdk-common = "0.6"
```

## Usage

```rust,ignore
use affinidi_tdk_common::{TDKSharedState, config::TDKConfig};

# async fn run() -> Result<(), affinidi_tdk_common::errors::TDKError> {
let config = TDKConfig::builder().build()?;
let state = TDKSharedState::new(config).await?;

// ...use state.client(), state.did_resolver(), etc...

// Graceful shutdown:
state.shutdown().await;
# Ok(())
# }
```

### Storing profile secrets in the OS keyring

```rust,ignore
use affinidi_tdk_common::secrets::KeyringStore;

# fn run(secrets: &[affinidi_secrets_resolver::secrets::Secret]) -> Result<(), affinidi_tdk_common::errors::TDKError> {
let store = KeyringStore::new("my-app");
store.save("did:example:alice", secrets)?;
let loaded = store.read("did:example:alice")?;
store.delete("did:example:alice")?;
# Ok(())
# }
```

## Platform support

The keyring backend is selected at compile time:

| Target | Backend |
|---|---|
| macOS | [`apple-native-keyring-store`](https://crates.io/crates/apple-native-keyring-store) (Keychain) |
| iOS | [`apple-native-keyring-store`](https://crates.io/crates/apple-native-keyring-store) (Protected Data) |
| Windows | [`windows-native-keyring-store`](https://crates.io/crates/windows-native-keyring-store) (Credential Manager) |
| Linux / FreeBSD / OpenBSD | [`dbus-secret-service-keyring-store`](https://crates.io/crates/dbus-secret-service-keyring-store) (Secret Service over D-Bus) |

## Migrating from 0.5.x

See [`CHANGELOG.md`](CHANGELOG.md) for the full breaking-change list and
side-by-side migration snippets.

## Key dependencies

This crate aggregates several TDK libraries:

- [`affinidi-did-resolver-cache-sdk`](../../identity/affinidi-did-resolver-cache-sdk/) — DID resolution
- [`affinidi-did-authentication`](../../identity/affinidi-did-authentication/) — DID authentication
- [`affinidi-data-integrity`](../../credentials/affinidi-data-integrity/) — Data integrity proofs
- [`affinidi-secrets-resolver`](../../core/affinidi-secrets-resolver/) — Secret management

## Related crates

- [`affinidi-tdk`](../affinidi-tdk/) — Unified TDK entry point
- [`affinidi-meeting-place`](../../applications/affinidi-meeting-place/) — Meeting Place SDK

## License

[Apache-2.0](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)
