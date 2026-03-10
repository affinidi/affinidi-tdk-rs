# affinidi-messaging-helpers

[![Crates.io](https://img.shields.io/crates/v/affinidi-messaging-helpers.svg)](https://crates.io/crates/affinidi-messaging-helpers)
[![Rust](https://img.shields.io/badge/rust-1.90.0%2B-blue.svg?maxAge=3600)](https://github.com/affinidi/affinidi-tdk-rs/tree/main/crates/affinidi-messaging/affinidi-messaging-helpers)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)

Setup tools, environment configuration, and example runners for
[Affinidi Messaging](../).

## Tools

| Binary | Description |
|---|---|
| `setup_environment` | Configure the initial environment for local or remote mediators |
| `mediator_administration` | Add, remove, and list mediator admin accounts |
| `generate_mediator_config` | Generate mediator configuration files |

## Getting Started

### Configure Your Environment

```bash
cargo run --bin setup_environment
```

This creates a `conf/profiles.json` file with your environment profiles.

### Set the Active Profile

Using an environment variable:

```bash
export TDK_ENVIRONMENT=local
cargo run --example mediator_ping
```

Or at run-time:

```bash
cargo run --example mediator_ping -- -e local
```

## Debug Logging

```bash
export RUST_LOG=none,affinidi_messaging_helpers=debug,affinidi_messaging_sdk=info
```

## Examples

Explore the [examples folder](./examples/) for available examples, including:

- `mediator_ping` — Send a trust ping to the mediator
- Sending and receiving messages
- Message pickup
- `protocol_comparison` — Benchmark comparing TSP vs DIDComm message packing
- `unified_messaging` — Demonstrates messaging-core trait abstraction across
  protocols

## Related Crates

- [`affinidi-messaging-sdk`](../affinidi-messaging-sdk/) — Messaging SDK (dependency)
- [`affinidi-messaging-mediator`](../affinidi-messaging-mediator/) — Mediator service
- [`affinidi-tdk`](../../affinidi-tdk/affinidi-tdk/) — Unified TDK entry point (dependency)

## License

[Apache-2.0](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)
