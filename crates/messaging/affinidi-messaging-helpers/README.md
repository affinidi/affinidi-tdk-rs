# affinidi-messaging-helpers

[![Crates.io](https://img.shields.io/crates/v/affinidi-messaging-helpers.svg)](https://crates.io/crates/affinidi-messaging-helpers)
[![Rust](https://img.shields.io/badge/rust-1.90.0%2B-blue.svg?maxAge=3600)](https://github.com/affinidi/affinidi-tdk-rs/tree/main/crates/affinidi-messaging/affinidi-messaging-helpers)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)

Administration tooling and example runners for
[Affinidi Messaging](../). The mediator itself ships its own setup
wizard — see
[`affinidi-messaging-mediator`](../affinidi-messaging-mediator/) and
its [setup guide](../affinidi-messaging-mediator/docs/setup-guide.md)
to provision a mediator end to end.

## Tools

| Binary | Description |
|---|---|
| `mediator_administration` | Add, remove, and list mediator admin accounts |

## Getting Started

The example runners (`mediator_ping`, `alice_bob`, `discover_features`,
`unified_messaging`, etc.) load mediator + profile configuration
from a JSON file at `environments.json` (overridable via
`-p <path>` or by passing `--environment` / `-e <name>` to pick
which named environment in the file to use).

### 1. Provision a mediator

Use the mediator's setup wizard to bring up a real mediator and
record the values you'll need to talk to it (mediator DID, public
URL, optional admin DID + secret):

```bash
cargo run --bin mediator-setup
```

### 2. Hand-write `environments.json`

The historical `setup_environment` binary is gone — the helpers
crate no longer ships an interactive environment-builder. Author
the file directly:

```json
{
  "local": {
    "default_mediator": "did:peer:2.Vz6Mk…",
    "profiles": {
      "alice": { "alias": "alice", "did": "did:peer:2.Ez6L…", "secrets": [...] },
      "bob":   { "alias": "bob",   "did": "did:peer:2.Ez6L…", "secrets": [...] }
    }
  }
}
```

The exact shape lives in [`TDKEnvironments`] in
`affinidi-tdk-common`. The example sources are the most current
reference for which profiles each example expects.

[`TDKEnvironments`]: ../../tdk/affinidi-tdk-common/src/environments.rs

### 3. Run an example

```bash
export TDK_ENVIRONMENT=local
cargo run --example mediator_ping
```

Or pick the environment explicitly at run-time:

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
- `protocol_comparison` — Benchmark comparing [TSP](../affinidi-tsp/) vs [DIDComm](../affinidi-messaging-didcomm/) message packing
- `unified_messaging` — Demonstrates [messaging-core](../affinidi-messaging-core/) trait abstraction across both protocols

## Related Crates

- [`affinidi-messaging-sdk`](../affinidi-messaging-sdk/) — Messaging SDK (dependency)
- [`affinidi-tsp`](../affinidi-tsp/) — Trust Spanning Protocol
- [`affinidi-messaging-mediator`](../affinidi-messaging-mediator/) — Mediator service
- [`affinidi-tdk`](../../affinidi-tdk/affinidi-tdk/) — Unified TDK entry point (dependency)

## License

[Apache-2.0](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)
