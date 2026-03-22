# affinidi-messaging-text-client

[![Rust](https://img.shields.io/badge/rust-1.90.0%2B-blue.svg?maxAge=3600)](https://github.com/affinidi/affinidi-tdk-rs/tree/main/crates/affinidi-messaging/affinidi-messaging-text-client)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)

A terminal-based DIDComm chat client for interacting with
[Affinidi Messaging](../) mediators. Useful for testing, demos, and debugging
message flows.

## Running

Ensure a mediator is configured and running (see
[mediator setup](../affinidi-messaging-mediator/)), then:

```bash
cargo run
```

## Related Crates

- [`affinidi-messaging-sdk`](../affinidi-messaging-sdk/) — Messaging SDK (dependency)
- [`affinidi-messaging-mediator`](../affinidi-messaging-mediator/) — Mediator service

## License

[Apache-2.0](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)
