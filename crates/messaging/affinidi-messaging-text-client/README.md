# affinidi-messaging-text-client

[![Rust](https://img.shields.io/badge/rust-1.95.0%2B-blue.svg?maxAge=3600)](https://github.com/affinidi/affinidi-tdk-rs/tree/main/crates/messaging/affinidi-messaging-text-client)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)

A terminal-based DIDComm chat client for interacting with
[Affinidi Messaging](../) mediators. Useful for testing, demos, and debugging
message flows.

This crate is `publish = false` — it's distributed via this repository, not
crates.io. Build it from source.

## Running

Ensure a mediator is configured and running (see
[mediator setup](../affinidi-messaging-mediator/)), then:

```bash
cargo run -p affinidi-messaging-text-client
```

## State file

The client persists its DID, mediator connections, and chat history to a
JSON state file managed by `State::save_to_file`. **The file contains the
client's DID private keys** (the `secrets` array). As of 0.12.2 it is
created with mode `0600` on Unix so only the owner can read it. On other
platforms the file is created with the platform default — restrict it
manually if running on a shared host.

Don't copy the state file off the host or commit it to source control.

## Related Crates

- [`affinidi-messaging-sdk`](../affinidi-messaging-sdk/) — Messaging SDK (dependency)
- [`affinidi-messaging-mediator`](../affinidi-messaging-mediator/) — Mediator service

## License

[Apache-2.0](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)
