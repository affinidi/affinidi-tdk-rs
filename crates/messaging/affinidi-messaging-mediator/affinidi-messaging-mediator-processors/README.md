# affinidi-messaging-mediator-processors

[![Rust](https://img.shields.io/badge/rust-1.90.0%2B-blue.svg?maxAge=3600)](https://github.com/affinidi/affinidi-tdk-rs/tree/main/crates/affinidi-messaging/affinidi-messaging-mediator/affinidi-messaging-mediator-processors)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)

Scalable processors for the Affinidi Messaging Mediator. Each processor can run
as a parallel task within the mediator or as a standalone service for horizontal
scaling.

## Processors

### Message Expiry Cleanup

Removes expired messages from the database based on expiry headers.

### Forwarding

Routes DIDComm messages to third-party mediators or DIDComm agents.
*(Work in progress)*

## Crate Layout

```
src/lib/              Shared library interfaces
  src/lib/<processor>  Processor-specific library code
src/<processor>/       Binary entry point for standalone mode
conf/<processor>.toml  Configuration for each processor
```

## Related Crates

- [`affinidi-messaging-mediator`](../) — Parent mediator service

## License

[Apache-2.0](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)
