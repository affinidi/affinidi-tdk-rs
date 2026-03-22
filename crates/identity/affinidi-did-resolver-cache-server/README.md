# affinidi-did-resolver-cache-server

[![Crates.io](https://img.shields.io/crates/v/affinidi-did-resolver-cache-server.svg)](https://crates.io/crates/affinidi-did-resolver-cache-server)
[![Documentation](https://docs.rs/affinidi-did-resolver-cache-server/badge.svg)](https://docs.rs/affinidi-did-resolver-cache-server)
[![Rust](https://img.shields.io/badge/rust-1.90.0%2B-blue.svg?maxAge=3600)](https://github.com/affinidi/affinidi-tdk-rs/tree/main/crates/affinidi-did-resolver/affinidi-did-resolver-cache-server)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)

A standalone network service for resolving and caching DID Documents at scale.
Uses WebSockets for transport and operates a service-wide cache backed by a pool
of parallel resolvers.

## Architecture

```mermaid
graph LR
    C1["Client 1"] -->|WebSocket| S["Cache Server"]
    C2["Client 2"] -->|WebSocket| S
    C3["Client N"] -->|WebSocket| S
    S -->|cache miss| R["Resolver Pool"]
    R --> M1["did:web"]
    R --> M2["did:ethr"]
    R --> M3["did:key"]
    R --> M4["..."]
```

Requests from clients can be multiplexed and may be responded to out of order.
The client SDK handles matching results to requests.

## Running

1. Configure via `./conf/cache-conf.toml` or environment variables.
2. Start the server:

```bash
cargo run
```

## Related Crates

- [`affinidi-did-resolver-cache-sdk`](../affinidi-did-resolver-cache-sdk/) — Client SDK (use `network` feature to connect)
- [`affinidi-did-common`](../affinidi-did-common/) — DID Document types (dependency)

## License

[Apache-2.0](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)
