# affinidi-messaging-sdk

[![Crates.io](https://img.shields.io/crates/v/affinidi-messaging-sdk.svg)](https://crates.io/crates/affinidi-messaging-sdk)
[![Documentation](https://docs.rs/affinidi-messaging-sdk/badge.svg)](https://docs.rs/affinidi-messaging-sdk)
[![Rust](https://img.shields.io/badge/rust-1.90.0%2B-blue.svg?maxAge=3600)](https://github.com/affinidi/affinidi-tdk-rs/tree/main/crates/affinidi-messaging/affinidi-messaging-sdk)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)

SDK for integrating [Affinidi Messaging](../) into your application. Provides a
high-level API for sending and receiving end-to-end encrypted
[DIDComm v2](https://identity.foundation/didcomm-messaging/spec/) messages via a
mediator service.

> **Note:** This SDK focuses on the DIDComm protocol. For
> [Trust Spanning Protocol (TSP)](https://trustoverip.github.io/tswg-tsp-specification/)
> messaging, see the [`affinidi-tsp`](../affinidi-tsp/) crate directly, or use
> [`affinidi-messaging-core`](../affinidi-messaging-core/) for a protocol-agnostic
> API that works with both DIDComm and TSP.

## Installation

```toml
[dependencies]
affinidi-messaging-sdk = "0.15"
```

## Quick Start

```rust
use affinidi_messaging_sdk::{ATM, config::Config};

let config = Config::builder()
    .with_ssl_certificates(&mut vec!["path/to/client.chain".into()])
    .with_my_did("did:peer:2...")
    .with_atm_did("did:peer:2...")
    .build()?;

let mut atm = ATM::new(config, vec![]).await?;

// Send a trust ping
atm.send_ping("did:peer:2...", true, true).await?;
```

## Transport

The SDK supports both **WebSocket** and **HTTPS REST** transports:

- **WebSocket** (default) — used for sending messages and receiving inbound
  message streams
- **REST** — used for authentication (JWT tokens) and as a fallback

WebSocket is created automatically when `ATM::new()` is called. You can disable
it or manage it manually:

```rust
let config = Config::builder()
    .with_websocket_disabled()
    .build()?;
let mut atm = ATM::new(config, vec![]).await?;

// Send via REST
atm.send_ping("did:peer:2...", true, true).await?;

// Start WebSocket later if needed
atm.start_websocket().await?;
atm.send_ping("did:peer:2...", true, true).await?;
atm.close_websocket().await?;
```

## Core API

### Sending Messages

| Method | Description |
|---|---|
| `send_ping(to, signed, response)` | Send a DIDComm Trust Ping |
| `send_didcomm_message(msg)` | Send a packed DIDComm message via REST |
| `ws_send_didcomm_message(msg)` | Send a packed DIDComm message via WebSocket |

### Message Management

| Method | Description |
|---|---|
| `list_messages(did, folder)` | List messages in Inbox or Outbox |
| `get_messages(request)` | Retrieve messages by ID |
| `delete_messages(request)` | Delete messages by ID |

### Packing & Unpacking

| Method | Description |
|---|---|
| `pack_encrypted(msg, from, sign_by)` | Encrypt (and optionally sign) a message |
| `pack_signed(msg, sign_by)` | Sign a plaintext message |
| `pack_plaintext(msg)` | Create an unencrypted DIDComm message |
| `unpack(msg)` | Unpack any DIDComm message |

## Debug Logging

```bash
export RUST_LOG=none,affinidi_messaging_sdk=debug
```

## Examples

Set up a mediator first (see [mediator README](../affinidi-messaging-mediator/)),
then:

```bash
export MEDIATOR_DID=<your-mediator-did>
export MEDIATOR_ENDPOINT=https://localhost:7037/mediator/v1

cargo run --example ping
cargo run --example send_message_to_me
cargo run --example message_pickup
```

See [affinidi-messaging-helpers](../affinidi-messaging-helpers/) for more
examples.

## Related Crates

- [`affinidi-messaging-didcomm`](../affinidi-messaging-didcomm/) — DIDComm protocol implementation (dependency)
- [`affinidi-tsp`](../affinidi-tsp/) — Trust Spanning Protocol (alternative protocol)
- [`affinidi-messaging-core`](../affinidi-messaging-core/) — Protocol-agnostic messaging traits
- [`affinidi-messaging-mediator`](../affinidi-messaging-mediator/) — Mediator service
- [`affinidi-did-resolver-cache-sdk`](../../affinidi-did-resolver/affinidi-did-resolver-cache-sdk/) — DID resolution

## License

[Apache-2.0](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)
