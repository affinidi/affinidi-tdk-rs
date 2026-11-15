# affinidi-messaging-sdk

[![Crates.io](https://img.shields.io/crates/v/affinidi-messaging-sdk.svg)](https://crates.io/crates/affinidi-messaging-sdk)
[![Documentation](https://docs.rs/affinidi-messaging-sdk/badge.svg)](https://docs.rs/affinidi-messaging-sdk)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)

The Affinidi Trusted Messaging (ATM) SDK: send and receive end-to-end
encrypted [DIDComm v2](https://identity.foundation/didcomm-messaging/spec/)
messages through a mediator, and, with the `tsp` feature,
[Trust Spanning Protocol](https://trustoverip.github.io/tswg-tsp-specification/)
messages over the same mediator. It handles packing, unpacking, routing,
authentication and transport.

The crate documentation on [docs.rs](https://docs.rs/affinidi-messaging-sdk)
is the reference; this page is the overview.

## Installation

```bash
cargo add affinidi-messaging-sdk
# with TSP support
cargo add affinidi-messaging-sdk --features tsp
```

## Key concepts

- **`ATM`**: the entry point. Holds the configuration, the profiles, and the
  background tasks (such as message deletion).
- **`ATMProfile`**: a DID together with its mediator. Each profile sends and
  receives on its own, over REST and optionally a websocket.
- **Mediator**: stores and forwards messages for a profile. Its REST and
  websocket endpoints are read from its DID document when the profile is
  created; a mediator DID that cannot be resolved fails profile creation.
- **Protocols**: Trust Ping, Message Pickup 3.0, Routing 2.0, Discover
  Features, OOB discovery and the mediator's Trust Tasks, reached through
  `atm.trust_ping()`, `atm.message_pickup()`, `atm.routing()`,
  `atm.discover_features()`, `atm.oob_discovery()` and `atm.trust_tasks()`.
- **Transports**: REST for authentication and request/response; a websocket
  per profile for low-latency sends and live delivery.

## Getting started

```rust,ignore
use affinidi_messaging_sdk::{ATM, config::ATMConfig, profiles::ATMProfile};
use affinidi_tdk_common::{TDKSharedState, config::TDKConfig};
use std::{sync::Arc, time::Duration};

// 1. The TDK shared state: DID resolution, secrets, and the HTTP client the
//    SDK's REST calls use.
let tdk = Arc::new(TDKSharedState::new(TDKConfig::builder().build()?).await?);

// 2. The SDK.
let config = ATMConfig::builder()
    // Optional: trust a private CA for the mediator websocket (wss://).
    .with_ssl_certificate_paths(["certs/ca.pem"])
    .build()?;
let atm = ATM::new(config, tdk.clone()).await?;

// 3. A profile. Its secrets go into the TDK's secrets resolver.
tdk.add_profile(&alice_tdk_profile).await;
let alice = atm
    .profile_add(&ATMProfile::from_tdk_profile(&atm, &alice_tdk_profile).await?, false)
    .await?;

// 4. Send a trust ping over REST.
let ping = atm
    .trust_ping()
    .send_ping(&alice, &mediator_did, true, true, false)
    .await?;

// 5. Open the websocket and wait for the pong on the live stream.
atm.profile_enable_websocket(&alice).await?;
let pong = atm
    .message_pickup()
    .live_stream_get(&alice, &ping.message_id, Some(Duration::from_secs(10)), true)
    .await?;

// 6. Shut down: websockets first, then the background tasks.
atm.graceful_shutdown().await;
```

`profile_enable_websocket` returns once the first connect attempt has
finished: `Ok` when connected, or that attempt's own error (a refused upgrade
stays a typed `ATMError::HttpStatus` carrying `Retry-After`, for example). A
mediator whose DID document has no websocket endpoint is refused at once with
`ATMError::ConfigError`. The wait for an attempt that hangs is bounded by
`ATMConfigBuilder::with_websocket_ready_timeout` (default 60s).

## Sending and receiving

- `atm.send_message(profile, packed, msg_id, wait_for_response, auto_delete)`
  sends an already packed message. Over the websocket it returns `Ok` only
  once the frame was written to the socket; a frame the transport could not
  write (disconnected, a failed or stalled write) is an `Err`, never a false
  success. `send_message_with_timeout` chooses how long to wait for a reply.
- `auto_delete` applies to the reply on both transports.
- `atm.message_pickup().live_stream_next(..)`, `live_stream_next_frame(..)`,
  `live_stream_next_packed(..)` and `live_stream_get(..)` take messages off the
  live stream. `wait: None` waits until one arrives. With `auto_delete` the
  message's deletion is queued after it is handed to you; if the deletion
  cannot be queued it is logged, the message is still returned, and the
  mediator may deliver it again. Treat delivery as at-least-once.
- `send_status_request`, `send_delivery_request` and
  `send_delivery_request_frames` drain the mediator's queue. A delivered
  message keeps its sender's `id`; acknowledge it with
  `UnpackMetadata::sha256_hash`, the mediator's id for it.

### One inbound channel for every profile

`ATMConfigBuilder::with_inbound_message_channel(capacity)` routes inbound
websocket messages from every profile to one bounded channel. Take its
receiver once with `atm.get_inbound_channel()`. It never drops a message: when
it is full the transport holds messages in its caches, then stops reading the
socket until you catch up.

## Connection state and receive health

The websocket reconnects by itself. Watch it rather than assuming it is up:

```rust,ignore
// Connecting / Connected / Disconnected, published on every drop and
// reconnect for the life of the transport.
if let Some(mut state) = alice.connection_state().await {
    while state.changed().await.is_ok() {
        println!("connection: {:?}", *state.borrow());
    }
}

// Is anything reaching this profile? A socket can be up while the mediator has
// stopped delivering, or while the application has stopped taking messages.
if let Some(health) = alice.receive_health().await {
    let health = health.borrow();
    if health.consumer_stalled() {
        eprintln!("{} inbound messages are waiting to be collected", health.held_frames);
    }
}
```

`ReceiveHealth` also reports the receive-leg probe (a live-delivery request
sent when inbound has been silent for `with_receive_probe`, default 60s, with
a reconnect if it goes unanswered) and frames that could not be unpacked.

For a transport-agnostic interface with acknowledgement after handoff, wrap a
profile in `DidCommTransport` (an `affinidi-messaging-core` `MessageTransport`).

## TSP

With the `tsp` feature, `atm.tsp()` packs, sends, routes and unpacks TSP
messages through the same profile and mediator, and
`live_stream_next_frame` / `send_delivery_request_frames` return DIDComm and
TSP frames side by side as `InboundFrame`. `atm.send_to(..)` chooses the
protocol per peer according to `ATMConfigBuilder::with_tsp_policy` (off by
default, so enabling the feature alone changes nothing). TSP relationship
state lives in a pluggable `RelationshipStore` (in memory by default).

Without the feature, a TSP frame arriving on a DIDComm-only stream is logged,
deleted and skipped.

## Configuration highlights

| Builder method | Default | What it does |
|---|---|---|
| `with_ssl_certificate_paths` | none | Extra trust roots (PEM files) for the mediator websocket, on top of the platform's. REST trust comes from the `TDKConfig`. |
| `with_request_timeout` | 15s | Bound on each REST call. |
| `with_websocket_ready_timeout` | 60s | Bound on waiting for the first websocket connect attempt. |
| `with_fetch_cache_limit_count` / `_bytes` | 100 / 10 MB | Per-profile limit on inbound messages held for the application, measured in wire bytes. Reading pauses when reached. |
| `with_inbound_message_channel` | off | One bounded channel for inbound messages from every profile. |
| `with_unpack_policy` | authcrypt only | Which envelope wrappings `unpack` and the pickup drain accept. |
| `with_unprocessable_message_channel` | off | Report messages that could not be processed before they are deleted. |
| `with_receive_probe` | 60s | Probe a silent receive leg; `None` turns it off. |
| `with_tsp_policy` (`tsp`) | off | Whether `send_to` picks TSP. |

## Debug logging

```bash
export RUST_LOG=none,affinidi_messaging_sdk=debug
```

## Examples

Runnable examples live in
[affinidi-messaging-helpers](https://github.com/affinidi/affinidi-tdk-rs/tree/main/crates/messaging/affinidi-messaging-helpers/examples/), e.g.
`trust_ping`, `mediator_ping`, `alice_bob` and `oob_invite`. They need a
mediator (see
[affinidi-messaging-mediator](https://github.com/affinidi/affinidi-messaging-mediator))
and a hand-written `environments.json` (schema in the helpers README).

## Related crates

- [`affinidi-messaging-didcomm`](https://github.com/affinidi/affinidi-tdk-rs/tree/main/crates/messaging/affinidi-messaging-didcomm/): the DIDComm implementation
- [`affinidi-tsp`](https://github.com/affinidi/affinidi-tdk-rs/tree/main/crates/messaging/affinidi-tsp/): the Trust Spanning Protocol implementation
- [`affinidi-messaging-core`](https://github.com/affinidi/affinidi-tdk-rs/tree/main/crates/messaging/affinidi-messaging-core/): protocol-agnostic messaging traits
- [`affinidi-messaging-delivery`](https://github.com/affinidi/affinidi-tdk-rs/tree/main/crates/messaging/affinidi-messaging-delivery/): reliable delivery on top of a transport
- [`affinidi-messaging-mediator`](https://github.com/affinidi/affinidi-messaging-mediator): the mediator

## License

[Apache-2.0](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)
