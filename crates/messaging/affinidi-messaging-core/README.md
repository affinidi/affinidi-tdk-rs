# affinidi-messaging-core

[![Rust](https://img.shields.io/badge/rust-1.90.0%2B-blue.svg?maxAge=3600)](https://github.com/affinidi/affinidi-tdk-rs/tree/main/crates/affinidi-messaging/affinidi-messaging-core)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)

Protocol-agnostic messaging traits for the Affinidi TDK. This crate defines a
unified API that both [DIDComm v2.1](https://identity.foundation/didcomm-messaging/spec/)
and the [Trust Spanning Protocol (TSP)](https://trustoverip.github.io/tswg-tsp-specification/)
implement, allowing application code to work with either protocol through a
single set of traits.

## Why Use This Crate?

Writing directly against a specific protocol ties your application to that
protocol's API. `affinidi-messaging-core` provides a thin abstraction layer so
you can:

- **Swap protocols** without changing application logic
- **Support multiple protocols** in the same application (e.g. a mediator that
  handles both DIDComm and TSP)
- **Write protocol-agnostic libraries** that consumers can use with whichever
  protocol they prefer

## Core Traits

| Trait | Purpose |
|---|---|
| `MessagingProtocol` | Pack and unpack messages (encrypt, sign, encode) |
| `IdentityResolver` | Resolve identifiers (DIDs/VIDs) to public keys and endpoints |
| `RelationshipManager` | Request, accept, cancel, and query relationships |
| `Transport` | Send packed messages over the network |

## Protocol Comparison

The abstraction normalizes key differences between the two protocols:

| Aspect | DIDComm | TSP |
|---|---|---|
| Relationships | Implicit (always `Bidirectional`) | Explicit handshake (invite → accept) |
| Anonymous send | Supported (anoncrypt) | Not supported (always authenticated) |
| Encoding | JSON (JWM/JWE/JWS) | Binary (CESR + HPKE) |
| Relay | Forward messages via mediators | Nested/routed messages |

## Installation

Add the dependency to your `Cargo.toml`:

```toml
[dependencies]
affinidi-messaging-core = { version = "0.1" }
```

Then enable the `messaging-core` feature on your protocol crate of choice:

```toml
# For DIDComm
affinidi-messaging-didcomm = { version = "0.1", features = ["messaging-core"] }

# For TSP
affinidi-tsp = { version = "0.1", features = ["messaging-core"] }
```

## Usage

### Creating a Protocol Adapter

Both DIDComm and TSP provide an adapter that implements the messaging-core
traits. The setup differs per protocol, but all subsequent operations use the
same API.

**DIDComm:**

```rust
use affinidi_messaging_didcomm::{DIDCommAgent, DIDCommAdapter};

let agent = DIDCommAgent::builder()
    .build()
    .await?;

let adapter = DIDCommAdapter::new(agent);
```

**TSP:**

```rust
use affinidi_tsp::{TspAgent, TspAdapter, PrivateVid};

let agent = TspAgent::new();
let vid = PrivateVid::generate("did:example:alice");
agent.add_private_vid(vid);

let adapter = TspAdapter::new(agent)
    .with_default_vid("did:example:alice");
```

### Packing and Unpacking Messages

Once you have an adapter, the messaging API is identical regardless of protocol:

```rust
use affinidi_messaging_core::MessagingProtocol;

async fn send_message(
    adapter: &impl MessagingProtocol,
    sender: &str,
    recipient: &str,
) -> Result<Vec<u8>, affinidi_messaging_core::MessagingError> {
    // Pack a message — protocol handles encryption and signing
    let packed = adapter.pack(b"Hello!", sender, recipient).await?;

    // Unpack a received message — protocol handles decryption and verification
    let received = adapter.unpack(&packed).await?;

    assert_eq!(received.payload, b"Hello!");
    assert!(received.verified);

    Ok(packed)
}
```

### Managing Relationships

The `RelationshipManager` trait normalizes the different relationship models.
DIDComm relationships are implicit and always return `Bidirectional`. TSP
relationships require an explicit handshake.

```rust
use affinidi_messaging_core::{RelationshipManager, RelationshipState};

async fn establish_relationship(
    adapter: &impl RelationshipManager,
    my_id: &str,
    their_id: &str,
) -> Result<RelationshipState, affinidi_messaging_core::MessagingError> {
    let state = adapter.request_relationship(my_id, their_id).await?;

    match state {
        // DIDComm: ready immediately
        RelationshipState::Bidirectional => Ok(state),

        // TSP: invite sent, wait for acceptance
        RelationshipState::Pending => {
            // The remote party calls accept_relationship() on their side,
            // which transitions both sides to Bidirectional
            Ok(state)
        }

        _ => Ok(state),
    }
}
```

### Resolving Identities

Look up public keys and service endpoints for any DID or VID:

```rust
use affinidi_messaging_core::IdentityResolver;

async fn lookup(
    adapter: &impl IdentityResolver,
    id: &str,
) -> Result<(), affinidi_messaging_core::MessagingError> {
    let identity = adapter.resolve(id).await?;

    println!("ID:             {}", identity.id);
    println!("Endpoints:      {:?}", identity.endpoints);
    println!("Encryption key: {} bytes", identity.encryption_key.len());
    println!("Signing key:    {} bytes", identity.verification_key.len());

    Ok(())
}
```

### Writing Protocol-Agnostic Code

The real power of this crate is writing functions that accept any protocol
adapter. This example works identically with DIDComm or TSP:

```rust
use affinidi_messaging_core::{
    MessagingProtocol, RelationshipManager, RelationshipState,
};

async fn secure_exchange(
    adapter: &(impl MessagingProtocol + RelationshipManager),
    my_id: &str,
    their_id: &str,
    message: &[u8],
) -> Result<Vec<u8>, affinidi_messaging_core::MessagingError> {
    // Ensure relationship is established
    let state = adapter.relationship_state(my_id, their_id).await?;
    if !state.can_send() {
        adapter.request_relationship(my_id, their_id).await?;
    }

    // Pack and return the message
    adapter.pack(message, my_id, their_id).await
}
```

## Related Crates

| Crate | Description |
|---|---|
| [`affinidi-messaging-didcomm`](../affinidi-messaging-didcomm/) | DIDComm v2.1 adapter (`DIDCommAdapter`) |
| [`affinidi-tsp`](../affinidi-tsp/) | TSP adapter (`TspAdapter`) |
| [`affinidi-messaging-sdk`](../affinidi-messaging-sdk/) | High-level messaging client SDK |
| [`affinidi-messaging-mediator`](../affinidi-messaging-mediator/) | Mediator service supporting both protocols |

## License

[Apache-2.0](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)
