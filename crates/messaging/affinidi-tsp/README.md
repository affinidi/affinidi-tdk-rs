# affinidi-tsp

[![Rust](https://img.shields.io/badge/rust-1.90.0%2B-blue.svg?maxAge=3600)](https://github.com/affinidi/affinidi-tdk-rs/tree/main/crates/affinidi-messaging/affinidi-tsp)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)

A Rust implementation of the
[Trust Spanning Protocol (TSP)](https://trustoverip.github.io/tswg-tsp-specification/),
a Trust Over IP Layer 2 protocol for authenticated, encrypted messaging between
Verifiable Identifiers (VIDs).

> **Reference Implementation:** The official TSP reference implementation is
> maintained at [github.com/trustoverip/tsp](https://github.com/trustoverip/tsp).
> This crate provides an independent implementation tailored for the Affinidi TDK
> ecosystem.

## Feature Flags

| Feature | Default | Description |
|---|---|---|
| `did-resolver` | Yes | DID-based VID resolution via `affinidi-did-resolver-cache-sdk` |
| `messaging-core` | No | Protocol-agnostic adapter for `affinidi-messaging-core` traits |

## Cryptographic Suite

| Operation | Algorithm |
|---|---|
| Authenticated encryption | HPKE-Auth (DHKEM(X25519) + HKDF-SHA256 + AES-128-GCM) per [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180) |
| Signing | Ed25519 |
| Message digest | BLAKE2s-256 |
| Encoding | CESR (Composable Event Streaming Representation) |

## Quick Start

Add the dependency to your `Cargo.toml`:

```toml
[dependencies]
affinidi-tsp = { version = "0.1" }
```

### Creating an Agent and VIDs

```rust
use affinidi_tsp::{TspAgent, PrivateVid};

// Create a TSP agent
let agent = TspAgent::new();

// Generate VIDs for Alice and Bob
let alice = PrivateVid::generate("did:example:alice");
let bob = PrivateVid::generate("did:example:bob");

// Register identities
agent.add_private_vid(alice.clone());
agent.add_private_vid(bob.clone());
```

### Establishing a Relationship

TSP requires an explicit relationship handshake before messages can be exchanged.
The lifecycle follows a state machine: **None** → **Pending**/**InviteReceived** →
**Bidirectional**.

```rust
use affinidi_tsp::message::direct::message_digest;

// Alice sends a relationship invite to Bob
let invite = agent.send_relationship_invite("did:example:alice", "did:example:bob")?;
let digest = message_digest(&invite);

// Bob receives and accepts the invite
let received = agent.receive("did:example:bob", &invite.bytes)?;
let accept = agent.send_relationship_accept(
    "did:example:bob",
    "did:example:alice",
    digest.to_vec(),
)?;

// Alice processes the acceptance — relationship is now Bidirectional
agent.receive("did:example:alice", &accept.bytes)?;
```

### Sending and Receiving Messages

Once a bidirectional relationship is established, agents can exchange encrypted,
authenticated messages:

```rust
// Alice sends a message to Bob
let packed = agent.send("did:example:alice", "did:example:bob", b"Hello, Bob!")?;

// Bob receives and decrypts the message
let received = agent.receive("did:example:bob", &packed.bytes)?;

assert_eq!(received.payload, b"Hello, Bob!");
assert_eq!(received.sender, "did:example:alice");
```

### Cancelling a Relationship

Either party can terminate the relationship at any time:

```rust
let cancel = agent.send_relationship_cancel("did:example:alice", "did:example:bob")?;
agent.receive("did:example:bob", &cancel.bytes)?;
// Relationship state returns to None
```

## Relationship State Machine

```
None ──[SendInvite]──► Pending ──[ReceiveAccept]──► Bidirectional
│                       │                              │
│ [ReceiveInvite]       │ [ReceiveCancel]              │ [SendCancel/ReceiveCancel]
▼                       ▼                              ▼
InviteReceived          None                           None
│
│ [SendAccept]
▼
Bidirectional
```

## Protocol-Agnostic Usage with messaging-core

For applications that need to support multiple messaging protocols (e.g. both
DIDComm and TSP), enable the `messaging-core` feature to use the
[`affinidi-messaging-core`](../affinidi-messaging-core/) abstraction layer.
This provides a unified interface for packing, unpacking, identity resolution,
and relationship management across protocols.

```toml
[dependencies]
affinidi-tsp = { version = "0.1", features = ["messaging-core"] }
affinidi-messaging-core = "0.1"
```

```rust
use affinidi_tsp::{TspAgent, TspAdapter, PrivateVid};
use affinidi_messaging_core::MessagingProtocol;

// Wrap a TspAgent in the protocol-agnostic adapter
let agent = TspAgent::new();
let vid = PrivateVid::generate("did:example:alice");
agent.add_private_vid(vid);

let adapter = TspAdapter::new(agent)
    .with_default_vid("did:example:alice");

// Use the unified MessagingProtocol trait
let packed = adapter.pack(b"payload", "did:example:alice", "did:example:bob").await?;
let received = adapter.unpack(&packed).await?;
```

## Related Crates

| Crate | Description |
|---|---|
| [`affinidi-messaging-core`](../affinidi-messaging-core/) | Protocol-agnostic messaging traits and types |
| [`affinidi-messaging-didcomm`](../affinidi-messaging-didcomm/) | DIDComm v2.1 implementation |
| [`affinidi-messaging-sdk`](../affinidi-messaging-sdk/) | High-level messaging client SDK |
| [`affinidi-cesr`](../../affinidi-tdk/common/affinidi-cesr/) | CESR encoding used for TSP envelopes |

## License

[Apache-2.0](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)
