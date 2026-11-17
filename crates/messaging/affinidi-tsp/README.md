# affinidi-tsp

[![Rust](https://img.shields.io/badge/rust-1.95.0%2B-blue.svg?maxAge=3600)](https://github.com/affinidi/affinidi-tdk-rs/tree/main/crates/messaging/affinidi-tsp)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)

A Rust implementation of the
[Trust Spanning Protocol (TSP)](https://trustoverip.github.io/tswg-tsp-specification/),
a Trust Over IP Layer 2 protocol for authenticated, encrypted messaging between
Verifiable Identifiers (VIDs).

This crate speaks **TSP 1.0** (wire version `1.0`, `YTSP-BAA`). Section numbers
in these docs cite Rev 3 of the specification where 1.0 left them unchanged.
1.0 does not interoperate with Rev 3 or Rev 2 peers — see the
[interop notes](https://github.com/affinidi/affinidi-tdk-rs/blob/main/docs/tsp/interop.md#the-version-field).

> **Reference Implementation:** The official TSP reference implementation is
> maintained at [github.com/trustoverip/tsp](https://github.com/trustoverip/tsp).
> This crate provides an independent implementation tailored for the Affinidi TDK
> ecosystem. It **wire-interoperates** with the reference (`tsp-sdk`) for every
> TSP message type (Direct, Routed, Nested, Control), both directions — see the
> [interop status](https://github.com/affinidi/affinidi-tdk-rs/blob/main/docs/tsp/interop.md) and the `interop/` harness.

> **Using TSP through the TDK?** This crate is the low-level protocol. For sending,
> receiving, relationships, WebSocket delivery, and authentication via the
> messaging SDK (`atm.tsp()`), see the **[TSP cookbook](https://github.com/affinidi/affinidi-tdk-rs/blob/main/docs/tsp/cookbook.md)**.

## Feature Flags

| Feature | Default | Description |
|---|---|---|
| `did-resolver` | Yes | DID-based VID resolution via `affinidi-did-resolver-cache-sdk` |
| `messaging-core` | No | Protocol-agnostic adapter for `affinidi-messaging-core` traits |
| `pq` | No | Post-quantum PKAE and signatures: the MLKEM768-X25519 hybrid KEM and ML-DSA-65 (provisional code points; see [`post-quantum.md`](https://github.com/affinidi/affinidi-tdk-rs/blob/main/docs/tsp/post-quantum.md)) |
| `test-vectors` | No | Byte-reproducible packing with caller-fixed ephemeral keys, to regenerate the specification's vectors. **Destroys confidentiality** — tests only |

## Cryptographic Suite

| Operation | Algorithm |
|---|---|
| Authenticated encryption | HPKE-Base (DHKEM(X25519) + HKDF-SHA256 + ChaCha20Poly1305), the mandatory PKAE mode (Rev 3 §8) |
| Authenticated encryption (deprecated) | Libsodium sealed box (X25519 + XSalsa20-Poly1305, Rev 3 §8.3), received and sent for interop |
| Signed-only | A non-confidential message (Rev 3 §3.5): signed, not sealed. `ReceivedMessage::confidential` is `false` for one; a consumer that needs confidentiality must check it |
| Signing | Ed25519 |
| Message digest | SHA2-256 for the `TSP_Digest` (Rev 3 §7.2.1); BLAKE2s-256 for opaque message ids |
| Encoding | CESR (Composable Event Streaming Representation), with its own minimal codec in `message::wire` |

## Quick Start

Add the dependency to your `Cargo.toml`:

```toml
[dependencies]
affinidi-tsp = { version = "0.5" }
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
// Alice sends a relationship invite to Bob
let invite = agent.send_relationship_invite("did:example:alice", "did:example:bob")?;

// Bob receives and accepts the invite. The accept derives the invite's thread
// digest from the store (recorded by `receive`), so it only needs the two VIDs.
let received = agent.receive("did:example:bob", &invite.bytes)?;
let accept = agent.send_relationship_accept("did:example:bob", "did:example:alice")?;

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
│ [ReceiveInvite]       │ [SendCancel/ReceiveCancel]   │ [SendCancel/ReceiveCancel]
▼                       ▼                              ▼
InviteReceived          None                           None
│
│ [SendAccept]
▼
Bidirectional
```

Every transition the FSM (`RelationshipState::transition`) allows:

| From | Event | To |
|---|---|---|
| `None` | `SendInvite` | `Pending` |
| `None` | `ReceiveInvite` | `InviteReceived` |
| `Pending` | `ReceiveAccept` | `Bidirectional` |
| `Pending` | `SendCancel` / `ReceiveCancel` | `None` |
| `InviteReceived` | `SendAccept` | `Bidirectional` |
| `InviteReceived` | `SendCancel` / `ReceiveCancel` | `None` |
| `InviteReceived` | `ReceiveInvite` (a re-sent invite) | `InviteReceived` |
| `Bidirectional` | `SendCancel` / `ReceiveCancel` | `None` |
| `Bidirectional` | `ReceiveInvite` (a fresh re-invite) | `InviteReceived` |

Any other pair is refused as an invalid transition.

A peer that lost its half re-forms the relationship by sending a new invite,
which takes an established relationship back to `InviteReceived` until it is
accepted again. A copy of an invite already acted on for that pair is refused
with `TspError::Discarded` and changes nothing; while still `InviteReceived`, a
re-sent copy of the invite being decided on is accepted as a no-op.

## Repeated messages

`TspAgent::receive` refuses a repeated copy of an invite (above), but TSP gives
an application message no identifier or sequence number to check, so
`receive` returns the same payload each time it is handed the same message. A
consumer that must act on a message once deduplicates it itself — for example on
an identifier in its own payload, or on the delivery layer's idempotency key.

## Protocol-Agnostic Usage with messaging-core

For applications that need to support multiple messaging protocols (e.g. both
DIDComm and TSP), enable the `messaging-core` feature to use the
[`affinidi-messaging-core`](https://github.com/affinidi/affinidi-tdk-rs/tree/main/crates/messaging/affinidi-messaging-core/) abstraction layer.
This provides a unified interface for packing, unpacking, identity resolution,
and relationship management across protocols.

```toml
[dependencies]
affinidi-tsp = { version = "0.5", features = ["messaging-core"] }
affinidi-messaging-core = "0.1"
```

```rust
use affinidi_tsp::{TspAgent, PrivateVid, adapter::TspAdapter};
use affinidi_messaging_core::{MessagingProtocol, RelationshipManager};

// Two endpoints, each knowing the other's public VID.
let alice_vid = PrivateVid::generate("did:example:alice");
let bob_vid = PrivateVid::generate("did:example:bob");
let alice_agent = TspAgent::new();
alice_agent.add_verified_vid(bob_vid.to_resolved());
alice_agent.add_private_vid(alice_vid.clone());
let bob_agent = TspAgent::new();
bob_agent.add_verified_vid(alice_vid.to_resolved());
bob_agent.add_private_vid(bob_vid);

let alice = TspAdapter::new(alice_agent).with_default_vid("did:example:alice");
let bob = TspAdapter::new(bob_agent).with_default_vid("did:example:bob");

// The relationship handshake. Each `*_with_control` call returns the control
// message to transmit; nothing is sent for you.
let invite = alice
    .request_relationship_with_control("did:example:alice", "did:example:bob")
    .await?;
bob.unpack(&invite.control_message.unwrap()).await?;
let accept = bob
    .accept_relationship_with_control("did:example:bob", "did:example:alice", &[])
    .await?;
alice.unpack(&accept.control_message.unwrap()).await?;

// Now Alice can pack for Bob, and Bob unpacks it.
let packed = alice.pack(b"payload", "did:example:alice", "did:example:bob").await?;
let received = bob.unpack(&packed).await?;
assert_eq!(received.payload, b"payload");
assert!(received.encrypted); // `false` for a signed-only message
```

The state-only `request_relationship` / `accept_relationship` /
`cancel_relationship` are refused with `MessagingError::NotSupported` by the
TSP adapter: they cannot hand back the control message the peer needs.

## Related Crates

| Crate | Description |
|---|---|
| [`affinidi-messaging-core`](https://github.com/affinidi/affinidi-tdk-rs/tree/main/crates/messaging/affinidi-messaging-core/) | Protocol-agnostic messaging traits and types |
| [`affinidi-messaging-didcomm`](https://github.com/affinidi/affinidi-tdk-rs/tree/main/crates/messaging/affinidi-messaging-didcomm/) | DIDComm v2.1 implementation |
| [`affinidi-messaging-sdk`](https://github.com/affinidi/affinidi-tdk-rs/tree/main/crates/messaging/affinidi-messaging-sdk/) | High-level messaging client SDK |

## License

[Apache-2.0](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)
