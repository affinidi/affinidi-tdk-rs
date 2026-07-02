# TSP cookbook

Copy-paste scenarios for using the **Trust Spanning Protocol (TSP)** through the
Affinidi TDK — sending and receiving TSP messages, relationship forming,
authentication, and running TSP over a WebSocket.

TSP is **additive alongside DIDComm**: one mediator carries both, one socket can
carry both, and the same accounts / ACLs / mailbox / pickup machinery is reused
(an account is keyed on `sha256(vid)`). You opt into TSP per build with the
`tsp` cargo feature; with it off, nothing here compiles in and DIDComm is
unchanged.

> The SDK snippets are marked `ignore` because they need an async runtime and a
> running mediator; they follow the patterns covered by the
> `affinidi-messaging-test-mediator` integration tests
> (`tests/tsp_delivery.rs`, `tests/tsp_websocket.rs`, `tests/tsp_auth.rs`),
> which are the runnable, CI-checked source of truth for these APIs.

---

## Contents

- [Enabling TSP](#enabling-tsp)
- [The carriage model](#the-carriage-model)
- [Sending](#sending)
- [Receiving](#receiving)
- [WebSocket delivery](#websocket-delivery)
- [Relationships](#relationships)
- [Authentication](#authentication)
- [Trust Tasks over TSP](#trust-tasks-over-tsp)

---

## Enabling TSP

**Cargo features** — enable `tsp` on the SDK (and the mediator, if you run one):

```toml
affinidi-messaging-sdk = { version = "0.18", features = ["tsp"] }
# Mediator deployments: run TSP alongside DIDComm (dual-protocol).
affinidi-messaging-mediator = { version = "0.16", features = ["didcomm", "tsp"] }
```

A TSP client today reuses the profile's **DIDComm-authenticated session**, so a
dual-protocol mediator (`didcomm,tsp`) is the normal deployment. For a *pure*-TSP
client see [Authentication](#authentication).

**Endpoint discovery** — for other mediators to route TSP to yours, your
mediator's DID document must advertise a `TSPTransport` service. With the `tsp`
feature on:

- **did:web** — added automatically at startup, mirroring the `DIDCommMessaging`
  endpoint (TSP and DIDComm share `/inbound`). No action needed.
- **did:peer / did:webvh** — the document is bound to the DID, so the
  `TSPTransport` service is baked in **when the DID is generated**. The setup
  wizard does this automatically when you select the `tsp` protocol; if you
  hand-roll the DID, add the service yourself. The mediator logs a startup
  warning if `tsp` is on but no `TSPTransport` service is advertised.

> Running a mediator? See the [operator enablement guide](./enablement.md) for
> the full build + DID-document + verification walkthrough.

---

## The carriage model

A TSP message is always sealed **end-to-end to its final recipient**. How it
*travels* there is the carriage:

| Carriage | What it is | API |
|----------|-----------|-----|
| **Direct** | sealed sender → recipient, no intermediary | `send` / `pack` |
| **Nested** | a Direct message wrapped once for a single intermediary (metadata privacy — only that intermediary learns the recipient) | `send_nested` |
| **Routed** | a Direct message relayed through one or more hops | `send_routed` |
| **Control** | relationship management (invite / accept / cancel) | `send_control`, or the [relationship](#relationships) helpers |

The crucial property: **the mediator strips the outer (Nested/Routed) layers; the
recipient always opens the innermost Direct message.** So `unpack` works
identically no matter how a message was carried — and a Nested/Routed inner can
even be a **DIDComm** message (the TSP↔DIDComm bridge), which the recipient then
opens with its native protocol.

---

## Sending

`atm.tsp()` is the entry point; every call takes the sender's `profile`.

**Direct** — seal straight to a recipient DID and POST it to the mediator:

```rust,ignore
atm.tsp().send(&alice.profile, &bob_did, b"hello over TSP").await?;
```

**Routed** — relay through hops; `route` is the ordered hop list ending at the
final recipient (the inner is sealed to `route.last()`):

```rust,ignore
let route = vec![mediator_did.clone(), bob_did.clone()];
atm.tsp().send_routed(&alice.profile, &route, b"routed hello").await?;
```

**Nested** — wrap a Direct (sealed to `to_did`) inside an outer envelope sealed to
`intermediary`; only the intermediary learns `to_did`:

```rust,ignore
atm.tsp()
    .send_nested(&alice.profile, &mediator_did, &bob_did, b"private hello")
    .await?;
```

**Bridging DIDComm over TSP** — `send_routed_opaque` / `send_nested_opaque` take
an *already-packed* inner (e.g. a DIDComm message from `atm.pack_encrypted`) and
relay it opaquely; the recipient unpacks it natively.

Lower-level building blocks: `pack(profile, to_did, payload)` returns the raw qb2
bytes without sending; `send_raw(profile, bytes)` POSTs already-packed bytes.

---

## Receiving

TSP messages land in the same mailbox as DIDComm. Fetched messages are
**tagged** with their protocol so you can route without inspecting the body:

```rust,ignore
let fetched = atm.fetch_messages(&bob.profile, &FetchOptions::default()).await?;
for el in fetched.success {
    let stored = el.msg.as_ref().expect("body");
    match el.protocol {
        Some(MessageProtocol::Tsp) => {
            let (payload, sender) = atm.tsp().unpack(&bob.profile, stored).await?;
            // `sender` is the authenticated sender VID.
        }
        _ => { /* DIDComm: atm.unpack(...) */ }
    }
}
```

Helpers: `is_tsp(stored)` (sniff a stored message), `decode`/`encode` (stored
`base64url(qb2)` ↔ raw qb2), and `unpack_bytes(profile, qb2)` to unpack raw qb2
directly (what the [WebSocket](#websocket-delivery) consumer yields).

---

## WebSocket delivery

For low-latency, opt a socket into **raw-TSP mode** with `connect_websocket`. It
offers a `tsp` subprotocol on the upgrade, so the mediator uses a
**flush-on-connect + delete-on-successful-send** contract: on connect it drains
your inbox as raw-TSP `Binary` frames and deletes each once it's sent; new
messages stream the same way. **You own failure handling** — a dropped socket
leaves undelivered messages in the inbox for the next connection.

```rust,ignore
let mut ws = atm.tsp().connect_websocket(&bob.profile).await?;
while let Some(qb2) = ws.recv().await? {            // next raw TSP message, None on close
    let (payload, sender) = atm.tsp().unpack_bytes(&bob.profile, &qb2).await?;
    // ... handle it ...
}
ws.close().await?;
```

`ws.send(&qb2)` sends a raw TSP message inbound over the same socket.

---

## Relationships

TSP relationships follow a small state machine, driven through `atm.tsp()` and
backed by a **pluggable store** (so where the state lives — memory, a database —
is yours to choose):

```text
None ──form_relationship──► Pending ──(peer accepts)──► Bidirectional
None ──(peer invites)─────► InviteReceived ──accept_relationship──► Bidirectional
                              (cancel from any state → None)
```

```rust,ignore
// Initiator
atm.tsp().form_relationship(&alice.profile, &bob_did).await?;   // → Pending (sends an invite)

// Responder, after receiving an invite control message:
let control = ControlMessage::decode(&payload)?;               // payload from unpack
atm.tsp().record_incoming_control(&bob.profile, &alice_did, &control).await?; // → InviteReceived
atm.tsp().accept_relationship(&bob.profile, &alice_did, &invite_wire).await?; // → Bidirectional

let state = atm.tsp().relationship_state(&alice.profile, &bob_did).await?;
```

Outbound calls **persist only after the control message is sent**.
`record_incoming_control` advances the FSM for a received invite/accept/cancel.

**Choosing a store** — the default is ephemeral (in-memory, wiped on restart).
Implement `RelationshipStore` against durable storage and inject it:

```rust,ignore
let config = ATMConfig::builder()
    .with_relationship_store(Arc::new(MyDurableStore::new(/* ... */)))
    .build()?;
```

---

## Authentication

**Dual-protocol clients** (the common case) authenticate with DIDComm; TSP calls
reuse that session automatically — nothing extra to do.

**Pure-TSP clients** (no DIDComm) authenticate by signing the mediator's
challenge with their VID's Ed25519 key. The SDK ships `TspAuthHandler`; register
it on the TDK at construction and every profile then authenticates over
`/tsp/authenticate`:

```rust,ignore
use affinidi_messaging_sdk::TspAuthHandler;
use affinidi_tdk::did_authentication::CustomAuthHandlers;

let handlers = CustomAuthHandlers::default()
    .with_auth_handler(Arc::new(TspAuthHandler::new(secrets.clone())));

let tdk_config = TDKConfig::builder()
    .with_secrets_resolver(secrets)        // the SAME resolver your VID keys live in
    .with_custom_auth_handlers(handlers)
    .build()?;
```

The handler resolves the mediator's `#auth` service, fetches a challenge, signs
it, and POSTs to `/tsp/authenticate` — minting the **same** JWT session the
DIDComm path issues, so all downstream ACL / pickup / WS gates are reused
unchanged.

---

## Trust Tasks over TSP

Trust Tasks (`messaging/ping`, account/acl/access-list/admin, …) are
transport-agnostic. The `trust-tasks-tsp` binding carries any Trust Task over
TSP — so a "TSP ping", account ops, etc. are just the corresponding Trust Task
sent over a TSP carriage:

```rust,ignore
use trust_tasks_tsp::{pack_trust_task, pack_trust_task_nested, pack_trust_task_routed};

let wire = pack_trust_task(&doc, &sender_private_vid, &recipient_resolved_vid)?;
// nested / routed variants mirror the carriage model above.
atm.tsp().send_raw(&profile, &wire).await?;
```

The consumer always opens the innermost Direct via `unpack_trust_task`,
regardless of carriage — the mediator strips the relay layers.
