# ADR 0005 — `AffinidiMessageService`: one socket, DIDComm + TSP multiplexed

- **Status:** Proposed
- **Date:** 2026-06-29
- **Relates to:** `affinidi-messaging-didcomm-service` (`DIDCommService`); the
  raw-TSP WebSocket delivery mode (#534) + SDK consumer `atm.tsp().connect_websocket`
  (#536); the mediator's one-websocket-per-DID rule (`w.websocket.duplicate-channel`,
  #550→#551); the downstream VTA TSP-inbound flap (verifiable-trust-infrastructure
  PR #595).

## Context

A node that speaks **both** DIDComm and TSP to the same mediator cannot hold two
websockets. The mediator registers **one websocket per DID** and terminates any
second connection for that DID with `w.websocket.duplicate-channel`. This is not
incidental — it's the invariant that fixed the earlier duplicate-channel flapping
(#550→#551).

Today the two transports are served by two unrelated paths:

- **`DIDCommService`** (this crate) owns the listener websocket and routes
  **unpacked DIDComm `Message`s** to a handler chain. Its inbound loop pulls via
  `atm.message_pickup().live_stream_next(profile, …)` — a DIDComm-pickup
  abstraction. It has **no TSP awareness**: the SDK websocket transport already
  sniffs the CESR magic byte and surfaces TSP frames as
  `WebSocketResponses::PackedMessageReceived`, but `DIDCommService` never sees
  them — `live_stream_next` yields only DIDComm messages, so TSP frames are
  effectively dropped at this layer.
- **`atm.tsp().connect_websocket`** (#536) opens a **separate, TSP-only**
  websocket (the `tsp` subprotocol, raw qb2 `Binary` frames). Correct for a
  **TSP-only** client, but fatal for a dual client: it's a *second* socket for
  the same DID.

The concrete failure: the VTA enabled both, opened a DIDComm listener socket
**and** a `connect_websocket` TSP socket under one DID, and the two evicted each
other on every connect — an endless `duplicate-channel` reconnect flap (VTI
#595). The lesson: **transport is per-DID, not per-protocol.** One DID → one
socket → both protocols multiplexed on it.

`DIDCommService`'s name and DIDComm-only routing are the obstacle. A sibling
`TSPService` with its own socket would reproduce the exact bug. Dual sockets are
ruled out by the mediator. The frames are self-describing (DIDComm JWE text vs
TSP CESR/qb2), so one socket can carry both — the missing piece is a service that
**owns the socket and routes by protocol**.

## Decision

Introduce **`AffinidiMessageService`** — a transport-multiplexing message service
that owns a single per-DID websocket and dispatches inbound frames to
per-protocol handlers, and unifies outbound send. `DIDCommService` becomes a thin
compatibility shim over it (DIDComm-only configuration).

1. **One socket, multiplexed by frame.** The service owns the single mediator
   websocket for its profile/DID. Inbound frames are classified at ingress —
   `is_tsp(frame)` → TSP path; otherwise DIDComm unpack → DIDComm path. Both
   converge on the consumer's handler surface. No second socket is ever opened.

2. **Protocols are configurable; at least one is required.** A
   `Protocols` config selects which transports the service advertises/handles:

   ```rust
   pub struct Protocols { pub didcomm: bool, pub tsp: bool }

   impl Protocols {
       pub fn new(didcomm: bool, tsp: bool) -> Result<Self, ConfigError> {
           if !didcomm && !tsp { return Err(ConfigError::NoProtocolEnabled); }
           Ok(Self { didcomm, tsp })
       }
       pub const DIDCOMM_ONLY: …  pub const TSP_ONLY: …  pub const BOTH: …
   }
   ```

   - **`{didcomm}`** — current `DIDCommService` behaviour.
   - **`{tsp}`** — TSP-only node (no DIDComm pickup; the socket carries only TSP).
   - **`{both}`** — dual node; the multiplexing case this ADR exists for.
   - **`{}` is rejected at construction** (`ConfigError::NoProtocolEnabled`) — a
     message service with no transport is a no-op and almost certainly a config
     bug. This is the service-level analogue of the mediator/VTA "at least one
     advertised transport" brick-prevention invariant.

3. **Per-protocol handler surface, shared dispatch.** DIDComm keeps the existing
   `Router` / `DIDCommHandler` chain unchanged. TSP adds a `TspHandler` that
   receives `(payload, sender_vid)` from `atm.tsp().unpack_bytes`. Consumers
   register one or both. The application layer (e.g. a VTA's
   `dispatch_trust_task_core`) is already transport-agnostic, so both handlers
   feed the same spine.

4. **Unified outbound.** `send(recipient, message)` packs+forwards over DIDComm
   or sends via `atm.tsp()` per the selected/looked-up protocol, reusing the one
   socket's authenticated session. (Protocol selection against the recipient's
   DID document — match by service `type` — is the consumer's concern; the
   service exposes both send paths.)

5. **SDK inbound surface (the one lower-level change).** `live_stream_next`
   yields only DIDComm. Add a sibling that yields a **`InboundFrame`**:
   `enum InboundFrame { DidComm(Box<Message>, Box<UnpackMetadata>), Tsp { qb2: Vec<u8> } }`
   so the service's loop gets DIDComm *and* TSP frames off the one stream. The
   existing `WebSocketResponses::{MessageReceived, PackedMessageReceived}` split
   already carries the distinction at the transport layer; this surfaces it one
   level up rather than dropping the packed (TSP) variant.

6. **`DIDCommService` becomes a shim.** It is re-expressed as
   `AffinidiMessageService` with `Protocols::DIDCOMM_ONLY` and the DIDComm
   handler wired. Its public API is preserved (or thinly re-exported) so existing
   consumers compile unchanged; new dual/TSP consumers use
   `AffinidiMessageService` directly. Deprecate `DIDCommService` over one
   release, don't remove it abruptly.

## Consequences

- **Fixes the VTI flap** (#595): a dual VTA runs **one** socket; the
  `connect_websocket` second-socket loop is deleted on the consumer side. TSP
  inbound becomes "register a `TspHandler`."
- **`connect_websocket` keeps its niche**: TSP-only clients (`Protocols::TSP_ONLY`)
  — there's no second socket to conflict with.
- **One place to reason about** per-DID transport, reconnect/backoff, shutdown,
  and the one-socket invariant — instead of two services racing.
- **Migration cost**: existing `DIDCommService` consumers are insulated by the
  shim; the real adopter is the dual node. The `Protocols` constructor's
  reject-empty rule is a small breaking-by-construction guard (consumers build it
  via `new`/constants, never a struct literal — consistent with ADR 0003's
  `#[non_exhaustive]` posture).
- **Naming churn**: a new public type + a soft-deprecated one for a release.

## Implementation plan (staged, individually reviewable)

1. **SDK inbound multiplex** — `InboundFrame` + a `live_stream_next`-sibling that
   surfaces TSP packed frames (no service changes yet; unit-test the
   classification).
2. **`AffinidiMessageService` skeleton** — `Protocols` + `ConfigError::NoProtocolEnabled`
   + the single-socket listener that routes DIDComm to the existing router and
   TSP to a `TspHandler`. Reuse `DIDCommService`'s restart/shutdown machinery.
3. **Unified outbound `send`** — DIDComm + TSP paths over the one session.
4. **`DIDCommService` shim** — re-express over `AffinidiMessageService`
   (`DIDCOMM_ONLY`); preserve/deprecate the public API.
5. **Downstream switch (VTI)** — replace the PR-#595 `connect_websocket` loop
   with a `TspHandler` on the shared service; delete the second socket. This is
   what a live VTA↔mediator dual run validates end-to-end.

Each stage is a separate PR; stage 5 lands in the VTI repo against the published
result of 1–4.

## Amendment (2026-07-02) — stage 6: symmetric TSP replies

Stages 1–5 make a node *receive* TSP and *initiate* a TSP send, but the two
handler surfaces were left asymmetric:

- **DIDComm**: `DIDCommHandler::handle -> Result<Option<DIDCommResponse>, _>`;
  the listener's `dispatch_message` auto-sends the returned response. A built-in
  `trust_ping_handler` round-trips for free.
- **TSP**: `TspHandler::handle -> Result<(), _>`; `dispatch_tsp` discarded any
  result. A consumer wanting a request/response round-trip (e.g. a VTA health
  probe, or any Trust Task that returns a document) had to reach into
  `ctx.atm.tsp()` and re-derive the route back to the sender by hand — the exact
  outbound plumbing this ADR set out to centralise.

**Decision.** Make `TspHandler` symmetric with `DIDCommHandler`:

```rust
pub struct TspResponse { pub payload: Vec<u8> }   // sealed + routed to sender_vid

pub trait TspHandler {
    async fn handle(&self, ctx, payload, sender_vid)
        -> Result<Option<TspResponse>, DIDCommServiceError>;   // was Result<(), _>
}
```

`dispatch_tsp` now mirrors `dispatch_message`: on `Ok(Some(resp))` it seals
`resp.payload` to the authenticated `sender_vid` and routes it back over the
**same** shared mediator socket — consumers never touch outbound TSP.

**Reply-routing rule.** A TSP unpack yields only the sender's VID (a bare DID),
not its mediator, so — unlike DIDComm, where mediator routing falls out of the
recipient's DID doc — the service must choose a route. It uses the listener
profile's own mediator: `send_routed([profile_mediator_did, sender_vid])`
(`ATMProfile::dids()` gives both). This is correct for the common case where
both parties share one mediator (the case the health probe and most intra-fleet
traffic hit). If the profile has no mediator, it falls back to a TSP Direct
`send`. Cross-mediator replies (sender reachable only via a *different* mediator)
are out of scope for the auto-reply — a handler that needs that returns
`Ok(None)` and drives `AffinidiMessageService::send_tsp_routed` with an explicit
route.

**Correlation** stays at the application layer: a TSP frame carries no thread id,
so a request/response id must live in the payload (e.g. a Trust Task `#response`
document's `threadId`). The transport ferries bytes; it does not correlate.

**Breaking**: `Result<(), _>` → `Result<Option<TspResponse>, _>`. Existing
implementors migrate `Ok(())` → `Ok(None)`; `IgnoreTspHandler` returns `Ok(None)`.
`tsp`-feature-only surface; default builds are source-compatible. Consequently
the VTI stage-5 `VtaTspHandler` (which today drops the Trust Task response) can
return it as `Ok(Some(..))` and the round-trip completes — enabling the `pnm
health` TSP probe end-to-end. Shipped in `affinidi-messaging-didcomm-service`
0.3.14.
