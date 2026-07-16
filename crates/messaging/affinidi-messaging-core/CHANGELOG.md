# Affinidi Messaging Core Changelog

## 16th July 2026

### 0.1.5 — `MessageTransport::outbox_message_ids` (outbox-drain evidence)

Add `MessageTransport::outbox_message_ids()` — the hop-ids still held in the
**sender's own outbox**, a transport's "not yet picked up" signal for the §5a
outbox-drain confirmation. A hop-and-hold transport (DIDComm/TSP via a mediator)
implements it; the default returns `None` (a stateless transport gives no such
signal), so the addition is non-breaking.


### 0.1.4 — `MessageTransport` wire contract

Add the `transport::MessageTransport` trait and its vocabulary
(`TransportKind`, `SendReceipt`, `Inbound`, `InboundAck`) — the contract a
messaging wire (DIDComm now, TSP and REST later) implements so the delivery
layer above can build reliability on it:

- **truthful send** — `send` resolves `Ok(SendReceipt)` only when the next hop
  accepts the bytes, `Err` otherwise; the receipt is hop-acceptance, never
  end-to-end delivery;
- **re-falsifiable connection state** — `connection_state()` hands out the
  `watch::Receiver<ConnState>` (from 0.1.3);
- **ack-after-handoff** — `inbound()` yields undeleted messages and the layer
  calls `ack()` only after a durable handoff.

Packing stays in `MessagingProtocol` (the crypto layer); `MessageTransport`
moves already-packed bytes. Definition only — no implementors in this crate
yet; the DIDComm adapter and conformance suite follow. Additive; pulls
`futures-util` (for `BoxStream`) and `tokio` (`sync` only, for `watch`).

### 0.1.3 — `ConnState` transport connection vocabulary

Add `transport::ConnState` (`Connecting` / `Connected` / `Disconnected`), a
`#[non_exhaustive]` enum for the re-falsifiable connection state a messaging
transport publishes over a `watch` channel. It is the shared vocabulary the
DIDComm websocket transport now emits and the forthcoming `MessageTransport`
trait / delivery layer observe, so connectivity is a live signal rather than a
boot-time latch (R6.2). Additive; no existing API changed.

## 14th June 2026

### 0.1.2 — non_exhaustive MessagingError (W7 sweep)

- `MessagingError` is now `#[non_exhaustive]` (ADR-0003) so new variants land
  additively. Patch bump keeps the `0.1` pin valid; consumers that `match` it
  must add a `_` wildcard arm. No behaviour change.
