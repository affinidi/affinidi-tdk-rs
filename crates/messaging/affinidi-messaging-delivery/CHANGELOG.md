# Changelog

## [0.1.1] - 2026-07-16

- Add the `MessagingService` front-end and its single inbound dispatcher — the
  API services call, over one transport + outbox:
  - `send(to, packed, Delivery)` — `BestEffort` sends once (truthful `Err` if not
    transmitted); `Guaranteed` enqueues a durable outbox entry. Returns `Sent`
    (`Accepted` for now; `Delivered`/`Unconfirmed` land with §5a confirmation).
  - `request(to, packed, correlation_thid, timeout)` — send + await the reply
    correlated by thread id; concurrent requests never steal each other's replies.
  - `subscribe()` — a per-subscriber stream of inbound messages not claimed by a
    request waiter (at-least-once; dedup on the idempotency key).
  - `status()` — `MessagingStatus` read off the transport's live
    `connection_state()`, never a boot-time latch.
  - One dispatcher reads `inbound()` exactly once, demuxes by thread id, and
    **acks each message once after handoff** (never per-caller, never before
    handoff).
  Fully unit-tested over a mock transport (no mediator). Additive.

## [0.1.0] - 2026-07-16

Initial release — the durable outbox and its drain, the first increment of the
reliable messaging delivery layer (D1 Phase 2) over the `MessageTransport`
contract in `affinidi-messaging-core`.

- `OutboxEntry` + `OutboxState` (`Queued → Sent → Delivered | Unconfirmed |
  Failed`; `Sent` is hop-accept, **not** delivered).
- `OutboxStore` trait + `InMemoryOutboxStore`, with per-`ordering_key` FIFO
  gating in `due`.
- `drain_once` / `drain_loop`: send due entries over a `MessageTransport`, mark
  `Sent` on a truthful hop-accept (and stop re-sending — the mediator owns
  redelivery), retry with exponential backoff on failure, and settle `Failed`
  when the delivery window expires while still queued.

End-to-end confirmation (`Sent → Delivered`) and the `MessagingService`
front-end build on this in later increments.
