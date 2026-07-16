# Changelog

## [0.1.3] - 2026-07-16

- Add the §5a **outbox-drain** delivery-evidence source: `poll_outbox_drain` /
  `outbox_drain_loop` confirm a `Sent` entry `Delivered` when its `hop_id`
  **drains** from the transport's outbox (`MessageTransport::outbox_message_ids`,
  the "recipient took pickup" signal).
  - `OutboxEntry` gains `hop_id` (recorded on `Sent` from `SendReceipt::hop_id`)
    and `outbox_observed` — the latter guards against the mediator's eventual
    consistency: a hop-id absent right after send may simply not be indexed yet,
    so "absent" only counts as pickup **after** the id was observed present.
  - The drain now records `hop_id` on a hop-accepted entry.
  Additive; verified against a real mediator via the DIDComm adapter.

## [0.1.2] - 2026-07-16

- Add the end-to-end delivery **confirmation** state machine (§5a): the
  `Sent → Delivered | Unconfirmed` transitions a hop-accepted entry awaits.
  - `confirm_delivered(store, key)` — record evidence: `Sent → Delivered`
    (idempotent; a re-delivered receipt for an already-`Delivered` entry is a
    no-op).
  - `sweep_confirmations(store, now)` / `confirmation_loop` — settle any `Sent`
    entry whose delivery window expired without evidence to `Unconfirmed` (a
    truthful "we can't know", distinct from the drain's `Failed` for a `Queued`
    entry that never even hop-accepted).
  - `OutboxStore::awaiting_confirmation()` — the `Sent` entries the sweep checks
    (default returns none; `InMemoryOutboxStore` overrides it).
  - `MessagingService::confirm(key)` — the evidence entry point (called by a
    layer-receipt recognizer or a protocol-reply handler) — and
    `delivery_state(key)` to poll the outcome after a `Guaranteed` `send`.
  The *evidence sources* — the receiver auto-emitting a layer receipt, polling
  the mediator's own outbox for drain, and re-sending over an alternate binding
  on expiry — layer on top of this state machine (they need live-mediator
  interaction). Additive; fully offline-tested.

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
