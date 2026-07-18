# Changelog

## [0.1.9] - 2026-07-18

- Add the **`MessageTransport` conformance suite** (`conformance` module, behind
  the `conformance` feature; design §11). Parameterized over the wire via a
  `ConformanceWire` factory + a `WireControl` surface: `run_all` drives the
  delivery layer over a fresh transport per case and asserts the seven
  guarantees — truthful send, connection-truth, demux, dedup, accept-then-die
  (→ `Unconfirmed`, never a false `Delivered`), outbox-drain (→ `Delivered`), and
  layer-receipt (→ `Delivered`). Ships an in-crate reference `MockWire` (the
  always-run baseline, e.g. the "REST-fallback"); a real wire (DIDComm now, TSP
  at phase 4) implements `ConformanceWire` to run the same suite. Additive,
  feature-gated (panicking assertions, off in a normal build).

## [0.1.8] - 2026-07-18

- **Fix: layer receipts carried over DIDComm are now recognised.** `receipt_key`
  parsed the transport `payload` directly as a `Receipt`, but the DIDComm
  transport sets `ReceivedMessage.payload` to the FULL plaintext message JSON
  (`Message::to_json()`), where the receipt lives under `body` — so the whole
  message never parsed as a `Receipt` and a layer receipt was silently ignored
  (§5a confirmation via `with_receipts` never fired). `receipt_key` now tries the
  payload as a receipt directly (a transport that surfaces the body, e.g. TSP)
  and falls back to extracting the DIDComm message `body`. Additive; 2 new tests.

## [0.1.7] - 2026-07-17

- Derive `Serialize`/`Deserialize` on `OutboxEntry` and `OutboxState` so a
  **durable** `OutboxStore` can persist entries (a service backing the outbox
  with an on-disk keyspace — the production path; the in-memory store is
  dev-only). Format-agnostic: JSON encodes `packed` as a byte array, CBOR/bincode
  compactly. Additive; no field or API change. 1 new roundtrip test.

## [0.1.6] - 2026-07-16

- Add **escalate-on-expiry** (§5a): when a `Sent` entry's delivery window passes
  with no evidence, the window passing is never a silent success — the sweep
  escalates it, visibly.
  - `ExpiryEscalator` trait + `Escalation` outcome: `Rebound { deliver_by_ms,
    hop_id }` (the escalator re-sent over an **alternate binding** — a dead
    mediator ≠ a dead peer — so re-arm the window and keep watching, `Sent`),
    `Failed` (no alternate — the delivery-critical send failed; **surface it**),
    or `Unconfirmed` (no evidence was ever possible — a truthful "we can't know").
  - `sweep_confirmations_with` / `confirmation_loop_with` apply the policy;
    `confirmation_loop_with` logs a **warning** tick whenever entries `Failed`
    (the operator-alert surface). `sweep_confirmations` / `confirmation_loop`
    are unchanged — the default policy settles `Unconfirmed`.
  - `ConfirmReport` gains `failed` and `rebound` counts (additive;
    `#[non_exhaustive]`).
  The concrete escalator — re-resolving the peer's DID document and re-sending
  over another transport/mediator — is wired by the service that owns the
  transports (lands with multi-transport / Phase 4); the layer applies the
  outcome. Additive. 4 new offline tests (34 total).

## [0.1.5] - 2026-07-16

- Add the §5a **protocol-reply** evidence source (the third §5a source, after
  layer-receipt and outbox-drain). An inbound message arriving *in the thread of*
  a `Sent` outbox entry — thread id matches its idempotency key — is proof the
  peer received the original `Guaranteed` send (you cannot reply in-thread to a
  message you never got), so the dispatcher settles that entry `Delivered` with
  no application ack of our own. Where the peer already replies (registry
  response, RPC, approver approve/deny), that reply *is* the receipt.
  - Consume-only, event-driven in the inbound dispatcher; needs no packer.
    Idempotent — a no-op when no `Sent` entry matches, and harmless when a layer
    receipt already confirmed the same entry. The reply is still delivered to the
    application as ordinary traffic.
  - A reply that confirms one of our own sends is **not** itself receipted (it is
    a reply, not a fresh `Guaranteed` push; its thread id is the original thread,
    not the reply's own key).
  Additive (dispatcher behaviour; no API change). 2 new offline tests (30 total).

## [0.1.4] - 2026-07-16

- Add the §5a **layer receipt** — the strongest delivery-confirmation evidence
  (`receipt` module). When the *receiving* layer durably persists an inbound
  message it emits a fire-and-forget receipt back to the sender; the *sending*
  layer recognises it and settles the matching outbox entry `Sent → Delivered`.
  Real end-to-end evidence for **every** `Guaranteed` message, one-way traffic
  included, with no application-protocol reply — and the only evidence that
  closes the mediator's power-loss window.
  - `Receipt` (a typed JSON body marked by `RECEIPT_TYPE`) + `receipt_key` /
    `receipt_of` recognisers; `ReceiptPacker` trait abstracts the crypto (like
    `OutboxStore` abstracts storage — a service/SDK wires in a DID-encrypting
    packer; the consume half needs none).
  - `MessagingService`: the dispatcher **consumes** an inbound receipt
    (`confirm_delivered`, never surfaced to the app; unknown key = no-op) —
    always active. `MessagingService::with_receipts(.., packer)` additionally
    **emits** a receipt for every unsolicited message it receives, echoing the
    thread-id correlation. A request reply is *not* receipted (it is its own
    protocol-reply evidence); a receipt is never receipted.
  Additive (new module + constructor; `new` unchanged); pulls `serde`/`serde_json`.
  8 new offline tests (28 total).

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
