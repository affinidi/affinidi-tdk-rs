# Changelog

## 0.1.17 — an ack that cannot be delivered is no longer dropped

An ack is a delete at the mediator, and the dispatcher issues it over the
transport the message arrived on. Two paths ended with no ack and no durable
trace of that: the source transport was **gone** (logged at `debug`, dropped),
or the ack call **failed** (logged at `warn`, dropped, no retry).

Neither loses the message — the mediator still holds it and offers it again on
the next pickup. But until that happens the message stays queued **against its
sender**, counting toward the sender's queue-depth limits. With those limits now
enforced on every path, a sender can be refused over messages its recipient
processed days ago. That is the shape reported upstream as an outbound queue
that never drained.

An undeliverable ack is now parked and retried on its own clock — not on
inbound traffic, since the transport that owes an ack is by definition the one
that has gone quiet. Retries are **same-transport-only**: a transport id names a
wire to a particular mediator, and an ack is a delete of a message id *at that
mediator*, so replaying it elsewhere would at best do nothing and at worst
delete an unrelated message sharing an id. A transport reinstalled under the
same id — the ordinary reconnect — is the same wire and settles the parked ack.

Bounded, and neither bound loses data: at most 4096 parked acks (past that the
**oldest** goes, being the one most likely already settled by a redelivery), and
an entry is abandoned after 5 minutes. Abandoning is safe for the same reason
the original bug was survivable — the mediator still holds the message. What is
not safe is doing it silently, so every abandonment is counted and logged.

New `MessagingService::ack_stats() -> AckStats`: `acked`, `deferred`, `settled`,
`abandoned`, `overflowed`, `no_consumer`, `pending`. Counters rather than
metrics because this crate keeps a deliberately small dependency set; a host
that scrapes Prometheus reads these and publishes them under its own names.

`abandoned` is the number that matters — each one is a message the recipient
handled that is still queued against its sender. `no_consumer` counts the
deliberate no-ack arm, which is the contract working rather than a failure, and
is counted for exactly that reason: a consumer that never subscribes otherwise
produces a steady climb and no other symptom until the recipient's queue fills.

Additive: no API removed, no behaviour change for a transport whose acks land.

## 0.1.16 — the outbox can be emptied

`OutboxStore` had no way to remove anything. `put` upserted, state moved
`Queued → Sent → Delivered | Unconfirmed | Failed`, and there it stopped — so an
outbox keyspace grew for the life of the deployment, and `due()` re-read and
re-decoded every entry ever written on every tick. The cost of draining rose
with everything that had already drained successfully.

Two additions, both defaulted so that a store which implements neither keeps its
previous behaviour exactly — this is **not** a breaking change:

- `OutboxStore::remove_if_terminal(key) -> bool` — deletes **only if** the entry
  is still terminal, atomically, and says whether it did. Conditional rather
  than a plain `remove` because the reaper works from a snapshot, and an entry
  can be re-queued between the read and the delete (CWE-367); a general delete
  would remove live work on a stale read. Re-reading first narrows that window
  without closing it, so the condition is evaluated where the delete happens,
  under whatever the store uses to make `put` atomic. Default: removes nothing.
- `OutboxStore::terminal_before(cutoff_ms)` — terminal entries created at or
  before the cutoff. Default: none.

A store opts into reaping by implementing both. Implementing `terminal_before`
without `remove_if_terminal` is the one incoherent pair, and it is visible
rather than silent: `ReapReport::skipped` counts entries the store offered and
then declined to remove.

Also `reap::{reap_terminal, reap_loop, TERMINAL_RETENTION, ReapReport}`. Terminal
entries are kept for the retention window (7 days, matching the mediator's own
`message_expiry_seconds` — a duplicate cannot arrive from a message the mediator
has already expired) rather than dropped on settle, because `idempotency_key` is
what makes at-least-once retry safe: delete it as soon as an entry settles and a
retry arriving afterwards reads as new work.

Only terminal entries are ever eligible. A `Queued` entry is unfinished work and
a `Sent` one is still awaiting evidence, and age does not make either
disposable.

`reap_loop` skips a pass and logs when the system clock cannot be read, rather
than defaulting the cutoff to 0: the cutoff decides which records are destroyed,
and a silent fallback means that decision gets made on a bad reading with
nothing to show for it.
## 16th September 2026

### 0.1.15 — build `Inbound` through its constructor

`Inbound` is `#[non_exhaustive]` as of `affinidi-messaging-core` 0.1.8, so the
conformance harness and the service tests construct it with `Inbound::new`
rather than a struct literal. No behavioural change.

## [0.1.14] - 2026-08-16

**A message no consumer received is no longer acked.** An ack is a delete at the
mediator, so acking an undelivered message destroys it — and the dispatcher was
acking unconditionally, including when `subscribers.send` had just reported that
nobody was listening. This is the contract `Inbound` documents ("only **after**
the message is durably handed off … never ack-before-handoff") and the one the
SDK's transport adapter sets `auto_delete = false` to honour; the layer was the
piece not keeping it.

The window is small and its consequences are not: no subscriber is installed for
a moment at startup and again on the way down, and what arrives in that window is
whatever the peer happened to send — a membership credential, a join verdict.
Downstream this surfaced as OpenVTC joins stuck `Pending` forever with clean logs
on both sides (OpenVTC/openvtc#221), because the only record was that nothing
happened.

- **Ack is now conditional on handoff.** `broadcast::send` returns `Err` when
  there are no subscribers; that is the signal. An unacked message stays at the
  mediator and is offered again on the next pickup, which is exactly what the
  contract is for.
- **A reply whose waiter died falls through to subscribers.** A caller that timed
  out leaves a dead `oneshot`; the reply used to be swallowed by it and acked
  anyway. It is still application traffic, so it now goes to `subscribe()` and is
  acked only if someone takes it.
- **A lagging subscriber is reported at `error!` instead of skipped in silence.**
  Overwritten messages are unrecoverable — the dispatcher acked them on the way
  in — so this is the one lossy step left in the inbound path, and it was also
  the only one with no trace. The count of lost messages is now named.
- `SUBSCRIBE_BUFFER`'s note claimed "at-least-once, dedup on the key". That holds
  for redelivery *before* an ack; this buffer sits after one. Corrected.

3 new tests (61 total).

## [0.1.13] - 2026-08-08

Dependency-pin bump only; no API or behaviour change.

- Track `affinidi-messaging-core` 0.1.6, which adds `Protocol::DIDCommV1` for
  the new `affinidi-messaging-didcomm-v1` crate and makes `Protocol`
  `#[non_exhaustive]`. This crate's exact-patch pin has to move in lockstep.
  Nothing here matches on `Protocol`, so no code changed.

## [0.1.12] - 2026-07-26

- **`MessagingService` is now usable multi-identity**, where each transport *is* a
  sender identity (one per persona / agent DID) rather than an alternative wire to
  the same peer. The multi-transport core from 0.1.10 already supported holding N
  of them; what was missing was outbound selection, drain routing, and a truthful
  per-transport status. Additive; 11 new tests (58 total).
  - **`send_via(transport_id, to, packed, delivery)`** — the outbound counterpart
    of 0.1.11's `request_via`. `send` routes to the primary, which is correct when
    transports are interchangeable wires and wrong when the transport determines
    the proven sender. `BestEffort` sends over the named transport; `Guaranteed`
    pins the outbox entry to it.
  - **`OutboxEntry::via: Option<String>`** (+ `with_via`) — the transport an entry
    **must** drain over. `None` keeps today's behaviour and is what makes mediator
    migration work: an unbound entry follows `promote` to the new primary rather
    than being pinned to the mediator current when it was enqueued. `Some(id)` is
    for the identity case, where draining entry A over identity B's socket would
    send it from the wrong sender — which the recipient authenticates and the
    mediator ACL judges.
  - **`drain_once_via` / `drain_loop_via`** — the per-identity drain. Over one
    shared store, every entry is claimed by **exactly one** drain: an unbound entry
    by `drain_once`, a pinned entry by the `_via` drain naming it. Nothing
    double-sends and nothing is orphaned.
  - **`transport_states()` / `transport_state(id)`** — per-transport live
    `ConnState`. `status()`'s aggregate assumes transports are alternative wires to
    one peer, so its `Degraded` means "a standby is down"; under multi-identity the
    same value would mean "one identity is offline", which is a different operator
    action. Rather than redefine `status()`, the per-identity view is its own
    accessor, and `status()` now documents the assumption it makes.
- **Behavioural change to `drain_once`, called out per R3.6:** it now **skips**
  entries with `via` set, leaving them to `drain_once_via`. No consumer is affected
  today — `via` is new and defaults to `None`, so every existing entry is still
  claimed by `drain_once` exactly as before — but a consumer that starts setting
  `via` must run a `_via` drain for those entries or they will sit queued until
  their delivery window settles them.
- `OutboxEntry` gains a field. `#[serde(default)]` keeps entries persisted by
  earlier versions loading (as unbound), and every known consumer constructs via
  `OutboxEntry::new`, so no `OutboxStore` implementation needs changing.

## [0.1.11] - 2026-07-18

- Add **`MessagingService::request_via(transport_id, …)`** — a correlated
  request/reply over a **specific** installed transport instead of the primary.
  The reply is awaited on the same merged inbound dispatcher (matched by thread
  id), so a service can round-trip-prove a **secondary** transport — e.g.
  trust-ping the VTA via a newly-added-but-not-yet-promoted mediator and await
  the pong — **before** `promote`ing it. `request` is refactored to share the
  same `request_over` core; behaviour unchanged. Additive; 1 new test (45 total).

## [0.1.10] - 2026-07-18

- **`MessagingService` is now multi-transport.** It holds N transports with
  runtime `add_transport` / `remove_transport` / `promote`, so a service (the
  VTA) can run its mediator lifecycle — migrate / rollback / drain — over the
  delivery layer instead of the framework's dynamic multi-listener model.
  - Every transport's `inbound()` is merged into the one dispatcher (each item
    tagged with its source transport); the dispatcher acks via the **source**
    transport, so a drained/removed mediator's in-flight messages still settle.
  - Outbound (`send` / `request` / the drain / receipt emit) routes to the
    **primary** transport; `primary_handle()` returns a `MessageTransport` that
    always follows the current primary, so `drain_loop(store, svc.primary_handle(),
    …)` survives a `promote`.
  - `status()` aggregates: `Connected` (primary + all up), `Degraded` (primary up,
    a secondary down — new `MessagingStatus::Degraded` unit variant), or
    `Disconnected` (no primary, or primary down).
  - **Fully backward-compatible**: `new` / `with_receipts` are unchanged (they
    install a single `"default"` primary) and stay non-async; all existing
    behaviour and tests are preserved. Additive; 6 new tests (44 total).

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
