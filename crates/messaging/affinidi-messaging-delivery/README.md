# affinidi-messaging-delivery

The reliable **messaging delivery layer** for the Affinidi messaging stack. It
sits just above the transports (`MessageTransport` in `affinidi-messaging-core`)
and turns "truthful send" into effectively-once delivery for delivery-critical
traffic, independent of the wire (DIDComm, TSP, REST).

This first increment provides the **durable outbox** and its **drain loop**:

- `OutboxEntry` — a transport-independent unit of delivery-critical work, keyed
  by an idempotency key, with a lifecycle `Queued → Sent → Delivered |
  Unconfirmed | Failed`.
- `OutboxStore` — the storage abstraction (an in-memory store ships here;
  services back it with a durable store, e.g. fjall).
- `drain_once` / `drain_loop` — pick due entries, send them over a
  `MessageTransport`, mark `Sent` on hop-acceptance (and **stop re-sending** —
  the mediator owns redelivery), or retry with exponential backoff on failure.

End-to-end delivery **confirmation** (`Sent → Delivered`, the §5a layer-receipt /
protocol-reply / outbox-drain / escalate logic) and the `MessagingService`
front-end (`send` / `request` / `subscribe` / `status`) build on this in
subsequent increments.
