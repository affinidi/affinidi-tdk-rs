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

End-to-end delivery **confirmation** (`Sent → Delivered`) comes from three
sources:

- **Delivery receipts** (`messaging/receipt/0.1`). A sender asks for one by
  stamping the entry's idempotency key as the binding's delivery id (DIDComm
  `delivery_id` header, TSP envelope `deliveryId`). A `MessagingService` built
  `with_receipts` sends one for each message that asks, and every service
  settles an entry on a receipt from that entry's recipient. The earlier
  `https://affinidi.com/delivery/1.0/receipt` body is still read.
- **Protocol replies** in the thread of a sent message.
- **Mediator status** (`messaging/message/status`), only for an entry whose
  recipient shares the sender's mediator (`DeliveryScope::Local`). A
  `Relayed` entry is never polled: the sender's mediator relayed it away and
  cannot answer for it.

When the window closes with no evidence, a relayed entry whose recipient is
not known to send receipts (`ReceiptReach`) settles `Unconfirmed` with
`UnconfirmedReason::NoEvidencePath` and is not escalated; every other entry
goes through the `ExpiryEscalator`.
