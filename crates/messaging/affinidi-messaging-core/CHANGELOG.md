# Affinidi Messaging Core Changelog

## Unreleased
### 0.1.11 — a transport can say why a message left the outbox

`MessageTransport::outbox_status(hop_ids)` reports where each sent message
stands at the sender's mediator, as an `OutboxStatus`: `Queued`, `Delivered`
(handed over, not yet removed), `Collected` (removed by the recipient),
`Withdrawn` (by the sender), `Discarded` (by the mediator — expired, or the
account removed) or `Unknown`. It defaults to `Ok(None)`, so existing
transports are unaffected.

`outbox_message_ids` could only say a message had gone, and a message goes the
same way whether its recipient took it or the mediator expired it — so a
delivery layer inferring pickup from it read expiries as deliveries, and never
saw a recipient that collected before its first poll. Who removed the message
is what separates delivery from loss, and this is how a transport reports it.
See affinidi-tdk-rs#896.

### 0.1.10 — `reply_expected` means an answer is still owed

Documentation only. `InboundKind::RelationshipControl::reply_expected` is
`true` when a TSP §7.3 answer to a cancellation is still owed by the consumer
— a transport that sends the answer itself reports `false` once it has — and
`thread_digest` on a cancellation is the relationship digest it named.

### 0.1.9 — a queue-full refusal is a distinguishable thing

`MessagingError::queue_full()` and `HttpStatusError::queue_full()` return which
of the mediator's three queue-depth gates refused a send, as a `QueueFullGate`
(`Peer` / `Sender` / `Recipient`). `MessagingError::retry_after()` exposes the
server's pacing hint alongside it.

Until now a queue-full `503` was indistinguishable from any other transport
failure, so every caller treated it as one: retry *this message* with backoff.
That is wrong twice over. The message is fine and the wire is fine — nothing
will succeed until the destination's queue drains — and doing it per message
means a peer holding fifty undelivered messages costs fifty pointless sends per
drain, against a mediator that is refusing precisely because it is already
holding too much.

The three gates are an enum rather than a boolean because they mean different
things to a sender: `Peer` is one relationship backing up and every other
destination still works, while `Sender` is the sender's own ceiling and
*everything* it sends is refused until its queue drains.

Recognised from the problem-report code in the body, not from the status alone
— a `503` could be anything — and matched on the code's suffix so the DIDComm
`e.p.` prefix is not part of the contract a client has to reproduce. Both the
mediator's wrapper shape and a bare problem report are accepted. It is
deliberately **not** a substring search: this decides whether to stop sending to
a destination, and prose that merely quotes a gate name must not trigger it.

Additive: new methods and a new type, nothing removed or changed.

### 0.1.8 — an `Inbound` says whether it is traffic or a request about the relationship

`Inbound` gains `kind: InboundKind`, distinguishing application data from a
request *about* the relationship carrying it (TSP Rev 3 §7.2 — an invite,
accept or cancel). `Inbound` becomes `#[non_exhaustive]` and is built through
`Inbound::new(..).with_kind(..)`.

Why a transport-level type has to say this: §7.2.2 makes an endpoint drop an
application message from a VID it holds no relationship with, so the control
exchange is a precondition of all traffic. Without the field a transport is
left making an authorization decision it has no standing to make — **recording**
an inbound control message is framework behaviour and admits everything that
follows, while **answering** it depends on an ACL the transport cannot see.

`InboundKind::RelationshipControl` carries `thread_digest` because
`accept_relationship` and `cancel_relationship` both require it and nothing on
the recorded relationship stores it — without it a consumer can decide what to
do and have no way to say it. It carries `introduces` for a §7.2.5 referral,
read only after the signature is verified.

`InboundKind` defaults to `Application`: defaulting the other way would make
every existing transport's messages look like control and route none of them.

**Semver note (R3.6).** This is breaking for any consumer that constructs or
exhaustively destructures `Inbound`, and it ships as a **patch** for the same
reason 0.1.6 did — and the reason is now load-bearing rather than theoretical.
`affinidi-messaging-core` is redirected through the workspace
`[patch.crates-io]`, and the external `vta-sdk` 0.40.0 requires `^0.1`. A minor
bump would stop the redirect applying and pull the registry copy back into the
graph — precisely the duplicate PR #811 had just removed, at the end of a
four-release cycle.

The blast radius was checked rather than assumed. `vta-sdk` 0.40.0 is the only
external consumer in the graph; it holds `Inbound` as `BoxStream<'static,
Inbound>` and reads fields, constructing none and destructuring none, so
neither the new field nor `#[non_exhaustive]` reaches it. Its TSP pump already
skips a frame that is not a binding envelope — its own comment names "TSP
control frames" as a case — so the control messages now surfaced are skipped
there exactly as they were never delivered before.

### 0.1.7 — `HttpStatusError`, and `MessagingError::HttpStatus`

A transport's HTTP failure reached a `MessagingService` caller as
`MessagingError::Transport(String)`, so a mediator `429` — and which service
sent it, and when to retry — was text.

- **Added `HttpStatusError`** (`affinidi_messaging_core::HttpStatusError`),
  moved here from `affinidi-messaging-sdk` 0.26.2 unchanged in shape
  (`#[non_exhaustive]`; `context`, `url`, `status`, `rate_limit_source`,
  `retry_after_secs`, `body`; `new` / `from_parts` / `with_url` /
  `is_rate_limited` / `retry_after`). It lives in this dependency-light crate so
  `affinidi-did-authentication`, the SDK and `MessagingError` share one type —
  the SDK depends on both of the others, so neither could depend on it. The SDK
  re-exports it at its old path.
- **Added `HttpStatusError::with_context`.**
- **`Retry-After` as an HTTP-date is now parsed** (RFC 9110 §10.2.3), into
  seconds from now; a date already past is `0`. Previously only delta-seconds
  were read and an HTTP-date left `retry_after_secs` `None`.
- **Added `MessagingError::HttpStatus(Box<HttpStatusError>)`**, with
  `MessagingError::http_status()` / `is_rate_limited()` and
  `From<HttpStatusError>`. Additive: `MessagingError` is `#[non_exhaustive]`.
  Every other transport failure is still `MessagingError::Transport`.
- New dependencies: `serde_json` (the rate-limit contract body) and `httpdate`
  (already in any graph that makes an HTTP call, via hyper).

## 8th August 2026

### 0.1.6 — `Protocol::DIDCommV1`, and `Protocol` is now `#[non_exhaustive]`

Add `Protocol::DIDCommV1` for the new `affinidi-messaging-didcomm-v1` crate, so
a consumer holding a `dyn MessagingProtocol` can tell DIDComm v1 apart from
DIDComm v2.1. The two share no wire format, no algorithms and no identifier
scheme, so folding v1 into the existing `DIDComm` variant would have made
inbound routing undecidable.

`Protocol` also gains `#[non_exhaustive]`, so future protocols are additive.

**Semver note (R3.6).** Both changes are, strictly, breaking for any consumer
that matches `Protocol` exhaustively — yet this ships as a **patch**. That is
deliberate: `affinidi-messaging-core` is redirected through the workspace
`[patch.crates-io]`, and the external `vta-sdk` pins `"0.1"`, so a minor bump
would break the redirect and put two copies of these types in the graph (the
trap that produced PRs #629/#630). The blast radius was checked rather than
assumed: no in-tree crate matches `Protocol` at all, and `vta-sdk` 0.21.6 uses
it only in two equality comparisons against `Protocol::TSP`. Any consumer that
does match exhaustively needs a `_ =>` arm.


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
