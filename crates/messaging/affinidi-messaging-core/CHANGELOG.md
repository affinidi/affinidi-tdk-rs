# Affinidi Messaging Core Changelog

## Unreleased

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
