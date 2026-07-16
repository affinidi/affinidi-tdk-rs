# Affinidi Messaging Core Changelog

## 16th July 2026

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
