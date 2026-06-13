# Affinidi TDK Test Support

## Changelog history

## 13th June 2026

### 0.2.0 — did:web/webvh mock server + StaticResolver (TI2)

- `did_web::MockDidWebServer`: an in-process HTTP origin (ephemeral `127.0.0.1`
  port) serving `did.json` / `did.jsonl` (+ witness) with fault injection
  (`Delay`, `Hang`, `Status`, `Garbage`, `Oversize`) and per-path request
  counts. `webvh_authority()` yields `localhost%3A<port>` for minting
  `did:webvh` DIDs that resolve over HTTP.
- `resolver::StaticResolver`: a deterministic, fault-injecting `AsyncResolver`
  with per-DID outcomes (`Resolves`, `Fails`, `NotHandled`, `Delays`, `Hangs`)
  and a recorded call log for cache-stampede / dedup assertions.
- Unblocks the W1/W2/W3 cache-server/SDK hardening regression tests.

### 0.1.0 — scaffold (TI0)

- New `affinidi-tdk-test-support` crate: the shared home for cross-cutting,
  in-process integration-test fixtures across the TDK workspace, complementing
  the mediator-specific `affinidi-messaging-test-mediator`.
- Scaffold only — `publish = false`, no fixtures yet. Establishes the crate, its
  workspace membership, and CI coverage so each TI-series harness lands as a
  thin, self-contained PR. First fixture (the did:web mock server) arrives in
  TI2.
