# Affinidi TDK Test Support

## Changelog history

## 13th June 2026

### 0.1.0 — scaffold (TI0)

- New `affinidi-tdk-test-support` crate: the shared home for cross-cutting,
  in-process integration-test fixtures across the TDK workspace, complementing
  the mediator-specific `affinidi-messaging-test-mediator`.
- Scaffold only — `publish = false`, no fixtures yet. Establishes the crate, its
  workspace membership, and CI coverage so each TI-series harness lands as a
  thin, self-contained PR. First fixture (the did:web mock server) arrives in
  TI2.
