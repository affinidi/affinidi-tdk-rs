# did:example

## Changelog history

## 14th June 2026

### 0.5.8 — non_exhaustive DidExampleError (W7 sweep)

- `DidExampleError` is now `#[non_exhaustive]` (ADR-0003) so new variants land
  additively. Patch bump keeps the `0.5` pin valid; consumers that `match` it
  must add a `_` wildcard arm. No behaviour change.
