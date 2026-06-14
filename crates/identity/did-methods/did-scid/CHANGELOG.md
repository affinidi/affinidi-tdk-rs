# did:scid

## Changelog history

## 14th June 2026

### 0.1.9 — non_exhaustive DIDSCIDError (W7 sweep)

- `DIDSCIDError` is now `#[non_exhaustive]` (ADR-0003) so new variants land
  additively. Patch bump keeps the `0.1` pin valid; consumers that `match` it
  must add a `_` wildcard arm. No behaviour change.
