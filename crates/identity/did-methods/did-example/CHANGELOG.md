# did:example

## Changelog history

## 19th July 2026

### 0.5.9 — affinidi-did-common 0.4

- Bumped the `affinidi-did-common` requirement from `"0.3"` to `"0.4"`.
  No functional change to this crate: `Document` gained a typed
  `also_known_as` field, which is additive.

## 14th June 2026

### 0.5.8 — non_exhaustive DidExampleError (W7 sweep)

- `DidExampleError` is now `#[non_exhaustive]` (ADR-0003) so new variants land
  additively. Patch bump keeps the `0.5` pin valid; consumers that `match` it
  must add a `_` wildcard arm. No behaviour change.
