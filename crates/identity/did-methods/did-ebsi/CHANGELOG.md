# did:ebsi

## Unreleased (0.1.5) — `rand` 0.10

No behaviour change: the identifier is still 16 bytes from the thread RNG.

rand 0.10 renamed the old `RngCore` to `Rng` and moved the sampling methods
onto a new `RngExt`, so `use rand::Rng` no longer brings `random()` into
scope — the import changes, the call does not.

## Changelog history

## 19th July 2026

### 0.1.4 — affinidi-did-common 0.4

- Bumped the `affinidi-did-common` requirement from `"0.3"` to `"0.4"`.
  No functional change to this crate: `Document` gained a typed
  `also_known_as` field, which is additive.

## 14th June 2026

### 0.1.3 — non_exhaustive EbsiError (W7 sweep)

- `EbsiError` is now `#[non_exhaustive]` (ADR-0003) so new variants land
  additively. Patch bump keeps the `0.1` pin valid; consumers that `match` it
  must add a `_` wildcard arm. No behaviour change.
