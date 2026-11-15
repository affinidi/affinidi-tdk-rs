# did:example

## Changelog history

## [0.5.9] - 2026-07-19

affinidi-did-common 0.4

- Bumped the `affinidi-did-common` requirement from `"0.3"` to `"0.4"`.
  No functional change to this crate: `Document` gained a typed
  `also_known_as` field, which is additive.

## [0.5.8] - 2026-06-14

non_exhaustive DidExampleError (W7 sweep)

- `DidExampleError` is now `#[non_exhaustive]` (ADR-0003) so new variants land
  additively. Patch bump keeps the `0.5` pin valid; consumers that `match` it
  must add a `_` wildcard arm. No behaviour change.
