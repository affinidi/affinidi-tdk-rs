# Affinidi OpenID4VP Changelog

## 14th June 2026 Release 0.1.3

- `Oid4vpError` is now `#[non_exhaustive]` (ADR-0003) so new variants land
  additively. Patch bump keeps the `0.1` pin valid; consumers that `match` it
  must add a `_` wildcard arm. No behaviour change. (W7 sweep)
