# Affinidi CESR

## Changelog history

## 16th June 2026

### 0.1.3 — guard qb64 parsers against non-ASCII input

- `Matter::from_qb64`, `Counter::from_qb64`, and `Indexer::from_qb64` now
  reject non-ASCII input up front (returning `CesrError::InvalidCharacter`)
  instead of panicking. qb64 is base64url (pure ASCII); the parsers slice the
  input on byte offsets derived from character counts, so a multi-byte UTF-8
  character could land mid-slice and panic with "byte index N is not a char
  boundary". Hardening only — no production caller is affected (the wire path
  uses the binary `from_qb2`). Patch bump; no behaviour change for ASCII input.

## 14th June 2026

### 0.1.2 — non_exhaustive CesrError (W7 sweep)

- `CesrError` is now `#[non_exhaustive]` (ADR-0003) so new variants land
  additively. Patch bump keeps the `0.1` pin valid; consumers that `match` it
  must add a `_` wildcard arm. No behaviour change.
