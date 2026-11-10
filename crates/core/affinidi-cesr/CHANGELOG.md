# Affinidi CESR

## Changelog history

## 10th November 2026

### 0.1.4 — indexed signature codes as keripy reads them

A fix to match keripy and the CESR specification. No signature's bytes change,
and no public signature changes; what `Indexer::ondex()` reports does, and
`Indexer::new` refuses a small both-lists code with an ondex that differs from
its index. A caller that relied on the swapped reading must change.


- **Both lists and current only were swapped.** `A`, `C`, `E`, `0A`, `2A`,
  `2C`, `2E`, `3A` mean the signing key is in both the current and the prior
  next-key list; `B`, `D`, `F`, `0B`, `2B`, `2D`, `2F`, `3B` mean current only
  (keripy `IndexedBothSigCodex` / `IndexedCurrentSigCodex`). This crate read
  them the other way round. The bytes of a signature do not change; what
  changes is `Indexer::ondex()`: `Some(index)` for `A`, `None` for `B`, and the
  encoded ondex for a big both-lists code.
- **Big indexed signatures parse.** Indexer codes have their own code lengths
  (keripy `Indexer.Bards`: `0`–`4` start two-character codes), and
  `Indexer::from_qb64` used the primitive table's, where `2…` is four
  characters, so every `2A…` was an unknown code. New `tables::indexer_hardage`.
- **The ondex is read and written as keripy does** (`tables::indexer_other_size`,
  keripy `os`): a big both-lists code carries its own ondex; a current-only
  code's ondex characters must be zero; a small both-lists code carries none,
  so `Indexer::new` refuses an ondex that differs from the index
  (`CesrError::InvalidIndex`, new). A current-only code carries none: one
  given to `Indexer::new` is dropped, as before.
- **Ed448 sizes** follow keripy: `0A`/`0B` are 156 characters, `3A`/`3B` 160.
- New `Indexer::is_current_only`, `tables::indexer_is_current_only`.

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
