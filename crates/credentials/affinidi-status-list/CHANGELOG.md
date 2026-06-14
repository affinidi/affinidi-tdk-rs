# Affinidi Status List Changelog

## 14th June 2026 Release 0.1.4

- `StatusListError` is now `#[non_exhaustive]` (ADR-0003) so new variants land
  additively. Patch bump keeps the `0.1` pin valid; consumers that `match` it
  must add a `_` wildcard arm. No behaviour change. (W7 sweep)

## 1st June 2026 Release 0.1.3

### Fixed

- **Decoy entries could collide, undercounting distinct set bits.**
  `BitstringStatusList::add_decoys()` checked `!assigned[index]` before
  placing a decoy but never marked the chosen index as assigned, and
  `set()` likewise left `assigned` untouched. Two decoys (or a decoy and
  a `set()` entry) could therefore land on the same index — each passing
  the check, re-setting an already-set bit, and still counting toward the
  total — so `add_decoys(N)` sometimes set fewer than `N` distinct bits.
  This also made the `decoy_entries` test flaky (~6–7%, a birthday
  collision) and surfaced as an unrelated CI failure. Both `add_decoys`
  and `set` now reserve the index in `assigned`, making it the single
  authority for which slots are free. Added a 500-round regression test.

## 28th May 2026 Release 0.1.2

### Security

- **HIGH — gzip-bomb DoS closed.** `BitstringStatusList::decode()` ran
  `GzDecoder::read_to_end()` on the attacker-supplied `encodedList` with
  no output limit. A few KB of crafted gzip can expand to gigabytes of
  zeros, OOMing any verifier that checks a credential's revocation
  status against a hostile status-list issuer. The decode path already
  knows exactly how many bytes it needs (`size.div_ceil(8)`), so the
  decoder is now wrapped in `.take(expected + 1)` and the existing
  length-check / truncate logic handles the rest. No change to the
  successful-decode path.
