# Affinidi Status List Changelog

## Unreleased (0.1.7) — IETF Token Status List

Additive: a new `token` module and three new `StatusListError` variants
(the enum is `#[non_exhaustive]`). Nothing existing changes.

- **`TokenStatusList`** — `draft-ietf-oauth-status-list-21` §4: entries 1, 2,
  4 or 8 bits wide, packed least-significant-bit first, ZLIB-compressed and
  base64url-encoded as `{ bits, lst }`. Decoding is capped
  (`DEFAULT_MAX_LIST_BYTES`, 16 MiB; `decode_with_limit` to choose), so a
  small `lst` cannot inflate without bound. An index past the end is an
  error, never a default. Decodes both of the draft's worked examples.
- **`TokenStatus`** — the §7 registry: `Valid`, `Invalid`, `Suspended`,
  `ApplicationSpecific(0x03 | 0x0C..=0x0F)`, and `Reserved(_)` for values
  this implementation cannot interpret.
- **`StatusListReference`** — a Referenced Token's `status.status_list`
  (`idx`, `uri`), read strictly: a negative, fractional or string `idx` is
  refused.
- **`VerifiedStatusListToken::verify`** — checks a `statuslist+jwt` in the
  §8.3 order. The signature is verified **first**, by a caller-supplied
  closure that returns the payload only after verifying it (key resolution is
  the caller's). Then `typ` (compared per RFC 7515 §4.1.9), `sub` equals the
  referenced `uri`, `iat` not in the future, `exp` not passed (with
  leeway), and the list decodes under the cap. Only the verified type answers
  `status_of`; the verified header and `iss` are exposed so the caller can
  bind the list's signer to the Referenced Token's issuer.
- **`status_list_token_payload`** — the payload a Status Issuer signs.

The CWT form (`statuslist+cwt`) is not implemented.

## Unreleased (0.1.6) — `rand` 0.10

No behaviour change and no public API change: this is a private dependencies here.
Verified by the crate's test suite.

## Unreleased (0.1.5) — dependency refresh

- Bumps `base64` 0.22 → 0.23.
- No source or API change; the bumps are declaration-only and the crate
  compiles unmodified against them. Bumped workspace-wide in the same
  change so no two versions of these crates are compiled side by side.

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
