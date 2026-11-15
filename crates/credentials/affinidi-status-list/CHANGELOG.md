# Affinidi Status List Changelog

## Unreleased (0.2.0) — issuer allocation state split out; multibase `encodedList`; all W3C status purposes

Breaking (R3.6): API and wire changes. Coordinate with every service that
publishes or fetches Bitstring Status List credentials.

- **Wire change — `encodedList` (#1059):** `BitstringStatusList::encode` now
  emits the multibase form W3C Bitstring Status List v1.0 requires: `u` +
  base64url (no padding) of the GZIP stream (`uH4sI...`). `decode` accepts
  that form and, for lists written by earlier versions, bare base64url (a
  GZIP stream's base64url always starts with `H`, so the two cannot be
  confused); any other multibase prefix is refused with a clear `Encoding`
  error. **Consumer note:** a verifier still on 0.1.x cannot decode a list
  issued by 0.2 (its decoder sees the extra `u`). Upgrade verifiers before,
  or together with, issuers.
- **`StatusPurpose` (#1059):** gains `Refresh`, `Message` and `Other(String)`
  and is `#[non_exhaustive]`, so a `BitstringStatusListEntry` with
  `statusPurpose: "refresh"`, `"message"` or an unknown value now parses
  instead of failing. It is no longer `Copy` (it is `Clone`), and has
  `as_str`, `From<&str>`, `From<String>` and `FromStr`. Wire values are
  unchanged for `revocation` / `suspension`.
- **Issuer allocation state (#1058):** new `StatusListAllocator` holds which
  indices have been handed out (a bitset plus a free count) and is
  `Serialize`/`Deserialize` (`{ "size", "assigned": <base64url bitset> }`,
  validated on load). **Persist it next to the list:** a `0` bit is the same
  for "free" and "issued to a valid credential", so an issuer that reloads
  only the encoded list can hand an index out twice, and revoking either
  credential then revokes both. `StatusListAllocator::from_list` recovers what
  a list alone can tell (set bits are reserved).
  - `allocate_index` moved from `BitstringStatusList` to the allocator. It is
    rejection sampling while at least a quarter of the list is free, falling
    back to a uniform pick by scanning the bitset — no per-call allocation (it
    used to build a ~1 MB `Vec` of free indices on every call at the default
    size) and still uniformly random.
  - `add_decoys` moved to `StatusListAllocator::add_decoys(&mut list, count)
    -> Result<usize>`: capped at the free count (returns how many were added)
    instead of looping forever when `count` exceeded the free slots, no panic
    on a size-0 list, and an error if the list is a different size.
  - `reserve(index)` records an index chosen by hand; `BitstringStatusList::set`
    no longer touches assignment state.
- **`BitstringStatusList`** is now the list only (bits, size, purpose), and
  `decode` no longer allocates a per-entry `Vec<bool>` (8x the list) for
  verifier-side use. It derives `PartialEq`/`Eq`.
- **Added (#1057):** `oid4vc` feature —
  `VerifiedStatusListToken::verify_with_jws_verifier` checks a Status List
  Token's signature with `affinidi-oid4vc-core`'s raw-bytes `JwtVerifier`
  (`Es256Verifier`, `EdDsaVerifier`, ...) under an algorithm allowlist, the
  same trait the OID4VC crates use. The closure-based `verify` is unchanged.

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
