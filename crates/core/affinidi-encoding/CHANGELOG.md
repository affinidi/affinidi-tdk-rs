# Affinidi Encoding Changelog

## Unreleased (0.1.6) — the post-quantum code points are now pinned, not trusted

No behaviour change: a test and a comment. Every value was already correct.

The seven PQC constants were carried with a comment saying they came from the
official table, and no record of when that was last true. All seven are `draft`
status upstream, which means they may legitimately move — and a moved code point
does not fail loudly. It produces `did:key`s and multikeys this workspace reads
back perfectly and nobody else can resolve, found by an interop partner months
later rather than by CI.

`pqc_code_points_match_the_multicodec_registry` now asserts each value, each
FIPS key length, and the `from_u64`/`to_u64` round trip, and names the revision
checked: `table.csv` at `38e3bf3e38f613679d76ef2041d73a8060f8622a`, verified
2026-09-15. All seven matched.

`slh_dsa_has_no_private_code_point_to_hold` records the other half — the
registry carries twelve `slhdsa-*-pub` rows and no `slhdsa-*-priv` of any
parameter set, so SLH-DSA secrets stay memory-only. It exists to stop that gap
being closed from this side by picking an unused number, which round-trips
in-workspace and is unreadable everywhere else.

## 14th June 2026 (0.1.5)

- **SEMVER:** `EncodingError` is now `#[non_exhaustive]` (ADR-0003), so new
  variants land additively. Patch bump keeps the `0.1` pin valid; consumers that
  `match` it must add a `_` wildcard arm. No behaviour change.

## 18th April 2026 (0.1.3)

- **FEATURE:** Added post-quantum multicodec constants aligned with the
  official multicodec registry (all currently `draft`):
  - `ML_DSA_44_PUB` (`0x1210`), `ML_DSA_65_PUB` (`0x1211`),
    `ML_DSA_87_PUB` (`0x1212`)
  - `ML_DSA_44_PRIV_SEED` (`0x131a`), `ML_DSA_65_PRIV_SEED` (`0x131b`),
    `ML_DSA_87_PRIV_SEED` (`0x131c`) — 32-byte seed representation
  - `SLH_DSA_SHA2_128S_PUB` (`0x1220`)

  SLH-DSA has no registered private-key multicodec, so we do not ship
  one. The matching `Codec` enum variants are gated on `ml-dsa` /
  `slh-dsa` feature availability in consumer crates.
- **SAFETY:** `MultiEncoded` is now `#[repr(transparent)]`. Unsafe
  transmutes in `MultiEncoded::new` and `MultiEncodedBuf::as_multi_encoded`
  carry `// SAFETY:` comments documenting the layout guarantee and
  varint-prefix validation invariant.
- **TESTS:** Existing round-trip test now covers all new codecs via
  byte-level varint-prefix assertions (in downstream
  `affinidi-secrets-resolver` tests).

## 0.1.1 — prior releases

(No CHANGELOG recorded for earlier 0.1.x releases.)
