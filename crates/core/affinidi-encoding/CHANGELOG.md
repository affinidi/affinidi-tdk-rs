# Affinidi Encoding Changelog

## [0.1.8] - 2026-11-15

Workspace lint and dependency housekeeping. No API or behaviour change.

- Dependency versions now come from the root `[workspace.dependencies]`
  for the external crates shared by five or more workspace members
  (#1070). The published manifest still names concrete requirements; the
  resolved dependency graph and every feature selection are unchanged.
- Workspace lints now include `unsafe_code = "deny"` (#1064).
- Minimum dependency requirements raised to versions already in use across the
  workspace (no new major/minor, Cargo.lock unchanged): `zeroize` 1 -> 1.8.
- `MultiEncoded::new` and `MultiEncodedBuf::as_multi_encoded` (the two
  `#[repr(transparent)]` slice casts) carry a scoped `#[allow(unsafe_code)]`
  beside their existing SAFETY comments. No code change.

## [0.1.7] - 2026-11-15

one checked multikey / did:key decoder

Additive (#1056).

- **Added:** `decode_multikey_checked(key) -> Result<(Codec, Vec<u8>)>`
  decodes a base58btc multikey and enforces `Codec::expected_key_length`
  (EC keys in compressed SEC1 form); an unknown codec is returned as
  `Codec::Unknown` without a length check. `decode_multikey_expecting(key,
  codec)` also requires one codec. `decode_multikey` and
  `decode_multikey_with_codec` are unchanged and still do no length check.
- **Added:** `did_key` module: `did_key::decode`, `did_key::decode_expecting`,
  `did_key::encode` and `DID_KEY_PREFIX`. Bare DIDs only: strip a `#fragment`
  first.
- **Added:** `EncodingError::InvalidKeyLength`, `UnexpectedCodec` and
  `InvalidDidKey` (the enum is `#[non_exhaustive]`).
- **Added:** the post-quantum codec constants (`ML_DSA_*_PUB`,
  `ML_DSA_*_PRIV_SEED`, `SLH_DSA_SHA2_128S_PUB`) are re-exported from the
  crate root, like the classical ones.
- **Fixed:** `MultiEncodedBuf::into_bytes` moves the buffer out instead of
  cloning it.
- Docs: `MultiEncoded`'s `Zeroize`/`ZeroizeOnDrop` derives never run (it is
  only held by reference). They are kept, because removing a trait impl would
  be a breaking change.


## [0.1.6] - 2026-09-15

the post-quantum code points are now pinned, not trusted

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

## [0.1.5] - 2026-06-14

- **SEMVER:** `EncodingError` is now `#[non_exhaustive]` (ADR-0003), so new
  variants land additively. Patch bump keeps the `0.1` pin valid; consumers that
  `match` it must add a `_` wildcard arm. No behaviour change.

## [0.1.3] - 2026-04-18

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

## [0.1.1] - 2026-02-01

prior releases

(No CHANGELOG recorded for earlier 0.1.x releases.)
