# Affinidi BBS

## Unreleased (0.3.3) — take the curve stack from `bls12_381_plus`'s re-exports

No behaviour change. `elliptic-curve`, `ff` and `group` are no longer declared
here; the types come from `bls12_381_plus::{elliptic_curve, ff, group}` instead.

This is not tidying. `bls12_381_plus` deliberately links **both** RustCrypto
generations — its `groups` feature is `["group_013", "group"]` and cannot be
narrowed — and its public API (`G1Projective::hash`) takes the **0.13**
`ExpandMsg`. Declaring our own copies meant pinning a generation by hand and
hoping it matched the one that crate's functions expect; a bump on either side
produced a trait-mismatch error naming neither crate, which is exactly what
happened while scoping #775.

Taking the types from the crate whose functions consume them makes the match
structural rather than coincidental, and removes three declarations that
`cargo outdated` will otherwise keep flagging as stale for as long as
`bls12_381_plus` stays on the older generation.

82 tests green, plus the 92 in `affinidi-data-integrity` that consume this.

## Changelog history

## 13th June 2026

### 0.3.1 — DoS-bound generator creation + explicit CSPRNG (W4)

- **Bounded generator creation.** On the verify path the generator/message
  count is derived from the *untrusted* proof length; an oversized bogus proof
  would force `create_generators` to do unbounded `O(n)` hash-to-curve work.
  `create_generators_with_api_id` now rejects counts above the new
  `MAX_GENERATORS` (1024) cap **before** the loop, so a multi-megabyte proof is
  rejected cheaply with `BbsError::InvalidProof`. No legitimate signing
  approaches the cap.
- **Explicit CSPRNG.** Proof-blinding and commitment scalars are now drawn from
  an OS-seeded `StdRng` (`StdRng::try_from_rng(&mut OsRng)`) instead of the
  thread-local RNG, and the CSPRNG contract is documented at each site.
- Adds adversarial-input tests (a ~4 MB proof is rejected fast) and a
  generator-cap boundary test.
