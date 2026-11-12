# Affinidi BBS

## 0.4.1 — proof verification rejects identity points and zero scalars

Proof verification now rejects a proof whose `Abar`, `Bbar` or `D` is the G1
identity point, returning `BbsError::InvalidProof`. draft-irtf-cfrg-bbs-signatures-10
§4.2.4.5 (`octets_to_proof`, step 7) requires this: each of the three points
must be a valid G1 subgroup point other than `Identity_G1`. Earlier versions
checked only curve and subgroup membership for these points, so such a proof
reached the challenge and pairing checks, which do not by themselves exclude
it. This applies to `proof_verify`, `core_proof_verify`, the pseudonym and
blind/nym proof verifiers, and the `bbs-2023` derived-proof verifiers in
`affinidi-data-integrity` that call them.

- New `generators::nonidentity_point_from_bytes`: `point_from_bytes` plus the
  identity check, for points read from a proof. `point_from_bytes` is
  unchanged.

Proof verification also rejects a proof containing a zero scalar (`e^`, `r1^`,
`r3^`, any `m^_j`, or the challenge) with `BbsError::InvalidProof`, per
§4.2.4.5 step 14 ("if s_j = 0 or if s_j >= r, return INVALID"). Only the
challenge was checked for zero before.

Only proofs that are INVALID under the draft are affected; proofs from a
conforming prover never contain an identity point, and contain a zero scalar
only with negligible probability, so no compatible caller sees a change.

## Unreleased (0.4.0) — `bls12_381_plus` 0.9, `rand` 0.10

**Breaking:** `bls12_381_plus` 0.9 moves its primary curve stack to the
RustCrypto 0.14 generation (`elliptic-curve` / `ff` / `group` 0.14), so the
re-exported `Scalar` is a different type from 0.3's. Callers that name it must
move to `bls12_381_plus` 0.9 too.

Hash-to-curve still runs on the 0.13 `ExpandMsg` — 0.9 keeps that API on
`elliptic_curve_013` — so `ExpandMsgXmd` is now imported from
`bls12_381_plus::elliptic_curve_013::hash2curve`, and `sha2` stays on 0.10
because that `ExpandMsg` is typed over digest 0.10. Output is unchanged: the
IETF BBS test vectors pass.

`rand` 0.10: the per-proof and commitment RNGs seed `StdRng` from `SysRng`
(the renamed `OsRng`); scalars are drawn through `RngExt`.

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
