# Affinidi BBS

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
