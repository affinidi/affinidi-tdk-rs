# BBS / vc-di-bbs — Security Audit Readiness

Status: **pre-audit**. Tracking issue: #363.

This document scopes the proof-bearing BBS cryptography in this workspace for an
external security audit: what it is, the trust model, what already gives
assurance, the findings of an internal self-review (and their resolution), and
the open questions we want an auditor to focus on.

> **Production gate.** None of this crypto should back real credentials until the
> external audit completes. The implementation is conformance-tested but
> un-audited.

## 1. Scope

In-house implementation of:

- **BBS signatures** over BLS12-381 — `draft-irtf-cfrg-bbs-signatures`
- **Blind BBS** — `draft-irtf-cfrg-bbs-blind-signatures`
- **Per-verifier pseudonyms / holder binding** — `draft-irtf-cfrg-bbs-per-verifier-linkability`
- The **W3C vc-di-bbs `bbs-2023`** document cryptosuite that wraps the above

| Crate | Path | Role | Audit priority |
|---|---|---|---|
| `affinidi-bbs` | `crates/core/affinidi-bbs` | BBS primitives: keygen, sign/verify, ProofGen/Verify, blind, nym/pseudonym | **Highest** (proof-bearing) |
| `affinidi-rdf-encoding` | `crates/credentials/affinidi-rdf-encoding` | RDF Dataset Canonicalization (RDFC-1.0), JSON-LD expansion → the bytes that get signed/hashed | High (canon correctness ⇒ what is signed) |
| `affinidi-data-integrity` | `crates/credentials/affinidi-data-integrity` | vc-di-bbs `bbs-2023` framing: proofHash, HMAC label map, grouping, CBOR `proofValue` | Medium (composition / encoding) |

Dependencies (crypto-relevant): `bls12_381_plus` (scalar/point arithmetic,
`subtle` constant-time), `rand` (CSPRNG), `zeroize`, `sha2`, `ciborium`,
`multibase`, `hmac`.

The legacy `affinidi_data_integrity::bbs_2023` module is **deprecated** and
out of scope (it is being removed; not interoperable, no production use).

## 2. Trust model

**Assets**
- Issuer BBS **secret key** (`SecretKey`) — forges credentials if leaked.
- Holder **`nym_secret`** / `prover_nym` / `secret_prover_blind` — durable holder
  secrets; leak enables impersonation and cross-verifier linkage.
- Per-proof **nonces / blindings** — reuse or predictability breaks
  unforgeability / unlinkability.

**Adversaries**
- A malicious **holder** crafting a derived proof to (a) prove undisclosed
  attributes, (b) forge without a valid signature, or (c) DoS the verifier with
  malformed input.
- A malicious **verifier** (or colluding verifiers) attempting to learn
  undisclosed attributes or link a holder across presentations.
- A network attacker submitting **arbitrary bytes** to any deserialization /
  verify entry point.

**Security goals**
- Unforgeability (EUF-CMA) of signatures and derived proofs.
- Selective-disclosure soundness (verifier learns nothing about undisclosed
  messages) and proof unlinkability.
- Per-verifier pseudonym: stable per `context_id`, unlinkable across, and bound
  so a proof can't be replayed against a different verifier.
- No panics / DoS on attacker-controlled input (verify must return `Result`).

**Out of scope / assumed**
- BLS12-381 field/group arithmetic and pairing in `bls12_381_plus` (assumed
  correct + constant-time; we rely on its `from_compressed` subgroup checks).
- The hardness assumptions of BBS (q-SDH / generalized) and the security of the
  IETF drafts themselves.
- Key management / storage outside the process; side channels below the Rust
  abstraction (cache, speculative execution).

## 3. What gives assurance today

- **Byte-exact conformance.** Every primitive is KAT-gated against the official
  IETF/DIF and W3C `vc-di-bbs` test vectors — signature reproduction, proof
  reproduction, blind commit/sign, pseudonym commit/sign/proof, and the full
  vc-di-bbs document flow (issuer/holder/verifier, plain + pseudonym). Our
  verifier accepts the W3C reference derived proofs byte-for-byte and vice versa.
- **Deserialization validation.** All G1/G2 points go through
  `from_compressed` (on-curve **and** prime-order subgroup `is_torsion_free`
  check, confirmed in `bls12_381_plus 0.8.18`); all scalars through
  `from_be_bytes` (rejects `>= r`, constant-time). Identity points are rejected
  for `PublicKey`, `Signature.A`, `Pseudonym`, and blind commitments.
  `point_from_bytes` carries a comment forbidding `from_compressed_unchecked`.
- **Issuer secret handling.** `SK` bytes hashed into `e` are zeroized; the
  `SK + e` intermediate is zeroized before the invertibility branch; `SecretKey`
  has a redacting `Debug` and a volatile-write `Drop` (now with a `compiler_fence`).
- **CSPRNG.** `rand::rng()` (`ThreadRng`, ChaCha-based, OS-seeded) — not
  seedable/predictable. Deterministic mocked scalars are strictly `#[cfg(test)]`.
- **Domain separation + transcript binding.** Distinct `api_id`s for
  core / blind / pseudonym / blind-generators. The Fiat-Shamir transcript binds
  `R`, the disclosed `(index, message)` pairs, `Abar/Bbar/D/T1/T2`, the pseudonym
  triple `(Pseudonym, OP, Ut)`, the `domain` (binding `PK`, generator count, all
  generators, `api_id`, length-prefixed header), and the length-prefixed
  presentation header. A test confirms a pseudonym proof does not verify as a
  plain proof (binding terms are non-strippable).

## 4. Internal self-review — findings & resolution

A focused crypto review was performed over `affinidi-bbs`. Two **High**
(remotely-triggerable verifier panics / DoS) were reproduced with live tests and
**fixed** in this change; lower findings are fixed or tracked below.

| # | Sev | Finding | Status |
|---|---|---|---|
| 1 | High | Verifier panic on out-of-bounds / duplicate disclosed index (`proof_verify_core` indexed `h_generators`/`disclosed_scalars` without validating the verifier-supplied indexes). | **Fixed** — bounds + duplicate + count validation mirrored into the verify path. Regression tests added. |
| 2 | High | Pseudonym verifier integer-underflow + OOB on a degenerate `L=0/U=0` proof (`l - 1`, `m_hats[u-1]`). | **Fixed** — `l == 0 / u == 0` guarded in the nym branch. Regression test added. |
| 5 | Med | Non-canonical proof length accepted (trailing partial-scalar bytes ignored) ⇒ encoding malleability. | **Fixed** — verify rejects lengths not `≡ min_len (mod scalar_len)`. Regression test added. |
| 7 | Low | Proof parser did not reject a zero `challenge`. | **Fixed** — zero challenge rejected. |
| 4 | Med | `SecretKey` Drop used a hand-rolled volatile loop without a fence. | **Hardened** — added `compiler_fence(SeqCst)`; invariants documented. (Full migration to the `zeroize` crate deferred — see §5.) |
| 6 | Low | Subgroup check relies on `from_compressed` with no guard against an accidental `_unchecked` swap. | **Mitigated** — explicit SECURITY comment in `point_from_bytes`. (A non-subgroup-encoding regression vector is still wanted — see §5.) |
| 3 | Med | Holder secrets (`nym_secret`, `prover_nym`, `secret_prover_blind`, `m~`/`m^` blindings) are not zeroized in the nym/blind paths. | **Deferred** — see §5 (needs API design; `Scalar` is `Copy` and re-exported). |
| — | Info | `Ciphersuite::Bls12381Shake256` is selectable but the hash layer is SHA-256-only (silent wrong output if selected). | **Deferred** — see §5. |

Things the review explicitly found **done well** are in §3.

## 5. Known limitations / recommended hardening (for the auditor)

1. **Holder-secret zeroization (Finding 3).** `bls12_381_plus::Scalar` is `Copy`
   and does not implement `Zeroize`; we also re-export `Scalar`, so callers hold
   their own copies. Fully zeroizing `nym_secret` / `secret_prover_blind` and the
   per-proof blinding vectors needs a `Zeroizing<Scalar>` newtype and an API
   decision about caller-owned copies. We want the auditor's view on the right
   boundary before committing to an API change.
2. **`SecretKey` Drop (Finding 4).** Current approach is volatile-write +
   `compiler_fence`. Question: prefer migrating to the `zeroize` crate's
   `Zeroize`/`Zeroizing` for the inner scalar?
3. **Subgroup regression vector (Finding 6).** We assert validation rejects
   malformed encodings but do not yet have a known *on-curve, non-subgroup* G1/G2
   encoding to assert rejection of. A vendored test vector would harden against
   an accidental `_unchecked` swap.
4. **SHAKE-256 ciphersuite.** Either implement it properly or make selecting it a
   hard error rather than silently emitting SHA-256 output with mismatched scalar
   lengths.
5. **RNG + `fork()`.** `ThreadRng` does not reseed on `fork()`. Do not fork after
   first RNG use (or reseed in children) to avoid nonce/blinding reuse across
   forked workers.
6. **Canonicalization is what gets signed.** The RDFC-1.0 / JSON-LD layer in
   `affinidi-rdf-encoding` determines the exact bytes signed and hashed; a
   canonicalization bug is a signature-soundness bug. It is W3C-`rdf-canon`-suite
   conformant (59/63; 4 documented poison/automorphism skips — #361) but is part
   of the trusted surface and worth auditor attention.

## 6. Reproducing the evidence

```sh
# Primitive + conformance KATs, incl. the verifier-robustness regression tests:
cargo test -p affinidi-bbs
# vc-di-bbs document layer + RDFC conformance (incl. official W3C rdf-canon suite):
cargo test -p affinidi-data-integrity --all-features
cargo test -p affinidi-rdf-encoding
```

The malformed-input regression tests live in `affinidi-bbs/src/lib.rs`
(`verify_rejects_*`, `pseudonym_verify_rejects_degenerate_proof`).
