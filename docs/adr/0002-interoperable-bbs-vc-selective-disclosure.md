# ADR 0002 — Standards-interoperable BBS for VC selective disclosure + holder binding

- **Status:** Accepted (2026-06-05) — **build in-house** (not adopt); breaking
  wire change confirmed acceptable (no BBS credentials issued in production yet)
- **Date:** 2026-06-05
- **Tracking issue:** #353 (per-verifier pseudonym / holder binding); builds on #347 (document-level bbs-2023), #346, #345
- **Relates to:** ADR 0001 (centralize crypto), the `vti-didcomm-js` wire-compat sibling, downstream OpenVTC `verifiable-trust-infrastructure#295` (VTC join verifier)

## Context

#353 asked for per-verifier pseudonym / holder-binding on top of the
existing BBS stack. While scoping it, the **hard requirement became
interoperability with external, standards-based implementations** (the
W3C VC test suite, EUDI/eIDAS-style verifiers, and the OpenVTC JS
sibling) — not just self-consistency inside the affinidi stack. That
requirement is not met today, at any layer, and the gaps must be fixed
bottom-up before a standards-compliant pseudonym can exist.

### What exists

- `affinidi-bbs` (core): a hand-rolled BBS over BLS12-381. Its low-level
  primitives — generator derivation, `hash_to_scalar`,
  `messages_to_scalars` — match the IETF draft and are pinned with
  DIF/IETF KATs.
- `affinidi-data-integrity::bbs_2023` (#347): wraps it at the W3C-VC
  level (`sign_vc_base` / `derive_vc` / `verify_vc_derived`).
- A #353 **prototype** on branch `feat/bbs-per-verifier-pseudonym`: a
  single-hidden-message pseudonym. Self-consistent, fully tested — but,
  as this ADR shows, wire-incompatible with the standard. It is superseded
  by this decision.

### Interop gaps found (evidence)

1. **Base `Sign` is not spec-compliant.** It hashes
   `SK ‖ domain ‖ messages`; draft-irtf-cfrg-bbs-signatures computes
   `e = hash_to_scalar(serialize(SK, msg_1..msg_L, domain))` — domain
   **last**. Signatures will not match the published signature vectors.
2. **`ProofGen` challenge transcript is not spec-compliant.** It
   serializes the points first, then grouped indexes/messages; the draft
   is `c_arr = (R, i1, msg_i1, …, iR, msg_iR, Abar, Bbar, D, T1, T2,
   domain)` then `I2OSP(len(ph),8) ‖ ph`. Proofs will not verify in a
   conforming verifier.
3. **No signature/proof KATs.** Only the sub-primitives are pinned, which
   is exactly why (1) and (2) went unnoticed. The drift is untested.
4. **The document layer is not vc-di-bbs.** It uses a bespoke
   `pointer\0jcs` statement encoding and a JSON `proofValue`, not RDF
   dataset canonicalization (RDFC-1.0) and the vc-di-bbs CBOR `proofValue`
   (base/derived). Its own module note says it "interoperates within the
   affinidi stack rather than with arbitrary W3C vc-di-bbs
   implementations."
5. **The prototype pseudonym is non-standard on every axis.** The
   IRTF-adopted draft computes `Pseudonym = OP · Σ nym_secrets[i]·zᶦ`
   with `z = hash_to_scalar(context_id)`, where `nym_secrets` combines
   prover contribution **and** `signer_nym_entropy`, bound via a
   commitment the signer blind-signs; and it places `(pseudonym, Ut)`
   into the challenge **between T2 and domain**. The prototype instead
   uses a single signed message, an affinidi-internal DST, and appends
   its terms after `ph`.

### Spec-lineage caveat

Per-verifier linkability has **two lineages**: the earlier
`draft-vasilis-bbs-per-verifier-linkability` ("the pid value is the last
message signed" — the slot model the prototype happens to match) and the
IRTF-adopted `draft-irtf-cfrg-bbs-per-verifier-linkability` (polynomial
over `nym_secrets` + `signer_nym_entropy` + blind issuance). These are
**wire-incompatible with each other**. The spec is still evolving, so the
exact draft revision must be pinned and treated as a moving target.

## Decision

Target = **full W3C vc-di-bbs interoperability.** Everything below is
KAT-locked against published vectors:

- **Primitive:** `draft-irtf-cfrg-bbs-signatures` (pin the revision at
  Stage 1) for Sign / Verify / ProofGen / ProofVerify.
- **Document:** W3C **vc-di-bbs** `bbs-2023`: RDFC-1.0 canonicalization,
  the spec's mandatory/selective statement selection, and the CBOR
  base/derived `proofValue` framing.
- **Holder binding:** `draft-irtf-cfrg-bbs-per-verifier-linkability` +
  `draft-irtf-cfrg-bbs-blind-signatures` (pin both), i.e. the
  blind-issued committed-secret + `signer_nym_entropy` construction — not
  the prototype's slot model.

### Build vs. adopt — the primary architectural fork

**Resolved (2026-06-05): build in-house.** `affinidi-bbs` is corrected to
match the drafts byte-for-byte and locked with the official vectors,
rather than vendoring an external BBS crate. The recommendation below is
retained for the record; the rationale for *not* taking it is captured in
"Alternatives considered". Consequence: the in-house ZK crypto stays in
the audit scope (see Consequences → Audit).

**(Original recommendation) Adopt a maintained, spec-compliant BBS crate
for the primitive + blind + pseudonym layers; keep
`affinidi-data-integrity` as the thin W3C wrapper** (RDFC via the existing
`affinidi-rdf-encoding`, plus the CBOR `proofValue`).

Rationale:

- It *is* the interop: the crate ships the official test vectors and
  tracks the drafts, so conformance is inherited rather than re-derived.
- It satisfies the repo rule — *prefer existing SDKs over custom
  implementations*, especially for proof-bearing ZK crypto — and shrinks
  the in-house audit surface to the W3C wrapper + binding glue.
- Candidates to evaluate at Stage 1:
  - **zkryptium** (Cybersecurity-LINKS) — Rust; implements CFRG BBS and
    Blind BBS with the draft vectors; used in EUDI contexts. Confirm
    per-verifier-pseudonym coverage and the exact draft revision.
  - **docknetwork crypto** — Rust core with a JS/WASM sibling; notable
    because the OpenVTC JS side could share the same core, giving
    cross-language wire-parity for free.
  - Selection criteria: pseudonym-draft coverage, BLS12-381-SHA-256
    ciphersuite, license (workspace is Apache-2.0-compatible — check),
    maintenance cadence, and audit status.

**Fallback (if a vendored BBS dependency is unacceptable):** fix
`affinidi-bbs` to the drafts in-house. Same stages, but it keeps bespoke
ZK crypto that must be fully audited.

### KAT-gated stages (apply to either path)

- **Stage 1 (this PR): ADR + official vectors as KATs + crate decision.**
  Import the DIF `bbs-signature` fixtures and draft appendix vectors as
  tests. They **fail** against today's code — that failure is the spec
  defining the target. Complete the build-vs-adopt evaluation and commit
  to a crate (or to in-house). No wire change beyond test scaffolding.
- **Stage 2: standards-compliant base BBS.** Adopt the crate (or fix
  `Sign`/`ProofGen`). Signature + proof KATs pass byte-for-byte.
  **BREAKING** wire change to `affinidi-bbs`.
- **Stage 3: vc-di-bbs document layer.** RDFC-1.0 (reuse
  `affinidi-rdf-encoding`), spec statement selection, CBOR `proofValue`.
  Lock with the W3C vc-di-bbs test vectors. **BREAKING** to `bbs-2023`.
- **Stage 4: holder binding.** Blind issuance (commit the nym secret +
  `signer_nym_entropy`) + ProofGen/VerifyWithPseudonym per the pseudonym
  draft; lock with the draft's vectors. Surface an optional binding mode
  through `sign_vc_base` / `derive_vc` / `verify_vc_derived`.

Each stage is one bump commit, rebased between merges. Stage 2 is a
breaking `affinidi-bbs` bump and must be coordinated with the OpenVTC JS
sibling; the KATs are the cross-language conformance contract (as in
ADR 0001).

### Implementation log

- **Stage 2 (done).** `affinidi-bbs` made byte-exact to
  `draft-irtf-cfrg-bbs-signatures`: fixed the `Sign` `e`-hash order, the
  `calculate_domain` id (`api_id`, not ciphersuite_id), and the **P1
  ciphersuite constant** (was the standard G1 generator); reordered the
  proof challenge transcript. Locked with the official DIF vectors
  (signature exact-match, proof verify, and exact proof reproduction via
  the vectors' recorded random scalars).
- **Stage 3a — RDFC-1.0 prerequisite (done).** Building vc-di-bbs first
  required a conformant canonicalizer; the in-tree `affinidi-rdf-encoding`
  was not. Root cause of the vc-di-bbs canonicalization divergence was the
  **JSON-LD native number conversion** (integral doubles like `7.0` must be
  `xsd:integer`; non-integers need the canonical `xsd:double` form, e.g.
  `5.5` → `5.5E0`) — a latent bug affecting every rdfc suite on numeric VCs.
  Also fixed: N-degree infinite recursion on cyclic blank-node graphs
  (issue the temp id *before* recursing), a `hash_related` `_:`-prefix bug
  that flipped symmetric-node ordering, RDF dataset dedup (set semantics),
  N-Quads `\b`/`\f`/DEL escaping, and N-Quads IRI handling (multi-byte
  advance + UCHAR unescape). Locked with the official **W3C `rdf-canon`
  suite** (59/63; the 4 skipped are documented poison/deep-automorphism
  graphs that do not occur in real VCs) and the **vc-di-bbs**
  canonicalization vector (byte-exact).
- **Stage 3b — vc-di-bbs document layer (issuer side done).** New module
  `affinidi-data-integrity::bbs_2023_transform`, every step KAT-locked
  byte-for-byte to the `w3c/vc-di-bbs` `TestVectors/`:
  - `proof_hash` = `SHA-256(RDFC(proofConfig))` (also proves JSON-LD
    expansion of the security vocabulary).
  - `hmac_canonicalize` — the HMAC blank-node label map.
  - `canonicalize_and_group` — skolemize + `selectJsonLd` + match selected
    statements to canonical indices → mandatory/non-mandatory groups +
    `mandatoryHash`. (Ported the vc-di-ecdsa `selectJsonLd`/`parsePointer`/
    skolemize algorithms; skolem labels are self-consistent, since grouping
    matches by statement content.)
  - `create_base_proof_value` — BBS-sign the non-mandatory statements
    (header = `proofHash || mandatoryHash`) and emit the CBOR `proofValue`
    (`0xd95d02` + `[bbsSignature, bbsHeader, publicKey, hmacKey,
    mandatoryPointers]`). **The base `proofValue` matches the W3C vector
    exactly** — confirming the IETF-compliant `affinidi-bbs` interoperates
    with the reference BBS implementation end-to-end.
  - Needed `affinidi-rdf-encoding::rdfc1::canonicalize_with_label_map`
    (input→c14n map) for selection correlation.

  - `verify_derived_proof` (verifier) — parse the derived CBOR, relabel the
    reveal document via the proof's label map, recompute `proofHash`/
    `mandatoryHash`, BBS `proof_verify`. **Accepts the reference W3C derived
    proof byte-for-byte** (and rejects tampering).
  - `create_derived_proof` (holder) — combined grouping, adjusted index
    sets, BBS `proof_gen`, reveal label map, CBOR `0xd95d03`. Structurally
    matches the W3C disclosure vector and round-trips through
    `verify_derived_proof`.

  **Stage 3b is complete:** all three vc-di-bbs roles interoperate with the
  reference implementation end-to-end — issuer (byte-exact base proof),
  verifier (accepts reference proofs), holder (reference-matching derived
  structure). What remains for the epic is wiring the new transform into the
  public `bbs_2023` document API (replacing the affinidi-internal encoding)
  and the breaking version bumps, then **Stage 4** (holder binding).
- **Stage 4 — holder binding (after 3b).** Per-verifier pseudonym + blind
  issuance, locked against the draft §12 and the `vc-di-bbs`
  `Pseudonym/`,`HolderBinding/`,`PseudonymHB/` vectors.

## Consequences

### Positive
- Real external interop: the W3C VC test suite, conforming third-party
  verifiers, and the OpenVTC JS sibling can all verify these proofs.
- Official vectors become the conformance contract; the (4)/(5) class of
  silent drift cannot recur unnoticed.
- Adopting an audited crate removes most bespoke ZK crypto from the
  in-house audit scope.

### Risks / costs
- **Breaking wire change** to `affinidi-bbs` and `bbs-2023`: existing
  affinidi-issued signatures/proofs will not verify afterward. Acceptable
  only if nothing in production depends on the current format — **confirm
  this**.
- **Moving spec.** The pseudonym/blind drafts are pre-final and have
  divergent lineages; pin exact revisions and budget for churn. The chosen
  crate's supported revision effectively picks the lineage.
- **Sibling lockstep.** `vti-didcomm-js` / OpenVTC must move with the
  breaking bump; mirror via the shared KATs.
- **Audit.** Still proof-bearing crypto over BLS12-381; adopting an
  audited crate reduces but does not remove review of the wrapper +
  binding glue.
- **Prototype disposition.** The `feat/bbs-per-verifier-pseudonym` branch
  is superseded. Its release-facing changes (the `affinidi-bbs 0.1.2` /
  `affinidi-data-integrity 0.6.2` bumps and the CHANGELOG entry describing
  the slot model) should be reverted so they don't ship as an accurate
  release; the code can be kept as throwaway reference or deleted.

## Alternatives considered

- **Keep the custom self-consistent scheme; define interop as "siblings
  match affinidi's format."** Rejected: no external interop, cannot pass
  the W3C suite, and re-creates the parallel-crypto smell ADR 0001 warns
  against.
- **Fix `affinidi-bbs` in-house (no external dependency).** Viable
  fallback; not the default because it retains unaudited bespoke ZK crypto
  when maintained, audited, spec-tested implementations exist.
- **Slot-model pseudonym (`draft-vasilis-…`) for simplicity** — what the
  prototype implements. Rejected for the interop target: the IRTF-adopted
  draft and the maintained libraries use the blind / `signer_nym_entropy`
  construction.
- **Big-bang single PR.** Rejected for the same reason as ADR 0001:
  unreviewable and unsafe for wire-affecting crypto. The KAT-gated stages
  are the safe path.
