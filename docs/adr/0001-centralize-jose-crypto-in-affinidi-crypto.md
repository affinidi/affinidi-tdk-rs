# ADR 0001 — Centralize JOSE crypto primitives in `affinidi-crypto`

- **Status:** Proposed
- **Date:** 2026-06-01
- **Tracking issue:** #327 (follow-up to #326, which fixed #322/#323/#324)
- **Supersedes / relates to:** the didcomm/vta-sdk patch interaction (#328), `vti-didcomm-js` wire-compat sibling

## Context

The workspace currently runs **two independent, overlapping crypto stacks**:

- `affinidi-crypto` (core) provides key types, JWK/multikey parsing,
  `did:key` conversions, ECDSA/EdDSA signing, X25519 helpers, and PQC
  (ML-DSA / SLH-DSA). It exposes **no** JOSE key-agreement / KDF / AEAD /
  key-wrap primitives.
- `affinidi-messaging-didcomm` hand-rolls its **entire** JOSE crypto
  stack in `src/crypto/`: ECDH-1PU (`ecdh_1pu.rs`), ECDH-ES
  (`ecdh_es.rs`), the JOSE Concat KDF, AES-256 Key Wrap (`aes_kw.rs`,
  RFC 3394), A256CBC-HS512 content encryption (`content_encryption.rs`),
  and EdDSA (`signing.rs`) — plus its own key/curve representation
  (`key_agreement.rs`: `Curve`, `PublicKeyAgreement`,
  `PrivateKeyAgreement`), parallel to `affinidi-crypto`'s key types.

This duplication is the **root cause of #322**: the ECDH-1PU Concat KDF
shipped feeding `cc_tag` into the KDF without its 32-bit length prefix,
deriving a non-spec KEK that broke all authcrypt interop with credo-ts /
didcomm-python. A single shared, audited KDF would not have shipped that
way. #326 fixed the bug, but the structural duplication remains — the bug
class can recur in any of the parallel implementations.

### Wider duplication (whole-workspace survey)

A survey of crypto across the repo (core, identity, messaging,
credentials, OID4VC, mDoc) found the JOSE duplication is the sharpest
case of a broader pattern. Primitives re-implemented in ≥2 places:

| Primitive | Occurrences (representative) |
|---|---|
| SHA-256/384/512 digest | `affinidi-sd-jwt/hasher.rs`, `affinidi-mdoc/issuer_signed_item.rs`, `affinidi-rdf-encoding/rdfc1/*`, `affinidi-data-integrity/lib.rs`, `affinidi-bbs/hash.rs` |
| base64url (URL_SAFE_NO_PAD) | sd-jwt, oid4vc-core (`jwt.rs`, `es256.rs`), affinidi-crypto JWK exporters, didcomm JWE/JWS |
| Compact JWS framing (encode/decode) | `oid4vc-core/jwt.rs`, `affinidi-sd-jwt/signer.rs` |
| ES256 (P-256 ECDSA) sign/verify | `affinidi-mdoc/es256_cose.rs`, `oid4vc-core/es256.rs` (identical `p256` wrapping, different framing) |
| JWK coordinate export | `affinidi-crypto/p256.rs`, `oid4vc-core/es256.rs` |
| Random salt/nonce (32B) | sd-jwt `disclosure.rs`, mdoc `issuer_signed_item.rs` |

The survey also confirmed a **healthy** baseline: the identity layer
(`affinidi-did-common`, `affinidi-secrets-resolver`) already delegates
key generation/signing to `affinidi-crypto`, and no crate pulls in the
vulnerable `rsa` crate. So the target — "one audited crypto core, thin
domain wrappers above it" — is already the house style; JOSE and the
hotspots above are where it isn't yet followed.

## Decision

**1. `affinidi-crypto` becomes the single home for low-level crypto
primitives.** Add a `jose` module providing:

- ECDH key agreement over X25519 / P-256 / K-256
- ECDH-1PU and ECDH-ES
- the JOSE Concat KDF, with the **length-prefixed `cc_tag`** baked in
- AES-256 Key Wrap (A256KW)
- A256CBC-HS512 content encryption

**2. Unify key types.** Reconcile didcomm's `Curve` /
`PublicKeyAgreement` / `PrivateKeyAgreement` with `affinidi-crypto`'s key
representation so there is **one** type for an agreement key, with
`From`/`Into` conversions at the boundary during migration.

**3. `affinidi-messaging-didcomm` keeps only the envelope layer.** After
migration it owns DIDComm/JOSE envelope logic (`pack`/`unpack`,
JWE/JWS framing, header construction, the legacy-KEK decrypt fallback)
and calls `affinidi-crypto::jose` for all crypto. It contains **no
bespoke crypto**.

**4. Behaviour is gated by known-answer tests.** The KAT harness added in
this PR (`src/crypto/kat.rs`) pins the byte-level output of every
primitive. The migration is only allowed to land if these same vectors
pass byte-identically against the relocated `affinidi-crypto::jose`
implementation.

### Target layering

```
            ┌─────────────────────────────────────────────┐
  envelope  │ affinidi-messaging-didcomm                  │
            │   pack / unpack, JWE & JWS framing,          │
            │   header build, legacy-KEK fallback          │
            └───────────────┬─────────────────────────────┘
                            │ calls (no crypto of its own)
            ┌───────────────▼─────────────────────────────┐
  crypto    │ affinidi-crypto                             │
  core      │   jose: ECDH(-1PU/-ES), Concat KDF,         │
            │         A256KW, A256CBC-HS512                │
            │   keys: Ed25519/X25519/P-256/P-384/K-256,    │
            │         JWK, did:key, PQC                    │
            └───────────────┬─────────────────────────────┘
                            │ wraps
            ┌───────────────▼─────────────────────────────┐
  vendored  │ ed25519-dalek, x25519-dalek, p256, k256,    │
            │ aes, cbc, hmac, sha2, subtle …              │
            └─────────────────────────────────────────────┘
```

The same core is the natural home for the wider hotspots (a shared
hasher, one base64url codec, one compact-JWS helper, one ES256, JWK
export helpers). Those are **out of scope for #327's PRs** but recorded
below as a follow-on roadmap so the consolidation is deliberate, not
incidental.

## Extensibility — adding new crypto types

A central goal: the JOSE core must make it cheap and **safe** to add new
algorithms (curves, KDFs, AEADs, key-wraps, signature schemes, and
eventually PQC/hybrid) without re-touching every call site or weakening
the security boundary. The current didcomm design fails this: `Curve` /
`PublicKeyAgreement` / `PrivateKeyAgreement` are closed enums, so adding
(say) P-521 means editing the enum plus every `match` in `key_agreement`,
`ecdh_1pu`, `ecdh_es`, and the JWK glue. The new `affinidi-crypto::jose`
module is designed around two ideas instead.

### 1. One trait per JOSE role; algorithms are implementations

Define a small trait per cryptographic role, each keyed by its JOSE
identifier:

- `KeyAgreement` — ECDH over a curve (X25519, P-256, K-256, …); produces
  the raw `Z`.
- `KeyDerivation` — Concat KDF (and room for HKDF-based JOSE KDFs).
- `KeyWrap` — A256KW today; A128KW / AES-GCM-KW later.
- `ContentEncryption` — A256CBC-HS512 today; A256GCM / XC20P later.
- `JwsSigner` / `JwsVerifier` — EdDSA today; ES256/ES384/ES256K, and PQC
  (ML-DSA via the existing `affinidi-crypto::ml_dsa`) later.

Adding an algorithm is then a **localized, additive** change: implement
the trait for the new type and register it. The envelope layer (didcomm)
keeps calling the trait, not a concrete primitive, so `pack`/`unpack`
don't change when a new `enc` or `alg` is added — only the registry does.
This is the open/closed seam the closed enums lack.

### 2. Typed wire identifiers stay the security boundary

Extensibility must not become uncontrolled algorithm agility — that is
how downgrade / `alg:none` bugs (cf. #321) creep in. So:

- The JOSE `alg` (e.g. `ECDH-1PU+A256KW`) and `enc` (e.g.
  `A256CBC-HS512`) identifiers remain **typed, exhaustively-matched
  enums** at the parse boundary. An unrecognised identifier is a hard
  error, never a silent fallthrough.
- The set of algorithms a given DIDComm message is *permitted* to use is
  an **allowlist in the envelope layer**, independent of what the crypto
  core *can* do. Registering a new primitive in `affinidi-crypto` does
  not auto-enable it on the wire; the envelope opts in.
- Negotiation / capability discovery (which curve, which `enc`) lives in
  the envelope layer, not the crypto core. The core just answers "do this
  named operation".

The net: the **registry** is open for extension (new impls), while the
**wire-acceptance policy** stays closed and explicit.

### 3. PQC / hybrid readiness

The core already ships PQC signatures (ML-DSA, SLH-DSA). Structuring key
agreement behind a `KeyAgreement` trait (rather than an X25519/P-256/K-256
enum) is what lets a future **hybrid KEM** — e.g. X25519 + ML-KEM
concatenated into `Z` before the KDF — slot in as just another
implementation, which is the expected direction for DIDComm/JOSE PQC.
Signature extensibility lands the same way via `JwsSigner`/`JwsVerifier`.

### 4. KATs scale with the design

Every new algorithm ships with its own KAT in the same harness this PR
establishes (a spec vector where one exists, a golden master otherwise).
The harness is structured per-primitive precisely so a new curve or `enc`
adds a test without disturbing the others — extensibility includes the
test surface, not just the code.

This trait-plus-typed-registry shape is a **requirement on PR 5b** (where
`affinidi-crypto::jose` is authored), called out here so the module is
born extensible rather than retrofitted. PR 5c's key-type unification
should land the `KeyAgreement` trait + curve registry rather than port
the closed enum across.

## Migration plan (KAT-gated, multi-PR)

- **PR 5a (this PR):** ADR + KAT harness locking current behaviour. No
  code moves.
- **PR 5b:** add the additive `affinidi-crypto::jose` module with the
  primitives + the *same* KATs ported across. No didcomm change yet.
- **PR 5c:** unify the key types behind the `KeyAgreement` trait + curve
  registry (see Extensibility), *not* a ported closed enum; add
  `From`/`Into` so the swap is mechanical and reversible.
- **PR 5d:** rebase didcomm `pack`/`unpack` onto `affinidi-crypto::jose`,
  delete `src/crypto/{ecdh_1pu,ecdh_es,aes_kw,content_encryption,
  key_agreement,signing}.rs`. KATs must still pass byte-for-byte.

Each PR is one bump commit, rebased between merges.

## Consequences

### Positive
- One audited KDF/AEAD/key-wrap path; the #322 bug class cannot recur in
  a forgotten parallel copy.
- `affinidi-crypto::jose` is reusable by the SDK, mediator, and future
  protocol crates instead of being trapped inside didcomm.
- A clear seam to later fold in the whole-workspace hotspots.

### Risks / costs
- **Wire compatibility is the whole ballgame.** The rewrite must produce
  byte-identical JWE/JWS. The KAT harness (this PR) is the guard; PR 5d
  may not merge unless every vector passes unchanged.
- **didcomm version bump re-triggers #328.** A **minor** bump of
  `affinidi-messaging-didcomm` (which PR 5d will need) un-unifies
  `vta-sdk` from the `[patch.crates-io]` redirect until vta-sdk is
  republished against the new didcomm. PR 5d must be paired with a
  vta-sdk republish. (PR 5a/5b are test/additive and can stay patch-level
  to avoid this.)
- **`vti-didcomm-js` sibling.** The OpenVTC JS DIDComm library is kept
  wire-compatible with this crate; any crypto/wire-affecting change must
  be mirrored there. The migration is meant to be wire-neutral, so the
  KATs double as the cross-language conformance contract.
- **Legacy-KEK fallback** (`derive_key_1pu_recipient_legacy`, the #322
  migration path) must move with the rest and keep its own KAT.

## Alternatives considered

- **Leave the stacks separate.** Rejected: keeps the duplication that
  caused #322 and blocks reuse.
- **New `affinidi-messaging-crypto` crate** instead of growing
  `affinidi-crypto`. Rejected for the JOSE core: it would re-create a
  parallel crypto crate, the exact smell we're removing. The primitives
  are protocol-agnostic and belong in the existing core. (TSP's HPKE in
  `affinidi-tsp/src/crypto/hpke.rs` is genuinely protocol-specific and
  stays put.)
- **Big-bang single PR.** Rejected: unreviewable and unsafe for
  wire-affecting crypto. The KAT-gated staged plan above is the safe path.

## Follow-on roadmap (out of scope for #327, recorded for deliberate sequencing)

Once `affinidi-crypto::jose` exists, fold the surveyed hotspots in,
prioritised by blast radius:

1. **Shared hasher** (SHA-256/384/512) — collapses ~5 sites; touches
   sd-jwt, mdoc, rdf-encoding, data-integrity.
2. **One base64url codec** + **one compact-JWS helper** — collapses the
   sd-jwt / oid4vc-core framing duplication.
3. **One ES256** shared by `affinidi-mdoc` (COSE framing) and
   `oid4vc-core` (JWS framing) over a common P-256 core.
4. **JWK export helpers** in `affinidi-crypto::jwk`.
5. **Shared random salt/nonce** helper.

Each is independently shippable and should get the same before/after
characterization-test treatment as the JOSE migration.
