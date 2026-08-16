# Affinidi Data Integrity Changelog

## 16th August 2026 (0.7.10)

Adds the **`ecdsa-jcs-2019`** cryptosuite — ES256 (P-256) signatures over
JCS-canonicalized documents, per [W3C vc-di-ecdsa](https://www.w3.org/TR/vc-di-ecdsa/).

Until now every Data Integrity suite here was EdDSA, BBS or post-quantum, so a
P-256 key could not sign a proof at all. That blocks any holder binding that is
key-shaped rather than DID-shaped — an ISO 18013-5 mdoc binds to a P-256 device
key, so a consent receipt naming that key as its data subject was unsignable.

`KeyType::P256` now has a default suite, and the local `Signer for Secret` impl
gained a P-256 arm routing through `affinidi_crypto::p256::sign` — the same way
the ML-DSA and SLH-DSA suites route, so no new dependency.

**P-256 only, deliberately.** The spec also defines P-384, paired with SHA-384,
while this pipeline hashes with SHA-256 unconditionally (`prepare_sign_input`
concatenates two SHA-256 digests). Accepting a P-384 key would emit proofs no
conformant verifier reproduces, so `compatible_key_types` is narrower than the
spec's and a test pins that, to stop a later "completeness" patch widening it
back without moving the pipeline first.

Note that ECDSA hashes its input as part of signing, so ES256 applies SHA-256
over the pipeline's 64-byte `proof_hash || doc_hash` — where Ed25519 signs those
bytes directly. Both match their respective specs; the asymmetry is not a bug.

One existing test changed meaning rather than breaking: `test_sign_bad_key`
asserted that a particular key could not sign, but that key is **P-256** and the
failure was only ever "no suite compiled in for this key type". It is now
`test_sign_p256_key_now_produces_an_ecdsa_jcs_2019_proof`, and a new
`test_sign_rejects_a_key_type_with_no_suite` (secp256k1) covers the case the old
name was really standing in for.

Both negative behaviours were mutation-checked: making `verify` accept any
signature fails the tampered-document test, and widening the key list to P-384
fails the exclusion test.

Patch bump, per [ADR 0003](../../../docs/adr/0003-public-api-semver-policy.md)
point 3 — additive (a new enum variant on a `#[non_exhaustive]` enum, a new ZST
impl, one signer arm), and a minor bump would break the `[patch.crates-io]`
redirects.

## 31st July 2026 (0.7.9)

The Ed25519 signing path takes the signature through the inherent
`Signature::to_bytes()` rather than the `SignatureEncoding` trait, which needs
`alloc` and does not resolve under every feature unification.

Moves to **curve25519-dalek 5** (`ed25519-dalek` 2 -> 3, `x25519-dalek` 2 -> 3),
which brings rand_core 0.10 and signature 3 with it. rand 0.10 renamed `OsRng`
to `SysRng` *and* made it fallible (`TryRng<Error = SysError>`), so it no longer
satisfies dalek's `CryptoRng` bound; key generation moves to `rand::rng()`.

Patch bump, per [ADR 0003](../../../docs/adr/0003-public-api-semver-policy.md) point 3: `vta-sdk` pins this crate through
`[patch.crates-io]`, and a minor bump would break the redirect and pull a second
copy from crates.io.

## 27th July 2026 Release 0.7.8

### Fixed

- **Verification no longer fails on ordinary clock skew.** A proof's
  `created` is stamped by the *signer's* clock and was compared strictly
  (`created > now`) against the *verifier's*, so a signer even
  milliseconds ahead made acceptance a race between clock skew and
  delivery latency: the same signed request was accepted or rejected
  depending on how quickly it arrived, with no way to configure a
  tolerance. Verification now allows a clock-skew window on a future
  `created`, defaulting to 60 seconds (`DEFAULT_CLOCK_SKEW`) — matching
  the leeway conventionally applied to JWT `iat`/`nbf`, past which a
  signer generally fails bearer-token validation anyway. This governs
  only how far *ahead* `created` may be; the library still does not
  reject old proofs, so replay protection remains the surrounding
  protocol's job.

### Added

- `VerifyOptions::with_clock_skew(TimeDelta)` and the `DEFAULT_CLOCK_SKEW`
  constant. Pass `TimeDelta::zero()` for the previous strict behaviour.
- `verify_conformance_with_skew(..)`, the explicit-tolerance form of
  `verify_conformance` (which had the same strict check and now applies
  `DEFAULT_CLOCK_SKEW`).

Note: `VerifyOptions` no longer `#[derive]`s `Default` — it has a manual
impl carrying the non-zero default. Behaviour of `VerifyOptions::new()` /
`::default()` is otherwise unchanged, and the struct remains
`#[non_exhaustive]`, so the added field is not a breaking change.

## 19th July 2026 Release 0.7.7

### Changed

- Bumped the `affinidi-did-common` requirement from `"0.3"` to `"0.4"`.
  No functional change to this crate: `Document` gained a typed
  `also_known_as` field, which is additive.

## 13th June 2026 Release 0.7.6

Semver wave (W10 — release W11). `DataIntegrityProof` is now `#[non_exhaustive]`
with a `DataIntegrityProof::new(..)` constructor for assembling a proof from
parts (`sign()` remains the primary path; fields stay public for reads). Patch
bump preserves the `didwebvh-rs` `[patch.crates-io]` coupling — see ADR 0003 and
the migration guide.

## 8th June 2026 Release 0.7.5

### Fixed

- **`bbs-2023` soundness — forged undisclosed/undefined attribute values
  (issue #381).** A credential holder could change the value of an attribute
  that the credential's `@context` does **not** define (e.g. `memberLevel`
  under the bare `credentials/v2` context), re-derive a fresh disclosure proof,
  and have `verify_derived_proof` accept it. Root cause: JSON-LD expansion
  **silently dropped** unmapped terms, so such an attribute was never part of
  the signed RDF dataset — neither covered by the issuer's signature nor checked
  by the verifier — yet it remained in the JSON envelope that applications read.
  The underlying `affinidi-bbs` primitive was sound; the defect was in the
  document/cryptosuite layer. Fix: every sign / derive / verify path now
  canonicalizes via JSON-LD **safe-mode** expansion
  (`affinidi-rdf-encoding::jsonld::expand_and_to_rdf_safe`), which errors on any
  term not defined by the active `@context`. Consequences:
  - Issuers (`sign_base_document`) **refuse** to sign a credential with an
    undefined claim instead of emitting one with an unprotected attribute.
  - Verifiers (`verify_derived_proof` / `verify_pseudonym_derived_proof`)
    **reject** a reveal document carrying an undefined term.

  Applies to both the basic and pseudonym (`0xd95d08` / `0xd95d09`) suites.
  Credentials whose claims are all defined by their context (e.g. via `@vocab`)
  are unaffected — all W3C `vc-di-bbs` KAT vectors still pass byte-for-byte.

### Changed

- Bump `affinidi-rdf-encoding` to `0.1.5` (adds safe-mode expansion).

## 7th June 2026 Release 0.7.4

### Changed

- Bump `affinidi-bbs` to `0.3` (BBS audit hardening: `SecretKey` zeroize-crate
  migration, on-curve non-subgroup G1 regression vector, and a hard error when
  the unimplemented SHAKE-256 ciphersuite is selected). No API change here; the
  `bbs-2023` cryptosuite output is unchanged (all KAT vectors still pass).

## 7th June 2026 Release 0.7.3

### Deprecated

- The legacy `bbs_2023` module (an affinidi-internal `pointer`/JCS statement
  encoding) is **deprecated** — it is **not** interoperable with other vc-di-bbs
  implementations (no RDF Dataset Canonicalization). Its public functions now
  carry `#[deprecated]` attributes. Use `bbs_2023_transform` — the
  standards-track, RDF-canonical `bbs-2023` cryptosuite pinned byte-for-byte to
  the official `w3c/vc-di-bbs` vectors (issuer / holder / verifier + per-verifier
  pseudonym). No BBS credentials using the legacy encoding were issued in
  production. The module is retained this release for migration and will be
  removed in a future release.

## 7th June 2026 Release 0.7.2

W3C vc-di-bbs **per-verifier pseudonym / holder binding** (`featureOption:
pseudonym`) — the document layer on top of the blind-BBS + pseudonym crypto in
`affinidi-bbs`. Closes the holder-binding work (#353).

### Added (under the `bbs-2023` feature)

- `create_pseudonym_base_proof_value` (issuer) — blind-signs the credential over
  the holder's commitment with `signer_nym_entropy`; serializes the `0xd95d08`
  base `proofValue`. Byte-exact to the W3C `Pseudonym/addSignedSDBase` vector.
- `create_pseudonym_derived_proof` (holder) — a selective-disclosure
  presentation bound to a per-verifier pseudonym derived from the verifier id;
  serializes the `0xd95d09` derived `proofValue`.
- `verify_pseudonym_derived_proof` (verifier) — accepts the W3C reference
  pseudonym derived proof **byte-for-byte**, and rejects a mismatched verifier.

Pseudonyms are stable per verifier (recognise repeat presentations) and
unlinkable across verifiers. Proof-bearing crypto over BLS12-381 — pending the
BBS security audit (#363) before backing real credentials.

## 7th June 2026 Release 0.7.1

### Fixed

- Republish requiring `affinidi-crypto 0.2`. 0.7.0 shipped (in #358) before
  `affinidi-crypto 0.2.0` and so pinned `crypto ^0.1`; its requirement was
  later moved to `0.2` without a version bump, leaving the published 0.7.0
  stale. Any downstream on `crypto 0.2` (e.g. `affinidi-tdk`) then resolved
  two `affinidi-crypto` copies (0.1.x + 0.2.0) and failed to build. Patch
  bump to republish with the correct requirement. No code/API change.

## 6th June 2026 Release 0.7.0

Standards-interoperable **W3C vc-di-bbs `bbs-2023`** selective disclosure
(behind the `bbs-2023` feature). The new `bbs_2023_transform` module
implements the full cryptosuite — issuer, holder, and verifier — RDF-canonical
and pinned byte-for-byte to the official `w3c/vc-di-bbs` test vectors. See
ADR 0002.

### Added

- `bbs_2023_transform`: `sign_base_document` / `create_base_proof_value`
  (issuer), `create_derived_proof` (holder), `verify_derived_proof` (verifier),
  plus the building blocks (`proof_hash`, `hmac_canonicalize`,
  `canonicalize_and_group`). The base `proofValue` matches the W3C vector
  exactly, and the verifier accepts the reference's derived proof.
- New optional deps `hmac` + `ciborium` under the `bbs-2023` feature.

### Changed / BREAKING

- **BREAKING:** bumped the `affinidi-bbs` dependency to `0.2` — its
  signature/proof wire format is now IETF-compliant (`draft-irtf-cfrg-bbs-signatures`)
  and is **not** compatible with the previous, self-consistent format. No BBS
  credentials had been issued in production.
- Bumped `affinidi-crypto` to `0.2` (P-384/P-521 key agreement +
  `#[non_exhaustive]` key-agreement enums, #357). No API change in this crate
  from that bump.

### Notes

- The earlier `bbs_2023` module (affinidi-internal statement encoding) is
  retained for now; new work should use `bbs_2023_transform`.
- Proof-bearing cryptography over BLS12-381 — pending the BBS security audit
  before backing real credentials. Per-verifier pseudonym / holder binding is
  in progress (the BBS pseudonym proof primitive lands in `affinidi-bbs 0.2`).

## 18th April 2026 Release 0.6.0

Follow-up release to 0.5.4 that removes the deprecated 0.5.x migration
surface now that didwebvh-rs 0.5.0 and affinidi-tdk 0.6.x have migrated
to the unified `sign` / `verify_with_public_key` API. No wire-format
changes — existing proofs still verify.

### Breaking removals

- **BREAKING:** Removed deprecated sign methods
  `DataIntegrityProof::sign_jcs_data`, `sign_jcs_data_with_suite`,
  `sign_rdfc_data`, and `sign_rdfc_data_with_suite`. Use
  [`DataIntegrityProof::sign`] with [`SignOptions`] and
  `SignOptions::with_cryptosuite(...)` to select a non-default suite.
- **BREAKING:** Removed deprecated free function
  `verification_proof::verify_data_with_public_key`. Use
  [`DataIntegrityProof::verify_with_public_key`] with [`VerifyOptions`]
  — sync, returns `Result<(), DataIntegrityError>`.
- **BREAKING:** Removed deprecated `DataIntegrityError` variants
  `InputDataError`, `CryptoError`, `SecretsError`, `VerificationError`,
  and `RdfEncodingError`. Match on the structured variants
  (`UnsupportedCryptoSuite`, `InvalidSignature`, `InvalidPublicKey`,
  `Canonicalization`, `MalformedProof`, `Conformance`, `Signing`,
  `Resolver`) instead.

### Internal

- Internal `bbs_2023.rs` uses `DataIntegrityError::signing(e)` for BBS
  sign / proof-gen failures and `InvalidSignature { suite: Bbs2023, ..}`
  for proof-verify failures, clearing the 0.5.4 self-deprecation
  warnings.

## 18th April 2026 Release 0.5.4

Large refactor for production-grade ergonomics. Contains multiple
**breaking** API changes that are acceptable under pre-1.0 minor-version
semantics. No wire-format changes, existing proofs still verify.
Version stays at 0.5.x in this release so downstream consumers
(didwebvh-rs 0.4.x, affinidi-tdk 0.6.x on crates.io) can continue to
resolve the workspace until they migrate; a 0.6.x bump is tracked for a
follow-up release once those consumers have updated.

### Post-quantum cryptography (experimental)

- **FEATURE:** `post-quantum` feature flag (off by default), umbrella for
  `ml-dsa` and `slh-dsa` sub-flags. Enables four new cryptosuites from
  W3C `di-quantum-safe` v0.3:
  - `mldsa44-jcs-2024`, `mldsa44-rdfc-2024` (ML-DSA-44 / FIPS 204)
  - `slhdsa128-jcs-2024`, `slhdsa128-rdfc-2024` (SLH-DSA-SHA2-128s / FIPS 205)
- **FEATURE:** NIST ACVP known-answer vectors pin full SHA-256 of expected
  public keys for ML-DSA-{44,65,87}; SLH-DSA-SHA2-128s full KAT.
- **FEATURE:** Official multicodec registry values used throughout
  (ML-DSA-44 priv-seed `0x131a`, etc.).

### Unified sign/verify API

- **BREAKING:** New `DataIntegrityProof::sign(doc, signer, SignOptions)`
  entry point replaces the four-way
  `sign_jcs_data` / `sign_jcs_data_with_suite` / `sign_rdfc_data` /
  `sign_rdfc_data_with_suite` matrix. Canonicalization is derived from
  the cryptosuite; the signer picks the default cryptosuite via the new
  `Signer::cryptosuite()` default method.
- **BREAKING:** New `DataIntegrityProof::verify_with_public_key(doc, pk, VerifyOptions)`
  method — sync, returns `Result<(), DataIntegrityError>`, replaces the
  top-level `verify_data_with_public_key` function.
- **FEATURE:** New `DataIntegrityProof::verify(doc, resolver, VerifyOptions)`
  async method — resolves the verification method via
  `VerificationMethodResolver`. Ships with a no-I/O `DidKeyResolver` for
  `did:key:` URIs.
- **DEPRECATED:** Old `sign_jcs_data*` / `sign_rdfc_data*` methods and
  `verify_data_with_public_key` function, kept as thin wrappers for one
  minor version.

### Options and error types

- **FEATURE:** `SignOptions` and `VerifyOptions` with hand-rolled `with_*`
  builders (no extra deps). Both are `#[non_exhaustive]` — new fields
  ship as additive minor releases.
- **BREAKING:** `DataIntegrityError` gained structured variants:
  `UnsupportedCryptoSuite`, `KeyTypeMismatch`, `InvalidSignature` (+
  `SignatureFailure::{Malformed, Invalid}`), `InvalidPublicKey`,
  `Canonicalization`, `MalformedProof`, `Conformance`, `Signing` (wraps
  arbitrary source errors), `Resolver`. The old string-payload variants
  (`InputDataError`, `CryptoError`, `SecretsError`, `VerificationError`,
  `RdfEncodingError`) are kept as `#[deprecated]`.
- **BREAKING:** `DataIntegrityError`, `CryptoSuite`, and `KeyType` are
  now `#[non_exhaustive]`.

### Extensibility

- **FEATURE:** `CryptoSuiteOps` trait with per-cryptosuite ZST impls in
  `suite_ops.rs`. Adding a new cryptosuite is now one trait impl + one
  enum variant + one match arm (down from ~5 scattered match arms in
  0.5). No runtime registry; static dispatch via `&'static dyn`.
- **FEATURE:** `Canonicalization` enum (`Jcs`, `Rdfc`, `Custom`) for
  future non-JCS/non-RDFC suites.
- **FEATURE:** `CryptoSuite::compatible_key_types()`,
  `CryptoSuite::default_for_key_type(key_type)`, and `Display` impl
  so downstream UI / key-generation flows don't re-match on suite names.

### Multi-proof / hybrid migration

- **FEATURE:** `DataIntegrityProof::sign_multi(doc, &[&dyn Signer], opts)`
  emits one proof per signer, fail-fast on any error. Intended for
  Ed25519 + ML-DSA hybrid signing during PQC migration.
- **FEATURE:** `verify_multi(proofs, doc, resolver, opts, policy)` with
  `VerifyPolicy::{RequireAll, RequireAny, RequireThreshold(n)}`. Returns
  a `MultiVerifyResult` with per-proof outcomes and the policy decision.

### Remote-signer support

- **FEATURE:** `prepare_sign_input(doc, proof_config, suite) -> Vec<u8>`
  returns the exact bytes a remote signer must sign — for KMS/HSM
  integrations that hash out-of-band.
- **FEATURE:** `examples/remote_signer_ed25519.rs` and
  `examples/remote_signer_ml_dsa.rs` — worked examples with a mock
  backend showing the Signer trait implementation pattern.

### Performance

- **FEATURE:** `CachingSigner<S: Signer>` wrapper caches the expanded
  ML-DSA signing key. Benchmarks show ~33% sign-latency reduction for
  ML-DSA-44 on cached paths (365 µs → 248 µs). No-op for Ed25519 and
  SLH-DSA.
- **FEATURE:** `MlDsaExpandedKey` in `affinidi-crypto` exposes the
  pre-expanded primitive for custom caching strategies.

### Spec conformance and regression testing

- **FEATURE:** `verify_conformance(proof, expected_suite)` checks proof
  shape against the spec (type, cryptosuite, proofPurpose,
  verificationMethod, proofValue decodability, `created` format and
  sanity) — independent of cryptographic verification. Catches
  malformed-but-cryptographically-valid cross-implementation bugs.
- **FEATURE:** `tests/fixtures/` with pinned deterministic proof outputs
  per supported suite. Regression test re-signs with stored inputs and
  asserts byte-for-byte equality. Regenerate with
  `AFFINIDI_DATA_INTEGRITY_REGEN_FIXTURES=1`.

### DID method helpers

- **FEATURE:** `did_vm` module with `VerificationMethodResolver` trait,
  `ResolvedKey` struct, and `DidKeyResolver` (handles `did:key:` with
  no I/O, supporting all enabled multicodec prefixes including ML-DSA
  and SLH-DSA).

### Security hardening

- **FEATURE:** `#[must_use = "ignoring a verification result is a security bug"]`
  on `Signer::sign`, `DataIntegrityProof::verify_with_public_key`, and
  `DataIntegrityProof::verify`.
- **FEATURE:** Zeroize coverage — `ml-dsa` and `slh-dsa` built with
  their `zeroize` features, `Zeroizing<>` wraps for intermediate stack
  copies of private key material.
- **FEATURE:** Panic audit — all `.unwrap()` / `.expect()` outside
  `#[cfg(test)]` are bounded-and-documented or removed.
- **FEATURE:** All signing deterministic across Ed25519, ML-DSA, SLH-DSA.
  Regression tests pin identical outputs for identical inputs.

### Deprecation schedule

Deprecated APIs (`sign_jcs_data`, `sign_jcs_data_with_suite`,
`sign_rdfc_data`, `sign_rdfc_data_with_suite`,
`verify_data_with_public_key`, plus the string-payload
`DataIntegrityError::{InputDataError, CryptoError, SecretsError,
VerificationError, RdfEncodingError}` variants) are kept as
`#[deprecated]` thin wrappers. **Planned removal in 0.6.0**.

### Migration guide

See the README for a 0.5 → 0.6 call-site migration table.

## 12th March 2026 Release 0.5.0

- **BREAKING:** Signing methods (`sign_jcs_data`, `sign_rdfc_data`) are now `async`
  and accept `&dyn Signer` instead of `&Secret`
  - Enables pluggable signing backends (KMS, HSM, cloud key management)
  - Existing code using `Secret` continues to work without a wrapper — `Signer`
    is implemented directly for `Secret`
  - Call sites must add `.await` to signing calls
- **FEATURE:** New `signer` module with `Signer` trait for abstracting signing operations
  - Implement `Signer` for custom backends (e.g. AWS KMS, Azure Key Vault, HSM)
  - `key_type()`, `verification_method()`, and `async sign()` methods
- **DEPENDENCY:** Added `async-trait`

## 2nd March 2026 Release 0.4.1

- **PERFORMANCE:** ~40% faster RDFC sign/verify operations (~330 µs → ~199 µs sign,
  ~343 µs → ~212 µs verify) via optimizations in `affinidi-rdf-encoding`
- **IMPROVEMENT:** Derive `Copy` on `CryptoSuite` enum, eliminating unnecessary clones

## 2nd March 2026 Release 0.4.0

- **FEATURE:** Added `eddsa-rdfc-2022` cryptosuite support (RDF Dataset Canonicalization)
  - New `sign_rdfc_data()` method for signing JSON-LD documents using RDFC-1.0
  - Verification auto-dispatches based on `proof.cryptosuite` — no caller changes needed
  - Validated against W3C vc-di-eddsa B.1 test vectors
- **BREAKING:** Removed `TryFrom<KeyType> for CryptoSuite` (ambiguous: Ed25519 maps to both suites)
  - Use `CryptoSuite::validate_key_type()` instead
- **DEPENDENCY:** Added `affinidi-rdf-encoding` for JSON-LD expansion and RDFC-1.0 canonicalization

## 1st February 2026 Release 0.3.5

- **CHORE:** Updated to latest dependencies

## 3rd December 2025 Release 0.3.1

- **FEATURE:** New function add `verify_data_with_public_key()` which allows for
  validating a proof where the public bytes are already known and thus a resolution
  of the DID verificationMethod is not required.
  - Use `verifiy_data_with_public_key()` when you already have the public key bytes
    available for verification
  - Use `verify_data()` when you need to resolve the DID Document to get the
    verificationMethod public key bytes

## 29th November 2025 Release 0.3.0

- **BREAKING FEATURE:** `verify_data()` now requires the following changes:
  1. DID Resolver implementing `DIDResolver` trait to be passed in
     - This allows for greater flexibility in DID resolution strategies
  2. function is now async due to DID resolution

This change allows for determination of the proof Verification Method from the
DID Document itself.

## 3rd November 2025 Release 0.2.4

- **MAINTENANCE:** Updated to latest `affinidi-secrets-resolver`
- **CHORE:** Updated to latest dependencies

## 3rd October 2025 Release 0.2.3

- **MAINTENANCE:** Updated to latest `affinidi-secrets-resolver`

## 30th September 2025 Release 0.2.2

- **MAINTENANCE:** Updating crate dependencies

## 10th September 2025 Release 0.2.1

- **IMPROVEMENT:** Removed SSI crate to lessen upstream dependencies
- **MAINTENANCE:** Updating crate dependencies

## 8th July 2025 Release 0.2.0

- **BREAKING:** API Changed to use generics that implement Serialize/Deserialize
  - Fixes a problem where the JCS library converts a JSON Number to a Fixed Floating
    point number causing it to be represented as `ff*`

## 5th July 2025 Release 0.1.4

- **FEATURE:** `sign_jcs_data()` you can now specify a signature `created` attribute
- **TESTING:** Added DataIntegrity Reference Test
- **MAINTENANCE:** Addressing Rust lint warnings
- **MAINTENANCE:** Updating crate dependencies

## 17th June 2025 Release 0.1.3

- **FEATURE:** **BREAKING** `GenericDocument` replaced with `SigningDocument` and
  `SignedDocument`
  - `SigningDocument`: Used when signing data
  - `SignedDocument`: Used when verifying data

## 17th June 2025 Release 0.1.2

- **BREAKING:** `sign_data_jcs()` renamed to `sign_jcs_data()`
- **BREAKING:** `sign_jcs_data()` no longer requires the `vm_id` parameter
- **BREAKING:** `sign_jcs_data()` `data_doc` parameter is now mutable, allowing
  in place insertion of the `DataIntegrityProof`
  - Optimisation that stops an in-memory clone of the entire document
- **FEATURE:** `sign_jcs_proof_only()` Generate Proof only and get `DataIntegrityProof`
  return
  - Optimisation method for witness nodes that only require proof, not the full
    signed document

## 6th June 2025 Release 0.1.1

- **FEATURE:** Can now verify a JSON Document
- **FEATURE:** Added example Verification tool for loading signed documents and
  verifying them
- **FIX:** Serialization of input documents was not correctly handling `@context`
  - It now correctly handles `@context` fields and places them in the proof

## 29th May 2025 Release 0.1.0

- Initial release of crate
