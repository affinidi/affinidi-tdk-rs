# Affinidi Data Integrity Changelog

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
