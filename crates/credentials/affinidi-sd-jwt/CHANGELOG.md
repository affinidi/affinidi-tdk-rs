# Affinidi SD-JWT Changelog

## 13th June 2026 Release 0.1.4

Semver wave (W7/W10 — release W11). `SdJwtError` and `SdJwt` are now
`#[non_exhaustive]`; `SdJwt::new(jws, disclosures, kb_jwt)` is the construction
path (fields stay public for reads). Patch bump — see ADR 0003 and the migration
guide.

## 13th June 2026 Release 0.1.3

### Security

- The test-only `HmacSha256Verifier` now compares signatures in constant time
  via `subtle::ConstantTimeEq` instead of `!=`, removing the timing side channel
  and the copy-paste hazard if the verifier is ever lifted out of the test-only
  module. `subtle` is pulled in by the existing `_test-utils` feature.

## 28th May 2026 Release 0.1.2

### Security

- **CRITICAL — Key-binding bypass closed.** `verify()` with `verify_kb=true`
  checked that the issuer-signed payload contained a `cnf.jwk` holder key,
  but if the caller passed `holder_verifier=None` it then decoded the
  KB-JWT *without* verifying its signature and still reported
  `kb_verified=Some(true)`. Anyone holding (or having intercepted) the
  SD-JWT could mint a KB-JWT with the right `sd_hash`/`aud`/`nonce` and
  be accepted as the bound holder, defeating key binding (RFC 9901 §8.3).
  Now `verify_kb=true` with no `holder_verifier` is a `KeyBinding` error;
  the unverified-decode fallback (and the private `decode_jwt_payload`
  helper) is removed. Callers must build the verifier from `cnf.jwk`.
  New regression test `verify_kb_without_holder_verifier_fails`.

### Tests

- Existing `verify_kb_aud_mismatch` and `verify_kb_nonce_mismatch` tests
  updated to pass a holder verifier (was implicitly relying on the
  removed fallback).
- `spec_vectors::spec_example_full_flow` updated likewise.
