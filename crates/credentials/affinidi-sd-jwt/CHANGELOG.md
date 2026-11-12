# Affinidi SD-JWT Changelog

## Unreleased (0.2.0) — key binding checked under `cnf.jwk`, with `aud`, `nonce` and `iat` required

Breaking (R3.6): `verify` changes signature and a requested key binding check
is stricter.

- **Changed:** `verifier::verify(sd_jwt, issuer_verifier, hasher, options)`.
  The `holder_verifier` argument is gone. The KB-JWT verifier is now built from
  the `cnf.jwk` of the signature-verified issuer payload, through the new
  `HolderKeyVerifier` trait (any `Fn(&Value) -> Result<Box<dyn JwtVerifier>>`
  closure implements it). Before, the caller passed a verifier that was never
  compared with `cnf.jwk`, so a KB-JWT checked against any other key was
  reported as bound.
- **Changed:** `VerificationOptions` is now `{ key_binding: Option<KeyBindingCheck> }`.
  `KeyBindingCheck` has required `audience`, `nonce`, `freshness`
  (`KbFreshness`) and `holder_key` members. Before, `expected_audience` and
  `expected_nonce` were documented as required with `verify_kb` but were only
  compared when given, so a KB-JWT for any audience and nonce was reported as
  verified. An empty expected audience or nonce is refused.
- **Changed:** with key binding, the KB-JWT must carry an integer `iat` inside
  the freshness window (RFC 9901 §4.3, §7.3). `verify_with_kb_freshness` is
  removed; its window is now the `freshness` member.
- **Fixed:** the freshness window saturates instead of overflowing, and a
  negative `iat` is refused. An `iat` of `i64::MIN` used to overflow
  `now - iat` (a panic with overflow checks, a pass without them).
- **Behaviour (stricter):** a payload with no `_sd_alg` uses `sha-256` (RFC 9901
  §4.1.1), so another hasher is refused with an `_sd_alg mismatch` error rather
  than a later digest error. A non-string `_sd_alg` is refused.
- **Changed:** `issuer::issue` writes `_sd_alg` whenever the hasher is not
  `sha-256`, even with no disclosures, so such an SD-JWT still verifies.
- **Behaviour (stricter):** with key binding, a `cnf.jwk` with `kty` `oct`,
  with no `kty`, or with a private member (`d`, `p`, `q`, `dp`, `dq`, `qi`,
  `oth`, `k`) is refused before the `HolderKeyVerifier` is called. The
  verifier it returns must pin `alg` to the key's `kty`/`crv` and never accept
  `none` or `HS*`.
- **Changed:** `KeyBindingCheck`, `VerificationOptions` and `KbFreshness` are
  `#[non_exhaustive]`. Build them with `KeyBindingCheck::new`,
  `VerificationOptions::default()` / `VerificationOptions::with_key_binding`,
  and `KbFreshness::new(..).with_max_future_skew_secs(..)`. Fields stay public
  for reads.
- **Added:** `DEFAULT_SD_ALG`, `HolderKeyVerifier`, `KeyBindingCheck`,
  `VerificationOptions::with_key_binding`, `KbFreshness::with_max_future_skew_secs`.
  `KbFreshness`, `KeyBindingCheck`, `HolderKeyVerifier`, `KB_JWT_TYP` and
  `DEFAULT_SD_ALG` are re-exported from the crate root. Test utilities (behind
  `_test-utils`) gain `hmac_test_jwk` and `hmac_verifier_from_jwk`, a stand-in
  holder key for HMAC tests that accepts `HS256` and is not for production.
- Without a `KeyBindingCheck`, a KB-JWT that is present is still reported as
  `kb_verified: Some(false)` and `is_verified()` is false, as before.

Migration:

```rust
// 0.1
let opts = VerificationOptions { verify_kb: true, expected_audience: Some(aud), expected_nonce: Some(nonce) };
verify(&sd_jwt, &issuer_verifier, &hasher, &opts, Some(&holder_verifier))?;
// 0.2
let holder_key = |jwk: &serde_json::Value| -> Result<Box<dyn JwtVerifier>, SdJwtError> {
    // Build a verifier for this public key, pinned to its own alg.
    Ok(Box::new(my_verifier_from_jwk(jwk)?))
};
let opts = VerificationOptions::with_key_binding(KeyBindingCheck::new(
    aud,
    nonce,
    KbFreshness::new(now, 300),
    &holder_key,
));
verify(&sd_jwt, &issuer_verifier, &hasher, &opts)?;
```

## Unreleased (0.1.8) — RFC 9901 §7.1 disclosure processing

Fixes #962. `holder::resolve_claims`, and so `verifier::verify`, now perform
RFC 9901 §7.1 steps 3–5 in one pass over the payload and every disclosed value.

- **Fixed (now accepted):** recursive Disclosures — a digest inside another
  Disclosure's value (RFC 9901 §4.2.6, Appendix A.2). The verifier collected
  digests from the issuer-signed payload only, so it refused the RFC's own A.2
  example and SD-JWTs this crate's `issuer::issue` makes from a nested frame.
- **Behaviour (stricter):** refused, where they were silently accepted:
  - a digest appearing more than once, at any level or through a Disclosure,
    disclosed or not (step 4);
  - an object `_sd` digest whose Disclosure has no claim name, names `_sd` or
    `...`, or names a claim already present at that level (step 3.c.ii) —
    previously the Disclosure overwrote the issuer's plain value;
  - an array `{"...": digest}` whose Disclosure has a claim name (step 3.c.iii);
  - a non-array `_sd`, or a non-string entry in it.
  - `resolve_claims` also refuses an unreferenced or repeated Disclosure
    (step 5), which only `verify` checked before.

  Each needs the issuer-signed payload itself to carry the structure: a holder
  cannot produce one from a well-formed SD-JWT. Only `{"...": digest}` objects
  with no other key are array-element digests (RFC 9901 §4.2.4.2).

## Unreleased (0.1.7) — Key Binding JWT `typ` and freshness

- **Behaviour (stricter):** with `verify_kb`, a Key Binding JWT whose header
  `typ` is not `kb+jwt` is refused (RFC 9901 §4.3, §7.3). Without the check, a
  JWT the holder signed with the same key for another purpose could pass as a
  KB-JWT. Every RFC 9901 producer sets it, including this crate's
  `holder::present`; the RFC 9901 and spec vectors still pass.
- **Added:** `verifier::verify_with_kb_freshness` and `KbFreshness` — `verify`,
  plus a window on the KB-JWT's `iat` (RFC 9901 §7.3 step 5): not older than
  `max_age_secs`, not more than `max_future_skew_secs` (default 60) ahead. A
  separate function rather than a new `VerificationOptions` member, so callers
  that build the options as a struct literal are unaffected. `KB_JWT_TYP`
  constant.

For the OpenID4VP verifier in OpenVTC/verifiable-trust-infrastructure#1988.

## Unreleased (0.1.6) — `rand` 0.10, `sha2` 0.11

No behaviour change and no public API change: these are private dependencies here.
Verified by the crate's test suite.

## Unreleased (0.1.5) — dependency refresh

- Bumps `base64` 0.22 → 0.23.
- No source or API change; the bumps are declaration-only and the crate
  compiles unmodified against them. Bumped workspace-wide in the same
  change so no two versions of these crates are compiled side by side.

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
