# Affinidi VC Changelog

## Unreleased (0.3.2) — SD-JWT VC `typ`

- **Changed:** `sd_jwt_vc::issue` signs with JWS header `typ` `dc+sd-jwt`
  (draft-ietf-oauth-sd-jwt-vc §3.2.1, `SD_JWT_VC_TYP`) instead of `sd+jwt`.
  The caller's signer is otherwise used as before.
- **Behaviour (stricter, R3.6):** `sd_jwt_vc::verify` requires header `typ`
  `dc+sd-jwt` or `vc+sd-jwt` (`ACCEPTED_TYPS`) and refuses anything else with
  `Verification`. Credentials issued by this crate before 0.3.2 carry `sd+jwt`
  and are refused by `verify`. `verify_temporal` and the rest of the module do
  not look at `typ`.

## Unreleased (0.3.1) — SD-JWT VC verification; temporal claims checked strictly

- **Added:** `sd_jwt_vc::verify(serialized, issuer_key, hasher, &VerifyOptions)`
  returning `VerifiedSdJwtVc { claims, vct, issuer, status, key_bound }`.
  - The issuer verifier comes from the credential's own `iss` through the new
    `IssuerKeyVerifier` trait (any `Fn(&str, &Value) -> Result<Box<dyn JwtVerifier>>`
    closure, called with `iss` and the JWS header). A credential therefore
    verifies only under its own issuer's key.
  - It verifies the SD-JWT, with key binding under `cnf.jwk` when
    `VerifyOptions::key_binding` is set. The KB-JWT's `aud` must be a single
    string. `VerifyOptions::now` is also the key-binding window's `now`.
  - It refuses a KB-JWT that no check was asked for, and a protected claim
    that came from a disclosure instead of the issuer-signed payload.
  - It requires a non-empty `vct` and `iss`, equal to the expected values when
    those are given, and checks `iat`/`exp`/`nbf` with
    `VerifyOptions::leeway_secs`.
  - The `status` claim is returned, not checked. Before, the module had no
    verification beyond `verify_temporal`.
- **Added:** `VerifyOptions` is `#[non_exhaustive]`. Build it with
  `VerifyOptions::new(now)`, `with_leeway_secs`, `expecting_vct`,
  `expecting_issuer` and `with_key_binding`. A verifier of holder-bound
  presentations must set `with_key_binding`.
- **Added:** `verify_temporal_with_leeway(payload, now, leeway_secs)`, and the
  `PROTECTED_CLAIMS` and `IAT_LEEWAY_SECS` constants.
- **Behaviour (stricter):** `verify_temporal` refuses an `iat`, `exp` or `nbf`
  that is present but not a non-negative integer (a string, a fraction, a
  negative number, `null`) with `InvalidTemporal`. Before, such a value was
  treated as absent, so `"exp": "1700000000"` never expired. A credential is
  now expired from the instant `now == exp` (RFC 7519 §4.1.4). Bounds
  saturate rather than overflow.
- `iat` kept in the payload, and `iss`/`iat` required, are this crate's
  profile on top of draft-ietf-oauth-sd-jwt-vc (which leaves them optional).
- **Behaviour (stricter):** `issue` refuses claims that are not a JSON object
  (`InvalidClaims`) instead of issuing without them. `status` and
  `vct#integrity` join the claims that cannot be selectively disclosed, and a
  protected claim in the frame is reported as `ProtectedClaim` rather than
  `InvalidVct`.
- **Added:** `SdJwtVcError::InvalidClaims`, `ProtectedClaim` and
  `Verification` (the enum is `#[non_exhaustive]`).

## Unreleased (0.3.0) — affinidi-sd-jwt 0.2

`affinidi-sd-jwt` moves to 0.2, and its `SdJwt` is part of this crate's API
(`SdJwtVc::sd_jwt`), so this crate moves a minor with it (R3.6). No source
change. See the `affinidi-sd-jwt` 0.2.0 entry for the key binding changes.

## 14th June 2026 (0.2.1)

`SdJwtVcError` is now `#[non_exhaustive]` (ADR-0003), completing the sealing the
W7 wave started on `VcError`. Patch bump keeps the `0.2` pin valid; match it with
a `_` wildcard arm. No behaviour change. (W7 sweep)

## 13th June 2026 (0.1.2)

Semver wave (W7/W10 — release W11). `VcError`, `VerifiableCredential`, and
`CredentialStatus` are now `#[non_exhaustive]`: match `VcError` with a wildcard
arm; obtain the structs via deserialization/issuance (fields stay public for
reads). Patch bump — see
[ADR 0003](../../../docs/adr/0003-public-api-semver-policy.md) and
[the migration guide](../../../docs/migration/2026-06-semver-wave.md).
