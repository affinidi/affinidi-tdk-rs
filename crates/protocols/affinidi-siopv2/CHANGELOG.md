# Affinidi SIOPv2 Changelog

## Unreleased (0.2.0) — ID Tokens are signed and verified

Breaking (R3.6). No in-workspace caller outside `affinidi-tdk`'s re-export.

- **New:** `SelfIssuedIdToken::sign(&dyn JwtSigner)` returns the compact JWS;
  for a DID subject the signer's `kid` must be a DID URL under `sub`.
- **New:** `verify_id_token(jwt, &IdTokenExpectations, Option<&dyn DidKeyResolver>)`
  enforces an algorithm allowlist, verifies the signature (with `sub_jwk` for a
  JWK Thumbprint subject, `ES256` / `EdDSA` only; with the caller-resolved key
  named by the header `kid` for a DID subject), then checks the claims.
  A DID subject without a resolver is rejected.
- **Renamed:** `SelfIssuedIdToken::validate(client_id, nonce)` is now
  `validate_claims(&IdTokenExpectations)`. It checks claims only and is
  documented as such; it takes the time and leeway from the expectations
  instead of reading the clock, and now also rejects an `iat` in the future.
- **Changed:** `SelfIssuedIdToken::aud` is `Audience` (string or array, per
  RFC 7519), so tokens with an array `aud` deserialize.
- **Changed:** `AuthorizationRequest::validate` requires `openid` as a
  whitespace-separated scope token (a scope such as `notopenid` was accepted)
  and an absolute `redirect_uri`.
- New `SiopError::SignatureInvalid`.
- README and crate docs no longer describe claim checks as complete
  validation.

## Unreleased (0.1.4) — `sha2` 0.11

No behaviour change and no public API change: this is a private dependencies here.
Verified by the crate's test suite.

## Unreleased (0.1.3) — dependency refresh

- Bumps `base64` 0.22 → 0.23.
- No source or API change; the bumps are declaration-only and the crate
  compiles unmodified against them. Bumped workspace-wide in the same
  change so no two versions of these crates are compiled side by side.

## 14th June 2026 Release 0.1.2

- `SiopError` is now `#[non_exhaustive]` (ADR-0003) so new variants land
  additively. Patch bump keeps the `0.1` pin valid; consumers that `match` it
  must add a `_` wildcard arm. No behaviour change. (W7 sweep)
