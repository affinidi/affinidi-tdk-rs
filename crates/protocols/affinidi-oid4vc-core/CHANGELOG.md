# Affinidi OID4VC Core Changelog

## 3rd June 2026 Release 0.1.3

### Added

- **`eddsa` feature — Ed25519 `JwtSigner` / `JwtVerifier`.** New
  `EdDsaSigner` / `EdDsaVerifier` (`eddsa` module) mirroring the existing
  `es256` impls, for the `EdDSA` JWS algorithm (RFC 8037). Ed25519
  `did:key` is the dominant holder-key shape in the stack, so consumers no
  longer hand-roll `verify_strict` to check an Ed25519-signed compact JWS.
  `from_bytes` / `generate` / `with_kid` / `public_key_bytes` /
  `public_key_jwk` (OKP) / `from_jwk`, symmetric with `es256`. Enabled by
  default alongside `es256`.
- **`jwt::Audience` — string-or-array `aud` helper.** RFC 7519 §4.1.3
  allows the `aud` claim to be a single string *or* an array. The new
  untagged `Audience` type deserialises both and offers `.contains()` /
  `.iter()`, so consumers stop re-implementing (and occasionally
  mishandling) the array form.

## 28th May 2026 Release 0.1.2

### Security

- **CRITICAL — `alg=none` / empty signature accepted as verified.**
  `decode_compact_jws_verified()` handed the signing input straight to
  the caller-supplied `JwtVerifier` without inspecting the protected
  header. That made the security of every SIOPv2 / OID4VCI / OID4VP
  token check depend on each verifier impl *happening to* reject a
  zero-length input — true for `Es256Verifier` today, but one
  permissive impl turns `{"alg":"none"}.<payload>.` into a verified
  token. The header is now decoded first; `alg: none`
  (case-insensitive), missing `alg`, and an empty signature segment
  are refused **before any verifier is consulted**. New regression
  test `jwt::tests::rejects_alg_none`.
