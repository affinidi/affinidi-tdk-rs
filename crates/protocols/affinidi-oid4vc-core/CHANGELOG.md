# Affinidi OID4VC Core Changelog

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
