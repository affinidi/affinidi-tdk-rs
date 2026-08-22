# Affinidi OID4VC Core Changelog

## Unreleased (0.1.8) — dependency refresh

- Bumps `base64` 0.22 → 0.23.
- No source or API change; the bumps are declaration-only and the crate
  compiles unmodified against them. Bumped workspace-wide in the same
  change so no two versions of these crates are compiled side by side.

## 2nd August 2026 (0.1.7)

**`Es256Signer::generate_with_rng` now bounds `R: rand::CryptoRng`** (rand
0.10) instead of the rand_core 0.6 traits. Callers passing a rand 0.8-era
RNG must update. This mirrors the same change made to `EddsaSigner` in the
curve25519-dalek 5 move.

The `es256` feature now also enables `rand_10`, which it needs directly.

Moves this crate to the **elliptic-curve 0.14** family (`p256` / `k256` /
`p384` / `p521` 0.13 -> 0.14), which brings rand_core 0.10, digest 0.11 and
signature 3 with it.

API changes handled: the sec1 traits were renamed (`ToEncodedPoint` ->
`ToSec1Point`, `FromEncodedPoint` -> `FromSec1Point`), `EncodedPoint` became a
generic alias for `Sec1Point<C>` so it needs a per-module binding, and the
deprecated `SigningKey::random(rng)` is now `Generate::generate()` (system
CSPRNG, panics on failure).

Patch bump, per [ADR 0003](../../../docs/adr/0003-public-api-semver-policy.md) point 3: `vta-sdk` and `didwebvh-rs` redirect
this crate through `[patch.crates-io]`, and a minor bump breaks the redirect.

Crypto behaviour is unchanged — the golden/KAT vectors (`p256_sign_verify_roundtrip`,
`secp256k1_es256k_golden` RFC 6979, `ecdh_1pu_x25519_kek_golden`,
`concat_kdf_es_golden`, `a256cbc_hs512_golden`) all still pass.

## 31st July 2026 (0.1.6)

`EddsaSigner::generate_with_rng` now bounds `R: rand::CryptoRng` (rand 0.10)
instead of the rand_core 0.6 traits. Callers passing a rand 0.8-era RNG must
update. `Es256Signer` is unchanged — p256 is still on elliptic-curve 0.13, so
this crate carries both rand generations.

Moves to **curve25519-dalek 5** (`ed25519-dalek` 2 -> 3, `x25519-dalek` 2 -> 3),
which brings rand_core 0.10 and signature 3 with it. rand 0.10 renamed `OsRng`
to `SysRng` *and* made it fallible (`TryRng<Error = SysError>`), so it no longer
satisfies dalek's `CryptoRng` bound; key generation moves to `rand::rng()`.

Patch bump, per [ADR 0003](../../../docs/adr/0003-public-api-semver-policy.md) point 3: `vta-sdk` pins this crate through
`[patch.crates-io]`, and a minor bump would break the redirect and pull a second
copy from crates.io.

## 14th June 2026 Release 0.1.5

- `JwtError` and `OAuthError` are now `#[non_exhaustive]` (ADR-0003) so new
  variants land additively. Patch bump keeps the `0.1` pin valid; consumers that
  `match` them must add a `_` wildcard arm. No behaviour change. (W7 sweep)

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
