# Affinidi OpenID4VCI Changelog

## [0.2.3] - 2026-11-15

documented as OpenID4VCI draft 13

Docs only; no code or wire change (#1060).

- The crate, README and module docs said "OpenID4VCI 1.0". The wire types are
  the **draft-13** shapes (`format` + `proof` in the credential request, a
  single `credential` + `c_nonce` in the response, `batch_credential_endpoint`
  in issuer metadata, `vc+sd-jwt`), which a 1.0 Final peer cannot exchange.
  The docs now name draft 13 and say so.
- Removed claims of features the crate does not have: no token endpoint
  types, PKCE or `tx_code` verification (the offer only carries the grant),
  and no batch request/response types.
- OpenID4VCI 1.0 Final types are tracked in #1152.

## [0.2.2] - 2026-11-12

key proof freshness check does not overflow

- **Fixed:** `KeyProof::verify_claims` (and so `verify`) computed
  `now + IAT_FUTURE_LEEWAY_SECS` and `now - iat` with plain `i64` arithmetic on
  the proof's `iat`. An `iat` of `i64::MIN` overflowed `now - iat`: a panic
  where overflow checks are on, and without them a wrapped negative age that
  passed the `max_age_secs` check. Both bounds now saturate.
- **Behaviour (stricter):** a proof with a negative `iat` is refused.

## [0.2.1] - 2026-06-14

- `Oid4vciError` is now `#[non_exhaustive]` (ADR-0003) so new variants land
  additively. Patch bump keeps the `0.2` pin valid; consumers that `match` it
  must add a `_` wildcard arm. No behaviour change. (W7 sweep)

## [0.1.3] - 2026-06-03

### Added

- **`proof` module — key-binding proof build + verify.** The credential
  endpoint requires the wallet to prove possession of the key the credential
  binds to (§8.2.1, `typ: "openid4vci-proof+jwt"`). Previously the proof was
  an opaque `String` on both sides and every consumer hand-rolled the
  security-critical JWT assembly / verification. Now:
  - `build_key_proof_jwt(signer, aud, nonce, iat)` (wallet) assembles and
    signs the proof over the `oid4vc-core` `JwtSigner` trait.
  - `KeyProof::parse` → `verify` (issuer) does the structural decode
    (`typ`/`alg`/key-id/claims), then signature + claim checks against a
    `ProofPolicy { audience, nonce, now, max_age_secs }`. The policy is a
    named-field struct on purpose — `nonce` (the `c_nonce` replay binding,
    §8.2.1.1) is easy to forget as a positional arg, so it must be stated
    explicitly. `aud`, `c_nonce`, and `iat` freshness are all enforced.
    **DID resolution stays with the caller** — `parse` surfaces the claimed
    `kid` / `jwk`; the consumer resolves it to a `JwtVerifier` (and must
    confirm the key's algorithm matches `proof.algorithm()`). The module is
    crypto-agnostic (depends only on `oid4vc-core`'s always-on `jwt`
    module, `default-features = false`).

### Changed

- `validate_credential_request` docs now state explicitly that it is a
  **structural check only** and does **not** verify the proof — issuers must
  call `proof::KeyProof` before issuing. (Closing a footgun: the function
  returned `Ok` for a request bearing a forged/expired proof.)

## [0.1.2] - 2026-05-28

### Security

- **HIGH — bearer credential in `Debug`.**
  `PreAuthorizedCodeGrant::pre_authorized_code` is a bearer credential:
  presenting it at the token endpoint is sufficient to obtain an access
  token (and so the credential) on behalf of the holder
  (OpenID4VCI §3.5). Deriving `Debug` meant any
  `tracing::debug!("{:?}", offer)` or panic-on-unwrap would leak it
  into logs. Manual `Debug` impl now redacts `pre_authorized_code`;
  `tx_code` only carries config metadata (input mode, length,
  description) and remains visible.
- Picks up the `affinidi-oid4vc-core` 0.1.2 `alg=none` rejection
  through the workspace path dep (no Cargo.toml edit required — pinned
  on `0.1`).
