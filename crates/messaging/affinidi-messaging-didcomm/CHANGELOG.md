# Changelog

All notable changes to `affinidi-messaging-didcomm` are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this crate follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.14.1] - 2026-06-01

Test-only; no shipped behaviour change (the published crate is
byte-identical to 0.14.0). Patch-level so the workspace `[patch.crates-io]`
keeps `vta-sdk` unified on one didcomm version.

### Added

- **Known-answer test harness for the JOSE crypto primitives**
  (`src/crypto/kat.rs`). Pins the byte-level output of AES-256 Key Wrap
  (a real RFC 3394 §4.6 vector), the ECDH-ES Concat KDF, the ECDH-1PU KEK
  derivation (including the #322 length-prefixed `cc_tag`), A256CBC-HS512,
  and EdDSA. This is the safety net for the #327 migration of this
  crate's hand-rolled crypto into `affinidi-crypto`: the relocated
  implementation must keep these vectors passing byte-for-byte. See
  `docs/adr/0001-centralize-jose-crypto-in-affinidi-crypto.md`.

## [0.14.0] - 2026-05-31

DIDComm v2.1 interop fixes found via an interop matrix against
[credo-ts](https://github.com/openwallet-foundation/credo-ts) (issues
#322, #323, #324). Authcrypt is **wire-affecting** — see Migration.

### Fixed

- **ECDH-1PU Concat KDF: length-prefix the content-encryption tag
  (#322).** `concat_kdf_1pu` fed `cc_tag` into the KDF without the 32-bit
  big-endian length prefix that every other OtherInfo field carries,
  yielding a key-encryption-key four bytes' worth of input different from
  every spec-following implementation (credo-ts/Askar, SICPA
  didcomm-python). `ECDH-1PU+A256KW` authcrypt now interoperates with
  spec-compliant peers. Affects key-agreement keys (X25519, P-256,
  K-256); anoncrypt (ECDH-ES) was never affected.
- **JWS verification: honour `kid` in the per-signature *unprotected*
  header (#323).** `JwsSignature` gained an optional unprotected `header`
  (RFC 7515 §7.2.1). DIDComm / credo-ts / didcomm-python place the signer
  `kid` there; it was previously dropped, so `signer_kid` came back
  `None`. Verification reads the protected header first, then the
  unprotected one.
- **`unpack()`: auto-unwrap sign-then-encrypt (#324).** When a decrypted
  JWE turns out to wrap a JWS (DIDComm v2.1 non-repudiation), the inner
  signature is now verified instead of failing with a missing-field
  error. `signer_public` is then required, and the result reports
  `non_repudiation = true` with the inner `signer_kid`.

### Added

- **Dual-KEK decrypt fallback (transitional).** To keep working during a
  staged rollout, decryption tries the spec-correct KEK first and, on
  AES-Key-Wrap failure, retries with the legacy (pre-0.14, unprefixed)
  KEK. `DecryptedJwe.legacy_kek_used` / `UnpackResult::Encrypted
  { legacy_kek_used, .. }` report when the legacy path was taken — a
  migration signal. Remove the fallback once it stops occurring.

### Changed

- `UnpackResult` is now `#[non_exhaustive]`; `UnpackResult::Encrypted`
  gained `legacy_kek_used`, `non_repudiation`, and `signer_kid` fields.
  Match with a `..` rest pattern.
- `DecryptedJwe` gained `legacy_kek_used`.

### Migration

Packing now emits the **spec-correct** KEK, so a 0.14 sender's authcrypt
cannot be decrypted by an un-upgraded 0.13 recipient. The dual-KEK
fallback only helps the receive side. **Upgrade recipients before
senders**: once all parties run ≥0.14 (they accept both old and new),
senders are safe. The previous behaviour only interoperated with other
affinidi 0.13 nodes — no working external interop is lost.
