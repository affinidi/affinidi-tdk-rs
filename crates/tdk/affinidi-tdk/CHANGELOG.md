# Changelog — `affinidi-tdk`

All notable changes to this crate are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this crate
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

For the full code history see `git log` on `crates/tdk/affinidi-tdk`.

## [0.7.4] - 2026-06-06

### Changed

- Bump `affinidi-crypto` to `0.2` (P-384/P-521 key agreement +
  `#[non_exhaustive]` key-agreement enums, #357). No API change in this
  crate.

## [0.7.3] - 2026-06-01

### Changed

- Release on `affinidi-messaging-didcomm` 0.15 (#327). This crate
  re-exports didcomm as `affinidi_tdk::didcomm`, so consumers now get the
  0.15 envelope crate (crypto centralized in `affinidi-crypto`; the
  `crypto` submodule was removed — its key-agreement types now live at
  `affinidi_crypto::jose::key_agreement`). Wire behaviour is unchanged.
  This release is what unblocks downstream crates (e.g. `vta-sdk`) from
  pulling two incompatible didcomm `Message` types.

## [0.7.2] - 2026-05-31

### Changed

- Bump `affinidi-messaging-didcomm` to 0.14 (DIDComm v2.1 interop fixes:
  ECDH-1PU authcrypt KDF #322, JWS unprotected `kid` #323,
  sign-then-encrypt unpack #324). No `affinidi-tdk` API change.

## [0.7.1] - 2026-05-02

### Deprecated

- `TDK::delete_did_secret`, `TDK::save_secrets_locally`, and
  `TDK::load_secrets` — one-shot wrappers that build a fresh
  `KeyringStore` per call. They were retained from the pre-0.6 API for
  source compatibility; the canonical replacement is to construct a
  `KeyringStore` once at the call site and reuse it (cheaper for
  repeated ops, explicit lifetime). Marked `#[deprecated]` in 0.7.1
  with a removal target of **0.8**.

## [0.7.0] - 2026-05-02

### Breaking

- Upgraded to `affinidi-tdk-common` 0.6 and `affinidi-meeting-place` 0.4.
  Both upstream bumps are SemVer-breaking, so consumers must adopt the
  accessor-method API on `TDKSharedState` / `TDKEnvironment` /
  `TDKProfile` (see the
  [`affinidi-tdk-common` 0.6.0 changelog](../affinidi-tdk-common/CHANGELOG.md#060--2026-05-02)
  for the full migration).
- `secrets::*` methods (`delete_did_secret`, `save_secrets_locally`,
  `load_secrets`) now take `&self` rather than consuming `self`. The
  `self`-by-value receiver was a holdover that prevented chained use.
- `secrets::*` is rewired onto the new
  [`KeyringStore`](https://docs.rs/affinidi-tdk-common/0.6.0/affinidi_tdk_common/secrets/struct.KeyringStore.html)
  rather than the removed free functions in tdk-common 0.5.

### Changed

- `TDK::new` now delegates to `TDKSharedState::new` (which loads the
  on-disk environment, builds the HTTPS client with extra TLS roots from
  `TDKEnvironment::ssl_certificate_paths`, and spawns the
  `AuthenticationCache`) instead of duplicating that logic. Profile
  secrets are loaded into the shared resolver via the public
  `add_profile` API.
- `verify_data` is rewritten with `?`-driven control flow; behaviour is
  identical.

### Added

- `TDK::shared(&self) -> &TDKSharedState` — borrow the shared state
  without bumping the `Arc` refcount. `get_shared_state()` is unchanged.
- `#![forbid(unsafe_code)]` at the crate root — security signal,
  zero-cost.
- This `CHANGELOG.md`.

### Documentation

- Crate-level rustdoc rewritten to describe the new
  `TDK::new` → `TDKSharedState::new` delegation flow.
- Example `did_auth.rs` updated for the new
  `create_http_client(&[])` signature, the
  `TDKEnvironment::profiles()` accessor, and `TDKProfile::take_secrets()`
  to drain plaintext into the resolver.

### Tests

- Three near-duplicate `verify_data` tests deduplicated via a
  `proof_with_vm` helper; behaviour unchanged.
