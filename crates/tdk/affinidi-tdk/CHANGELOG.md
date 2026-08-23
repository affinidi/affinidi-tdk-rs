# Changelog — `affinidi-tdk`

All notable changes to this crate are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this crate
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

For the full code history see `git log` on `crates/tdk/affinidi-tdk`.
## 0.8.6

### Added

- `did-webs` feature, re-exporting `affinidi-did-webs` as `did_webs` and joining
  the `did-methods` group.

## [0.8.5] - 2026-08-05

> **BREAKING CHANGE (inherited), shipped as a patch — read this before
> upgrading.** This crate re-exports the messaging SDK
> wholesale — `pub use affinidi_messaging_sdk as messaging;`, under the
> default-on `messaging` feature — so `affinidi-messaging-sdk` 0.19.0's breaking
> changes reach every consumer of this facade:
>
> - **Behavioural:** `messaging::ATM::unpack` (and the message-pickup delivery
>   drain) now reject non-authenticated envelopes by default — only
>   `authcrypt(plaintext)`, `authcrypt(sign(plaintext))` and
>   `anoncrypt(authcrypt(plaintext))` are accepted, with message-layer addressing
>   consistency enforced. Code that previously received anoncrypt, plaintext or
>   signed-only messages will start seeing `ATMError::UnexpectedEnvelope` /
>   `AddressingMismatch`.
> - **Compile:** `messaging::messages::compat::UnpackMetadata` gains two public
>   fields and is now `#[non_exhaustive]`, so downstream struct-literal
>   construction of it stops compiling.
>
> **Why this is a patch and not `0.9.0`.** On the merits it should be a minor
> bump: a `^0.8` consumer picks this up on a routine `cargo update` and inherits
> both breaks with no opportunity to opt in. It ships as a patch anyway, under
> ADR 0003 point 3, because `vta-sdk` — an external crates.io crate this
> workspace itself depends on (via the mediator and `mediator-setup`) — pins
> `affinidi-tdk = "0.8"`. Our root `[patch.crates-io]` redirect only applies
> while the local version satisfies that pin, so `0.9.0` breaks the redirect and
> cargo resolves a *second*, registry copy of `affinidi-tdk` (and transitively of
> `affinidi-messaging-sdk`) into the graph — the duplicate-type failure the
> workspace-duplicates guard catches. This was tried and rejected on exactly
> that evidence, not assumed.
>
> A true `0.9.0` therefore requires **first** releasing a `vta-sdk` that depends
> on `affinidi-tdk` `0.9`, then bumping here — the coordination ADR 0003 point 3
> calls for. Until then the version number cannot carry the warning, so this note
> has to: **treat this patch as a breaking upgrade.**
>
> (`affinidi-messaging-sdk` is not caught by the same constraint even though
> `vta-sdk` also pins it at `"0.18"` — that dependency is optional and is not
> activated in this workspace's feature graph, whereas the `affinidi-tdk` one is.
> Hence the SDK can take its honest `0.19.0` minor while the facade cannot.)
>
> **Migration:** pin `affinidi-tdk = "=0.8.4"` if you are not ready, and see the
> `affinidi-messaging-sdk` 0.19.0 changelog for how to restore the previous
> acceptance behaviour via `ATMConfigBuilder::with_unpack_policy(..)` if a
> protocol legitimately expects an unauthenticated wrapping.

### Changed

- Track `affinidi-messaging-sdk` 0.19.0 (secure-by-default `unpack`). No source
  change in this crate, but the re-export makes the SDK's breaking changes
  observable through `affinidi_tdk::messaging` — see above.

## [0.8.4] - 2026-07-19

### Changed

- Bumped the `affinidi-did-common` requirement from `"0.3"` to `"0.4"`.
  No functional change to this crate: `Document` gained a typed
  `also_known_as` field, which is additive.

## [0.8.1] - 2026-06-13

### Added

- Re-export the DID resolver cache SDK as `affinidi_tdk::did_resolver` so the
  resolver is reachable through the facade (it was the only core dep not
  re-exported).
- Facade-first examples (W13): `examples/did_auth.rs` rewritten to import only
  through `affinidi_tdk::*`; new `examples/resolve_did.rs`. A CI step
  (`cargo build -p affinidi-tdk --examples`) keeps them compiling.

## [0.8.0] - 2026-06-13

### Added

- **Facade feature completion (W12).** Every published capability crate is now
  reachable through a facade feature and re-exported under a module:
  - `credentials` group → `vc`, `sd-jwt`, `sd-jwt-vc`, `mdoc`, `status-list`
    (+ `data-integrity`).
  - `protocols` group → `oid4vc-core`, `siopv2`, `openid4vci`, `openid4vp`.
  - `did-methods` group → `did-web`, `did-ebsi`, `did-scid`.
  - `trust` (`affinidi-trust-lists`), `tsp` (`affinidi-tsp`).
  - All optional and `dep:`-gated; individual + group features both available.
- Facade feature-matrix CI job (`checks-features.yaml`) building default,
  no-default, each group, and all-features.

### Changed

- Foundation deps (`affinidi-crypto`, `affinidi-tdk-common`) kept at
  `major.minor` (caret), **not** exact-pinned: these crates ship frequent patch
  releases (see ADR 0003), so an exact pin would break the facade on every
  patch. Use the facade **or** direct sub-crate deps, not both.
- `did-peer` documented as a code-gate feature (no extra dependency; gates the
  did:peer helpers in `dids`).

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
