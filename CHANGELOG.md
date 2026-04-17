# Changelog

All notable changes to this workspace are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the workspace
crates follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Per-crate version history is summarised here; for the full code history see
`git log`.

## [Unreleased]

## 2026-04-17

### Security

- **`affinidi-crypto` 0.1.1 → 0.1.2** — Replaced the direct `rand 0.8`
  dependency with `rand_core 0.6` (with the `getrandom` feature) to clear
  [GHSA-cq8v-f236-94qc](https://github.com/advisories/GHSA-cq8v-f236-94qc).
  The advisory targets the `rand` crate (`>= 0.7.0, < 0.9.3`); the trait crate
  `rand_core` is unaffected and remains compatible with `ed25519-dalek 2.x`,
  `k256`/`p256`/`p384` 0.13.x, which all consume `rand_core 0.6` traits.
  Closes [#287](https://github.com/affinidi/affinidi-tdk-rs/issues/287).
- **`affinidi-messaging-didcomm` 0.13.0 → 0.13.1** — Same `rand 0.8` → `rand_core 0.6`
  swap.
- **`affinidi-tsp` 0.1.0 → 0.1.1** — Same `rand 0.8` → `rand_core 0.6` swap.
- **`affinidi-oid4vc-core` 0.1.0 → 0.1.1** — Removed unused optional `rand 0.8`
  dependency from the `es256` feature; `Es256Signer::generate` already used
  `p256::elliptic_curve::rand_core::OsRng`.

### Added

- **`affinidi-crypto`** — Infallible `generate_random()` helpers on the `p256`,
  `p384`, and `secp256k1` modules. The existing `generate(secret: Option<&[u8]>)`
  API is unchanged; the new helper is a thin wrapper for the `None` case so
  callers do not have to handle a `Result` that can never be `Err`.
- **`affinidi-crypto`** — Crate-root type alias re-exports for the per-curve
  `KeyPair` structs: `Ed25519KeyPair`, `P256KeyPair`, `P384KeyPair`,
  `Secp256k1KeyPair`. Gated by the same feature flags as the source modules.
- **`affinidi-oid4vc-core`** — `Es256Signer::generate_with_rng<R>(rng)` accepts
  a caller-supplied RNG. Useful for tests that want a seeded RNG. The existing
  `generate()` now delegates to it with `OsRng`.

### Changed

- Workspace transitive dependency refresh via `cargo update`: `tokio 1.50 → 1.52`,
  `rand 0.9.2 → 0.9.4` (closes the `0.9.x` half of the same advisory),
  `uuid 1.22 → 1.23`, plus minor bumps across `wasm-bindgen`, `serde_spanned`,
  `webpki-roots`, etc. No source changes triggered by these updates.
