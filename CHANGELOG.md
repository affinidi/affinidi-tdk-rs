# Changelog

All notable changes to this workspace are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the workspace
crates follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Per-crate version history is summarised here; for the full code history see
`git log`.

## [Unreleased]

## 2026-04-17 — TLS/webpki fix, MSRV 1.94, workspace dep hygiene (PR #292)

### Security

- **`affinidi-did-resolver-cache-sdk` 0.8.4 → 0.8.5** — Dropped the upstream
  `did-web` crate and its `reqwest 0.11` / `rustls 0.21` /
  `rustls-webpki 0.101.x` transitive chain. The cache-sdk now calls
  [`affinidi-did-web`](#) (new) which sits on `reqwest 0.13` /
  `rustls 0.23` / `rustls-webpki 0.103.x` (patched). Clears
  [GHSA-xgp8-3hg3-c2mh](https://github.com/advisories/GHSA-xgp8-3hg3-c2mh) and
  [GHSA-965h-392x-2mh5](https://github.com/advisories/GHSA-965h-392x-2mh5) from
  the cache-sdk dependency chain. Closes
  [#288](https://github.com/affinidi/affinidi-tdk-rs/issues/288).

### Added

- **`affinidi-did-web` 0.1.0 (new crate)** — Minimal in-workspace `did:web`
  resolver following the shape of our other DID method crates (`did-ebsi`,
  `did-scid`, `didwebvh-rs`). Exposes `DIDWeb::new()` / `DIDWeb::with_client()`
  / `resolve(did)` plus `build_url(domain, segments)` for URL construction in
  isolation. Lives at `crates/identity/did-methods/did-web/`.
- **`affinidi-did-resolver-cache-server` 0.7.2 → 0.7.3** — New `-c / --config
  <FILE>` CLI flag (clap-derive) so the binary can be installed in one
  location and started with a config file from another (default stays
  `conf/cache-conf.toml`). Public `server::start_with_config(path)` entry
  point added alongside the existing `start()`.
- **`affinidi-did-resolver-cache-server`** — New `network` feature flag
  (default-on) gating the `/did/v1/ws` WebSocket endpoint. Building with
  `--no-default-features` produces an HTTP-only server that still serves
  `/did/v1/resolve/{did}` and the health endpoints without pulling the
  WebSocket/rustls stack.

### Changed

- **Workspace MSRV bumped `1.90.0 → 1.94.0`** to align with the pinned
  toolchain in `rust-toolchain.toml` and unlock the current AWS SDK line
  (`rust-version = "1.91.1"` on aws-* 1.8.15 / 1.1.12 / etc.).
- **Workspace-wide dep pin relaxation** — every member `Cargo.toml` had its
  version pins loosened: `1.x.y` / `1.x` → `1`, `0.x.y` → `0.x`. Future
  `cargo update` now auto-picks up upstream patches and (for 1.x crates)
  minors without a manifest edit.
- **`cargo update` sweep** after the MSRV and pin changes:
  - AWS SDK stack: `aws-config 1.8.13 → 1.8.15`, `aws-runtime 1.6.0 → 1.7.2`,
    `aws-smithy-http-client 1.1.9 → 1.1.12`, `aws-smithy-runtime 1.10.0 →
    1.11.1`, `aws-sdk-secretsmanager 1.99.0 → 1.103.0`, `aws-sdk-ssm
    1.103.0 → 1.108.0`, and their matching `aws-sdk-sts`/`sso`/`ssooidc` /
    `aws-sigv4` / `aws-smithy-*` bumps.
  - Targeted: `reqwest 0.13.1 → 0.13.2`, `bls12_381_plus 0.8.13 → 0.8.18`
    (removed the retired `hashing` feature from `affinidi-bbs`; the
    underlying hash-to-curve functionality stayed in `elliptic-curve`),
    `rand 0.8.5 → 0.8.6`, plus the usual transitive drift through tokio /
    uuid / webpki-roots / etc.
- **`affinidi-bbs` 0.1.0 → 0.1.1** — Dropped the now-retired `hashing`
  feature on the `bls12_381_plus` dependency. No code change; the same
  hash-to-curve primitives are still enabled via `elliptic-curve`'s
  `hash2curve` feature.
- **`publish = false` sweep** — every workspace crate whose local manifest
  version already matches the version on crates.io is now explicitly
  `publish = false`, so the release workflow only uploads the five crates
  that actually moved this cycle (`affinidi-bbs`,
  `affinidi-did-resolver-cache-sdk`, `affinidi-did-web`,
  `affinidi-oid4vc-core`, `affinidi-tsp`).

### Notes

- Remaining `rustls-webpki 0.101.7` entries in `cargo tree` are AWS SDK
  transitives through `aws-smithy-http-client 1.1.12` → `legacy-rustls` in
  the mediator only. Not visible through the `affinidi-tdk` → `cache-sdk`
  consumer chain (which is what downstream projects like OpenVTC see).

## 2026-04-17 — rand 0.8 advisory fix (PR #289)

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
