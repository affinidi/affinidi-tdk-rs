# Changelog

All notable changes to this workspace are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the workspace
crates follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Per-crate version history is summarised here; for the full code history see
`git log`.

## [Unreleased]

### Added

- **`TestTopology` multi-mediator fixture (TI1).** `affinidi-messaging-test-mediator`
  0.2.10 adds `TestTopology` — spawns N in-process relay-enabled mediators (Blind
  or Rewrap), each wired to its own SDK environment, and a `forward(..)` helper
  that drives the routing-2.0 double forward hop-to-hop. Cross-mediator and
  relay-REWRAP scenarios become plain `#[tokio::test]`s with no Redis and no
  external network. Additive (patch).

### Security

- **OID4VC JWT algorithm allowlist (W5).** `affinidi-oid4vc-core` 0.1.4 adds
  `jwt::decode_compact_jws_verified_with_algs(jws, verifier, allowed_algs)`,
  which rejects a JWS whose header `alg` is not in the caller's allowlist
  **before** verifying the signature — closing algorithm-substitution attacks.
  The old `decode_compact_jws_verified` (any alg but `none`) is **deprecated**.
  **`affinidi-openid4vci` 0.2.0** threads an `allowed_algs` argument through
  `KeyProof::verify` / `verify_signature` (breaking) and ships a
  `DEFAULT_PROOF_ALGS = ["ES256", "EdDSA"]` default; `affinidi-tdk` 0.8.3 picks
  up the new openid4vci. Also adds `oid4vc-core::nonce::NonceStore`, an optional
  in-memory single-use TTL helper, and documents that **replay prevention is a
  MUST** (matching a nonce value is not sufficient).

### Changed

- **`affinidi-sd-jwt-vc` merged into `affinidi-vc` (W18b).** SD-JWT VC is a
  credential format, so it now lives at `affinidi_vc::sd_jwt_vc` (in
  **`affinidi-vc` 0.2.0**) instead of its own crate. The public surface is
  unchanged — only the import path moved. **`affinidi-sd-jwt-vc` 0.2.0** is now
  a deprecated re-export shim kept for one release; direct consumers should
  switch to `affinidi_vc::sd_jwt_vc` and drop the dependency. **`affinidi-tdk`
  0.8.2** re-points `affinidi_tdk::sd_jwt_vc` at the new home (no source change
  for facade users; the `sd-jwt-vc` feature now implies `vc`). See
  [docs/migration/2026-06-sd-jwt-vc-merge.md](docs/migration/2026-06-sd-jwt-vc-merge.md).

## 2026-05-05 — Test-mediator ergonomics, routing self-loopback fix, types relocation

### Breaking

- **`affinidi-messaging-sdk` 0.17.0 → 0.18.0** — `MediatorACLSet::*`
  fallible methods now return `Result<_, ACLError>` instead of
  `Result<_, ATMError>`. `ACLError` is a lightweight enum living in
  `affinidi-messaging-mediator-common::types::acls`. Callers using `?`
  against `ATMError` are unaffected (a `From<ACLError> for ATMError`
  is provided); match-on-variant callers need
  `.map_err(ATMError::from)` or to match `ACLError` directly.

### Changed

- **`affinidi-messaging-mediator-common` 0.13.0 → 0.14.0** — Now owns
  the storage-trait–facing protocol vocabulary (ACLs, accounts, ACL
  handler responses, admin types, message-pickup types, problem
  reports). Storage backends compile against this crate alone — no
  SDK dependency. The SDK re-exports each type at its original public
  path so existing imports keep working.
- **`affinidi-messaging-sdk` 0.17.0 → 0.18.0** — Now depends on
  `affinidi-messaging-mediator-common` (was the other way around).

### Added

- **`affinidi-messaging-mediator` 0.14.1 → 0.15.0** — Routing-2.0
  forward handler now classifies a service URI as local when its
  `(host, port)` matches the mediator's bind address or any
  operator-declared alias. New `[server.local_endpoints]` TOML
  config + matching `MediatorBuilder::local_endpoints` setter for
  declaring URL aliases (load balancer / reverse-proxy deployments).
  Hostname comparison is case-insensitive; ports default to scheme
  defaults for http/https/ws/wss.
- **`affinidi-messaging-test-mediator` 0.1.0 → 0.2.0** —
  `enable_external_forwarding(bool)` builder setter,
  `TestMediatorHandle::{register_local_did, add_user}` runtime
  counterparts to `local_did`, `TestMediator::with_users(["alice",
  "bob"])` convenience for non-ATM consumers, and a "Local vs. remote
  routing" README section. `TestEnvironment::add_user` now mints
  user DIDs whose service URI is the mediator's DID (the routing-2.0
  shape) rather than the mediator's HTTP URL.

## Per-crate changelogs

Some crates maintain their own changelogs alongside their source. Entries below
this line are workspace-wide rollups; per-crate detail lives in the linked
files.

- [`crates/tdk/affinidi-tdk-common/CHANGELOG.md`](crates/tdk/affinidi-tdk-common/CHANGELOG.md)
  — last release: **0.6.0** (2026-05-02, hardening + API tightening,
  KeyringStore, accessor encapsulation).

## 2026-04-20 — `did:key` raw-bytes helpers for HPKE / sealed transfer

### Added

- **`affinidi-crypto` 0.1.4 → 0.1.5** — New `did_key` module (gated on the
  `ed25519` feature) exposes a raw-bytes API for apps doing HPKE, sealed
  transfer, or other non-DIDComm key agreement:
  `ed25519_pub_to_did_key`, `did_key_to_ed25519_pub`, and
  `ed25519_pub_to_x25519_bytes`. The existing multikey-string helpers in
  `ed25519.rs` remain for multikey-native callers such as
  `affinidi-secrets-resolver`. Purely additive — no existing APIs changed.

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
- **MSRV + pin-relaxation cascade bump** — every publishable workspace
  library received a patch version bump (e.g. `affinidi-messaging-sdk
  0.16.3 → 0.16.4`, `affinidi-tdk 0.6.3 → 0.6.4`, `affinidi-messaging-mediator
  0.13.0 → 0.13.1`, `affinidi-data-integrity 0.5.0 → 0.5.1`, and so on across
  all 31 touched libraries) so that downstream consumers receive the new
  1.94 MSRV floor and the loose pins together instead of on a delayed
  schedule. The five crates with *material* changes
  (`affinidi-bbs 0.1.1`, `affinidi-did-resolver-cache-sdk 0.8.5`,
  `affinidi-did-web 0.1.0`, `affinidi-oid4vc-core 0.1.1`,
  `affinidi-tsp 0.1.1`) keep their previously-assigned versions.
- **`affinidi-did-resolver-cache-server` 0.7.2 → 0.7.3** — publish flipped
  back on (was `publish = false` historically; the binary is now
  distributed via crates.io so operators can `cargo install` it).
- **Still `publish = false`**: `affinidi-messaging-helpers` and
  `affinidi-messaging-text-client`, which are repo-internal utilities.

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
