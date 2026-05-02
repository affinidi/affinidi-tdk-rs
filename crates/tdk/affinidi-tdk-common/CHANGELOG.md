# Changelog — `affinidi-tdk-common`

All notable changes to this crate are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this crate
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

For the full code history see `git log` on `crates/tdk/affinidi-tdk-common`.

## 0.6.0 — 2026-05-02

Major hardening + API tightening release. Multiple breaking changes; see
**Migration** below.

### Breaking

- **`secrets` API replaced.** The free functions `save_secrets_locally`,
  `delete_did_secret`, and `TDKSharedState::load_secrets` are gone. Use the new
  [`KeyringStore`](secrets::KeyringStore) handle, which binds `service_id`
  once and exposes `save` / `read` / `delete` / `load_into`.
- **Keyring on-disk format changed** — entries now store raw JSON bytes instead
  of `BASE64_STANDARD_NO_PAD(json)`. A read-shim auto-detects and migrates
  legacy 0.5.x entries on first read; the legacy reader will be removed in
  **0.8**.
- **`TDKSharedState` fields are now `pub(crate)`.** Use the accessor methods:
  `config()`, `did_resolver()`, `secrets_resolver()`, `client()`,
  `environment()`, `authentication()`. The internal layout can now evolve
  without breaking consumers.
- **`TDKSharedState::default()` removed.** It was a `pub async fn` that
  panicked on real init failures (DID resolver, network). Replace with
  `TDKSharedState::new(TDKConfig::builder().build()?).await?`.
- **`create_http_client` now returns `Result<Client, TDKError>`.** Previously
  panicked on TLS init failure. The crypto-provider install is also now
  `OnceLock`-guarded, so repeated calls are no-ops.
- **`tokio` features narrowed** from `["full"]` to
  `["macros", "rt", "rt-multi-thread", "sync", "time"]`. Downstream binaries
  that were implicitly relying on tdk-common to enable other tokio features
  for them must enable those features explicitly.
- **`TDKError` is now `#[non_exhaustive]`.** Match arms must include a
  wildcard.

### Added

- **`KeyringStore<'a>`** — namespace-scoped handle into the platform native
  credential store. `save` / `read` / `delete` / `load_into`.
- **`secrets::init_keyring()`** — eager, optional keyring initialisation for
  apps that want to surface platform-store failures at startup.
- **`AuthenticationCache::authenticate_default(profile_did, target_did)`** —
  drop-in helper using `DEFAULT_AUTH_RETRIES` and the default timeout.
- **`TDKSharedState::authenticate_profile(&profile, target_did)`** — convenience
  wrapper over `AuthenticationCache::authenticate_default` taking a
  [`TDKProfile`].
- **`TDKSharedState::shutdown()`** — graceful drain. Sends `Terminate` to the
  authentication task and awaits its `JoinHandle`.
- **`tasks::authentication`** public consts: `DEFAULT_AUTH_RETRIES`,
  `DEFAULT_AUTH_TIMEOUT`, `AUTHENTICATED_QUERY_TIMEOUT`,
  `COMMAND_CHANNEL_CAPACITY`.
- **Per-crate `CHANGELOG.md`** (this file).

### Changed

- **`AuthenticationCacheInner`**: removed the always-held `tokio::sync::Mutex`.
  Inner state is now moved into the spawned task by value at `start()` time;
  the `Mutex<Option<...>>` retained on the `AuthenticationCache` is for the
  start/terminate handshake only.
- **`Expiry::expire_after_create`** for auth records: saturating-subtract
  against `UNIX_EPOCH`, returning `Duration::ZERO` for already-expired tokens
  instead of panicking on subtraction overflow.
- **Hash key for the auth cache** now writes both DIDs through `AHasher` with a
  length-prefix delimiter — eliminates the `concat()` allocation and removes
  the `("ab","c") == ("a","bc")` collision class.
- **`TDKEnvironments::load_file`** error messages: distinguish "file does not
  exist" (returns empty) from "stat failed" (propagates as `TDKError::Profile`)
  and from "deserialise failed".
- **`KeyringStore::delete`** treats the `NoEntry` keyring error as success
  (idempotent delete) and propagates real errors.

### Documentation

- Crate-level rustdoc rewritten with a four-section overview.
- `secrets` module documents the threat model, default-store registration
  semantics, and the legacy-format migration policy.
- `TDKConfig::custom_auth_handlers` documented.
- `README.md` updated for 0.6 (drops the retired `messaging` feature row,
  fixes the MSRV badge to 1.94, adds a feature overview and migration guide).
- `SECURITY.md` extended with a brief threat-model summary.

### Tests

- Unit tests added for `KeyringStore` (save/read/delete + legacy-base64
  migration shim, using `keyring_core::mock::Store`),
  `TDKEnvironments::{load_file, save, fetch_from_file}` (using `tempfile`),
  `TDKConfig` builder defaults and overrides, error `From` conversions,
  authentication-cache hash determinism and collision avoidance, and the
  `expire_after_create` already-expired path. **18 tests, all green.**

### Migration

```rust
// 0.5.x:
use affinidi_tdk_common::secrets::{save_secrets_locally, delete_did_secret};

save_secrets_locally("my-app", "did:example:1", &secrets)?;
state.load_secrets("my-app", "did:example:1").await?;
delete_did_secret("my-app", "did:example:1")?;

// 0.6:
use affinidi_tdk_common::secrets::KeyringStore;

let store = KeyringStore::new("my-app");
store.save("did:example:1", &secrets)?;
store.load_into("did:example:1", state.secrets_resolver()).await?;
store.delete("did:example:1")?;
```

```rust
// 0.5.x:
let client = state.client.clone();
let resolver = state.did_resolver.clone();

// 0.6:
let client = state.client().clone();
let resolver = state.did_resolver().clone();
```

```rust
// 0.5.x:
let state = TDKSharedState::default().await;

// 0.6:
let state = TDKSharedState::new(TDKConfig::builder().build()?).await?;
```

## 0.5.3 — 2026-05-02

### Changed

- Replaced the bundled `keyring 3.x` dependency with the new split-out
  [`keyring-core 1.0`](https://crates.io/crates/keyring-core) plus per-target
  platform store crates: `apple-native-keyring-store` (macOS `keychain`, iOS
  `protected`), `windows-native-keyring-store`, and
  `dbus-secret-service-keyring-store` (`crypto-rust`). The public
  `secrets::{save_secrets_locally, delete_did_secret, TDKSharedState::load_secrets}`
  surface was unchanged — a `OnceLock`-guarded
  `keyring_core::set_default_store(...)` runs lazily on the first secret op
  and is a no-op if the host application has already registered its own
  default store.
- Bumped `rustls-platform-verifier` 0.6 → 0.7 for the upstream patch line.
- Retired the empty `messaging` Cargo feature. It only gated the
  `use_atm: bool` field on `TDKConfig` / `TDKConfigBuilder` while the actually
  meaningful gate lives on `affinidi-tdk` (which carries the
  `dep:affinidi-messaging-sdk` linkage). `use_atm` is now unconditionally
  present, matching `affinidi-tdk`'s already-unconditional read of it.

## 0.5.2 and earlier

See workspace `git log` (versions before per-crate changelog).
