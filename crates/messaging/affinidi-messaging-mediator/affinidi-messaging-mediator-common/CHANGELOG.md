# Affinidi Messaging Mediator Common

## Changelog history

## 24th April 2026

### 0.13.0 — Unified Secret Backend

Consolidates the unified-backend foundation (originally landed on
`b20daae` as Phases A–L on 20 April) and the cloud-backends
completion (24 April) into one release.

- **FEAT:** New `SecretStore` trait + pluggable backends under
  `secrets::backends::*`. Single URL (`[secrets].backend = "<url>"`)
  selects which store the mediator uses at boot, with per-entry
  env-var overrides for CI (e.g. `MEDIATOR_SECRETS_ADMIN_CREDENTIAL`).
- **FEAT:** Schema-versioned `Envelope<T>` wrapper for every
  stored entry (`{version, kind, data}`), with end-to-end
  `probe()` via a sentinel round-trip.
- **FEAT:** Well-known key constants + typed `MediatorSecrets`
  accessors for `ADMIN_CREDENTIAL`, `JWT_SECRET`,
  `OPERATING_SECRETS`, `OPERATING_DID_DOCUMENT`,
  `VTA_LAST_KNOWN_BUNDLE`. VTA cache entries carry an HMAC-SHA256
  keyed from the admin credential's private key (HKDF-SHA256,
  salt `"mediator-vta-cache-hmac-v1"`).
- **FEAT:** Feature-gated backends:
  - `secrets-keyring` — OS keychain, base64-encoded values.
  - Always-on `file://` (plaintext JSON) and `file://?encrypt=1`
    (AES-256-GCM + Argon2id; passphrase via
    `MEDIATOR_FILE_BACKEND_PASSPHRASE` / `_FILE`).
  - `secrets-aws` — AWS Secrets Manager with 3-attempt
    exponential-backoff retry keyed off per-backend
    `RetryPolicy`. Throttling / 5xx / transport errors retry;
    NotFound / AccessDenied / Validation short-circuit.
  - `secrets-gcp` — GCP Secret Manager via the official
    `google-cloud-secretmanager-v1` crate (gRPC/tonic, rustls
    via `default-rustls-provider`). Authenticates through
    Application Default Credentials. `put` appends a new
    SecretVersion and falls back to `CreateSecret` →
    `AddSecretVersion` on NotFound; `get` reads
    `versions/latest`; `delete` removes the whole secret.
  - `secrets-azure` — Azure Key Vault via
    `azure_security_keyvault_secrets` 0.14 with
    `azure_identity::DeveloperToolsCredential` (Azure CLI →
    Azure Developer CLI). Secret names normalise `_ → -` to
    fit Key Vault's `[0-9A-Za-z-]` constraint; the mapping is
    bijective because the flat well-known key schema never
    uses `-` inside keys.
  - `secrets-vault` — HashiCorp Vault KV v2 via `vaultrs` 0.8
    (rustls transport, token auth via `VAULT_TOKEN`). URL
    shape is `vault://<host>/<mount>[/<prefix>]`; first path
    segment is the KV v2 mount.
- **FEATURE:** `MediatorSecrets::{store,load,delete}_bootstrap_seed`
  helpers for the non-interactive sealed-handoff phase-1 → phase-2
  seed handoff. Each write updates a `BOOTSTRAP_SEED_INDEX` entry
  with a `created_at` timestamp.
- **FEATURE:** `MediatorSecrets::sweep_bootstrap_seeds(max_age)`
  reaps abandoned phase-1 seeds older than the given age. Failed
  per-entry deletes stay in the index for the next sweep (best
  effort, no silent loss). New `bootstrap_seed_index()` accessor
  exposes pending entries without the internal implementation
  details.
- **BREAKING:** `AdminCredential.vta_did` is now `Option<String>`
  (was `String`). Self-hosted admin credentials set it to `None`;
  VTA-linked credentials set both `vta_did` and `vta_url` to
  `Some`. Half-set combinations are rejected at `store` time with
  `InvalidShape`. Added `AdminCredential::is_vta_linked()` helper.
  `#[serde(default, skip_serializing_if = "Option::is_none")]` so
  the wire format stays compact and forward-compatible.
- **BREAKING:** Renamed every well-known key from the path-style
  `"mediator/<a>/<b>"` form to a flat `"mediator_<a>_<b>"` form.
  Constant Rust names (`ADMIN_CREDENTIAL`, `JWT_SECRET`,
  `OPERATING_SECRETS`, `OPERATING_SIGNING`,
  `OPERATING_KEY_AGREEMENT`, `OPERATING_DID_DOCUMENT`,
  `VTA_LAST_KNOWN_BUNDLE`) are unchanged so rust callers are
  unaffected — but any entries written under the old key strings
  will not be found. Unshipped on main at the time of this
  release, no migration path provided.
- **FEATURE:** New well-known constants:
  `BOOTSTRAP_EPHEMERAL_SEED_PREFIX`, `BOOTSTRAP_SEED_INDEX`,
  `PROBE_SENTINEL_PREFIX`.
- **FEATURE:** `Envelope<T>` gains an optional `created_at: u64`
  (Unix seconds) stamped on every `Envelope::new`. `Option<u64>`
  with `#[serde(default, skip_serializing_if = "Option::is_none")]`
  so pre-change envelopes still deserialize. Consumed by the
  bootstrap-seed sweeper; ignored by `get`/`put`.
- **FEATURE:** `SecretStore::probe()` default impl now writes
  under `PROBE_SENTINEL_PREFIX` + a hyphen-free UUID (simple form)
  — keeps sentinels inside the flat `[a-z0-9_]` class every
  backend accepts verbatim.
- **CHORE:** Retry + backoff helper (`secrets::retry::with_retry`)
  exposes `RetryPolicy<E>` so each backend supplies its own
  transient/terminal classifier.
- **CHORE:** Deleted `backends::stubs` — every scheme now routes
  to a real implementation.

## 28th March 2026

### 0.12.3

- **FIX:** Replaced `deadpool-redis` connection pool with direct `redis` crate
  `ConnectionManager` (auto-reconnecting multiplexed connection)
  - Fixes XREADGROUP BLOCK timeout errors caused by redis 1.x's 500ms default
    response timeout conflicting with blocking commands
  - `DatabaseHandler` now uses `ConnectionManager` for normal operations and a
    dedicated `MultiplexedConnection` (no response timeout) for blocking commands
  - `database_timeout` config now maps to `ConnectionManagerConfig` response/connection timeouts
  - `database_pool_size` config is deprecated and ignored
- **CHORE:** Upgraded `redis` from `1.0` to `1.1` with `connection-manager` feature
- **CHORE:** Cleaned up log messages for readability
  - Removed per-second idle DEBUG spam from message expiry cleanup
  - Simplified DID resolver cache log messages (removed hash arrays)
  - Simplified ACL check and auth handler log messages

## 10th March 2026

### 0.12.2

- **CHORE:** Updated import paths (`affinidi_didcomm` → `affinidi_messaging_didcomm`)

## 5th March 2026

### 0.12.1

- **CHORE:** Updated Redis dependencies
  - `redis` upgraded from `0.32` to `1.0`
  - `deadpool-redis` upgraded from `0.22` to `0.23`
