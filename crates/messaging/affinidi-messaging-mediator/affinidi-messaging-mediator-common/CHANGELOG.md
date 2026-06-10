# Affinidi Messaging Mediator Common

## Changelog history

## 10th June 2026

### 0.15.5 — `RelayMode` config for inter-mediator relay (#385 item 3)

- Adds the `RelayMode` enum (`Blind` | `Rewrap`, default `Blind`) and two
  fields on `ForwardingConfig`: `relay_mode` and `relay_trusted_mediators`
  (a peer-mediator DID allowlist used only in `Rewrap`). Purely additive —
  `Default` keeps the historical blind-relay behaviour, so existing
  deployments are unchanged. Consumed by the mediator's routing/inbound
  rewrap paths (see `affinidi-messaging-mediator` 0.15.20).

### 0.15.4 — `ForwardingProcessor` compiles for all storage backends

- `tasks::forwarding::processor` is no longer gated on `redis-backend`.
  The processor has been backend-agnostic since the `MediatorStore`
  trait refactor — it consumes only the `forward_queue_*` trait methods
  (Redis implements them with Streams consumer groups; Fjall and Memory
  with an in-process pending-claim emulation) — but the stale cfg gate
  kept it out of Fjall/Memory builds. Its HTTP/WS delivery dependencies
  (`reqwest`, `tokio-tungstenite`) already ride on the `server` umbrella
  feature, so non-Redis builds gain no new dependencies.
- Multi-process scaling (the standalone `forwarding_processor` binary in
  `mediator-processors`) still requires the Redis backend; Fjall and
  Memory forward queues are single-process by design.

## 1st June 2026

### 0.15.3 — clarify `Session::expires_at` semantics (docs)

- **DOCS:** Corrected the `Session::expires_at` doc comment (#308 item 6).
  It previously claimed Redis "honours this directly" and that Fjall/
  memory "sweep expired sessions" based on it — both wrong. The field is
  the issued **access-token** expiry, stamped by the auth handler for the
  authorization response; it is *not* the storage TTL. Session storage
  lifetime is driven solely by the `ttl` argument to `put_session` (Redis
  `EXPIRE`, which doesn't even persist this field; Fjall/memory store
  their own derived expiry). No code change.

### 0.15.2 — session expiry sweep trait method

- Added `MediatorStore::sweep_expired_sessions(now_secs)` returning a new
  `SessionSweepReport { scanned, expired }`. The trait method has a
  **default no-op** so native-TTL backends (Redis) and any external
  implementations compile and behave unchanged. Backends without native
  TTL (Fjall, in-memory) override it to reclaim session records that have
  expired but were never read again — closing the doc-promised-but-missing
  session sweeper noted in #308. Purely additive; no breaking change.

## 9th May 2026

### 0.15.1 — `MediatorStore` access-list signatures take `&[String]`

Trivia release: cleans up four pre-existing clippy lints that get
promoted to errors under `RUSTFLAGS=-D warnings` (which the workspace
CI uses). Surfaced incidentally during PR #311's
`/admin/status` hardening work — the lints had been accumulating on
recent merges because clippy was failing-but-merged on every PR.

- **BREAKING (recompile-only for out-of-tree impls):**
  `MediatorStore::access_list_{add,remove,get}` now take
  `hashes: &[String]` instead of `&Vec<String>`. Callers that pass
  `&vec![...]` keep working (deref-coercion); only out-of-tree
  implementations of the trait need to update their method signatures
  to match. In-tree impls (`RedisStore`, `MemoryStore`, `FjallStore`)
  updated synchronously.
- **FIX:** `clippy::collapsible_match` in `AzureRetryPolicy::classify`
  suppressed inline with a justification comment — the nested
  `match err.kind() { HttpResponse { status } => match *status { ... }`
  form is more readable than the collapsed alternative which splits
  transport-level arms (`Connection`/`Io`) away from HTTP-status
  arms.
- **FIX:** `clippy::uninlined_format_args` in
  `types/problem_report.rs` test code — `panic!("...{}", err)`
  → `panic!("...{err}")`.

## 5th May 2026

### 0.15.0 — Feature-gated server stack + `ACLError` non-exhaustive

Reorganizes this crate's dependency graph so the SDK and other
client-side consumers don't pay for the server's compile-time deps.
Existing server-side consumers (mediator binary, mediator-setup,
mediator-processors, test-mediator) are unaffected because the
new `server` feature is on by default.

- **BREAKING (recompile-only for non-default consumers):** Heavy
  server-side deps — `axum`, `redis`, `reqwest`, `tokio-tungstenite`,
  `aes-gcm`, `argon2`, `metrics`, etc. — are now optional and gated
  behind `server` (default-on) or `redis-backend` (Redis client).
  Default builds compile exactly as before. SDK-style consumers
  (`default-features = false`) get just the lean `types` module
  with `serde`/`serde_json`/`thiserror`/`regex` and nothing else
  — axum/redis/reqwest no longer flow into their build graph
  via this crate.
- **BREAKING:** `ACLError` is now `#[non_exhaustive]`. New variants
  added in future minor releases will be a non-breaking change.
  Downstream code matching on `ACLError` must include a wildcard
  arm. The SDK's `From<ACLError> for ATMError` was updated; outside
  the workspace, callers that exhaustively-matched `Config | Denied`
  must add `_ => …` (or migrate to the SDK's wrapper).
- **NOTE:** `impl GenericDataStruct for String` (introduced in 0.14)
  is a foreign-crate blanket on `String`. If you have your own
  `GenericDataStruct` impl on `String` in a downstream crate, drop
  it — the orphan-rule fence won't bite, but the impl is now
  redundant.
- **FEAT:** `mediator-setup` consumers should depend on this crate
  with `default-features = false, features = ["server"]` (or just
  let `default = ["server"]` apply) to get the secrets module.
  Cloud-secret backends (`secrets-{aws,gcp,azure,vault,keyring}`)
  now imply `server` automatically.

### 0.14.0 — Protocol-vocabulary types relocated here

The mediator's `MediatorStore` trait used to import its protocol
vocabulary (`MediatorACLSet`, `Account`, `Folder`, `ProblemReport`,
…) from `affinidi-messaging-sdk` — wrong direction; storage backends
shouldn't depend on the client SDK. Those types now live here, and
the SDK depends on this crate to re-export them at their original
public paths.

- **FEAT:** New `crate::types::*` module owning the storage-trait–facing
  vocabulary:
  - `types::acls` — `MediatorACLSet`, `AccessListModeType`, plus a new
    lightweight `ACLError` enum (`Config(String)` / `Denied(String)`)
    that replaces `ATMError` as the return type of `MediatorACLSet::*`
    fallible methods.
  - `types::accounts` — `Account`, `AccountType`, `MediatorAccountList`,
    `MediatorAccountRequest`, `AccountChangeQueueLimitsResponse`.
  - `types::acls_handler` — `MediatorACL*Response`,
    `MediatorAccessList*Response`, `MediatorACLRequest`,
    `MediatorACLExpanded`.
  - `types::administration` — `MediatorAdminList`, `AdminAccount`,
    `MediatorAdminRequest`.
  - `types::messages` — `Folder`, `MessageList`, `MessageListElement`,
    `GetMessagesResponse`, `FetchDeletePolicy`, `FetchOptions`,
    `GenericDataStruct`.
  - `types::problem_report` — `ProblemReport`, `ProblemReportSorter`,
    `ProblemReportScope`.
- **CHORE:** Dropped the `affinidi-messaging-sdk` dependency. The
  dependency arrow now points sdk → common.
- **CHORE:** Added `regex` dependency (used by `ProblemReport::interpolation`).

Storage-trait implementors (`RedisStore`, `MemoryStore`, `FjallStore`,
plus any third-party backend) now reference `crate::types::*` directly
instead of importing from the SDK.

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
