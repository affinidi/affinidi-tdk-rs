# Affinidi Messaging Mediator Common

## Changelog history

## 13th June 2026

### 0.15.12 — Admin audit-log query request (simplification T25, part b)

- Adds the `AuditLogList { cursor, limit }` variant to `MediatorAdminRequest`
  (wire tag `audit_log_list`) so the audit log recorded in 0.15.11 can be paged
  back over the admin-management protocol. Additive; a serde wire-contract test
  guards the tag. Response is the existing `MediatorAuditLogList`.

### 0.15.11 — Audit-log store API for privileged changes (simplification T25, part a)

- Adds the storage layer for a privileged-change audit log. New
  `types::audit` module: `AuditLogEntry` (timestamp, actor/target DID hash,
  `AuditAction`, detail), `AuditAction` (set-acl, access-list add/remove/clear,
  account add/remove/change-type/change-queue-limits, admin add/strip),
  `MediatorAuditLogList` (cursor-paginated page), and `AUDIT_LOG_MAX_ENTRIES`
  (10,000 — the log is a bounded ring).
- New `MediatorStore` trait methods `audit_log_record` (append + trim) and
  `audit_log_list` (newest-first, cursor-paginated). Implemented for the Redis
  backend here as a capped `LPUSH`/`LTRIM` list with `LRANGE` paging.
- Additive only — no behaviour change to existing methods. The mediator's
  Fjall/Memory backends implement the same trait methods, and recording is
  wired into the admin/ACL handlers, in the mediator crate. Reading the log
  back over the admin protocol is a later increment (T25b).

## 12th June 2026

### 0.15.10 — Consolidate the access-list method family (simplification T16, part 3)

- Extracts the access-list admission *decision* into `store::ops`: a new
  `ops::access_list_allowed(recipient_acls, Sender)` captures the pure logic
  the in-process backends each inlined — anonymous senders follow the
  `anon_receive` ACL bit; known senders are judged by the recipient's
  access-list mode (`ExplicitAllow` admits only listed senders, `ExplicitDeny`
  admits all but listed). `FjallStore` and `MemoryStore` now call it (they
  still do their own backend-specific account/membership lookups); the decision
  can no longer drift between them. Unit-tested directly. (Redis evaluates the
  equivalent in Lua and is unaffected.)
- Removes the `access_list_count` trait method. It had no production caller —
  callers read a DID's entry count from `account_get().access_list_count` or by
  paging `access_list_list`, and the standalone primitive was redundant. The
  backends' internal count helpers (used by `account_get`/`access_list_add`)
  are retained.
- Trait method count: 61 → 60. `get_did_acl` was evaluated for folding into
  `account_get` but kept deliberately — it is an O(1) read on the per-message
  inbound ACL gate, whereas `account_get` additionally computes the
  access-list count (an O(list) scan on Fjall), so folding would regress that
  hot path. No behaviour change.

### 0.15.9 — Remove legacy 1:1 aliases from `MediatorStore` (simplification T16, part 2)

- Removes ten pure rename-only default methods from the `MediatorStore` trait,
  each of which delegated 1:1 to its canonical counterpart: `get_db_metadata`
  (→ `get_global_stats`), `get_forward_tasks_len` (→ `forward_queue_len`),
  `forward_queue_enqueue_with_limit` (→ `forward_queue_enqueue`),
  `account_change_type` (→ `account_set_role`), the four streaming aliases
  `streaming_register_client` / `streaming_start_live` / `streaming_stop_live`
  / `streaming_deregister_client` (→ `streaming_set_state(state)`), and
  `global_stats_increment_websocket_open` / `_close`
  (→ `stats_increment(WebsocketOpen|WebsocketClose, 1)`). Call sites now invoke
  the canonical method directly. No behaviour change — each alias was a thin
  delegate. The multi-step legacy helpers (`create_session`,
  `update_send_stats`, `add_admin_accounts`, `strip_admin_accounts`, the
  session-rename helpers) are retained. The Redis backend's inherent methods of
  the same names are unaffected (they are storage-level, not trait methods).

### 0.15.8 — Extract shared store decision logic to `store::ops` (simplification T16)

- Adds `store::ops`, a home for backend-agnostic decision logic shared by the
  in-process Rust backends so it can't drift between them. First extraction:
  `ops::delete_message_permitted` (message-delete authorization — Admin
  bypasses; an Owner must be the recipient or the non-anonymous sender), which
  `FjallStore` and `MemoryStore` previously each implemented identically. Now
  unit-tested directly; both backends call it. Additive, no behaviour change.
  (The Redis backend performs the equivalent check in Lua and is unaffected.)

## 10th June 2026

### 0.15.7 — ACL bitfield round-trip safety net (simplification T5)

- **TEST:** adds exhaustive round-trip coverage for `MediatorACLSet`'s
  hand-packed `u64` layout — a full-set `set → to_u64 → from_u64 → get`
  identity test (all 19 bits at once), every capability pair × both
  access-list modes, and a bit-independence test (setting one capability
  flips exactly one bit). These guard the "fields and bit order must stay
  in sync" invariant the module header warns about.
- **DOCS / invariant:** `MediatorACLSet::default()` is **kept** as
  `ExplicitAllow` (deny-by-default: an empty access list denies unlisted
  senders). The T5 plan suggested aligning it to the config's
  `mediator_acl_mode` default (`ExplicitDeny`), but auditing the call sites
  showed `default()` is the recipient-fallback ACL on the direct-delivery
  (`inbound.rs`) and forward (`routing.rs`) paths, so flipping it to
  `ExplicitDeny` would make every default-ACL recipient accept *all*
  unlisted senders — a loosening, not a hardening. The divergence is now
  documented on `AccessListModeType` and pinned by
  `default_is_explicit_allow_deny_by_default`. No behaviour change.

### 0.15.6 — Fail-closed session rename in the trait default (simplification T4)

- `MediatorStore::update_session_authenticated`'s **default** implementation
  previously did `put_session(new)` then `delete_session(old)` — a crash (or
  a failed delete) between the two could leave the old (challenge) session id
  valid alongside the new authenticated one. It now **deletes the old session
  before writing the new one** (via a new `rename_session_fail_closed`
  helper), so an interruption can only *lose* the new session — forcing
  re-authentication — and the two never coexist. An in-place overwrite
  (`old == new`) skips the delete.
- No change to `RedisStore` (`RENAME`+`HSET`) or `FjallStore` (`Batch`),
  which already override the method with a single atomic operation; this
  hardens any backend (e.g. `MemoryStore`, external impls) that falls back
  to the default. Unit-tested (ordering, fail-closed on a failed write, no
  write on a failed delete, in-place overwrite).

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
