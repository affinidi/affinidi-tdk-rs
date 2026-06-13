# Affinidi Messaging Mediator

## Changelog history

## 13th June 2026

### 0.15.43 — Record privileged changes to an audit log (simplification T25, part a)

- Every privileged change is now recorded to a bounded, newest-first audit log:
  ACL set, access-list add/remove/clear, account add/remove/change-type/
  change-queue-limits, and admin promote/strip. Each entry captures *who*
  (`actor_did_hash`), *what* (action + short detail), *to whom*
  (`target_did_hash`), and *when* (timestamp).
- Recording is wired into the ACL, account-management, and administration
  DIDComm handlers via a shared `record_audit` helper, fired only after the
  underlying change succeeds. It is best-effort: a failure to record logs a
  warning but never turns a successful admin action into an error.
- The Fjall and Memory backends gain the `audit_log_record` / `audit_log_list`
  store methods (Fjall: a dedicated `audit_log` partition, insertion-ordered
  with an oldest-first trim; Memory: a capped `VecDeque`). The Redis
  implementation ships in mediator-common 0.15.11.
- Conformance suite extended (eleven areas now): a new `audit_log_lifecycle`
  check exercises record, newest-first ordering, and cursor pagination across
  Memory, Fjall, and Redis. Querying the log back over the admin protocol is the
  next increment (T25b). Requires mediator-common >= 0.15.11.

### 0.15.42 — Activate dead metrics + add VTA health metrics (simplification T24)

- Observability depth. The metrics registry defined many metric names that were
  never emitted; this wires up the ones with a natural, non-invasive home and
  adds the previously-missing VTA health metrics.
- **Histogram buckets:** `init_metrics` now configures fixed second-scale buckets
  for every `*_duration_seconds` histogram (was relying on exporter defaults).
- **Forwarding queue depth:** the statistics task now publishes
  `forward_queue_length` (a gauge) by sampling `forward_queue_len()` each cycle —
  works on every backend (Redis/Fjall/Memory).
- **Store totals → Prometheus:** the statistics task already polled the store's
  cumulative metadata every 60s but only *logged* it. It now also publishes those
  totals as counters via `.absolute()` — `messages_stored/delivered/deleted_total`,
  `store_{received,sent,deleted}_bytes_total`,
  `websocket_connections_{opened,closed}_total`,
  `sessions_{created,authenticated}_total`, and `oob_invites_{created,claimed}_total`.
- **VTA health:** the refresh task now emits `vta_refresh_total{result=vta|cache|error}`,
  the `vta_refresh_duration_seconds` histogram, and the
  `vta_last_success_timestamp_seconds` gauge (alert on staleness when the VTA has
  been unreachable across refresh windows).
- Hot request/WS paths are untouched — all new emission is in the existing 60s
  statistics poll and the VTA refresh loop. HTTP request metrics, per-store-op
  latency histograms, and circuit-breaker metrics remain for later increments.
  No version change to any other crate.

## 12th June 2026

### 0.15.41 — Move config loading + validation into the mediator-config crate (simplification T18, part b)

- Completes T18. The env-var override logic + config-file reading
  (`read_config_file`, `apply_env_overrides`) and the boot-time validation checks
  (DID syntax, JWT-expiry ordering, TLS presence, and the suspicious-combo
  warnings) move out of `src/common/config/{helpers,validate}.rs` into the
  `affinidi-messaging-mediator-config` crate, so both the mediator and (next, T19)
  the `mediator-setup` wizard share one implementation.
- The crate gains a lean `ConfigError` (it can't use the server-tier
  `MediatorError`); the mediator maps it back at the single `read_config_file`
  call site. `validate_config(&Config)` stays here as a thin orchestrator over the
  crate's pure check helpers. The relay-warning check is decoupled from the
  mediator's `authz` module (direct `MediatorACLSet` bit accessor) so the schema
  crate needs only the lean ACL types.
- Behaviour-identical; the moved checks keep their unit tests (now in the crate).
  No mediator-common change. mediator-config bumped to 0.1.1.

### 0.15.40 — Extract the `mediator-config` crate: raw TOML schema (simplification T18, part a)

- Phase 4 (config unification) begins. The mediator's TOML *schema* — the
  `*ConfigRaw` serde types that mirror `mediator.toml` — moves into a new,
  dependency-light `affinidi-messaging-mediator-config` crate so it can be shared
  with the `mediator-setup` wizard (which today hand-renders the same TOML with
  no shared types). The crate pulls only serde + the lean tier of
  mediator-common; **no** axum/redis/secrets/SDK.
- Moved: `ConfigRaw` + `ServerConfig` / `StreamingConfig` / `DIDResolverConfig` /
  `SecretsConfigRaw` / `StorageConfig` / `SecurityConfigRaw` / `LimitsConfigRaw` /
  `ProcessorsConfigRaw` (+ the forwarding/cleanup raw structs) and their serde
  default fns. The mediator re-exports them (`pub use
  affinidi_messaging_mediator_config::*`), so every `crate::common::config::*`
  path — and external consumers like `affinidi-messaging-test-mediator` — keep
  resolving unchanged.
- Stayed in the mediator (all runtime concerns): the resolved `Config` /
  `SecurityConfig` / `LimitsConfig` / `ProcessorsConfig`, every `ConfigRaw →
  Config` conversion, the secret-backend/VTA/DID-resolver loading, and (for now)
  the env-var overrides + boot validation. Three conversions that the orphan rule
  no longer allows as inherent/`TryFrom` impls became free fns / an extension
  trait with **verbatim bodies**: `did_resolver_cache_config`,
  `forwarding_config_from_raw`, and `SecurityConfigRawExt::convert`.
- **Scope note:** the env-var override logic and boot-time validation were
  originally slated for this PR but both carry mediator-common's server-tier
  `MediatorError`; they move together in T18b (with a crate-local config error
  type) rather than dragging the server stack into the schema crate. Behaviour is
  byte-identical; a golden test parses the shipped `conf/mediator.toml` into the
  relocated `ConfigRaw`. (`DatabaseConfigRaw` — the one raw field type that
  previously lived in mediator-common — is defined in the config crate itself, so
  mediator-common is unchanged and the schema crate stays publishable against any
  0.15.x.)

### 0.15.39 — Schema-version marker for the Fjall backend (simplification T17, part 2)

- Completes the Fjall/Redis operational-parity work: the Redis backend records
  applied schema migrations in a `SCHEMA_MIGRATIONS` set so a record-shape
  change runs exactly once, but Fjall had no equivalent — a future change to an
  on-disk record shape would silently deserialise old bytes as `serde` defaults
  with no signal. `FjallStore` now writes a **schema-version marker** into the
  `globals` partition and checks it on every `initialize()`.
- New `store::fjall_migrations` module: a `CURRENT_SCHEMA_VERSION` constant, an
  append-only migration registry (`all_migrations()`, empty until the first
  record-shape change), and a `run_migrations` runner. On startup it stamps the
  current version on a fresh (or pre-versioning) data dir, runs any pending
  migrations in ascending order on an older one — advancing the marker only
  after each migration's `up` succeeds, so a crash mid-migration re-runs from
  the same point — and **aborts with a clear `DB_SCHEMA_VERSION_ERROR`** when
  the marker is *newer* than the running binary supports, rather than risk
  misreading records it doesn't understand.
- The version-comparison logic is a pure `plan_schema` function (initialise /
  up-to-date / migrate / too-new), unit-tested across every branch; registry
  invariants (unique, ascending, in-range versions; unique non-empty names) are
  enforced by tests mirroring the Redis migration suite. Behaviour tests cover
  fresh-init stamping, idempotent re-init across a reopen, and the newer-schema
  rejection. No config-file change; no behaviour change for existing data dirs
  (their current shape is the version-1 baseline).

### 0.15.38 — Circuit breaker for the Fjall backend (simplification T17, part 1)

- Gives `FjallStore` a circuit breaker for operational parity with the Redis
  backend, so `/readyz` degrades cleanly on disk errors. The embedded store
  has no per-request connection chokepoint, so the breaker is **probe-driven**:
  the overridden `circuit_breaker_state()` does a single cheap point read
  against the `globals` partition on each call (`/readyz` and `/admin/status`
  already poll it). A healthy read keeps the breaker closed; a disk I/O error
  records a failure and, after `circuit_breaker_threshold` consecutive
  failures, trips it open — `/readyz` then reports the backend unavailable and
  the probe fails fast until the recovery window elapses, when one probe tests
  recovery. `health()` now maps the breaker state to `StoreHealth` instead of
  always returning `Healthy`.
- Tuning reuses the shared `[database]` config: `FjallStore::open_with_circuit_breaker`
  threads `circuit_breaker_threshold` / `circuit_breaker_recovery_secs` (the
  binary uses it; `FjallStore::open` keeps the same defaults — 5 / 10 — for the
  builder and tests). No config-file change required.
- Unit tests cover the healthy-probe, trip-after-threshold, and
  recover-after-window paths; the breaker state machine itself is already
  covered in `mediator-common`.

### 0.15.37 — Route access-list admission through `store::ops` (simplification T16, part 3)

- `FjallStore` and `MemoryStore` now call `mediator-common`'s new
  `store::ops::access_list_allowed` for the sender-admission decision instead
  of each inlining the mode/anon-bit logic. Pure refactor — the decision is
  unchanged and now unit-tested in one place; the backends still perform their
  own account and access-list-membership lookups.
- Drops the backends' `access_list_count` trait implementations following its
  removal from the trait (no production caller). Backend-internal count helpers
  used by `account_get`/`access_list_add` are unchanged.
- Requires `affinidi-messaging-mediator-common` 0.15.10.

### 0.15.36 — Migrate off the removed `MediatorStore` legacy aliases (simplification T16, part 2)

- Updates the ~15 call sites that used the ten rename-only `MediatorStore`
  aliases removed in `mediator-common` 0.15.9 to call the canonical methods
  directly: stats/forward-queue reads (`get_global_stats`, `forward_queue_len`,
  `forward_queue_enqueue`), the account role change (`account_set_role`), the
  WebSocket streaming state transitions (`streaming_set_state(...)`), and the
  websocket-open/close counters (`stats_increment(...)`). No behaviour change —
  the aliases were thin delegates; verified against the store-conformance suite
  and the cross-mediator / WebSocket e2e suites.
- Requires `affinidi-messaging-mediator-common` 0.15.9.

### 0.15.35 — Route store delete-authorization through `store::ops` (simplification T16)

- `FjallStore` and `MemoryStore` now call `mediator-common`'s new
  `store::ops::delete_message_permitted` for the message-delete authorization
  check instead of each carrying their own identical copy. Pure refactor — the
  decision (Admin bypasses; an Owner must be the message's recipient or
  non-anonymous sender) is unchanged and now unit-tested in one place.
- Requires `affinidi-messaging-mediator-common` 0.15.8.

### 0.15.34 — Supervise the WebSocket streaming task (T2 follow-up)

- The WebSocket live-streaming task was the last background task still
  spawned detached, with its `JoinHandle` dropped — a panic killed live
  delivery silently with no restart and no health signal. It now runs under
  the `TaskSupervisor` (`StreamingTask::spawn_supervised`), so a panic or a
  transient startup error (`streaming_clean_start` / `streaming_subscribe`)
  restarts it with capped backoff and surfaces it as a component in `/readyz`.
- Registered **not load-bearing**: if streaming is down, clients fall back to
  message-pickup polling, so it degrades `/readyz` rather than failing it
  (consistent with the statistics/sweep tasks).
- The command channel survives restarts: the `tx` (held in `SharedData` and
  every WebSocket handler) is unchanged, and the `rx` is wrapped in an
  `Arc<Mutex<_>>` that each restart re-locks, so queued commands and live
  socket registrations aren't lost. Side effect: a streaming backend hiccup
  at startup no longer aborts mediator boot — it degrades and retries.

### 0.15.33 — Finish routing `process()` decomposition (T10 follow-up)

- Completes the conservative `process()` decomposition started in 0.15.29 by
  extracting the two remaining inline account-resolution blocks into named
  async helpers:
  - `resolve_next_account` — fetch the next-hop account, registering it with
    the global default ACL on first contact;
  - `resolve_forward_sender` — resolve the account a forward is *from* (the
    `from` DID, auto-registered with a minimal relay ACL on first contact, or
    a synthetic account for an anonymous forward), enforcing `SEND_FORWARDED`.
- `process()` no longer contains any inline account-store operations; its body
  is now ~260 lines (down from ~745 before 0.15.29).
- Pure refactor — behaviour byte-identical (problem reports, the relay-sender
  least-privilege seed, and validation ordering all preserved verbatim).
  Verified by the routing unit tests and the
  `affinidi-messaging-test-mediator` `cross_mediator_forwarding` e2e suite
  (the real Alice → A → B → Bob forward path, blind and rewrap).

### 0.15.32 — Per-DID WebSocket cap + always-on admin TTL (hardening T13)

- **(a) Per-DID WebSocket connection cap.** Adds
  `limits.max_websocket_connections_per_did` (env
  `LIMIT_MAX_WEBSOCKET_CONNECTIONS_PER_DID`, default `100`, `0` = unlimited),
  enforced at WebSocket upgrade so a single DID can't exhaust the global
  `max_websocket_connections` budget. The reserved slot is released by an RAII
  guard, so it's decremented on every connection-teardown path (including the
  early returns the global counter misses). Over-cap connections complete the
  101 handshake and are then closed by the server.
- **(b) Admin-message TTL hardening.** The `created_time` / TTL check that
  bounds admin-message replay was duplicated inline across the three admin
  protocol handlers (`acls`, `administration`, `accounts`). Consolidated into
  one unit-tested helper, `authz::admin_message_ttl_status`, which all three
  now call (byte-identical problem reports). Audit note: the check was already
  enforced **unconditionally** — it never depended on `block_remote_admin_msgs`
  (that flag only gates the admin *signature* check), so the replay window the
  plan flagged was already closed; the helper + tests pin that invariant so it
  can't regress.
- Tests: new `affinidi-messaging-test-mediator` e2e
  (`second_connection_for_one_did_over_the_cap_is_closed`) and unit tests for
  `admin_message_ttl_status` (fresh / stale / future / missing / `expiry == 0`).

### 0.15.31 — Explicit inter-mediator relay flag (simplification T12)

- Adds `security.enable_inter_mediator_relay` (env `ENABLE_INTER_MEDIATOR_RELAY`,
  default `false`) — an explicit switch for acting as an inter-mediator relay
  (accepting anonymous `/inbound` forwards). The anonymous-relay synthesis path
  (`jwt_auth`) now gates on `flag || global_acl_default grants SEND_FORWARDED`.
- **Deprecation (non-breaking this release):** existing mediators that relay
  *implicitly* — `global_acl_default` grants `SEND_FORWARDED` without the flag —
  keep working, but now log a deprecation **warning** at boot
  (`validate_config`). A future release will require the explicit flag
  (`flag && ACL`).
- **Migration:** if your mediator relays inter-mediator forwards, set
  `security.enable_inter_mediator_relay = "true"`. If it should not relay, drop
  `SEND_FORWARDED` from `global_acl_default`. Documented in `conf/mediator.toml`.
- Verified: new unit tests for the gate (`anonymous_session_for` with/without
  the flag) and the boot warning (`warn_implicit_relay`); new
  `affinidi-messaging-test-mediator` e2e
  (`non_relay_mediator_rejects_cross_mediator_forward`) confirms a non-relay
  mediator drops the anonymous cross-mediator hop, while the existing relay e2e
  suite still delivers.

### 0.15.30 — Dedupe authenticate unpack/verify boilerplate (simplification T11)

- The `authenticate` response and refresh handlers carried byte-identical
  copies of the "unpack the DIDComm message, then require it be signed AND
  encrypted" block. Extracted it into `helpers::unpack_auth_message`, so the
  encrypted-AND-authenticated invariant for the unpacked message lives in
  exactly one place. Behaviour unchanged (same `message.unpack` /
  `authentication.message.not_signed_or_encrypted` problem reports).
- The helper takes the already-built `MetaEnvelope` (the two handlers use
  different envelope-parse error codes, so that step stays handler-local) and
  borrows it, so the response handler can still run its post-unpack
  inner/outer `from`-match check. The response handler also keeps its
  separate pre-unpack outer-envelope check (a distinct earlier gate) so error
  precedence is preserved.

### 0.15.29 — Decompose routing `process()` (simplification T10)

- Extracts the deepest, longest blocks of `routing::process()` (~745 lines,
  7-deep nesting) into named, single-purpose functions, taking the body from
  ~745 to ~390 lines and removing the worst nesting:
  - `decode_first_attachment` — the base64/JSON/JWS/links attachment decode;
  - `deliver_forward` — the inner-envelope read, anonymous-receive gate, and
    the ephemeral / remote-enqueue (+ relay re-wrap) / local-store decision;
  - `parse_next_did`, `validate_sender_queue_limit`,
    `validate_recipient_queue_limit`, and a pure `queue_at_capacity`
    predicate.
- **Pure refactor — behaviour byte-identical**: every problem report (code,
  message, args, HTTP status) and the exact validation ordering are
  preserved. Verified by the unchanged routing unit tests plus the
  `affinidi-messaging-test-mediator` `cross_mediator_forwarding` e2e suite
  (which drives the real Alice → A → B → Bob forward path, blind and rewrap,
  trusted and untrusted), and new unit tests for `queue_at_capacity` and
  `parse_next_did`.
- Conservative scope (by design): the account-resolution blocks
  (`next_account` / forwarding-sender) and the remaining short linear
  validations stay inline — they're security-sensitive account-mutation
  paths, already well-commented, and a clean target for a follow-up pass.

### 0.15.28 — Migrate routing + ACL-protocol checks to authz (simplification T9)

- Completes the authz migration so every runtime permission decision flows
  through `common/authz.rs`:
  - routing forward-path gates → `require_capability(ReceiveForwarded)` /
    `require_capability(SendForwarded)` (sender account + anonymous-session
    paths) and the next-hop access-list check → `check_access_list`;
  - the `relay_sender_acls` seed condition and `jwt_auth`'s
    `anonymous_inbound_allowed` → `authz::grants(SendForwarded)`;
  - the refresh handler's blocked-DID gate → `require_capability(NotBlocked)`;
  - the admin-protocol self-change validator `acl_change_ok` (a pure
    authorization predicate) relocated from the mediator ACL handler into
    `authz`.
- After this, `get_send_forwarded` / `get_receive_forwarded` / `get_blocked`
  appear only in `authz` and the `MediatorACLSet` type itself (outside of
  tests). Structure only — behaviour byte-identical (same problem reports,
  same allow/deny verdicts); the routing `relay_sender_acls` unit suite
  passes unchanged. `check_permissions` (admin/self + signature) is left in
  the admin handler — it makes no capability-bit decision, so it's outside
  the authz capability surface.

## 10th June 2026

### 0.15.27 — Migrate handler/direct-delivery ACL checks to authz (simplification T8)

- Adds `authz::check_access_list` (the single wrapper over the store's
  `access_list_allowed`, returning a typed allow/deny) and routes the
  message-path ACL gates through the authz module:
  - `message_inbound` `SEND_MESSAGES` gate → `require_capability(SendMessages)`;
  - direct-delivery sender `SEND_MESSAGES` gate (`inbound.rs`) →
    `require_capability(SendMessages)`;
  - direct-delivery recipient access-list check (`inbound.rs`) →
    `check_access_list`.
- No inline capability/access-list logic remains in those handlers.
  Structure only — behaviour byte-identical (same `authorization.send` /
  `authorization.access_list.denied` problem reports, same anonymous-sender
  handling). Phase 2, building on T7.

### 0.15.26 — Central authz module: auth-time checks (simplification T7)

- Introduces `common/authz.rs` as the single home for permission semantics:
  a `Capability` vocabulary with `require_capability` / `grants` (the one
  definition of what each ACL bit means), plus the relocated
  `authentication_check` (the pre-auth "can this DID connect?" check). Unit
  tested across every capability.
- Migrates the first auth-time call sites onto it and **deletes the old
  inline/duplicated logic**: the blocked-DID gate in `jwt_auth.rs` now calls
  `require_capability(NotBlocked)`, and the `authenticate` challenge/response
  handlers call `authz::authentication_check`. The former
  `common/acl_checks.rs` (`ACLCheck` trait) is removed.
- Structure only — behaviour is byte-identical (same blocked → `Blocked` /
  problem-report responses). First task of Phase 2 (authz centralization);
  the remaining handler/routing ACL sites and the access-list check migrate
  in the following tasks.

### 0.15.25 — Boot-time config invariant validation (simplification T6)

- Adds a single `validate_config` pass at config load (`common/config/validate.rs`)
  that fails fast on hard misconfigurations and warns on suspicious-but-legal
  combinations, replacing the lone inline JWT-expiry check.
- **Errors (abort startup):** `mediator_did` / `admin_did` not valid DID
  syntax; `jwt_access_expiry >= jwt_refresh_expiry`; `use_ssl = true` with a
  missing, empty, or unreadable certificate/key file (previously only caught
  later, at the TLS handshake in the binary path).
- **Warnings (logged, non-fatal):** `admin_did == mediator_did` (privilege
  confusion); `mediator_acl_mode = ExplicitDeny` together with a
  `global_acl_default` of `ALLOW_ALL` (every new DID accepts everything);
  `block_remote_admin_msgs = false` (remote DIDs may send admin messages).
- `admin_did == mediator_did` is a **warning, not an error** despite the plan
  listing it as fatal: the shipped example config (and possibly live
  deployments) use one DID for both, and the validation contract requires that
  no currently-valid deployment starts failing to boot. The footgun is still
  surfaced loudly. Each check is a pure helper with unit tests (valid config
  passes; each bad input fails with the right message).

### 0.15.24 — Fail-closed session rename for the in-memory backend (simplification T4)

- Picks up the fail-closed `update_session_authenticated` default from
  `affinidi-messaging-mediator-common` 0.15.6: `MemoryStore` (which uses the
  trait default) now deletes the old challenge session before writing the
  new authenticated one, so an interruption can never leave both. `RedisStore`
  and `FjallStore` were already atomic here (no behaviour change). No
  mediator-crate source change.

### 0.15.23 — Explicit timeout on request-validation storage calls (simplification T3)

- Adds an explicit, configurable, backend-agnostic timeout
  (`common::storage_timeout::with_storage_timeout`) around the storage
  calls made while *admitting/validating* a request — the routing
  forward-queue-depth admission check and the `/readyz` Redis-metadata and
  forward-queue-length probes. On expiry these now return a clean
  `DatabaseError` (HTTP 503 "Service temporarily unavailable") instead of
  hanging the request (which would amplify load via client retries).
- The bound reuses the existing `[database] database_timeout` (default 2s)
  via a new `SharedData::storage_timeout()` accessor — no new config knob.
- **Context:** the production Redis backend already caps every command at
  `database_timeout` (the request path only uses the response-timeout
  connection; the un-timed connection is reserved for background blocking
  reads), so this is primarily defense-in-depth — it makes the admission/
  probe bound explicit and testable, and extends it to in-process backends
  (Fjall/Memory) and any future backend lacking its own command timeout.
  Verified with a unit test that drives a never-resolving store through the
  timeout.

### 0.15.22 — Supervised background tasks + `/livez` health split (simplification T2)

- **Background tasks are now supervised.** Every long-lived background task
  (statistics, forwarding processor, message- and session-expiry sweeps,
  VTA secrets refresh) is spawned through a new `TaskSupervisor` instead of
  a bare `tokio::spawn`. A task that returns an error or **panics** is
  restarted with capped exponential backoff (1s → 60s); the supervisor
  never gives up. Previously any of these tasks could die silently — e.g. a
  panic in the forwarding processor would stop all forwarding with no
  signal. This is the deliberate "restart-and-degrade, never fail-fast"
  posture: the mediator keeps serving while the fault is logged at ERROR
  with its restart history and corrective hint, and surfaced via `/readyz`.
- **Health-probe contract.**
  - New `GET …/livez` — process-liveness only, always 200 while the server
    answers. An orchestrator should use this for liveness so it does not
    kill a mediator that is still serving traffic while a background
    component is degraded.
  - `GET …/readyz` now folds in supervised-task health under a new
    `components` array (name / state / load_bearing / restarts /
    last_error). A **load-bearing** component that isn't running fails
    readiness (503 `not_ready`); a non-load-bearing one only marks the
    instance `degraded` (still 200, stays in rotation). Load-bearing:
    `forwarding_processor`, `vta_refresh`. Non-load-bearing: `statistics`,
    `message_expiry_sweep`, `session_expiry_sweep`.
- The WebSocket streaming task (which owns its own task lifecycle via
  `StreamingTask`) is not yet routed through the supervisor — a focused
  follow-up.
- Internal: `SharedData` gains a `component_health` registry (a
  `dashmap::DashMap`); the supervisor owns task cancellation, so the
  supervised loop bodies no longer carry their own shutdown `select!`.

### 0.15.21 — Streaming task: remove lock-poison hazard (simplification T1)

- The WebSocket streaming task guarded its in-flight inbox-redelivery set
  with a `std::sync::Mutex<HashSet<String>>` accessed via `.lock().unwrap()`.
  If any holder panicked, the mutex would be poisoned and every subsequent
  `.unwrap()` would panic in turn — turning one fault into a cascading
  failure of the streaming task. Replaced with a `dashmap::DashSet`, which
  has no poisoning and no `.unwrap()`; `DashSet::insert` returns the same
  "newly inserted" boolean the duplicate-drain guard relies on, so behaviour
  is unchanged. `dashmap` was already compiled in the tree (via `governor`),
  so this adds no new dependency to the build graph. First task of the
  mediator architectural-simplification plan (Phase 1).

### 0.15.20 — Per-hop re-wrapping for inter-mediator relay (#385 item 3, #388)

- Final piece of #385. Adds **per-hop re-wrapping** for the inter-mediator
  relay path, behind the new `[processors.forwarding] relay_mode` config
  (`blind` | `rewrap`, default `blind` — **no behaviour change** for
  existing deployments).
- **Why:** in the historical *blind* relay the relaying mediator forwards
  the inner envelope byte-for-byte, so (a) the receiving mediator never
  sees the relaying *peer's* identity — making a trusted-peer allowlist
  impossible at the DIDComm layer — and (b) the inner authcrypt JWE carries
  the original sender's key id (`skid`) in cleartext on the
  mediator↔mediator hop. In `rewrap` mode each mediator re-encrypts the
  inner forward in a fresh `forward` authcrypted *from itself* to the next
  hop: the original sender and inner envelope are hidden from on-wire
  observers, and the receiver gets an authenticated peer identity to
  allowlist.
- **Send** (`routing.rs::rewrap_for_relay`): wraps the inner attachment in a
  new `forward` authcrypted from this mediator to the next hop (carrying the
  running `hop_count`), enqueued instead of the verbatim bytes.
- **Receive** (`inbound.rs::peel_relay_rewrap_layers`): a pre-pass (rewrap
  mode only) that strips `forward`-to-self layers a peer produced,
  authenticates the relaying peer against `relay_trusted_mediators`
  (empty = any; non-empty = members only, anonymous rejected with
  `authorization.relay.untrusted_peer`), and continues on the inner
  envelope. Bounded by `max_hops`. Implemented as a pre-pass so
  `handle_inbound_didcomm`'s body is unchanged — zero regression risk on the
  direct-delivery and normal-message paths; cost is one extra unpack of the
  outer layer for to-mediator messages on a rewrap mediator.
- Both mediators in a relaying pair must use the same mode. Verified
  end-to-end on the memory backend by `affinidi-messaging-test-mediator`'s
  `cross_mediator_forwarding` suite (rewrap round trip + trusted-peer
  admit/reject), now possible because #399 made the forwarding processor
  run on non-Redis backends; the on-wire crypto is covered by
  `tests/relay_rewrap.rs`. Closes #385.

### 0.15.19 — Forwarding runs on Fjall and in-memory backends (#399)

- The forwarding processor now spawns for every storage backend, not just
  Redis. The `#[cfg(feature = "redis-backend")]` gate on the spawn in
  `server.rs` predated the `MediatorStore` trait refactor: the processor
  consumes only the backend-agnostic `forward_queue_*` trait methods, and
  both `FjallStore` and `MemoryStore` already implement the full set
  (blocking reads via `tokio::sync::Notify`, durable/in-process pending
  claims, autoclaim recovery). With the gate removed, a mediator built
  with `fjall-backend` or `memory-backend` forwards messages to remote
  mediators when `[processors.forwarding]` is enabled — which also makes
  external forwarding testable against the embedded test-mediator fixture
  (memory backend) without a Redis instance.
- Per-backend semantics: Fjall forward queues are durable — claimed but
  unACKed entries survive a restart and are recovered via autoclaim
  (regression test added); Memory queues are lost with the process.
  Multi-process forwarding (standalone `forwarding_processor` binary)
  remains Redis-only, as Fjall and Memory are single-process backends.
- New integration tests run `ForwardingProcessor` against `MemoryStore`
  end-to-end (REST delivery to a stub `/inbound` endpoint, plus the
  HTTP-5xx retry/re-enqueue path).
- `conf/mediator.toml`: the `[processors.forwarding]` section now
  documents per-backend queue durability, and the `consumer_group`
  comment no longer describes the field as Redis-specific. mediator-setup
  embeds this template, so wizard-generated configs pick the notes up
  automatically. Notably, a Fjall deployment generated by mediator-setup
  previously built the mediator with `--no-default-features`, which
  compiled the forwarding processor out entirely despite the generated
  config saying `enabled = "true"` — with this release the same build
  forwards as configured.

### 0.15.18 — Boot guard covers network-published (VTA) DIDs (#398)

- The operating-secret coverage guard added in #394 only ran for self-hosted
  DIDs (`did_web_self_hosted` set), so a VTA-managed / network-published
  mediator booted without verifying that its loaded operating secrets can
  actually decrypt its own inbound DIDComm. A VTA key-label/kid mismatch
  (e.g. `vta-sdk` < 0.11.1's label-as-kid bug) therefore surfaced only at
  runtime, failing every message — including the `/authenticate` handshake —
  with `No local secret matches any JWE recipient`, while the mediator
  otherwise booted clean.
- The guard now also runs in the non-self-hosted path: it resolves the
  mediator's own published DID document and verifies the loaded operating
  secrets cover a `keyAgreement` verification-method id, aborting boot with an
  actionable error on a confirmed gap. A resolver failure is logged and
  skipped so a transient DID-host outage cannot block startup; only a
  *confirmed* coverage gap is fatal. Logic extracted into
  `assert_operating_secrets_cover_key_agreement` with regression tests.

## 9th June 2026

### 0.15.17 — Consolidate mediator self-DID resolver preload (#395)

- Follow-up to #392, which preloaded the mediator's own DID document into the
  request-time server resolver so `did:web`/`did:webvh` mediators can pack
  DIDComm responses without resolving their own DID over HTTPS. That fix
  re-deserialised `mediator_did_doc` at server startup and silently swallowed a
  parse failure. This change:
  - carries the typed `Document` parsed during config load on the new
    `Config::mediator_did_document` field, so the server resolver preloads it
    without a second deserialisation (the file-config path now parses the
    document once, not twice);
  - routes both the config-validation resolver and the request-time server
    resolver through a single `preload_self_did` helper, establishing the
    "the resolver knows its own DID" invariant in one place;
  - logs a `warn!` instead of silently dropping a parse failure on the
    builder-constructed fallback path (which only sets the JSON string form).
  - Adds a regression test that `preload_self_did` leaves the DID resolvable
    straight from cache. No behavioural change for did:peer mediators.

### 0.15.16 — vta-sdk 0.11 (canonical provision-integration Trust Task URI)

- Bump `vta-sdk` `0.9.11` → `0.11`. The legacy
  `https://firstperson.network/protocols/provision-integration/1.0` message
  type that `0.9.11` sent was retired upstream and is rejected by current VTAs
  with `validation error: unsupported message type`. `0.11` emits the canonical
  Trust Task URI (`https://trusttasks.org/spec/provision/integration/0.1`) the
  VTA now expects. No mediator source changes; the `affinidi-messaging-didcomm`
  `[patch.crates-io]` still unifies (a single `affinidi-messaging-didcomm` in
  the lockfile), and the `integration` API surface is unchanged.

## 7th June 2026

### 0.15.15 — Redeliver in-flight messages on duplicate-WebSocket replacement (#374)

- When a second WebSocket connects for a DID that already has a live streaming
  channel, the streaming task closed the old channel without telling the
  surviving socket to re-cover what was in flight. A live-stream notification
  published in that instant was stranded — the message is durably stored in the
  inbox (the store both live-pushes *and* persists every non-ephemeral message),
  but a client relying on live delivery never learned of it and the round-trip
  timed out. This was the transport-layer root cause behind the downstream
  `get_key_secret(#key-1)` provisioning timeout (OpenVTC
  `verifiable-trust-infrastructure#302`).
- On a duplicate replacement, the surviving socket now receives a redelivery of
  the recipient's undelivered inbox (`fetch_messages` with `DoNotDelete`,
  paginated, run as a detached task so the shared streaming loop never blocks).
  Redelivery is at-least-once and idempotent by message id — consistent with the
  existing message-pickup delete-to-ack contract. The one-socket-per-DID
  invariant is unchanged: the newest socket still wins.
- Flip-flop damping: a redelivery already in flight for a DID suppresses a
  second concurrent drain, so a duel that replaces the socket every few seconds
  can't amplify into repeated whole-inbox dumps. The drain is bounded
  (`REDELIVERY_MAX`) and logs if the cap is hit.
- New Prometheus counters: `websocket_duplicate_replacements_total`,
  `websocket_redelivered_messages_total`, and `websocket_duplicate_churn_total`
  (rapid replacement within a 5s window) to make the flip-flop diagnosable in
  production.
- Known limitation: ephemeral (`return_route=all`) messages are not stored and
  therefore cannot be redelivered — but those are synchronous same-socket
  responses, not the live-streaming duplicate case addressed here.

## 6th June 2026

### 0.15.14 — P-384/P-521 key agreement (#357)

- The DIDComm-compat pack/unpack paths now recognise P-384 and P-521
  key-agreement keys (sender secret resolution, recipient verification-method
  decoding, and the secret-key-type → curve mapping). Previously these curves
  were silently skipped by a wildcard arm, so a mediator could not pack to or
  unpack from a P-384/P-521 peer.
- Updated `vta-sdk` to `0.9.11` and `didwebvh-rs` to `0.5.4`, both of which
  now build on `affinidi-crypto 0.2` / `affinidi-data-integrity 0.7`. This
  resolves the earlier un-unification where the older `vta-sdk 0.9.x`
  (`crypto 0.1`) and `didwebvh-rs 0.5.3` (`data-integrity 0.6 → crypto 0.1`)
  dragged a second `affinidi-crypto` into the tree. The whole crate now
  resolves to a single `affinidi-crypto 0.2.0`.

## 5th June 2026

### 0.15.13 — coverage-build fix + redis 1.2

- **FIX (#351):** Gated the `store::auth_flow_harness` module (added in
  0.15.11) to `#[cfg(all(test, any(feature = "fjall-backend", feature =
  "memory-backend")))]`. Its only callers live in the Fjall and memory
  test modules, so under a `redis-backend`-only build (the coverage CI
  job) the harness was dead code and tripped `-D warnings`, failing the
  job. Test-only; no shipped behaviour change.
- **DEPS:** Bumped `redis` `1.1` → `1.2` (compatible upgrade).

## 1st June 2026

### 0.15.12 — release on didcomm 0.15

- Release on `affinidi-messaging-didcomm` 0.15 (#327). The
  `didcomm_compat` layer now imports key-agreement types from
  `affinidi-crypto`'s `jose` module (the `didcomm::crypto` module was
  removed); `affinidi-crypto` is added as an optional dep under the
  `didcomm` feature. No behaviour change.

### 0.15.11 — backend-parameterised auth-flow tests

Completes #308 (items 5–6). Test-only + docs; no shipped behaviour change.

- **TEST:** Added a backend-agnostic auth-flow harness
  (`store::auth_flow_harness::run_auth_session_flow`) that drives the full
  `create_session → update_session_authenticated → get_session(new, did)
  → refresh-hash rotation → delete_session` sequence the auth handlers
  run, and call it from both the Fjall and in-memory test modules. Fjall
  and memory now have parity with the Redis path's auth integration
  coverage.
- Pairs with the `Session::expires_at` doc clarification in
  `affinidi-messaging-mediator-common` 0.15.3 (#308 item 6).

### 0.15.10 — Fjall session-op consistency & atomicity

Hardening for the Fjall backend's session path (items 2–4 of #308). No
config or API change; behaviour-preserving except where noted.

- **FIX (consistency):** `put_session` / `delete_session` now take the
  cross-partition `write_lock` like every other write op in the backend,
  so session writes stay sequenced against other partitions.
- **FIX (atomicity):** `update_session_authenticated` is overridden to
  promote-and-rename a session in a single `db.batch()`. The trait
  default does `put_session(new)` then `delete_session(old)`, leaving a
  window where both keys exist — and on a crash mid-rename the old
  `ChallengeSent` key lingered until lazy expiry. The new + old keys now
  appear/disappear together.
- **FIX (robustness):** `update_refresh_token_hash` is overridden with a
  targeted read-by-key/mutate/write-back. The trait default round-trips
  through `get_session(session_id, "")` + `put_session`, which can
  substitute a corrupt `Session::default()` (state `Unknown`) and resets
  the TTL. The override rewrites only `refresh_token_hash`, preserving
  every other field **including the existing expiry** (matching Redis'
  `HSET`), and now **errors on a missing session** instead of fabricating
  a record.

### 0.15.9 — Fjall/in-memory session expiry sweeper

Closes the missing background session sweeper tracked in #308.

- **FIX:** Backends without native TTL (Fjall, in-memory) expire
  sessions only lazily on `get_session`, so a session that is created
  but never read again — e.g. a one-off DID running
  `/authenticate/challenge` and disappearing — accumulated on disk / in
  the map unbounded. A new background task now calls
  `MediatorStore::sweep_expired_sessions` on a 300s cadence to reclaim
  them. On Redis the sweep is a no-op (native `EXPIRE` already handles
  it), so the loop just ticks and finds nothing.
- **CONFIG:** New `[processors.session_expiry_cleanup]` block with a
  single `enabled` flag (default `true`), overridable via
  `PROCESSOR_SESSION_EXPIRY_CLEANUP_ENABLED`. The block is optional —
  configs written before this release parse unchanged and default to
  enabled.
- Requires `affinidi-messaging-mediator-common` 0.15.2 (new
  `sweep_expired_sessions` trait method + `SessionSweepReport`).

### 0.15.8 — vta-sdk 0.9 (didcomm 0.14 unification)

Dependency-only release; no mediator config or API change.

- **CHORE:** Bumps `vta-sdk` from `0.7` to `0.9` (both the mediator's
  `integration` dependency and the `mediator-setup` wizard's
  `provision-client` / `test-support` dependencies). vta-sdk 0.7 pinned
  `affinidi-messaging-didcomm` at `0.13`, which the workspace
  `[patch.crates-io]` redirect (now at `0.14`) no longer satisfied — so
  the build dragged in an unpatched `affinidi-messaging-didcomm 0.13.3`
  from crates.io alongside the in-tree `0.14.0`. vta-sdk 0.9 pins
  `0.14`, so the patch re-applies and the whole tree unifies on the
  in-tree `0.14.0` (carrying the DIDComm v2.1 interop/security fixes
  from 0.15.7). The duplicate `0.13.3` copy is gone.
- `mediator-setup` bumped to `0.1.5` for the coordinated vta-sdk pin.

## 31st May 2026

### 0.15.7 — DIDComm v2.1 interop fixes (via affinidi-messaging-didcomm 0.14)

Picks up `affinidi-messaging-didcomm` 0.14, which corrects the ECDH-1PU
authcrypt KDF (#322), reads the signer `kid` from the JWS unprotected
header (#323), and auto-unwraps sign-then-encrypt messages (#324). The
mediator's authcrypt — including the DID-authentication handshake — is
now spec-correct and interoperable with credo-ts / didcomm-python. The
0.14 dual-KEK decrypt fallback keeps the mediator able to receive from
not-yet-upgraded peers during rollout. No mediator config or API change.

### 0.15.6 — CORS policy in the setup wizard + sub-domain wildcards

Additive, backward-compatible release. Existing `cors_allow_origin`
configs keep their current behaviour; no configuration changes are
required.

#### Added

- **CORS policy question in `mediator-setup`.** The Security series of
  the setup wizard now asks for the browser CORS policy and writes the
  result to `[security].cors_allow_origin`. Three choices:
  - **Deny all cross-origin** (default) — leaves `cors_allow_origin`
    unset (the mediator's existing default-closed posture).
  - **Allow any origin** — writes `cors_allow_origin = "*"`. Suggested
    for public mediators; safe because the endpoints gate on a bearer
    token, not an ambient cookie.
  - **Specific domains** — collects a validated, comma-separated
    allowlist (written verbatim).
  The choice is also surfaced on the review screen and round-trips
  through the build-recipe (`[security].cors` / `cors_domains`).
- **Sub-domain wildcard origins.** `cors_allow_origin` now accepts
  leftmost-label wildcards such as `https://*.affinidi.com` alongside
  exact origins. A wildcard matches any sub-domain of the suffix (at any
  depth) with an exact scheme and port; the matched request `Origin` is
  echoed back, so responses stay CORS-spec compliant (the
  `Access-Control-Allow-Origin` header itself has no wildcard form). A
  wildcard does **not** cover its own apex — add `https://affinidi.com`
  explicitly if needed. The same matcher backs both the REST `CorsLayer`
  and the WebSocket `Origin` defence-in-depth check, so the two cannot
  drift apart.

## 24th May 2026

### 0.15.5 — vta-sdk 0.7 + messaging security fixes

Security fixes plus the coordinated `vta-sdk` 0.7 wire bump. No
configuration changes required — `vta-sdk` was an internal dep and
the trust-task surface has no external consumers yet.

#### Security

- **FIX (security):** direct-delivery ACL bypass. On the direct-
  delivery branch (envelope addressed to a local account, not the
  mediator), the mediator cannot decrypt the JWE and so cannot
  cryptographically verify the sender. `envelope.from_did` is read
  from the unverified `skid`/`apu` and was then trusted for the
  per-DID send ACL and the recipient's `access_list_allowed` check.
  An authenticated session could therefore set `skid` to any
  allow-listed DID and bypass both checks. When
  `force_session_did_match` is enabled, the mediator-destined branch
  already bound the verified sender kid to `session.did`; this
  release applies the same policy to direct delivery so the ACL
  checks operate on the authenticated session identity.
- **FIX (security):** unbounded `/outbound` request list.
  `message_outbound_handler` iterated `body.message_ids` issuing one
  database get (and optionally a delete) per id, with no upper
  bound, letting any LOCAL-authenticated client pin a worker on
  database round-trips with a single request. Now rejects requests
  over `config.limits.listed_messages` (default 100), matching the
  existing `message_delete` pattern.
- **FIX (security):** WebSocket `ws_size` cap enforced too late.
  The `/ws` handler only checked `msg.len() > limits.ws_size` *after*
  `socket.recv()` returned, by which point tungstenite had already
  buffered the full message (default `max_message_size` 64 MiB,
  `max_frame_size` 16 MiB). With the default `ws_size` of 10 MiB an
  authenticated client could push frames ~6× the configured cap and
  have them allocated before rejection. Sets `max_message_size` /
  `max_frame_size` on the `WebSocketUpgrade` from `limits.ws_size`
  so oversized frames are dropped during framing.
- **FIX (security):** redact tokens in `AuthRefreshResponse` `Debug`.
  The mediator-side response carries the freshly minted bearer
  `access_token` plus the rotated one-time `refresh_token`. The
  derived `Debug` impl printed both in the clear; any tracing of
  the response struct (or a panic in the refresh handler that
  captured it) would dump session credentials into the mediator's
  logs. Replaces the derived `Debug` with a manual impl that
  redacts both token fields while keeping the expiry timestamps
  visible, matching the treatment applied in `affinidi-did-
  authentication` and `affinidi-messaging-sdk`.

#### Dependencies

- **CHORE:** Bumps `vta-sdk` from `0.6` to `0.7` to stay on a single
  wire version with the mediator-setup wizard. The 0.7 release
  renames the trust-task wire URIs to the framework-canonical
  `trusttasks.org/spec/...` form and threads `did → subject`
  through the auth challenge / authenticate payloads. The wire
  break is intentional — the trust-task surface has no external
  consumers yet.
- **CHORE:** Workspace MSRV raised from `1.94.0` to `1.95.0` to
  satisfy `vta-sdk@0.7.0`'s MSRV (workspace `rust-toolchain.toml`
  and the four GitHub Actions workflows that pin the toolchain).
- **CHORE:** Picks up `affinidi-messaging-didcomm 0.13.3` and
  `affinidi-messaging-sdk 0.18.3` via the workspace path deps
  (released the same day for additional security hardening). All
  dependents pin major.minor (`0.13` / `0.18`), so no
  `Cargo.toml` edits required.

`affinidi-messaging-test-mediator` re-exports the mediator with a
caret `version = "0.15"` pin and picks up 0.15.5 automatically — no
cascade bump needed.

## 21st May 2026

### 0.15.4 — browser-friendly WebSocket auth + configurable CORS wildcard

Lets a browser-based DIDComm client talk to the mediator directly. All
changes are additive for existing native clients — the
`Authorization: Bearer` WebSocket path is unchanged and exercised by a
regression test.

- **FEAT (WebSocket auth):** the `/ws` upgrade now also accepts the
  session JWT via the `Sec-WebSocket-Protocol` request header as a
  `bearer.<jwt>` entry, because browsers can't set an `Authorization`
  header on `new WebSocket(...)`. The server strips the literal
  `bearer.` prefix (prefix-strip, not split, so the JWT's own `.`
  separators survive) and validates the token identically to the
  header path — same signature/claims/expiry/DID-match/ACL checks,
  same `Session`, same JWT-expiry timeout. The 101 response **never**
  echoes the bearer entry; only genuine (non-`bearer.`) application
  subprotocols the client offered are echoed.
  - Client call: `new WebSocket("wss://…/ws", ["bearer." + token])`.
    Real browsers accept a 101 that selects no subprotocol; strict
    non-browser clients that require subprotocol confirmation should
    offer a benign app subprotocol alongside the bearer entry
    (Kubernetes `base64url.bearer.authorization.k8s.io` convention),
    which the server echoes.
- **FEAT (CORS):** `security.cors_allow_origin` now accepts a single
  `*` to allow ANY origin (maps to `AllowOrigin::any()`), in addition
  to the existing comma-separated explicit allowlist. Safe here because
  these endpoints authenticate with a bearer token, not an ambient
  cookie — a wildcard creates no CSRF exposure, and `allow_credentials`
  is never set. Previously a `*` value would **panic at startup**
  (tower-http's origin list rejects wildcards); it is now parsed into
  the allow-any policy. Default remains unset = no cross-origin access.
- **FEAT / behavioural note (WebSocket `Origin` check):** as
  defence-in-depth, `/ws` upgrades now enforce a server-side `Origin`
  allowlist mirroring the CORS policy (WebSocket upgrades aren't subject
  to CORS preflight, but browsers still send `Origin`). A browser
  upgrade whose `Origin` isn't permitted is refused with 403 — the
  check runs before auth, so a disallowed origin is rejected even with
  a valid token. **Requests with no `Origin` header (all native
  clients, incl. the Rust SDK) are unaffected.** With the default
  (unset) CORS policy, any upgrade that announces an `Origin` is
  refused; set `cors_allow_origin` (explicit origins or `*`) to permit
  browser WebSocket clients. No released client could have relied on
  the prior behaviour — browser WebSocket auth did not exist before
  this release, and native clients send no `Origin`.
- **DOCS:** `conf/mediator.toml` `cors_allow_origin` comment rewritten —
  documents `*` support and its bearer-token safety rationale, the
  WebSocket `Origin` check, and an operational note to redact the
  `Sec-WebSocket-Protocol` request header at fronting proxies /
  load-balancers (the JWT rides in it for the browser path; `wss://` +
  short `jwt_access_expiry` mitigate; the mediator itself never logs
  it).
- **REFACTOR:** JWT token→`Session` validation extracted into a shared
  `authenticate_token()` in `common/jwt_auth.rs`, called by both the
  `Authorization` header extractor and the new WebSocket subprotocol
  path so both apply byte-identical checks.
- **TEST:** 14 unit tests (subprotocol token extraction, echo-filter,
  `Origin` allowlist, CORS `*`/list/none parsing). End-to-end coverage
  ships in `affinidi-messaging-test-mediator` 0.2.3.

## 9th May 2026

### 0.15.3 — `/admin/status` auth + `/readyz` redaction

Defensive hardening of the public HTTP surface. **No secret material
was ever disclosed** by either endpoint — what was exposed was
infrastructure metadata (uptime/throughput/queue depth/masked Redis
URL on `/admin/status`; `secrets_backend_url` and probe-error text on
`/readyz`) that helps an attacker fingerprint a deployment. This
release closes that reconnaissance channel.

- **BREAKING (HTTP):** `GET /admin/status` is now gated on an
  admin-tier session. Unauthenticated requests get 401 from the
  existing JWT extractor; authenticated non-admin sessions get 403.
  Admin tier = `Admin`, `RootAdmin`, or `Mediator` account_type.
  External tooling that scrapes `/admin/status` without auth must
  update — the in-tree `mediator-monitor` ships a matching update in
  this PR.
- **FIX:** `GET /readyz` no longer echoes `secrets_backend_url` (was
  in three places: per-check success entry, per-check failure entry,
  top-level field). The probe failure message is now generic
  (`"Secret backend probe failed"`) and the underlying error is
  surfaced via a `warn!` log instead of the response body so it
  doesn't leak hostnames / ARNs / Vault paths / project IDs to an
  unauthenticated probe path. The boolean `secrets_backend_reachable`
  is still returned so k8s / load-balancer readiness probes work
  unchanged.
- **CHORE:** Doc comments on `Config::secrets_backend_url`,
  `MediatorBuilder::secrets_backend_url`, and the in-builder default
  comment updated to reflect the new exposure surface (startup logs
  + authenticated `/admin/status` only — never `/readyz`).
- **CHORE:** `MemoryStore::account_add` rewritten to use the
  struct-update form so it stops tripping
  `clippy::field_reassign_with_default`.
- **TEST:** Integration test `admin_status_returns_metrics_json`
  renamed to `admin_status_requires_authentication` and rewritten to
  assert 401 on an unauthenticated GET (was: assert 2xx + JSON
  shape, exactly the behaviour this release removes). The existing
  `mediator_serves_readyz` test continues to pass — it only asserts
  200/503, not specific JSON fields.

## 6th May 2026

### 0.15.2 — `api_prefix` normalisation + startup-panic fix

Foolproof handling of `api_prefix`. Previously, certain configurations
caused a deterministic startup panic before the listener bound (which
manifested as a permanent 502 from any reverse proxy fronting the
mediator) or silently produced wrong route paths.

- **FIX:** Setting `api_prefix = ""` no longer panics at startup.
  The health/readiness/admin/metrics route registration in `server.rs`
  was string-concatenating the prefix into the path, producing
  `"healthchecker"` (no leading `/`) which axum rejects. With the
  empty prefix now normalised to `""` and a `join_api_path` helper
  used to build full paths, the resulting route is always
  `/healthchecker` (or `/foo/healthchecker` when prefixed).
- **FIX:** `api_prefix = "/foo"` (no trailing slash) no longer
  silently produces glued-together routes like `/fooreadyz`. All
  routes go through `join_api_path` which inserts the separator
  correctly.
- **FIX:** WebSocket endpoint URL builder no longer emits
  `ws://host:portws` when the prefix is empty — uses `join_api_path`
  for the WS suffix, producing `ws://host:port/ws`.
- **FEAT:** New helpers `normalize_api_prefix` and `join_api_path` in
  `common::config::helpers`. The canonical form is `""` (mount at
  root) or `"/<segment>"` with no trailing slash — the form axum's
  `Router::nest` requires. All of `"/foo/"`, `"/foo"`, `"foo/"`,
  `"foo"`, `"  /foo/  "` normalise to the same canonical value.
- **FEAT:** Config-load emits an `INFO` log line when normalisation
  changes the configured value, so operators can spot config drift.
- **CHG:** `MediatorBuilder::api_prefix(...)` now accepts any of the
  above forms and normalises internally. The previous validation
  (`api_prefix must end with '/'`) is removed since normalisation
  makes it unnecessary.
- **CHG:** Default `Config::api_prefix` is now `"/mediator/v1"`
  (canonical) rather than `"/mediator/v1/"`. The published
  `http_endpoint` URL still ends with `/` (preserved contract for
  callers that concatenate suffixes).
- **TEST:** 7 new unit tests covering normalisation edge cases —
  empty/whitespace/`/`/multi-slash collapse, leading/trailing slash
  stripping, idempotence, and `join_api_path` always returning a
  valid axum path.
- **DOC:** `conf/mediator.toml` documents the accepted forms inline.

Existing configs using `api_prefix = "/mediator/v1/"` are
byte-for-byte compatible — same routes, same URLs, same DID-Doc
service endpoints. The change is purely additive: it accepts more
inputs without changing any working ones.

## 5th May 2026

### 0.15.1 — IPv6 host normalization + wildcard-bind warning

Patch follow-up to 0.15.0 fixing two real-world holes in the
self-loopback routing fix.

- **FIX:** IPv6 host normalization. `Url::host_str()` returns IPv6
  literals wrapped in brackets (`"[::1]"`) while
  `SocketAddr::ip().to_string()` returns them bare (`"::1"`). The
  routing handler's lookup and the startup-time authority cache now
  funnel both forms through a shared `normalize_host` helper, so a
  `http://[::1]:7037/` DID-Doc URI matches a `[::1]:7037` bind
  address. Without this, IPv6-bound mediators silently never matched
  themselves and devolved to remote forwarding.
- **FEAT:** Startup warning when `listen_address` is bound to a
  wildcard (`0.0.0.0` / `::`) and `local_endpoints` is empty.
  Service endpoints in DID Docs essentially never use the literal
  `0.0.0.0`, so the default deployment shape silently rendered the
  loopback fix a no-op. The warning points operators at the
  `local_endpoints` config field.
- **DOC:** `local_endpoints` is now documented in the sample
  `conf/mediator.toml` with a commented example.
- **TEST:** Routing test coverage extended — IPv6 (both bracketed
  and bare host forms), `wss://`, query/path/fragment URIs, and a
  `compute_self_authorities` integration test that round-trips an
  IPv6 listen address through the lookup path.
- **REFACTOR:** `compute_self_authorities` and `default_port_for`
  hoisted to `pub(crate)` so the routing tests can drive them
  directly. New `compute_self_authorities_from(listen, endpoints)`
  takes the two relevant fields rather than a full `Config`.

### 0.15.0 — Self-loopback routing fix + `local_endpoints` config

Fixes a subtle routing-2.0 bug where a `forward` envelope whose
next-hop DID Document advertised an HTTP/WS URL pointing back at
*this* mediator (different hostname, same port; or via a load
balancer) was treated as remote and pushed onto `FORWARD_Q` —
where it tried (and usually failed) to relay back to itself.

- **FEAT:** `service_endpoint_for_remote` (routing 2.0 forward
  handler) now treats a service URI as local when its
  `(host, port)` matches the mediator's bind address or any
  operator-declared alias. Hostnames are compared
  case-insensitively; the URL's port falls back to the
  scheme-default (80/443) when omitted.
- **FEAT:** New `[server.local_endpoints]` TOML field accepting a
  list of full URLs (`http://`, `https://`, `ws://`, `wss://`) to
  declare as local. The bind address is always treated as local, so
  this is only needed when the mediator is reachable via hostnames
  or ports that differ from its `listen_address` — e.g. behind a
  load balancer or reverse proxy.
- **FEAT:** `MediatorBuilder::local_endpoints` mirror of the config
  field for embedding callers (test mediator, custom binaries).
- **CHORE:** New `SharedData::self_authorities` field caches the
  parsed `(host, port)` set at startup so the routing hot path
  doesn't re-parse on every forward.
- **CHANGED:** Bumped `affinidi-messaging-mediator-common` pin from
  `0.13` to `0.14` (relocated protocol-vocabulary types) and
  `affinidi-messaging-sdk` pin from `0.17` to `0.18` (consequent
  signature change to `MediatorACLSet::*` returning `ACLError`).

### 0.14.1 — Drop `--cfg tracing_unstable` requirement

The statistics task previously logged its `tags` HashMap as a
`valuable::Valuable` field, which required the unstable `valuable`
support in `tracing-core` and forced every consumer to set
`rustflags = ["--cfg", "tracing_unstable"]` in their own
`.cargo/config.toml`. Now the tags are logged via standard `Debug`
formatting (`?tags`), so the cfg flag is no longer needed.

- Removed `valuable` features from the `tracing` and
  `tracing-subscriber` dependencies.
- Removed the workspace and crate-level `.cargo/config.toml` files
  that set `--cfg tracing_unstable`.
- External consumers of the mediator crate can drop the same
  `.cargo/config.toml` from their own repositories.

The user-facing log shape is unchanged in spirit; tags now render
as Debug output instead of a structured object. Operators relying
on machine-parseable tag fields in JSON logs should switch to
including the relevant tag values as individual `info!` fields if
they need typed access — none of the affinidi-* deployments did so
when this change landed.

## 24th April 2026

### 0.14.0 — Setup Wizard, Monitoring, Unified Secret Backend

Consolidates the wizard/monitoring/Redis-optimisation work (16
April), the unified-backend foundation (Phases A–L on 20 April),
and the cloud-backends completion (24 April) into one release.
Replaces the fragmented pre-branch secret model
(`[vta].credential` / `[security].mediator_secrets` /
`[security].jwt_authorization_secret`) with a single
`[secrets].backend = "<url>"` pointer and six fully-implemented
backends.

**BREAKING**
- Hard-cut from `[vta].credential` / `[security].mediator_secrets` /
  `[security].jwt_authorization_secret` to
  `[secrets].backend = "<url>"`. No compatibility shim. Migration
  path in [docs/secrets-backend.md](docs/secrets-backend.md) (Path
  A: re-run the wizard; Path B: hand-provision the well-known keys
  then `mediator-setup --force-reprovision`).
- Removed `string://` (inline TOML secrets) and `vta://` as storage
  backends. Use `file://?encrypt=1` (AES-256-GCM + Argon2id) for
  dev-only; `keyring://` / `aws_secrets://` / `gcp_secrets://` /
  `azure_keyvault://` / `vault://` for production. `vta://` was
  never a *store* — the VTA is a key *source*.
- Self-hosted admin credentials are stored as an `AdminCredential`
  with `vta_did: None` / `vta_url: None`. The config-load path
  gates the VTA integration branch on `admin.is_vta_linked()` —
  self-hosted setups no longer attempt to authenticate to a VTA at
  boot. `rotate-admin` refuses to run against a self-hosted
  credential.
- Well-known key name schema flattened from `mediator/<a>/<b>` to
  `mediator_<a>_<b>` so every backend's native name rules accept
  the keys verbatim. Entries seeded under the old names need
  re-seeding.

**Backends (all feature-gated, all live)**
- `keyring://<service>` — OS keychain (unchanged).
- `file:///<path>` and `file:///<path>?encrypt=1` — JSON file,
  optional Argon2id + AES-256-GCM envelope. Wizard gates plaintext
  `file://` behind a typed-acknowledgement screen.
- `aws_secrets://<region>/<prefix>` — AWS Secrets Manager with a
  3-attempt exponential-backoff retry (100ms → 400ms) on
  throttling / internal / network errors.
- `gcp_secrets://<project>/<prefix>` — **new.** GCP Secret Manager
  via the official `google-cloud-secretmanager-v1` crate.
- `azure_keyvault://<vault-name-or-url>` — **new.** Azure Key
  Vault via `azure_security_keyvault_secrets`. Accepts bare name
  (auto-expands to `https://<name>.vault.azure.net`) or full
  `https://…` URL for sovereign clouds.
- `vault://<endpoint>/<mount>[/<prefix>]` — **new.** HashiCorp
  Vault KV v2 via `vaultrs`, token auth (`VAULT_TOKEN` env).

**Sealed-handoff air-gapped bootstrap**
- Replaces the legacy Cold-start flow. Wizard generates a
  `BootstrapRequest` JSON, accepts the VTA admin's HPKE-armored
  reply via paste/file, optionally verifies the out-of-band
  SHA-256 digest, and projects the admin credential onto a
  `VtaSession`.
- Non-interactive two-phase flow via `--from recipe.toml` (phase 1
  emits request) + `--from … --bundle bundle.armor` (phase 2
  applies). The HPKE recipient seed round-trips through the
  configured secret backend (under
  `mediator_bootstrap_ephemeral_seed_<id>` + a sibling sweep
  index), not the filesystem.
- Automatic sweeper removes abandoned phase-1 seeds older than 24h
  (`MEDIATOR_BOOTSTRAP_SEED_TTL` overrides). Runs on every wizard
  invocation before the "don't clobber" check.
- TUI no longer writes any key material to disk — single-process
  session, in-memory HPKE secret across phases.

**Admin identity**
- `mediator rotate-admin [--dry-run]` subcommand. Mints a fresh
  did:key, mirrors the existing ACL scope, writes the new
  credential into the unified backend, revokes the old ACL entry.
  Old + new DIDs logged for audit. VTA-linked credentials only.
- ADMIN_GENERATE (self-hosted) runs now persist the admin private
  key into the backend as `mediator_admin_credential` with
  VTA-fields unset. Stdout echo of the private key is still there
  for operator bookkeeping but prefixed with a red-background
  `UNSAFE` banner naming that the key is already in the backend.

**Operational surfaces**
- `/readyz` JSON adds `secrets_backend_reachable: bool`,
  `secrets_backend_url: String`, `vta_cache_age_secs: Option<u64>`,
  `operating_keys_loaded: bool`. Boot-time backend probe fails
  fast on unreachable backends instead of waiting for the first
  secret read.
- JWT secret can be operator-provided — wizard's Security step
  asks "generate or provide"; provide mode reads from
  `MEDIATOR_JWT_SECRET` / `--jwt-secret-file` at boot.
- `/admin/status` now reports migration-registry state.

**Wizard (`mediator-setup`)**
- `--force-reprovision` flag. Wizard refuses to overwrite a
  provisioned setup unless passed.
- `--uninstall` flag. Lists every well-known key, prompts for
  typed `DELETE`, removes both backend entries and local config
  files.
- Per-backend Cargo features (`secrets-keyring`, `secrets-aws`,
  `secrets-gcp`, `secrets-azure`, `secrets-vault`), all in default
  so `cargo install` speaks every backend; operators who want
  leaner binaries can `--no-default-features --features
  secrets-<X>`.
- Wizard automatically probes the chosen backend before writing
  anything, so misconfigured storage fails fast rather than after
  the request file has been emitted.

**CI / build**
- New `.github/workflows/checks-features.yaml` — 2×5 matrix runs
  `cargo check --no-default-features --features secrets-<X>` for
  each backend X against both the mediator binary and the setup
  wizard. Catches `cfg`-gate omissions that the default-feature
  build misses.

**Dependencies** (coordinated workspace bump, see
[docs/dependency-bumps.md] — err, the commit message at `8cfe5ba`
for the detailed list)
- `ratatui 0.29 → 0.30`, `crossterm 0.28 → 0.29`, `tui-input 0.14
  → 0.15` across mediator-setup, mediator-monitor, and
  affinidi-messaging-text-client (required in lockstep because
  ratatui 0.29 pins `unicode-width = "=0.2.0"`).
- `ratatui-image 8 → 10` and `tui-logger 0.17 → 0.18` in
  text-client.
- `lru 0.12 → 0.17` in mediator-processors.
- `rand 0.9 → 0.10` in mediator-setup (aligns with
  mediator-common).

**Docs**
- New [docs/secrets-backend.md](docs/secrets-backend.md) — per-key
  JSON schemas, backend URL shapes, legacy → unified-backend
  migration matrix, HA topology guidance.
- [docs/setup-guide.md](docs/setup-guide.md) rewritten for the
  three wizard modes (online VTA, sealed-mint, sealed-export,
  self-hosted).

**Internal**
- `affinidi-messaging-mediator-common 0.12 → 0.13`.
- `affinidi-messaging-mediator-processors 0.12 → 0.13` (in
  lockstep; processors code itself unchanged apart from the
  `lru` bump).

**Startup hardening (folds in #282)**
- **BREAKING:** `database.functions_file` is now required. Earlier
  builds silently exited with success when it was unset, claiming
  the mediator had started; the wizard always emits a value, so
  this only bites hand-rolled configs.
- **CHORE:** `server::start` returns `Result<(), MediatorError>` and
  the panic-style paths in startup (config init, DB open / init,
  LUA load, streaming task, DID resolver, TLS cert/key, listen-addr
  parse, HTTP/HTTPS bind+serve) propagate typed errors instead of
  `expect()` / `unwrap()` / `process::exit(1)`. `main.rs` prints the
  error and exits non-zero.
- **CHORE:** `database::initialize` propagates failures via `?`
  instead of `expect`-ing on the hardcoded ACL parse and admin
  account setup.
- **CHORE:** Per-IP and per-DID rate limiter constructors use a
  `let-else` on `NonZeroU32::new(per_second)` and
  `unwrap_or(NonZeroU32::MIN)` for burst, dropping the
  `expect("checked non-zero above")` invariant comments.
- **CHORE:** `shutdown_signal` no longer panics if a Ctrl-C or
  SIGTERM handler fails to install; the failed branch logs and
  parks on `pending::<()>` so the surviving handler can still
  trigger graceful shutdown.

**Container deployment**
- **FEAT:** Container mode now generates a `docker-compose.yml`
  alongside the `Dockerfile`, so `docker compose up --build` brings
  up a self-contained stack (mediator + bundled Redis on a private
  network, named volume for Redis persistence). The mediator's
  `database.database_url` from `mediator.toml` is overridden via
  the `DATABASE_URL` env var so the same image still works against
  an external Redis when run outside of compose. Redis is internal
  to the compose network and not exposed on the host.
- **FIX:** Container Dockerfile's `EXPOSE` line now uses the port
  derived from `listen_address` instead of the hardcoded `7037`.

**Pluggable storage abstraction**
- **FEAT:** `MediatorStore` trait in `affinidi-messaging-mediator-common`
  with three concrete impls — `RedisStore` (default, multi-mediator
  clusters), `FjallStore` (embedded LSM, single-node persistence,
  no Redis sidecar), `MemoryStore` (tests, in-process integration).
  `SharedData.database` is now `Arc<dyn MediatorStore>`; handler
  code is backend-agnostic.
- **FEAT:** `MediatorBuilder` / `MediatorHandle` API for embedded
  callers — spin the mediator up without TOML, without CWD
  assumptions, with a real bound URL surfaced even when binding
  to `:0`. TLS optional. Non-published
  `affinidi-messaging-test-mediator` crate provides
  `TestMediator::spawn()` defaulting to Memory.
- **FEAT:** Every background task — statistics, forwarding processor,
  websocket streaming, message expiry sweep — runs against
  `Arc<dyn MediatorStore>`. The standalone `mediator-processors`
  binaries stay Redis-only by design (Redis Streams consumer
  groups + atomic SPOP coordination across hosts) and are
  documented as horizontal-scaling tooling for Redis deployments.
- **FEAT:** Per-backend CI matrix
  (`.github/workflows/checks-storage.yaml`) plus
  `test-mediator (memory)` and `test-mediator (fjall)` e2e jobs.
- **FEAT:** Wizard's Database step picks Redis (URL) or Fjall
  (data dir); generated `docker-compose.yml` switches between the
  bundled-Redis stack and a single-container Fjall stack.
- **CHANGED:** **BREAKING** for out-of-tree handlers: anything
  taking `&Database` directly needs `&dyn MediatorStore` (or
  `Arc<dyn MediatorStore>`).
- **CHANGED:** `mediator` no longer depends on
  `affinidi-messaging-mediator-processors`; in-process workloads
  run through `MediatorStore` instead.

**Deployment-feedback hardening (4 May 2026)**

A first-customer rollout from 0.13.x → 0.14.x surfaced six
production issues in the auth/session/VTA-bootstrap chain. All
fixed without a version bump; the section below documents what
changed so operators upgrading from 0.13.x can correlate log lines
to fixes.

- **FIX (auth):** `update_session_authenticated`'s trait default
  passed a SHA-256 hash to `get_session` (which expects the raw
  DID), so the read-modify-write fell through to a
  `Session::default()` substitute and wrote `did = ""` over the
  real session. Every subsequent JWT auth read back an empty DID
  and every WebSocket inbound message tripped
  `e.p.authorization.did.session_mismatch`. Fixed by renaming the
  trait param to `did`, computing the hash internally, plus a
  defensive blank-DID-fill from input. RedisStore overrides the
  trait default with the legacy atomic `RENAME` + `HSET` path
  (same wire behaviour as 0.13.x). Added
  `session_auth_rename_preserves_did` regression test.
- **FIX (auth):** `update_refresh_token_hash` and
  `get_refresh_token_hash` had the same bug class — trait
  defaults called `get_session(session_id, "")` with an empty
  DID, then `unwrap_or_else(|_| Session::default())` substituted
  `state = Unknown`, and `put_session` wrote that corrupt default
  back. Result: spurious `Error parsing role_type!` warnings on
  `/authenticate/refresh`, then 500 on the next `/ws` connect.
  Fixed by overriding both methods on `RedisStore` to call the
  inherent single-field `HSET refresh_token_hash` /
  `HGET refresh_token_hash` paths directly. Added
  `refresh_token_rotation_preserves_did_and_state` test.
- **FIX (auth):** Three defence-in-depth additions for empty/legacy
  session DIDs — `handlers/authenticate/challenge.rs` rejects
  non-`did:`-shaped `did` with HTTP 400; `common/jwt_auth.rs`
  validates `saved_session.did == jwt.sub` after `get_session`
  and rejects with `InvalidToken` on mismatch (cross-tenant
  replay guard); `tasks/websocket_streaming.rs` refuses to
  register a streaming client whose `did` or `did_hash` is empty
  and closes the upstream channel. Strengthened the existing
  `session_lifecycle` round-trip test in MemoryStore + FjallStore
  to assert `did` and `did_hash` survive `put_session` /
  `get_session`.
- **FIX (data migration):** Pre-0.13 mediators didn't write
  `ROLE_TYPE` on user account records. New migration
  `m003_backfill_role_type` scans every account via the
  `account_list` cursor and writes `ROLE_TYPE = "Standard"` on
  records where the field is missing. Idempotent and safe during
  rolling restart.
- **FIX (session recovery):** `get_session` now detects
  unparseable `state` values (e.g. `Unknown` left over from
  pre-fix runs), deletes the corrupt SESSION record in place,
  and returns HTTP 401 instead of 503. Clients re-authenticate
  cleanly on the next refresh attempt rather than looping on the
  same stale record.
- **FEAT (VTA bootstrap):** Boot-time circular-dependency
  detection for self-mediated VTA setups (the VTA's
  `DIDCommMessaging` service routes through this very mediator,
  causing a DIDComm-to-self deadlock).
  `common/config/vta_bootstrap.rs` adds a probe that compares
  the cached mediator DID against the VTA's
  `service.DIDCommMessaging.mediator_did`. On match: skip the
  live VTA fetch, boot from cache (or force `PreferRest` if no
  cache). Probe failures degrade silently to default `Auto`
  startup — the probe must never block boot.
- **FEAT (VTA freshness):** Periodic VTA refresh task in
  `tasks/vta_refresh.rs` — fire-and-forget background loop,
  cadence `clamp(cache_ttl/4, 5min, 1h)` (default 6h when
  `cache_ttl == 0`). Two roles: keeps the cache within TTL during
  long uptimes (was written once at boot, never refreshed), and
  re-fetches once the listener is up after a circular-bootstrap
  cache-only boot so DIDComm-to-self resolves cleanly.
- **FEAT (operator UX):** Multi-line operator recovery playbook
  printed to stderr when the mediator can't boot because the
  VTA is unreachable AND no usable cached bundle exists. Three
  concrete recovery paths (restore connectivity / sealed-export
  reprovision via `vta contexts reprovision` / greenfield
  re-setup) with the exact `mediator-setup` command lines.
  Bypasses `RUST_LOG` filtering so the message reaches the
  operator regardless of log configuration on a terminal failure.
- **CHORE:** Dropped the `vta-sdk` workspace-level path override.
  Published 0.5 has the same surface; pulling from crates.io.

**Earlier work (16 April — Wizard / Monitoring / Redis perf)**
- **FEAT:** Interactive TUI setup wizard (`mediator-setup`) replacing three
  fragmented tools (setup_environment, generate_mediator_config, mediator-setup-vta)
  - Real crypto generation: did:peer, did:webvh, did:key, JWT (Ed25519), SSL
  - Non-interactive CLI mode (`--non-interactive`) for CI/CD
  - Reconfiguration mode (backs up existing config)
  - TSP marked as experimental
- **FEAT:** Real-time monitoring TUI (`mediator-monitor`) — btop-inspired dashboard
  - Polls `GET /admin/status` for version, uptime, connections, message throughput,
    forwarding queue depth, circuit breaker state
  - Rate calculations from 30-snapshot sliding window (msg/s, bytes/s)
- **FEAT:** Admin status endpoint (`GET /admin/status`) — JSON operational data for
  monitoring tools. Redis password masked in response.
- **FEAT:** Sequential migration registry replacing version-coupled schema upgrades
  - Each migration has unique ID, tracked in Redis `SCHEMA_MIGRATIONS` set
  - Automatic bootstrap from legacy `GLOBAL:SCHEMA_VERSION`
  - 6 invariant tests for migration registry integrity
- **FEAT:** Error code registry (`error_codes.rs`) — 37 error codes documented as
  named constants organized by category
- **FEAT:** Prometheus metrics expanded to 24 names with type annotations
  (counter/gauge/histogram). Instrumented: inbound messages, store latency,
  circuit breaker state, ACL denials.
- **FEAT:** Redis auth/TLS startup warnings for unauthenticated or unencrypted connections
- **FEAT:** Configurable circuit breaker thresholds (was hardcoded 5/10s)
- **PERF:** Lua `store_message` — MAXLEN trimming on per-DID streams
- **PERF:** Lua `fetch_messages` — batch MGET (N+1 calls → 2)
- **PERF:** Lua `clean_start_streaming` — SPOP batch limit (500)
- **PERF:** DIDComm unpack — eliminated double JSON parse per encrypted message
  (~10-15% CPU reduction)
- **PERF:** EndpointRateTracker — O(n) Vec replaced with O(1) time-bucketed counter
- **PERF:** Static regex in inbox_fetch (was compiled per-request)
- **SECURITY:** Lua `delete_message` — explicit admin_did_hash replaces magic string
- **FIX:** Blocking `std::thread::sleep()` in async database retry loops replaced
  with `tokio::time::sleep()` (critical: was blocking the tokio runtime)
- **FIX:** ForwardingProcessor panic replaced with Result return
- **FIX:** All forwarding ACK/delete/enqueue errors now logged (were silently discarded)
- **FIX:** Unused `self` imports cleaned up from auth handlers
- **REMOVED:** `setup_environment`, `generate_mediator_config` binaries (helpers crate)
- **REMOVED:** `mediator-setup-vta` binary and `setup` feature flag
- **REMOVED:** Old `upgrades/` migration system
- **CHORE:** Tools reorganized into `tools/` subdirectory
- **CHANGED:** Bumped `didwebvh-rs` dependency from `0.4` to `0.5` for the
  data-integrity API refactor and PQC support in `affinidi-data-integrity 0.5.4`.
  No behavioural change to the mediator — wire format is unchanged.

## 15th April 2026

- **DOC:** Added README section on running without a secure credential store
  (`string://` usage for dev/CI without keyring or AWS Secrets Manager)

## 1st April 2026

### 0.13.0 — VTA Integration

- **FEAT:** Integrate VTA SDK for centralized key management
  - Mediator DID and secrets can now be managed through a Verifiable Trust
    Agent using `vta://` scheme for `mediator_did` and `mediator_secrets`
  - Two-tier authentication: lightweight REST (did:key VTAs) with session-based
    challenge-response fallback (did:web/did:webvh VTAs)
  - Circular dependency detection via VTA health probe — warns when VTA routes
    DIDComm through this mediator
  - REST-first bootstrap prevents deadlock when VTA depends on this mediator
- **FEAT:** Unified VTA startup with local secret caching
  - On startup, fetches fresh secrets from VTA via `integration::startup()`
  - Caches secrets locally (keyring, AWS Secrets Manager, or string backend)
  - Falls back to cached secrets when VTA is unreachable
  - Uses shared `vta-sdk` integration module (same pattern as webvh-service)
- **FEAT:** Interactive setup wizard (`mediator-setup-vta`)
  - Accepts Context Provision Bundle or plain Credential Bundle
  - Credential storage backends: `string://`, `aws_secrets://`, `keyring://`
  - Context selection, DID creation (did:webvh), and existing DID import
  - Multibase-multicodec private key validation during import
  - `--rest` flag resolves VTA DID document for `VTARest` service endpoint
    discovery, bypassing DIDComm transport
  - Saves VTA configuration to mediator.toml
- **FEAT:** VTA credential storage feature gates
  - `vta-aws-secrets` — AWS Secrets Manager credential backend
  - `vta-keyring` — OS keyring credential backend
  - `setup` — interactive setup wizard binary
- **FIX:** Log session ID and DID on duplicate websocket connections
  - Upgraded from debug to WARN with structured fields: `did`, `old_session`,
    `new_session` for easier troubleshooting
  - `StreamingUpdateState::Register` now carries session_id and DID
- **REFACTOR:** Use `fetch_did_secrets_bundle()` for VTA secret loading
  - Replaces manual `fetch_context_secrets` + `list_keys` + zip/remap pattern
  - SDK now maps key labels to verification method IDs automatically
  - Proper pagination (page size 100) instead of single 1000-key page
- **FIX:** Various VTA key management fixes
  - Multicodec prefix handling for Ed25519, X25519, and P256 keys
  - DID verification method ID used as key label for secret lookup
  - AWS SDK region auto-detection from instance metadata
  - Full error details in debug format for AWS SDK errors
- **FIX:** Empty secrets bundle from VTA is now a hard error
  - Prevents starting with zero signing keys due to misconfiguration
- **FIX:** VTA startup timeout (default 30s) prevents hangs when VTA is
  partially reachable
- **FIX:** Dead WebSocket channels cleaned up on send failure
  - Previously, disconnected channels accumulated in the streaming HashMap
- **CHORE:** Replace all `println!`/`eprintln!` with tracing macros
  - Log output now respects log level configuration and JSON formatting
- **CHORE:** Extract `parse_scheme()` helper for `scheme://path` config parsing
- **CHORE:** Switch `vta-sdk` dependency from git nightly to crates.io `0.3.0`

## 28th March 2026

### 0.12.5

- **FIX:** Accept authcrypt (ECDH-1PU) as sender authentication
  - The anonymous message check (`block_anonymous_outer_envelope`) previously
    only recognized JWS signatures (`sign_from`), rejecting authcrypt-only
    messages as "anonymous" even though they are sender-authenticated
  - Now accepts EITHER authcrypt (`metadata.authenticated`) OR JWS
    (`metadata.sign_from`) as proof of sender identity
  - Session DID matching and admin permission checks updated to use
    `sign_from.or(encrypted_from_kid)` as the sender key ID
  - Fixes SDK protocol messages (live-delivery-change, message-pickup, etc.)
    being rejected when `block_anonymous_outer_envelope: true`
- **FIX:** Replaced `deadpool-redis` connection pool with direct `redis` crate
  `ConnectionManager` (auto-reconnecting multiplexed connection)
  - Fixes XREADGROUP BLOCK timeout errors caused by redis 1.x's 500ms default
    response timeout
- **CHORE:** Cleaned up log messages for readability
  - Removed per-second idle DEBUG spam from message expiry cleanup
  - Simplified DID resolver cache, ACL, and auth handler log messages
  - Demoted noisy per-request JWT auth messages from INFO to DEBUG
- **TEST:** Added 19 unit tests for sender authentication handling
  - `check_session_sender_match`: JWS, authcrypt, anonymous, fragment, multi-key
  - `check_admin_signature`: JWS, authcrypt, mismatch, anonymous, malformed
  - `check_permissions`: admin signing with authcrypt kid, anonymous rejection
  - Anonymous detection: authcrypt-only, JWS-only, both, anoncrypt-only
