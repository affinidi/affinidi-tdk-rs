# Affinidi Messaging Mediator

## Changelog history

## 1st June 2026

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
