# Affinidi Messaging Mediator

## Changelog history

## 20th April 2026

### Unreleased — Unified Secret Backend (Phases A–L)

- **BREAKING:** Hard-cut from `[vta].credential` / `[security].mediator_secrets` /
  `[security].jwt_authorization_secret` to a single `[secrets].backend = "<url>"`
  unified secret store. There is no compatibility shim. See
  [docs/secrets-backend.md](docs/secrets-backend.md) for the migration path
  (Path A: re-run the wizard; Path B: hand-provision well-known keys then
  `mediator-setup --force-reprovision`).
- **BREAKING:** Removed `string://` (inline TOML secrets) and `vta://` as
  storage backends. Use `file://?encrypt=1` (Argon2id + AES-256-GCM) for
  dev-only, `keyring://` / `aws_secrets://` for production. `vta://` was
  never a *store*; the VTA is a key *source*.
- **FEAT:** Wizard `--force-reprovision` and `--uninstall` flags. Wizard
  refuses to overwrite a provisioned setup unless `--force-reprovision` is
  passed; `--uninstall` lists every well-known key, prompts for typed
  `DELETE`, and removes both backend entries and local config files.
- **FEAT:** Air-gapped sealed-handoff bootstrap mode replaces the legacy
  Cold-start. Wizard generates a `BootstrapRequest` JSON, accepts the VTA
  admin's HPKE-armored reply via paste/file, optionally verifies the
  out-of-band SHA-256 digest, then projects the admin credential onto a
  `VtaSession`.
- **FEAT:** `mediator rotate-admin [--dry-run]` subcommand. Mints a fresh
  did:key, mirrors the existing ACL scope, writes the new credential into
  the unified backend, revokes the old ACL entry. Old + new DIDs logged
  for audit.
- **FEAT:** AWS Secrets Manager calls now go through a 3-attempt
  exponential-backoff retry (100ms → 400ms) keyed off a per-backend
  `RetryPolicy`. Throttling / internal / network errors retry; not-found
  / access-denied / validation errors short-circuit.
- **FEAT:** `/readyz` JSON adds `secrets_backend_reachable: bool`,
  `secrets_backend_url: String`, `vta_cache_age_secs: Option<u64>`, and
  `operating_keys_loaded: bool`. Boot-time backend probe fails fast on
  unreachable backends instead of waiting for the first secret read.
- **FEAT:** JWT secret can be operator-provided. Wizard's Security step
  asks "generate or provide" — provide mode reads the key from
  `MEDIATOR_JWT_SECRET` / `--jwt-secret-file` at boot.
- **FEAT:** `file://` is gated behind a typed-acknowledgement screen in
  the wizard ("type `I understand` to continue"). Plaintext-on-disk is
  acceptable for dev only; production deployments are routed to keyring
  / cloud backends.
- **DOCS:** New [docs/secrets-backend.md](docs/secrets-backend.md) with
  well-known key JSON schemas, HA topology guidance, and the legacy →
  unified-backend migration matrix.

## 16th April 2026

### 0.14.0 — Setup Wizard, Monitoring, Redis Optimization

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
