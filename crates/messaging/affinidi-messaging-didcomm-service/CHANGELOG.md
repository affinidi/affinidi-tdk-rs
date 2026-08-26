# Changelog

## Unreleased (0.4.0) — `trust-tasks-rs` 0.12

- Bumps `trust-tasks-rs` 0.11 → 0.12. No source change; the crate compiles
  unmodified against it.
- Released as a minor bump rather than a patch because `trust-tasks-rs` types
  reach this crate's API surface, so a consumer must move in lockstep — two
  versions in one graph fail to compile rather than warn.
## [0.3.27] - 2026-08-19

### Changed

- **Track `trust-tasks-rs` 0.11.0**, up from 0.9.0. Both releases in between are
  additive — new task families, no change to any type this crate uses — so
  nothing here had to move but the requirement:

  - **0.10.0** added the `vta/contexts/*` and `vta/webvh/*` families (the
    did:webvh lifecycle: DIDs, hosting servers, agent names) and the eight
    `vta/services/*` families that supersede a VTA's `/services/*` REST routes.
  - **0.11.0** corrected two of those `vta/services/*` schemas after writing the
    handlers found them unable to express the operation: rollback can
    legitimately publish no log entry, and disable takes a drain window the
    agent may refuse to honour.

  The reason to take it here is that a VTA cannot: `vta-sdk` must speak the same
  `trust-tasks-rs` these crates do, because `acl_setup` builds a `MediatorAcl`
  and hands it to `TrustTasks::account_update`. Two semver-incompatible copies
  make that a type error, so the VTA stays on 0.9 until this workspace moves.


## [0.3.26] - 2026-08-17

### Changed

- **Track `trust-tasks-rs` 0.9.0** and `affinidi-messaging-sdk` 0.19.8, up from
  0.6.1 / 0.19.7. Version requirements only — the single use here is
  `specs::messaging::account`, whose `v0_1` types are shape-identical across the
  move. See the SDK's 0.19.8 entry for what the three intervening breaking
  releases changed and why this ships as a patch.

## [0.3.25] - 2026-08-14

### Changed

- **Track `trust-tasks-rs` 0.6.1** (from 0.4.0), and move the
  `affinidi-messaging-sdk` requirement to 0.19.7 alongside it. The pairing is
  the invariant 0.3.24 established: a crate declaring both must name the SDK
  version whose public `trust_tasks()` types match its own `trust-tasks-rs`, or
  a resolver can satisfy the manifest with a pair the compiler rejects.

  The two breaking releases in between — an optional `ceremony` member on the
  `TrustTask<P>` envelope (0.5.0) and `DigestMultibase` narrowing to the `z` and
  `u` multibase headers (0.6.0) — reach nothing here: this crate hands
  `trust_tasks_rs::specs::messaging::account` types to `atm.trust_tasks()` and
  builds no envelopes by struct literal. No source changed.

## [0.3.24] - 2026-08-09

### Fixed

- **Require `affinidi-messaging-sdk` 0.19.3, not "0.19".** 0.3.23 shipped asking
  for `^0.19` while itself requiring `trust-tasks-rs` `^0.4.0`. Those two are
  mutually satisfiable by a resolver and mutually incompatible at compile time:
  `trust-tasks-rs` is a public dependency of the SDK's `trust_tasks()` surface,
  and 0.19.2 exposes it as 0.2.x. This crate hands
  `trust_tasks_rs::specs::messaging::account` types to `atm.trust_tasks()`, so
  the pair 0.19.2 + 0.4.0 fails with `E0308`.

  A fresh resolve picks 0.19.3 and compiles — which is why publishing 0.3.23
  succeeded — but a consumer with an existing lockfile pinning 0.19.2, or one
  passing `--precise 0.19.2`, gets the mismatch. The packaged manifest now names
  the minimum SDK carrying the matching `trust-tasks-rs`, so a stale one is
  rejected at resolve time instead of at compile time.

  Same failure mode as `affinidi-messaging-didcomm-v1` 0.1.0's
  `affinidi-messaging-core` requirement (#688).

## [0.3.23] - 2026-08-09

### Changed

- Track `trust-tasks-rs` 0.4.0 (was 0.2.46) and `affinidi-messaging-sdk` 0.19.3.
  This crate uses `trust_tasks_rs::specs::messaging::account` to register with a
  mediator; those types are unchanged across the bump, so no code changed.

  `trust-tasks-rs` is a public dependency of the SDK's `trust_tasks()` surface
  and therefore of this crate's, so a consumer still on `trust-tasks-rs` 0.2.x
  must move to `0.4` in the same change that takes this version. See the
  `affinidi-messaging-sdk` 0.19.3 entry for why this is a patch rather than a
  minor.

## [0.3.22] - 2026-07-30

### Changed

- Track `affinidi-messaging-sdk` 0.19.0 (secure-by-default `unpack`: the
  configured `UnpackPolicy` is enforced, rejecting non-authenticated wrappings).
  Dependency bump only; no behavioural change in this crate.

## [0.3.21] - 2026-07-29

### Changed

- Startup ACL-mode configuration now sends `messaging/account/update` (the
  `acl` member) instead of the retired `messaging/acl/set`, following the
  `messaging/*` trust-task rationalization (affinidi/affinidi-tdk-rs#667;
  affinidi-messaging-sdk 0.18.65). Same partial-update semantics — only
  `accessListMode` is set, everything else is left unchanged.

## [0.3.20] - 2026-07-19

### Changed

- Bumped the `affinidi-did-common` requirement from `"0.3"` to `"0.4"`.
  No functional change to this crate: `Document` gained a typed
  `also_known_as` field, which is additive.

## [0.3.19] - 2026-07-16

- Ack (delete) live inbound messages only AFTER the handler has processed them,
  not on receipt (D1-F5, R1.6/R1.7). `process_next_message` used
  `live_stream_next(auto_delete = true)`, which deleted the mediator's copy the
  instant the frame arrived — then dispatched the message to the handler in a
  *spawned* task. A teardown (or crash) between the delete and the handler
  running lost the message permanently, since the mediator had already dropped
  it. The live path now pulls with `auto_delete = false` and acks via
  `delete_message_background` inside `dispatch_message`, once the handler has had
  the message; a teardown before that leaves the message queued for redelivery
  on the next pickup instead. The operator's `auto_delete = false` opt-out is
  honoured (no ack at all). Behaviour is otherwise unchanged: the offline-sync
  drain already batch-acked after dispatch, and the TSP-multiplexed live path is
  unchanged (its ack-after-handoff lands with TSP conformance). Failed acks are
  non-fatal — the message is redelivered and de-duplicated by the receiver.

## [0.3.18] - 2026-07-16

- Keep the caller-seeded DID resolver across listener restarts (D1-F4).
  `Listener::connect()` runs on every iteration of the restart loop
  (`restart::run_with_restart`), but it consumed the pre-seeded `TDKConfig`
  with `Option::take()` — leaving the field `None`, so every retry after the
  first fell back to a cold `TDKConfig::headless()` and lost the caller's
  DID resolver and its warm cache. It now `clone()`s the config instead; both
  `TDKConfig` and its `DIDCacheClient` are `Arc`-cheap clones that share the
  same underlying resolver state, so every reconnect keeps the warm resolver.
  Behaviour-preserving for the first connect; fixes the degraded-resolution +
  extra cold-resolver cost on every subsequent reconnect.

## [0.3.16] - 2026-07-03

- Fix a TSP poison-loop in the offline-sync poller. `AffinidiMessageService` runs a periodic
  offline/backlog drain (`run_periodic_offline_sync`, every 30s) alongside the TSP-aware live
  loop, but that drain was DIDComm-only: it blindly `atm.unpack()`d every queued message, so
  a queued **TSP** frame failed to unpack ("Cannot parse message as JSON") and — never being
  acked/deleted — was redelivered every 30s forever. The drain is now TSP-aware: it fetches
  the backlog via the new `send_delivery_request_frames`, routes TSP frames to the same
  `TspHandler` the live loop uses, dispatches DIDComm frames as before, and acks **all**
  fetched frames (including undeliverable ones) so nothing loops. `tsp`-feature only; the
  DIDComm-only path is unchanged.

## [0.3.15] - 2026-07-02

- Fix inbound TSP: `dispatch_tsp` handed the **qb64** pickup string (`base64url(qb2)`, `-E…`
  text) straight to `atm.tsp().unpack_bytes`, which expects **decoded qb2** — so every
  multiplexed inbound TSP frame failed with `couldn't parse TSP envelope: missing -E
  envelope wrapper` and was dropped. Use `atm.tsp().unpack` (decodes base64url first),
  matching the mediator round-trip tests. The raw-TSP `connect_websocket` path already
  yields decoded qb2 and is unaffected. This is what made a TSP Trust-Ping to a VTA fail
  end-to-end even with the listener correctly in `Protocols::BOTH`.

## [0.3.14] - 2026-07-02

Symmetric TSP replies (ADR 0005 stage 6). `TspHandler::handle` now returns
`Result<Option<TspResponse>, DIDCommServiceError>` instead of `Result<(), _>`, mirroring
`DIDCommHandler`: return `Ok(Some(TspResponse::new(bytes)))` and the service seals the reply
to the authenticated `sender_vid` and routes it back over the *same* shared mediator socket
(no second connection, no consumer-side outbound plumbing). Routing rule: `send_routed(
[profile_mediator_did, sender_vid])` when the listener profile has a mediator, else a TSP
Direct `send` fallback. `Ok(None)` keeps the previous one-way (fire-and-forget) behaviour;
cross-mediator replies remain a consumer concern via `AffinidiMessageService::send_tsp_routed`.

**Breaking**: existing `TspHandler` implementors must change their return type (`Ok(())`
→ `Ok(None)`, or return `Ok(Some(..))` to reply). `IgnoreTspHandler` now returns `Ok(None)`.
`tsp`-feature only; default builds are source-compatible. New `TspResponse` type re-exported
from the crate root.

## [0.3.12] - 2026-06-30

Fixes the publish-verify failure that has blocked the release pipeline since the listener
multiplex landed. The `Listener::tsp_handler` field is only read by `process_next_frame`,
which is `#[cfg(feature = "tsp")]`; `cargo publish` verifies the packaged tarball with
**default features** under `-D warnings`, where the field is set but never read, so the
`dead_code` lint became a hard error (`field tsp_handler is never read`). Gated the lint
with `#[cfg_attr(not(feature = "tsp"), allow(dead_code))]`. No behaviour change; the `tsp`
build is unaffected.

## [0.3.8] - 2026-06-24

Migrated `set_acl_mode` off the deprecated `atm.mediator()` methods onto
`atm.trust_tasks().acl_set` (a non-admin self-service ACL change, now supported by the
mediator). The Trust Tasks partial-update model replaces the previous read-modify-write
(no `account_get` / `MediatorACLSet` decode needed). Dropped the `#![allow(deprecated)]`.

## [0.3.7] - 2026-06-24

Allows the now-`#[deprecated]` legacy `atm.mediator()` methods it still calls
(`#![allow(deprecated)]` in `service/mediator.rs`) so the build stays clean under
`-D warnings`. No behaviour change; migration to `atm.trust_tasks()` is a follow-up.

## [0.3.6] - 2026-06-14

### Changed

- `TransportError`, `StartupError`, and `DIDCommServiceError` are now
  `#[non_exhaustive]` (ADR-0003) so new variants land additively. Patch bump
  keeps the `0.3` pin valid; match them with a `_` wildcard arm. No behaviour
  change. (W7 sweep)

## [0.3.5] - 2026-06-10

### Fixed

- Listener now tears down its websocket transport (`stop_websocket`) on
  terminal exit — shutdown, `RestartPolicy::Never`, or exhausted
  `OnFailure` retries — not only on the reconnect path. The SDK websocket
  runs as an independent, self-reconnecting spawned task with no `Drop`
  hook, so dropping the listener's `ATM`/profile previously left it alive.
  In an in-process service teardown (e.g. a host's *soft restart*, where
  the process keeps running) the orphaned socket kept reconnecting to the
  mediator while the newly-started service opened a second channel for the
  same DID, producing an endless `w.websocket.duplicate-channel` flood.

## [0.3.3] - 2026-06-01

### Changed

- Offline sync no longer logs a misleading `Offline sync failed ... No
  response from API` warning when a websocket reconnect (e.g. the mediator
  closing the socket on access-token expiry) aborts an in-flight poll. The
  reconnect race is now recognised via `ATMError::Disconnected` and logged
  at `debug` ("Offline sync skipped: websocket reconnecting"); it self-heals
  on the next 30s cycle. Genuine failures still warn. Bumps
  `affinidi-messaging-sdk` to 0.18.5.

## [0.3.2] - 2026-05-31

### Changed

- Bump `affinidi-messaging-didcomm` to 0.14 (DIDComm v2.1 interop fixes:
  ECDH-1PU authcrypt KDF #322, JWS unprotected `kid` #323,
  sign-then-encrypt unpack #324). No service API change.

## [0.3.0] - 2026-05-02

### Breaking

- Migrated to `affinidi-tdk-common` 0.6 and `affinidi-messaging-sdk` 0.17.
  Both upstream bumps are SemVer-breaking, so this crate's public API is
  re-exported through the new types.
- The `connect()` retry path no longer falls back to
  `TDKSharedState::default().await` (removed upstream). It now requires a
  `TDKConfig` (either supplied via `ListenerConfig.tdk_config` or built
  internally with `with_load_environment(false) / with_use_atm(false)`).
  Initialisation failures now surface as `TDKError` instead of silently
  panicking.
- `ListenerConfig` literals using `TDKProfile { ... }` must switch to
  `TDKProfile::new(...)` — the `secrets` field is `pub(crate)` in
  tdk-common 0.6.

## [0.2.3] - 2026-04-25

### Fixed

- `Listener::run_with_restart` now races the cancellation token against `connect()` and the inter-attempt backoff sleep. Previously a listener whose mediator was unreachable could take a full backoff window (up to `max_delay_secs`, default 60s) to honour shutdown.
- `DIDCommService::wait_connected` now races the service's internal shutdown token in addition to its timeout. A `Ctrl-C` arriving during a startup wait returns `NotConnected` immediately rather than parking the caller through the full timeout.
- `DIDCommService::shutdown` now actually awaits each listener task's `JoinHandle` (with a 5-second per-task outer timeout) instead of `await`ing already-cancelled child tokens that resolved instantly. Listener tasks are guaranteed to have returned (or the timeout to have fired) when `shutdown()` returns.

### Added

- `DIDCommService::wait_connected_with_cancel(listener_id, timeout, cancel)` — overload that races against a caller-supplied `CancellationToken` for callers that own their own shutdown signal.

## [0.2.1] - 2026-04-15

### Fixed

- Reject duplicate DID listeners: `add_listener()` and `start()` now return `DuplicateDid` error when attempting to register a listener with a DID that is already in use by another listener, preventing mediator connection conflicts.

## [0.2.0] - 2026-04-13

### Added

- `DIDCommService` now implements `Clone` — eliminates the need for `Arc<DIDCommService>` wrappers since the struct is already cheaply cloneable (all fields are `Arc`-wrapped internally).
- `DIDCommService::wait_connected(listener_id, timeout)` blocks until a listener has established its mediator connection, eliminating the race between `start()` and first `send_message()`.
- `DIDCommService::send_message_with_retry(listener_id, message, recipient_did, max_retries, initial_backoff)` retries on `NotConnected` errors with exponential backoff, using `wait_connected` between attempts.
- `DIDCommService::listener_did(listener_id)` returns the DID associated with a listener for self-contained outbound message building.
- `DIDCommService::subscribe()` returns a `broadcast::Receiver<ListenerEvent>` for listener lifecycle notifications.
- `ListenerEvent` enum with `Connected`, `Disconnected { error }`, and `Restarting { attempt, delay }` variants, emitted as listeners connect, fail, or restart.
- `ListenerConfig::new(id, profile)` constructor — takes the two required fields and defaults the rest.
- `HandlerContext::listener_id` field — handlers can now identify which listener received the message.
- `Debug` derive on `DIDCommResponse`, `DIDCommServiceConfig`, `ListenerConfig`, `RestartPolicy`, `RetryConfig`.
- `PartialEq` derive on `ListenerEvent`, `ListenerState`, `ListenerStatus`.
- `MiddlewareResult` type alias is now publicly exported.
- Specific error variants `MessageAlreadyExtracted`, `MetadataAlreadyExtracted`, `ExtensionNotFound`, `InvalidRoutePattern` — replacing generic `Internal(String)` for known error conditions.
- Documentation on `DIDCommResponse` explaining auto-fill behavior for `from`, `to`, `thid`, `pthid`.

### Changed

- **Breaking:** `DIDCommService::shutdown()` now takes `&self` instead of consuming `self`, making it compatible with shared ownership patterns (`Arc`, cloned instances).
- **Breaking:** `ErrorHandler::on_error()` is now `async` and returns `Option<DIDCommResponse>`. The default error handler now sends a problem report back to the sender instead of silently dropping the error.
- **Breaking:** `HandlerContext` has a new `listener_id: String` field.

## [0.1.5] - 2026-04-13

### Added

- `DIDCommService::send_message()` for sending proactive (unsolicited) DIDComm messages through an existing listener's mediator connection, avoiding duplicate websocket sessions.
- `NotConnected` error variant returned when attempting to send through a listener that hasn't established its mediator connection yet.
- Warning log when `message.from` doesn't match the profile DID, which would cause recipients to reject the message.
- Unit tests for `send_message` error paths (`ListenerNotFound`, `NotConnected`) and connection handle lifecycle.
