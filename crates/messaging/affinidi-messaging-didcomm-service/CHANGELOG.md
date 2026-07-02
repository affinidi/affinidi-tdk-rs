# Changelog

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
