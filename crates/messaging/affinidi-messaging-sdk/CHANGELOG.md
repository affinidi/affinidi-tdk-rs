# Changelog

## [0.18.0] - 2026-05-05

### Breaking

- `MediatorACLSet::*` fallible methods now return `Result<_, ACLError>`
  instead of `Result<_, ATMError>`. `ACLError` is a lightweight enum
  (`Config(String)` / `Denied(String)`) that lives in
  `affinidi-messaging-mediator-common::types::acls` so the mediator's
  storage trait can describe its API without depending on this crate.
  Callers using `?` against `ATMError` are unaffected — a
  `From<ACLError> for ATMError` is provided. Callers that
  match-arm on `ATMError::ACLDenied(_)` / `ATMError::ACLConfigError(_)`
  need to convert via `.map_err(ATMError::from)` (or update to match on
  `ACLError` directly).

### Changed

- The mediator protocol vocabulary moved out of this crate and into
  `affinidi-messaging-mediator-common::types::*`. Affected types:
  `MediatorACLSet`, `AccessListModeType`, `Account`, `AccountType`,
  `MediatorAccountList`, `AdminAccount`, `MediatorAdminList`,
  `Folder`, `MessageList`, `MessageListElement`, `GetMessagesResponse`,
  `FetchDeletePolicy`, `FetchOptions`, `ProblemReport`, plus the
  ACL-handler / admin request and response shapes. Each type is
  re-exported from its original `affinidi_messaging_sdk::*` path so
  existing imports keep working unchanged.
- This crate now depends on `affinidi-messaging-mediator-common`
  (was the other way around). Removes a circular-feeling layering
  where the storage trait imported from the client SDK.

## [0.17.0] - 2026-05-02

### Breaking

- Migrated to `affinidi-tdk-common` 0.6. The change is mechanical only —
  `TDKSharedState` field accesses (`tdk_common.client`, `.did_resolver`,
  `.secrets_resolver`, `.authentication`, `.environment`) replaced with
  the corresponding accessor methods on every code path. No behavioural
  changes within the SDK itself.
- `ATMProfile::to_tdk_profile` now constructs the `TDKProfile` via
  `TDKProfile::new(...)` instead of a struct literal — the `secrets`
  field is `pub(crate)` in tdk-common 0.6 and only constructible through
  the public API.

### Tests

- `unpack` test helpers (`create_atm_with_secrets`, `create_atm`,
  `create_atm_no_unpack_forwards`) updated to build a `TDKSharedState`
  via `TDKConfig::builder().with_load_environment(false)
  .with_use_atm(false).build()?` + `TDKSharedState::new`, replacing the
  removed `TDKSharedState::default().await`.

## [0.16.5] - 2026-04-25

### Fixed

- `ATM::list_messages` and `ATM::delete_messages_direct` now apply a 15-second per-request HTTP timeout. Previously the calls were unbounded and would block for the OS-level TCP RTO (~30–60s on macOS) when the mediator was unreachable, contributing to slow shutdowns in downstream consumers that wrap them in their own connect path.

## [0.16.3] - 2026-04-15

### Fixed

- Add exponential backoff (1s-60s cap) on WebSocket reconnection after server-initiated disconnects. Previously, server-initiated Close frames (including mediator `duplicate-channel` rejections), protocol resets, and connection errors triggered immediate reconnection with zero delay, causing an infinite reconnect loop between two profiles sharing the same DID.
- Missed pong timeout now immediately drops the WebSocket and applies backoff, instead of leaving a half-closed connection.

## [0.16.2] - 2026-03-28

### Fixed

- Handle inbound WebSocket Ping frames from the mediator by responding with a Pong, instead of logging them as unknown message types.
