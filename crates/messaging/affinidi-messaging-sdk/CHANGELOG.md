# Changelog

## [0.18.7] - 2026-06-06

### Changed

- **Robust key-agreement negotiation in `pack_encrypted` (#357).** The
  authcrypt path now enumerates *all* of the sender's usable key-agreement
  keys and negotiates the best shared curve with the recipient by a
  documented preference order (`X25519 > P-256 > secp256k1`), rather than
  deriving the curve from the sender's *first* key only — so a sender whose
  first KA curve has no recipient match but whose second does now packs
  successfully, and a no-common-curve failure names the curve set each side
  offered. The anoncrypt path now selects the recipient's most-preferred
  usable key-agreement curve using the **same** ordering as authcrypt
  (skipping undecodable/unsupported entries) instead of blindly taking
  `first()`, so the two paths never disagree on curve choice. The duplicated
  negotiation/resolution helpers were removed in favour of
  `affinidi-did-common`'s shared `key_negotiation` module (its new
  `key-agreement` feature).
- **P-384/P-521 key agreement + configurable curve preference (#357).**
  `pack_encrypted` now supports the P-384 and P-521 key-agreement curves
  (sender key-type → curve mapping), and `ATMConfigBuilder` gains
  `with_curve_preference(Vec<Curve>)` to override the default curve ordering
  (`X25519 > P-256 > P-384 > P-521 > secp256k1`) at runtime — e.g. P-256
  first for a FIPS deployment. The override applies to both authcrypt and
  anoncrypt.

## [0.18.6] - 2026-06-01

### Fixed

- Fix `cargo test` compilation in the `ws_cache` unit tests: a `oneshot`
  send was `.unwrap()`-ed, which requires `WebSocketResponses: Debug` (not
  derived). Assert on `.is_ok()` instead. Test-only; no runtime change.

## [0.18.5] - 2026-06-01

### Changed

- **In-flight websocket requests now fail fast on disconnect.** When the
  connection to the mediator drops (server `Close`, reset, missed pong, or
  any socket error), every pending `live_stream_get` / `live_stream_next`
  waiter is notified immediately instead of blocking until its own timeout
  elapses. Previously a request that was in flight when the socket dropped
  (e.g. the mediator closing the socket on access-token expiry) sat idle for
  up to the full wait window and then surfaced as a misleading
  `MsgSendError("No response from API")`.
  - New `WebSocketResponses::Disconnected` variant carries the signal to
    waiters. `live_stream_next` / `live_stream_next_packed` map it to
    `Ok(None)` (streaming callers quietly retry on reconnect);
    `live_stream_get` maps it to the new `ATMError::Disconnected` so
    request/response callers can distinguish a reconnect race from a genuine
    no-response.

## [0.18.4] - 2026-05-31

### Security

- **`unpack()` now verifies JWS signatures.** Previously a signed
  (JWS) message was parsed *without* checking the signature and returned
  with `non_repudiation: true` — i.e. a forged signature was accepted and
  labelled non-repudiable. `unpack()` now resolves the signer's Ed25519
  key from its `kid` (via the DID resolver) and verifies the signature;
  an unresolvable signer or an invalid signature is an **error**. The
  signer is attributed in `UnpackMetadata.sign_from`, read from the
  protected header and falling back to the unprotected header (#323).
  Behaviour change: flows that relied on the previous lax parsing of
  unverified JWS will now receive an error instead of a message.

### Added

- **Sign-then-encrypt support (#324).** When a decrypted JWE wraps a JWS
  (DIDComm v2.1 non-repudiation), `unpack()` verifies the inner signature
  and reports `non_repudiation` + `sign_from` alongside the encryption
  metadata, instead of failing to parse.

### Changed

- Bump `affinidi-messaging-didcomm` to 0.14 (corrected ECDH-1PU authcrypt
  KDF + dual-KEK fallback, #322). The decrypt path picks these up
  transparently.
- Verification-material parsing now delegates to
  `affinidi-did-common`'s `VerificationMethod::decode_public_key`,
  removing the SDK's bespoke JWK/multibase branch (shared with the
  DID-authentication layer).

## [0.18.3] - 2026-05-24

### Security

- `OOBDiscovery::retrieve_invite` no longer panics on malformed
  responses from the invitation endpoint. The four `.unwrap()` /
  `.expect()` sites on the response envelope, base64url payload,
  UTF-8 decode and inner `Message` parse now return
  `ATMError::TransportError`. Previously a misbehaving or hostile
  mediator could crash the SDK client.
- `AuthorizationResponse` no longer derives `Debug`; a manual impl
  redacts `access_token` and `refresh_token` while leaving the
  `*_expires_at` fields visible. The derived impl printed both
  tokens verbatim, so any `debug!`/`warn!("{:?}", resp)` or panic
  dump leaked credentials granting a full authenticated session.
  Matches the redaction already applied to the equivalent structs
  in `affinidi-did-authentication`.

## [0.18.1] - 2026-05-05

### Changed

- `From<ACLError> for ATMError` now includes a wildcard arm because
  `mediator-common 0.15.0` marked `ACLError` as `#[non_exhaustive]`.
  Future ACL variants surface as `ATMError::ACLConfigError` until
  the SDK adds a more specific mapping. No behavior change for
  existing `Config` and `Denied` variants.
- Bumped `mediator-common` caret pin to `"0.15"` to pick up the
  feature-gating rework. The SDK already takes
  `default-features = false`, so this build no longer pulls
  `axum`, `redis`, or `aes-gcm`/`argon2` via mediator-common.

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
