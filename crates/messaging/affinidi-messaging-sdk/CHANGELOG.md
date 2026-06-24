# Changelog

## [0.18.31] - 2026-06-24

The legacy `atm.mediator()` management methods are now `#[deprecated]` in favour of the
`atm.trust_tasks()` core: `account_get`/`account_add`/`account_remove`/`accounts_list`/
`account_change_type`/`account_change_queue_limits`, `acls_get`/`acls_set`,
`access_list_{list,add,remove,clear,get}`, and `get_config`/`add_admins`/`strip_admins`/
`list_admins`/`list_audit_log` — each points to its `atm.trust_tasks().*` replacement.
The methods still work (legacy DIDComm wire); they will be removed in a future major
release (the breaking change). **Additive — patch bump, `0.18` pin stays valid.** (The
deliberately-louder minor/major bump is reserved for the removal, per the workspace's
patch-not-minor convention.)

## [0.18.30] - 2026-06-24

`atm.trust_tasks()` gains the admin family: `admin_add` / `admin_strip` / `admin_list` /
`admin_audit_log` / `admin_config` (all admin only). Completes the messaging Trust Tasks
client surface. Additive.

## [0.18.29] - 2026-06-24

`atm.trust_tasks()` gains the access-list family: `access_list_add` / `access_list_remove`
/ `access_list_clear` / `access_list_get` / `access_list_list` (self-or-admin; `None` =
own list). Completes the messaging Trust Tasks client surface. Additive.

## [0.18.28] - 2026-06-24

`atm.trust_tasks().account_add(profile, did_hash, account_type, acl)` — create an
account and return its realized view. Completes the account-family client surface.
Additive.

## [0.18.27] - 2026-06-24

`atm.trust_tasks()` gains `acl_get(profile, did_hashes)` (self-or-admin; batched ACL
read → entries + unknown) and `acl_set(profile, did_hash, acl)` (admin only; partial
ACL update → realized ACL). Additive.

## [0.18.26] - 2026-06-24

`atm.trust_tasks().account_change_type(profile, did_hash, account_type)` (admin only) —
change an account's role and return its realized view. Only a root admin may assign the
root-admin role or modify a root-admin account. Additive.

## [0.18.25] - 2026-06-24

`atm.trust_tasks().account_remove(profile, did_hash)` — remove an account (self-or-admin;
`None` = self) and return whether a record was removed. The mediator's own and the
root-admin accounts can't be removed. Additive.

## [0.18.24] - 2026-06-24

`atm.trust_tasks().account_change_queue_limits(profile, did_hash, send, receive)` —
change an account's queued-message limits and return the updated view. `None` target
= self; each limit is `Some(-1)` (unlimited) / `Some(n)` / `None` (unchanged). Additive.

## [0.18.23] - 2026-06-24

`atm.trust_tasks().account_list(profile, cursor, limit)` (admin only) — returns one
page of accounts plus an opaque `next_cursor` (present only when more remain); pass
it back to continue. Additive.

## [0.18.22] - 2026-06-24

`atm.trust_tasks().account_get(profile, did_hash)` — fetch the mediator's view of an
account as a typed `account/get` response. `None` requests the caller's own account
(self; no admin rights needed). Shares the binding-envelope send path with `ping`
(refactored into an internal `exchange` helper). Additive.

## [0.18.21] - 2026-06-23

New `atm.trust_tasks()` accessor with `.ping(profile, nonce)` — sends a
`messaging/ping` Trust Task to the mediator (over the DIDComm binding envelope) and
returns the typed `ping` response (server time, status, supported protocols, echoed
nonce). Additive — the first of the messaging Trust Tasks client surface; account /
acl / access-list follow, and the legacy `atm.mediator()` / `atm.trust_ping()`
methods will route through this core (the breaking change that lands then is
signalled by a minor bump).

## [0.18.20] - 2026-06-23

`MessageType` gains a `TrustTaskEnvelope` variant (the Trust Tasks DIDComm binding
envelope `type`), so the mediator can route Trust Task documents. Additive
scaffolding for the messaging Trust Tasks migration; no API change. The deliberate
minor bump that signals the migration's breaking client changes lands with
`atm.trust_tasks()` (next).

## [0.18.19] - 2026-06-23

WebSocket live-stream is now TSP-safe. An inbound frame is sniffed (the frame is
self-describing CESR qb64); a TSP message is delivered **packed** — so the
consumer unpacks it via `atm.tsp()` — instead of being routed into the DIDComm
`unpack`, where it previously failed and was silently dropped. DIDComm frames are
unchanged, and the sniff is gated on the `tsp` feature (no-op without it).

## [0.18.18] - 2026-06-23

Re-exports `MessageProtocol` (from `affinidi-messaging-mediator-common`).
Fetched messages now carry a `protocol` field (`Some(MessageProtocol::DidComm |
Tsp | …)`), tagged server-side, so a client can route each message natively
without inspecting it. Additive; patch bump.

## [0.18.17] - 2026-06-23

`atm.tsp().send_routed_opaque(profile, route, inner)` — route an **already-packed**
inner message through TSP relay hops. The inner may be a **DIDComm** message (the
TSP↔DIDComm bridge): pack it with `atm.pack_encrypted`, then route it over TSP to a
recipient who unpacks it natively. `send_routed` now builds on this. Additive;
patch bump.

## [0.18.16] - 2026-06-23

`atm.tsp()` gains routed send:
- `send_routed(profile, route, payload)` — send a TSP message through one or more
  relay hops. The payload is sealed end-to-end to the final recipient
  (`route.last()`), wrapped in a routing layer sealed to the first hop
  (`route[0]`, a TSP-routing mediator); each hop unwraps and forwards onward.
- `send_raw(profile, bytes)` — POST an already-packed TSP message to `/inbound`
  (the shared transport `send()` now builds on this).

Verified end to end against a live mediator relay in
`affinidi-messaging-test-mediator`. Additive; patch bump.

## [0.18.15] - 2026-06-22

Picks up the `affinidi-did-common` 0.3.8 fix for
`DocumentExt::find_authentication`, which **fixes DIDComm signed-message
verification when the signer's `kid` is a bare DID** (no fragment): the unpack
path looked up the first authentication key via that method and previously got a
keyAgreement (X25519) key, so verification failed. Fragment-qualified kids were
unaffected. Also drops the local workaround in `atm.tsp()` (now that
`find_authentication` is correct). No API change; patch bump.

## [0.18.14] - 2026-06-22

TSP send/receive — `atm.tsp()` can now pack, send, and unpack TSP **Direct**
messages end to end:

- `pack(profile, to_did, payload)` builds a TSP Direct message — extracting the
  profile's Ed25519 signing key (from its `authentication`) and X25519 encryption
  key (from its `keyAgreement`) via the secrets resolver, and resolving the
  recipient's keys from its DID document.
- `send(profile, to_did, payload)` packs and POSTs to the mediator `/inbound`,
  reusing the profile's existing (DIDComm) authenticated session for the bearer
  token; the mediator sniffs the TSP magic byte and stores it for pickup.
- `unpack(profile, stored)` decodes a fetched message, resolves the sender, and
  decrypts + verifies with the profile's key, returning `(payload, sender_vid)`.

Verified end to end against a live mediator in
`affinidi-messaging-test-mediator` (alice packs → mediator stores → bob unpacks).
Additive (no `tsp` feature = no change); patch bump keeps the `0.18` pin valid.

NB: works around a copy-paste bug in `affinidi-did-common`'s
`DocumentExt::find_authentication(None)` (it returns `keyAgreement` ids) by
reading `doc.authentication` directly.

## [0.18.13] - 2026-06-22

TSP client support — foundation. New optional `tsp` feature and an `atm.tsp()`
ops accessor (the TSP sibling of `atm.routing()` etc.). This first slice adds the
**storage-format codec** a client needs on pickup: a mediator stores a TSP message
`base64url(qb2)` (its CESR qb64 text form, `1AAF…`), so `atm.tsp().is_tsp()`
distinguishes it from a DIDComm JSON envelope and `decode()`/`encode()` convert
to/from the raw qb2 bytes. Purely additive (no `tsp` feature = no change); patch
bump keeps the `0.18` pin valid. The pack/send and fetch/unpack paths land next.

## [0.18.12] - 2026-06-14

`ATMError` is now `#[non_exhaustive]` (ADR-0003) so new variants land additively.
Patch bump keeps the `0.18` pin valid; match it with a `_` wildcard arm. No
behaviour change. (W7 sweep)

## [0.18.11] - 2026-06-14

Injectable clock for the SDK's expiry/TTL reads (TI4b-2).

### Added

- `ATMConfigBuilder::with_clock(Arc<dyn Clock>)` injects the clock the SDK uses
  for its time reads (defaults to the real `SystemClock`). The `Clock` trait
  comes from `affinidi-messaging-mediator-common` (shared with the mediator,
  TI4b-1), so a test can drive both with one `TestClock`.

### Changed

- The SDK's expiry/TTL **decisions** now read the injected clock instead of the
  wall clock directly: forwarded-message expiry (`extract_forward_payload`) and
  the WebSocket token-refresh TTL (`refresh_deadline`). Additive — existing
  callers are unaffected. The refresh deadline is still *scheduled* on tokio's
  monotonic timer; only the TTL computation moved to the injected clock.
- Outbound protocol-message `created_time`/`expires_time` stamps still read the
  wall clock (a documented follow-up); the mediator's own injected clock governs
  enforcement, so this does not affect expiry tests.

## [0.18.10] - 2026-06-13

WS resilience (W16, part 2 of 2).

### Added

- **Proactive WebSocket token refresh.** The mediator force-closes a WebSocket
  at access-token expiry (it only checks the JWT at upgrade, and has no in-band
  refresh). The transport now records the token's expiry and, at ~80% of its
  lifetime, refreshes the token via the refresh-token flow
  (`AuthenticationCache::refresh`, which has the mediator re-verify the DID is
  still allowed to connect) and reconnects with the fresh token — *before* the
  forced close — rather than waiting to be kicked and reconnecting reactively.

### Changed

- **The background deletion handler is now supervised** via the shared
  `affinidi-task-utils` `TaskSupervisor`: a panic or error is detected and the
  task restarted with capped backoff (it previously died silently, leaving
  background deletions unprocessed for the life of the process). Shutdown now
  flows through a `CancellationToken`. Public method signatures are unchanged.

## [0.18.9] - 2026-06-13

SDK request-path hardening (W16, part 1 of 2).

### Added

- **Configurable request timeout.** `ATMConfig::with_request_timeout(Duration)`
  (default 15s) overrides the per-request timeout for mediator REST calls. The
  previously hardcoded `MEDIATOR_REQUEST_TIMEOUT` constants (duplicated in
  `delete.rs`/`list.rs`) are removed in favour of the config value.

### Fixed

- **No panic on a malformed mediator response.** `delete_messages_direct`,
  `list_messages`, and `get_messages` parsed the response body with
  `.ok().unwrap()`, panicking the caller (or the deletion-handler task) on any
  non-JSON 2xx body. They now return `ATMError::TransportError` instead.
- **`get_messages` had no request timeout** and could hang indefinitely on a
  network stall; it is now bounded by the configured request timeout like the
  other REST calls.

### Changed

- **WebSocket reconnect backoff is now jittered (±15%).** The exponential
  backoff (1→2→4…→60s) previously reconnected in lock-step across clients;
  jitter spreads reconnections so a recovering mediator isn't stampeded.
  (`rand` promoted from dev- to normal dependency for non-cryptographic jitter.)

## [0.18.8] - 2026-06-13

### Added

- **`Mediator::list_audit_log` (and `MediatorOps::list_audit_log`)** — admin
  client method to page the mediator's privileged-change audit log (newest-first,
  cursor-paginated), sending the new `audit_log_list` administration request.
  Re-exports `AuditLogEntry`, `AuditAction`, and `MediatorAuditLogList` from
  `affinidi-messaging-mediator-common`. Pairs with mediator 0.15.44 / simplification T25b.

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
