# Affinidi Messaging Test Mediator

## Changelog history

## 2nd July 2026

### 0.2.36 — TSP capability-learning e2e

- New `tests/tsp_capability.rs` covers SDD phase 2: observing an inbound TSP message
  upgrades a peer to `Supported` so `send_to` switches DIDComm → TSP; the same is inert
  under the default `Off` policy; and a full relationship handshake (the repo's first
  end-to-end TSP invite/accept) marks both peers `Supported`.

### 0.2.35 — TestEnvironment::spawn_with_tsp_policy + send_to e2e

- New `TestEnvironment::spawn_with_tsp_policy(policy)` builds the SDK's `ATM` with a chosen
  `TspPolicy`, so `atm.send_to` protocol selection can be driven end-to-end. New
  `tests/tsp_send_to.rs` exercises the TSP branch (capability `Supported` → TSP, DIDComm
  `Message` recovered from the TSP payload), the DIDComm fallback (`Unsupported` → forward
  delivery), and the `Required`-policy error. Internal `new_with_config` now takes the
  `ATMConfig` explicitly; no behaviour change to existing spawns.

## 29th June 2026

### 0.2.34 — TSP federation: advertise TSPTransport in the mediator's did:peer

- `generate_mediator_identity` now bakes a `TSPTransport` service (id `#tsp`, endpoint =
  the mediator's bound base URL) into the mediator's `did:peer`, so a peer mediator can
  resolve its TSP endpoint and forward across mediators. (Production `did:web` mediators
  auto-advertise this at startup; a `did:peer` bakes its document into the DID, so it must
  be present at generation — mirroring the production expectation for `did:peer`/`did:webvh`
  deployments.) Enables the new two-mediator `tsp_federation` e2e test.

## 27th June 2026

### 0.2.33 — TSP: pure-TSP authentication e2e

- New `TestEnvironment::spawn_with_tsp_auth()` (tsp-gated): builds the TDK with a shared
  secrets resolver + a registered `TspAuthHandler`, so every profile authenticates over
  TSP (`/tsp/authenticate`) instead of DIDComm. `new()` was refactored to delegate to a
  private `new_with_config` — `spawn()` behaviour is unchanged.
- New `tsp_auth` e2e (`pure_tsp_authentication_round_trips_a_direct_message`): a pure-TSP
  client sends + fetches a TSP Direct message; both legs require a JWT minted by the
  `TspAuthHandler` (challenge → Ed25519-sign → `/tsp/authenticate`), so a green round-trip
  proves the full pure-TSP auth chain.

### 0.2.32 — TSP: WebSocket SDK-consumer e2e

- New `tsp_websocket_sdk_consumer_flushes_and_deletes`: drives the SDK's
  `atm.tsp().connect_websocket` + `recv` + `unpack_bytes` (rather than a raw tungstenite
  client) against the embedded mediator — asserts the queued TSP is flushed, unpacks to the
  payload + sender, and is deleted afterwards. The raw-wire test is retained alongside it.

## 26th June 2026

### 0.2.31 — TSP: WebSocket delivery e2e

- New `tsp_websocket` test: Alice sends a TSP Direct message to Bob, Bob opens a raw
  WebSocket with the `tsp` subprotocol, and the test asserts the queued message is flushed
  on connect as a raw-TSP `Binary` frame (decodes to the original payload + sender) and is
  deleted afterwards (a subsequent fetch is empty). Adds `base64` as a dev-dep to re-encode
  the raw frame for `atm.tsp().unpack`.

## 24th June 2026

### 0.2.30 — TSP: Control relay e2e

- New `tsp_control_message_relays_through_the_mediator`: Alice sends a relationship-
  forming invite (a `Control` message) to Bob via `atm.tsp().send_control`; the mediator
  relays it, and Bob unpacks + decodes the invite. Adds `affinidi-tsp` as a dev-dep for
  the `ControlMessage` types.

### 0.2.29 — TSP: Nested relay e2e

- New `tsp_nested_message_relays_through_the_mediator`: Alice wraps an inner Direct
  (sealed to Bob) in a `Nested` envelope sealed to the mediator; the mediator unwraps
  its layer and forwards the inner to Bob, who unpacks the original payload + sender.

### 0.2.28 — Trust Tasks: acl/set self-service e2e

- New `acl_set_self_service_changes_a_self_manageable_flag` (alice changes her own
  `anonReceive`) and `acl_set_self_service_refuses_an_admin_only_flag` (alice can't set
  `blocked`); the cross-account denial test is reframed accordingly.

### 0.2.27 — Trust Tasks: admin family denial e2e

- `admin_family_denies_a_non_admin`: a standard account is refused all five
  `messaging/admin/*` tasks.

### 0.2.26 — Trust Tasks: access-list lifecycle e2e

- `access_list_self_lifecycle`: alice adds, queries, lists, removes, and clears entries
  on her own access list, asserting counts and present/absent partitioning throughout.

### 0.2.25 — Trust Tasks: account/add e2e

- `account_add_self_register_creates_a_standard_account` (a standard account adds a new
  account under the default `ExplicitDeny` mode) and
  `account_add_denies_a_non_admin_creating_an_admin`.

### 0.2.24 — Trust Tasks: acl/get + acl/set e2e

- `acl_get_self_returns_the_decoded_acl` (alice reads her own ACL) and
  `acl_set_denies_a_non_admin` (a standard account can't set ACLs).

### 0.2.23 — Trust Tasks: account/change-type denial e2e

- New `account_change_type_denies_a_non_admin` test. Adds a `trust-tasks-rs` dev-dep so
  tests can name Trust Task payload types (e.g. `AccountType`).

### 0.2.22 — Trust Tasks: account/remove e2e

- New `account_remove_self_removes_the_account` test: alice removes her own account
  and the store reports a record was removed.

### 0.2.21 — Trust Tasks: account/change-queue-limits e2e

- New `account_change_queue_limits_self_applies_caps_and_persists` test: alice changes
  her own limits (a value, and `-1` = unlimited), the change persists across a fresh
  read, and an over-limit request from a standard account is capped at the hard maximum.

### 0.2.20 — Trust Tasks: account/list authz e2e

- New `account_list_denies_a_non_admin` test: a standard account is refused
  `account/list`. (The admin happy-path listing isn't exercised end-to-end — an
  `add_admin` identity isn't a streaming-registered account, so the synchronous
  WebSocket response can't be established on the in-memory harness; the account view
  itself round-trips via the `account/get` test, which `account/list` reuses.)

### 0.2.19 — Trust Tasks: account/get e2e

- New `account_get_self_returns_the_callers_account` test: alice fetches her own
  account via `atm.trust_tasks().account_get(.., None)` and asserts the identity
  (hash as `Vid`), account type, and decoded ACL booleans round-trip through a live
  mediator.

## 23rd June 2026

### 0.2.18 — Trust Tasks ping e2e

- New `trust_tasks` integration test: `atm.trust_tasks().ping()` round-trips through
  a live mediator (SDK → DIDComm binding envelope → the mediator's Trust Tasks
  consumer → typed response), asserting status, nonce echo, and advertised protocols.

### 0.2.17 — Assert message-protocol tagging

- The Direct and bridge e2e tests now assert the fetched message's `protocol`
  field (TSP and DIDComm respectively) — proving the mediator tags the wire
  protocol on pickup transparently.

### 0.2.16 — TSP remote-forwarding e2e

- New `tsp_routed_forwards_to_a_remote_recipients_mediator` test: the recipient
  lives on another mediator (his `did:peer` advertises a `tsp` transport endpoint
  elsewhere). The mediator resolves the remote endpoint and enqueues the message
  for forwarding. Unblocked by the `affinidi-did-common` 0.3.9 fix to `did:peer`
  custom-service-type resolution.

### 0.2.15 — TSP↔DIDComm bridge e2e

- New `tsp_routed_bridges_a_didcomm_message_to_the_recipient` test: Alice authcrypts
  a DIDComm message to Bob and routes it over TSP through the mediator; the mediator
  delivers the opaque DIDComm inner and Bob unpacks it natively. Proves protocol
  bridging end to end.

### 0.2.14 — TSP routed relay e2e

- New `tsp_routed_message_relays_through_the_mediator` test: Alice sends a TSP
  message routed through the mediator (as a relay hop) to Bob, asserting the
  payload survives the relay and the original sender is recovered. Complements the
  existing Direct delivery test.

## 22nd June 2026

### 0.2.13 — TSP end-to-end fixture

- New opt-in `tsp` feature spawns the mediator with TSP support and enables the
  SDK's `atm.tsp()`, so the suite can exercise dual-protocol (DIDComm + TSP)
  flows.
- New `tsp_delivery` integration test: a full TSP Direct round-trip through the
  mediator driven by the SDK (alice packs → `/inbound` sniff + store → bob fetches
  + unpacks), asserting payload and sender are recovered. DIDComm suite unchanged.

## 14th June 2026

### 0.2.12 — non_exhaustive error enums (W7 sweep)

- `TestEnvironmentError`, `TestMediatorError`, and `TestTopologyError` are now
  `#[non_exhaustive]` (ADR-0003) so new variants land additively. Patch bump
  keeps the `0.2` pin valid; consumers that `match` them must add a `_` wildcard
  arm. No behaviour change.

### 0.2.11 — inject a clock for fast expiry tests (TI4b)

- `TestMediatorBuilder::clock(Arc<dyn Clock>)` injects a clock into the spawned
  mediator. Pair a `TestClock` with `jwt_expiry(..)` to expire a token in
  milliseconds: issue with a short lifetime, then `clock.advance_secs(..)` past
  it. Re-exports `Clock` / `SystemClock` / `TestClock` (enables the
  `affinidi-messaging-mediator-common/test-clock` feature).
- New `tests/clock_injection.rs`: authenticate, advance the clock past the token
  lifetime (no real time passes), and confirm the mediator rejects the token.
- Tracks the mediator's 0.16 bump.

## 11th June 2026

### 0.2.9 — builder support for the per-DID WebSocket cap (mediator T13)

- Adds `TestMediatorBuilder::max_websocket_connections_per_did(usize)` (passing
  a custom `LimitsConfig` through to the mediator) and a new e2e
  (`second_connection_for_one_did_over_the_cap_is_closed`) verifying the
  over-cap WebSocket connection is closed by the server.

### 0.2.8 — builder support for the explicit relay flag (mediator T12)

- Adds `TestMediatorBuilder::enable_inter_mediator_relay(bool)` to override
  `SecurityConfig.enable_inter_mediator_relay`, and a new e2e
  (`non_relay_mediator_rejects_cross_mediator_forward`) verifying a non-relay
  mediator drops the anonymous cross-mediator hop.

## 10th June 2026

### 0.2.7 — health-endpoint integration tests (mediator T2)

- **TEST:** new `health_endpoints` suite covering the task-supervision
  health contract added in `affinidi-messaging-mediator` 0.15.22 — `/livez`
  returns 200 (process-liveness only) and `/readyz` reports supervised
  background tasks under `components` with the always-on `statistics` task
  and the load-bearing `forwarding_processor` task both `running`. Runs on
  the default in-memory backend; fixture API unchanged.

### 0.2.6 — relay rewrap builder knobs + end-to-end rewrap tests (#388)

- **FEAT:** `TestMediatorBuilder::relay_mode(RelayMode)` and
  `relay_trusted_mediators(...)` expose the inter-mediator relay posture so
  tests can stand up `RelayMode::Rewrap` mediators (per-hop re-encryption)
  with an optional trusted-peer allowlist. `RelayMode` is re-exported from
  the crate root.
- **TEST:** extends `cross_mediator_forwarding` with three rewrap
  end-to-end cases on the memory backend — a bidirectional rewrap round
  trip, a trusted-peer allowlist *admitting* the relaying mediator, and an
  allowlist *rejecting* an unlisted peer (no delivery; the relay is refused
  with `authorization.relay.untrusted_peer`). This is the automated pre-merge
  verification `affinidi-messaging-mediator` #388 had been waiting on — the
  full rewrap plumbing (routing rewrap → FORWARD_Q → processor → HTTP →
  inbound peel), now exercisable without Redis thanks to #399.

### 0.2.5 — cross-mediator forwarding test + production-shaped mediator DID

- **FIX:** the fixture's generated mediator `did:peer` advertised its
  DIDComm (`dm`) HTTP service endpoint *with* a trailing slash
  (`http://<host>/mediator/v1/`). The production mediator DID advertises
  the bare base with no trailing slash (see mediator-setup's `did_peer`
  generator), and the SDK builds request URLs by concatenation
  (`{endpoint}/inbound`) — so the trailing slash produced `…/v1//inbound`,
  which the mediator router 404s. Any SDK HTTP send against the fixture
  hit this; it was masked until now because existing tests retrieve over
  WebSocket. The `dm` endpoint is now trimmed to match production; the
  `#auth` endpoint string is unchanged, so authentication/WS tests are
  unaffected.
- **TEST:** new `cross_mediator_forwarding` suite — two in-process
  mediators (Alice on A, Bob on B), with Alice's message routed
  A → mediator-A → mediator-B → Bob via the routing-2.0 double forward and
  picked up on Bob's live stream. Covers both one-way delivery and a
  round trip, exercising the relay-sender auto-registration on each
  mediator. This is the end-to-end regression for
  `affinidi-messaging-mediator` #399 (forwarding processor running on the
  memory backend) and the first multi-mediator scenario built purely on
  the published `TestMediator` / `TestEnvironment` fixtures — no Redis.
- Adds an `affinidi-messaging-didcomm` dev-dependency for the `Message`
  builder the test uses to hand-roll the double forward.

## 1st June 2026

### 0.2.4 — rebuilt against the didcomm 0.15 mediator

- Release rebuilt against `affinidi-messaging-mediator` 0.15.12 /
  `affinidi-messaging-didcomm` 0.15 (#327). Test fixture only; no
  behaviour change. Lets downstream test trees (e.g. `vta-sdk`) build on
  a single didcomm 0.15.

## 21st May 2026

### 0.2.3 — WebSocket subprotocol auth integration tests

Test-only release — the shipped fixture API (`src/`) is unchanged.

- **TEST:** new `websocket_subprotocol_auth` integration suite covering
  the mediator's browser-friendly WebSocket auth (paired with
  `affinidi-messaging-mediator` 0.15.4): subprotocol `bearer.<jwt>`
  authentication, the `Authorization` header regression path, the 101
  response not echoing the token, invalid-token rejection, and the
  WebSocket `Origin` check. Uses raw `tokio-tungstenite` clients plus a
  hand-rolled handshake for the bearer-only browser case (which
  tokio-tungstenite's strict client can't express, since it errors when
  the server selects no subprotocol).
- **CHORE:** add the `tokio` `io-util` dev-dependency feature for the
  raw-socket handshake test.

## 5th May 2026

### 0.2.2 — ACL / security mode simulation + admin identity

Significant additive surface for tests that need to simulate
non-default mediator deployments. Defaults match prior releases —
existing tests run unchanged.

- **FEAT:** `acl` preset module — typed `allow_all()` and `deny_all()`
  constructors that mirror the production
  `MediatorACLSet::from_string_ruleset` parser arm-by-arm via the
  public bit-setter API. Avoids string-ruleset parsing in test code;
  ruleset typos can no longer hide as runtime errors.
- **FEAT:** Re-exports of `AccessListModeType`, `MediatorACLSet`, and
  `ACLError` from `mediator-common` so consumers don't need a direct
  dep just to construct an `acl_mode(...)` argument or inspect a
  `get_acl(...)` return.
- **FEAT:** `TestMediatorBuilder` ACL knobs — `acl_mode`,
  `global_acl_default`, `local_direct_delivery`,
  `block_anonymous_outer_envelope`, `force_session_did_match`,
  `block_remote_admin_msgs`, `jwt_expiry`, `local_endpoints`. All
  Option-typed; `None` keeps the production default.
- **FEAT:** `TestMediatorHandle::add_user_with_acl(alias, acls)`,
  `set_acl(did, acls)`, `get_acl(did) -> Option<MediatorACLSet>` for
  per-user ACL CRUD. `set_acl` and `get_acl` go through the underlying
  `MediatorStore` directly — the **fixture-bypass** path. Use this
  for verifying admin-protocol writes; for testing protocol
  enforcement itself, drive the SDK's `acls_set` from an admin-
  authenticated profile (see `add_admin`).
- **FEAT:** `AdminIdentity` struct + `TestMediator::random_admin_identity()`
  associated function. Mints a fresh `did:peer:2` admin with usable
  secrets; pair with `TestMediatorBuilder::admin_identity(...)` to
  pin the mediator to a known admin DID.
- **FEAT:** `TestEnvironment::add_admin(AdminIdentity)` wires an SDK
  profile authenticated as the configured admin DID. Validates
  `identity.did == mediator.admin_did()` to surface misuse early
  (returns `TestEnvironmentError::AdminMismatch`). Admin secrets are
  inserted into the SDK resolver but **not** the mediator's own
  server-side resolver — the admin authenticates via DID resolution
  + signature verification, so the private key never crosses the
  fixture boundary.
- **FEAT:** `did_hash()` on both `TestUser` and `TestMediatorUser` —
  SHA-256 of the DID, the canonical key shape used by admin-protocol
  calls (`acls_set`, `access_list_add`, `account_remove`). Removes a
  leak of internals from every admin-protocol test.
- **REFACTOR:** Internal `register_local_did` now uses
  `acl::allow_all()` instead of `MediatorACLSet::from_string_ruleset("ALLOW_ALL")`.
  Minor code cleanup; behavior unchanged.
- **TEST:** 11 new lifecycle tests covering the new surface — ACL
  CRUD, `add_admin` happy / mismatch paths, security-knob plumbing,
  preset constructors, and a `did_hash` round-trip.

### 0.2.1 — Routing-fix test additions (bundled with mediator 0.15.1)

- **TEST:** `add_user_dids_have_mediator_did_as_service_uri` and
  `with_users_dids_have_mediator_did_as_service_uri` — resolve a
  minted user DID and assert its DIDCommMessaging service URI is the
  mediator's DID. The architectural contract the routing-2.0
  self-loopback fix relies on.
- **TEST:** `enable_external_forwarding_disabled_spawns_successfully` —
  smoke-tests the builder option.
- **CHORE:** Bumped internal pin on
  `affinidi-messaging-mediator-common` to `0.15` to track the
  feature-gating rework.

### 0.2.0 — Initial public release

- Embedded mediator fixture with `MemoryStore` default backend
  (Redis-free spawn) and an optional `fjall-backend` feature for
  on-disk persistence tests.
- `TestEnvironment` for end-to-end tests with a wired SDK client.
- `TestMediator::with_users` / `add_user` for one-shot multi-user
  setup against the routing-2.0 service-URI shape.
