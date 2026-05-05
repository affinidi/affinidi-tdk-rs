# Affinidi Messaging Test Mediator

## Changelog history

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
