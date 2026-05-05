# affinidi-messaging-test-mediator

[![Crates.io](https://img.shields.io/crates/v/affinidi-messaging-test-mediator.svg)](https://crates.io/crates/affinidi-messaging-test-mediator)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)

Embedded mediator fixture for integration tests against
[`affinidi-messaging-mediator`]. Spins up a fully-functional mediator
on `127.0.0.1:0` (ephemeral port) with a freshly-generated `did:peer`
identity, a random JWT signing key, and the caller's choice of
storage backend — `MemoryStore` by default, optional `FjallStore` for
on-disk persistence semantics.

## When to use

Anywhere you need an in-process mediator for tests:
- SDK round-trip tests that exercise the full DIDComm v2.1 pickup,
  routing, and trust-ping flows.
- Auth flow tests (challenge/response, JWT, WebSocket upgrade).
- Multi-mediator forwarding scenarios (run two test mediators in
  the same process and route a message through both).
- ACL coverage for the mediator's own access-list logic.

## Quick start

```toml
# Cargo.toml
[dev-dependencies]
affinidi-messaging-test-mediator = "0.1"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

```rust,ignore
use affinidi_messaging_test_mediator::TestMediator;

#[tokio::test]
async fn end_to_end_round_trip() {
    let mediator = TestMediator::spawn()
        .await
        .expect("test mediator spawn");

    let endpoint = mediator.endpoint();
    let did = mediator.did();
    // ... use SDK against `endpoint` and `did` ...

    mediator.shutdown();
    mediator.join().await.unwrap();
}
```

For the full e2e flow with an SDK client and named users, use
[`TestEnvironment`]:

```rust,ignore
use affinidi_messaging_test_mediator::TestEnvironment;

#[tokio::test]
async fn alice_sends_to_bob() {
    let env = TestEnvironment::spawn().await.unwrap();
    let alice = env.add_user("Alice").await.unwrap();
    let bob = env.add_user("Bob").await.unwrap();

    // Exercise the SDK against `env.atm`, `alice.profile`, `bob.profile` ...

    env.shutdown().await.unwrap();
}
```

## Local vs. remote routing

A common footgun for callers wiring up their own DIDs against the
test mediator: **the recipient's DIDComm service URI should be the
mediator's DID, not the mediator's HTTP URL**.

Routing 2.0 (`messagepickup/3.0` + `routing/2.0`) treats the
service URI as a logical pointer. When the mediator processes a
`forward` envelope it looks up the next-hop DID Document and asks:

- service URI matches *my own DID* → store locally, deliver via
  pickup or live stream;
- service URI is an HTTP(S)/WS(S) URL whose `(host, port)` matches
  the mediator's bind address (or any operator-declared
  `local_endpoints` alias) → also stored locally;
- service URI is an HTTP(S)/WS(S) URL pointing somewhere else →
  enqueue on `FORWARD_Q` and the forwarding processor relays to that
  remote mediator.

The bind-address match is a defensive measure (added in mediator
0.15.0) so a self-pointing URL doesn't loop through `FORWARD_Q`.
But hostname-fronted deployments (load balancers, public DNS)
still need an explicit alias declared via `MediatorBuilder::local_endpoints`
or the `[server.local_endpoints]` config — and using the mediator's
DID as the service URI sidesteps the whole question, which is why
the test-mediator helpers default to that shape.

**The right shape for a user DID:**

```text
did:peer:2.{recipient keys}.S{service entry pointing at <mediator's DID>}
```

The mediator's own DID Document then resolves the HTTP/WS endpoints
for the network round-trip — exactly one hop, locally delivered.

The fixture's helpers all follow this shape:

```rust,ignore
// One-shot: spawn + pre-create users.
let (mediator, users) = TestMediator::with_users(["alice", "bob"])
    .await
    .unwrap();
let alice = &users[0]; // alice.did points at mediator.did() as its service
```

```rust,ignore
// Add users incrementally after spawn.
let mediator = TestMediator::spawn().await.unwrap();
let alice = mediator.add_user("alice").await.unwrap();
```

Both register the user as `LOCAL, ALLOW_ALL` on the mediator and
insert the user's secrets into the mediator's resolver, so callers
can pack/unpack messages without further wiring.

If you need to drive the mediator with externally-created DIDs, mint
them yourself with the mediator's DID as their DIDComm service URI
and call [`TestMediatorHandle::register_local_did`] to land the
account record:

```rust,ignore
let (did, secrets) = generate_my_did(mediator.did())?;
mediator.register_local_did(&did).await.unwrap();
```

### Escape hatch: disable external forwarding

When a test legitimately wants to drive forwarding-shaped messages
through the mediator without the relay step (for example, when
exercising `routing/2.0/forward` in isolation), flip
[`TestMediatorBuilder::enable_external_forwarding`] to `false`.
Every `forward` then falls through to local delivery regardless of
what the next-hop DID Document says — useful as a stop-gap, but it
does not exercise the production forwarding path.

```rust,ignore
let mediator = TestMediator::builder()
    .enable_forwarding(true)
    .enable_external_forwarding(false)
    .spawn()
    .await
    .unwrap();
```

## Authenticating non-admin DIDs over WebSocket

The mediator's WebSocket handler refuses upgrades unless the
authenticated session has the `LOCAL` ACL bit set. By default, a DID
that authenticates fresh against the test mediator is auto-registered
with `global_acl_default` — which has `local = false` for the test
fixture. Tests that open a WS connection from a non-admin DID need to
register the DID at startup:

```rust,ignore
let mediator = TestMediator::builder()
    .local_did(client_did.clone())
    .spawn()
    .await
    .expect("spawn");
```

Then the SDK's `profile_add(_, /* live_stream */ true)` flow completes
the JWT handshake and opens the WebSocket without hitting the 403.

For finer control over per-user ACLs, use
[`add_user_with_acl`](TestMediatorHandle::add_user_with_acl) (see
"Simulating different ACL modes" below).

## Simulating different ACL modes

Production deployments configure the mediator with a few interrelated
ACL knobs:

- `mediator_acl_mode` — `ExplicitDeny` (denylist; default) or
  `ExplicitAllow` (allowlist).
- `global_acl_default` — the `MediatorACLSet` applied to any DID that
  authenticates without a pre-existing account.
- per-DID `MediatorACLSet` — overrides the global default for
  registered accounts.

The fixture exposes typed setters for all three. **Defaults match
`SecurityConfig::default`** so tests that don't touch these knobs are
unaffected; today's `ExplicitDeny` + `MediatorACLSet::default()` +
per-user `ALLOW_ALL` shape is preserved.

```rust,ignore
use affinidi_messaging_test_mediator::{
    AccessListModeType, TestMediator, acl,
};

// Allowlist deployment + strict global default. Non-registered DIDs
// authenticate fine but every send/receive permission is denied until
// an admin grants them.
let mediator = TestMediator::builder()
    .acl_mode(AccessListModeType::ExplicitAllow)
    .global_acl_default(acl::deny_all())
    .spawn()
    .await
    .expect("spawn");

// Mint alice with a custom per-DID ACL — typed presets cover the
// common cases; build a `MediatorACLSet` directly for finer control.
let alice = mediator
    .add_user_with_acl("alice", acl::allow_all())
    .await
    .expect("add alice");

// Revoke mid-flow without going through the admin protocol — the
// fixture-bypass path. Use this when you're testing client behavior
// against a denied path, not the admin protocol itself.
mediator
    .set_acl(&alice.did, acl::deny_all())
    .await
    .expect("set_acl");

// Read back via the same bypass path.
let observed = mediator
    .get_acl(&alice.did)
    .await
    .expect("get_acl")
    .expect("alice has ACL record");
assert_eq!(observed.to_u64(), acl::deny_all().to_u64());
```

The [`acl`](crate::acl) module exports `allow_all()` and `deny_all()`
as typed equivalents of the production string presets. For
fine-grained ACLs, build a `MediatorACLSet` directly via
`MediatorACLSet::default()` plus the bit setters — both
[`MediatorACLSet`] and [`AccessListModeType`] are re-exported from
this crate so consumers don't need a direct dep on
`affinidi-messaging-mediator-common`.

Other security flags exposed on the builder for completeness:
[`local_direct_delivery`](TestMediatorBuilder::local_direct_delivery),
[`block_anonymous_outer_envelope`](TestMediatorBuilder::block_anonymous_outer_envelope),
[`force_session_did_match`](TestMediatorBuilder::force_session_did_match),
[`block_remote_admin_msgs`](TestMediatorBuilder::block_remote_admin_msgs),
[`jwt_expiry`](TestMediatorBuilder::jwt_expiry),
[`local_endpoints`](TestMediatorBuilder::local_endpoints).

## Admin protocol tests

The mediator's admin DID is configured at startup via
`MediatorBuilder::admin_did`. By default the fixture mints an opaque
`did:key:z6Mk{uuid}` shape with no usable secrets — fine for tests that
don't authenticate as admin. To drive the mediator-administration
protocol from a real SDK client, mint a usable admin identity and
attach it to the builder:

```rust,ignore
use affinidi_messaging_test_mediator::{TestEnvironment, TestMediator, acl};

// Step 1 — mint admin DID + secrets. The same `AdminIdentity` value
// can drive multiple test-mediator instances if needed.
let admin = TestMediator::random_admin_identity().expect("admin identity");

// Step 2 — pin the mediator to that admin.
let mediator = TestMediator::builder()
    .admin_identity(admin.clone())
    .spawn()
    .await
    .expect("spawn");
let env = TestEnvironment::new(mediator).await.expect("env new");

// Step 3 — wire an SDK profile authenticated as that admin. The
// admin's secrets are inserted into the SDK resolver here (so it can
// sign auth challenges); they are NOT inserted into the mediator's
// own server-side resolver.
let admin_user = env.add_admin(admin).await.expect("add_admin");

// Step 4 — drive the admin-protocol surface. The protocol takes
// hashed DIDs, exposed on TestUser / TestMediatorUser as
// `did_hash()`.
let alice = env.add_user("alice").await.expect("add alice");
env.atm
    .protocols()
    .mediator()
    .acls()
    .acls_set(&env.atm, &admin_user.profile, &alice.did_hash(), &acl::deny_all())
    .await
    .expect("admin acls_set");

// Step 5 — verify via the fixture-bypass read path. Independent
// verification of a write that went through the protocol.
let observed = env
    .mediator
    .get_acl(&alice.did)
    .await
    .expect("get_acl")
    .expect("alice has ACL record");
assert_eq!(observed.to_u64(), acl::deny_all().to_u64());
```

**Secrets ownership.** `AdminIdentity::secrets` stays with the caller.
[`add_admin`](TestEnvironment::add_admin) inserts them into the SDK's
secrets resolver so the SDK can sign on the admin's behalf. The
mediator's own server-side secrets resolver is **not** touched — that
resolver holds the mediator's operating keys, not its admin's. The
admin authenticates via DID resolution + signature verification of
the HTTP-auth challenge, so the private key never crosses the fixture
boundary.

## Crypto provider

The fixture installs rustls' `aws_lc_rs` `CryptoProvider` as the
process-wide default during `spawn`. This avoids the dual-provider
panic that bites consumers who depend on both this crate (built
against `aws_lc_rs`) and another crate that activates the
`rust_crypto` rustls provider. The install is idempotent — call
[`install_default_crypto_provider`] yourself if you need it before
the first `spawn`.

If your test crate transitively pulls in conflicting providers, run
`cargo tree -e features` and pin to `aws_lc_rs` everywhere — the
mediator (and therefore this fixture) is not built or tested against
`rust_crypto`.

## Storage backends

`MemoryStore` is the default — fastest, no I/O, automatic cleanup.
Pass a custom store via [`TestMediatorBuilder::store`] for tests
that need different semantics:

- **Fjall** (on-disk LSM) — compile with the `fjall-backend` feature
  and call [`TestMediatorBuilder::fjall_backend`]. The fixture
  manages a temp directory whose lifetime is tied to the handle, so
  no partition files leak.
- **Redis** — supply an `Arc<RedisStore>` via `store(...)`. Useful
  for tests that exercise multi-mediator coordination, but requires
  a reachable Redis instance.

## Cross-workspace consumption

When using this crate from outside the `affinidi-tdk-rs` workspace
(via crates.io or git pin), be aware of the
[`[patch.crates-io]` gotcha](../README.md#using-affinidi--crates-from-outside-this-workspace)
documented in the workspace README. In short: consumers using *any*
affinidi-* crate via git/path need to mirror the workspace's patch
table so the type graph stays unified across the dependency closure.
The crates.io build is self-consistent and needs no patches.

## License

[Apache-2.0](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)

[`affinidi-messaging-mediator`]: https://crates.io/crates/affinidi-messaging-mediator
[`TestMediatorBuilder::store`]: https://docs.rs/affinidi-messaging-test-mediator/latest/affinidi_messaging_test_mediator/struct.TestMediatorBuilder.html#method.store
[`TestMediatorBuilder::fjall_backend`]: https://docs.rs/affinidi-messaging-test-mediator/latest/affinidi_messaging_test_mediator/struct.TestMediatorBuilder.html#method.fjall_backend
[`TestMediatorBuilder::enable_external_forwarding`]: https://docs.rs/affinidi-messaging-test-mediator/latest/affinidi_messaging_test_mediator/struct.TestMediatorBuilder.html#method.enable_external_forwarding
[`TestMediatorHandle::register_local_did`]: https://docs.rs/affinidi-messaging-test-mediator/latest/affinidi_messaging_test_mediator/struct.TestMediatorHandle.html#method.register_local_did
[`TestEnvironment`]: https://docs.rs/affinidi-messaging-test-mediator/latest/affinidi_messaging_test_mediator/struct.TestEnvironment.html
[`install_default_crypto_provider`]: https://docs.rs/affinidi-messaging-test-mediator/latest/affinidi_messaging_test_mediator/fn.install_default_crypto_provider.html
