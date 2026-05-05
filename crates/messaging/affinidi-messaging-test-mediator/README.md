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
[`TestEnvironment`]: https://docs.rs/affinidi-messaging-test-mediator/latest/affinidi_messaging_test_mediator/struct.TestEnvironment.html
[`install_default_crypto_provider`]: https://docs.rs/affinidi-messaging-test-mediator/latest/affinidi_messaging_test_mediator/fn.install_default_crypto_provider.html
