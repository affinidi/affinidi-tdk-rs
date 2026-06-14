# affinidi-tdk-test-support

[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)

Shared in-process test fixtures and harnesses for the Affinidi TDK workspace.

This crate is the single home for cross-cutting integration-test infrastructure,
so a fixture is written once and reused by every workspace member (and,
eventually, by external consumers writing their own e2e tests). It complements
[`affinidi-messaging-test-mediator`], which owns the embedded-mediator fixture;
this crate covers the rest of the workspace (DID resolution, credentials,
multi-service topologies, deterministic test inputs).

## When to use

Pull it in as a `dev-dependency` when a test needs infrastructure that isn't
mediator-specific — a mock did:web server, a deterministic resolver, a
credential issuer/holder/verifier scenario, or a multi-mediator topology — and
you don't want to stand up external services.

## Fixtures

| Module                     | Fixture                                                          |
|----------------------------|-----------------------------------------------------------------|
| `did_web` / `resolver`     | did:web / did:webvh mock server (fault injection) + injectable `StaticResolver` |
| `determinism`              | Seeded `did:peer` generation (same seed → same identity)        |
| `credential_scenario`      | `CredentialScenario` — SD-JWT VC issue / present / verify + revocation |
| `mdoc_scenario` / `oid4vp` | mdoc (COSE) flows + OID4VP present / verify (both eIDAS formats) |
| `vectors`                  | Shared `tests/vectors/` layout + loader                         |

The embedded-mediator fixtures (`TestMediator`, `TestEnvironment`,
`TestTopology`) live in the sibling [`affinidi-messaging-test-mediator`] crate.

## Cookbook

Copy-paste scenarios for both crates — three-line in-process mediator, two-hop
forward, did:web rotation, seeded identities, issue / present / verify,
revocation — plus the language-agnostic `docker compose` path are in
[`docs/testing/cookbook.md`](../../../docs/testing/cookbook.md). Every Rust
snippet there mirrors a runnable, CI-compiled doc example on the corresponding
module.

## Stability

A `0.x` testing crate. Minor releases may evolve the API, but breaking changes
get a minor bump and a `CHANGELOG` entry. The fixture config enums
(`did_web::Fault`, `resolver::Outcome`) and the error enums are
`#[non_exhaustive]`, so new variants land additively — match arms over them must
carry a `_` wildcard. Each module ships a runnable doc example
(`cargo test --doc`) of its happy path.

[`affinidi-messaging-test-mediator`]: ../../messaging/affinidi-messaging-test-mediator
