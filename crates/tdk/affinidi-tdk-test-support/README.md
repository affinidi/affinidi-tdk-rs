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

## Status

Fixtures land per task in the TI-series (see `tasks/testing-todo.md`):

| Task  | Module                | Fixture                                                       | Status |
|-------|-----------------------|---------------------------------------------------------------|:------:|
| TI1   | `topology`            | Multi-mediator `TestTopology` (in-process, no Redis)          |  ⏳   |
| TI2   | `did_web` / `resolver`| did:web / did:webvh mock server + injectable `StaticResolver` |  ✅   |
| TI4   | `determinism`         | Seeded did:peer generation + injectable clock                 |  ⏳   |
| TI5a  | `credential_scenario` | `CredentialScenario` SD-JWT VC issue / present / verify        |  ✅   |
| TI5b  | `mdoc_scenario` / `oid4vp` | mdoc (COSE) flows + OID4VP present / verify (both eIDAS formats) |  ✅   |
| TI7   | `vectors`             | Shared `tests/vectors/` layout + loader                       |  ✅   |

[`affinidi-messaging-test-mediator`]: ../../messaging/affinidi-messaging-test-mediator
