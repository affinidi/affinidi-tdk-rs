/*!
 * Shared in-process test fixtures for the Affinidi TDK workspace.
 *
 * This crate is the single home for cross-cutting integration-test
 * infrastructure so that fixtures are written once and reused by every
 * workspace member (and, eventually, by external consumers writing their own
 * e2e tests).
 *
 * It deliberately sits in the `tdk` layer — above messaging, credentials and
 * identity — so it may depend on any lower-layer crate. Consumers pull it in as
 * a `dev-dependency`; nothing in the normal build graph depends on it, so the
 * upward dev-dependency edges create no cycle.
 *
 * # Roadmap (TI-series, see `tasks/testing-todo.md`)
 *
 * Modules are added by the task that needs them; this scaffold establishes the
 * crate, its workspace wiring, and CI coverage so each fixture lands as a thin,
 * self-contained PR.
 *
 * - **TI1** — `topology`: multi-mediator `TestTopology` (in-process, no Redis).
 * - **TI2** — [`did_web`] / [`resolver`]: in-process did:web / did:webvh mock
 *   server with fault injection, plus an injectable `StaticResolver`. ✅
 * - **TI4** — `determinism`: seeded did:peer generation and an injectable clock.
 * - **TI5** — `credentials`: issuer/holder/verifier `CredentialScenario`.
 * - **TI7** — `vectors`: shared `tests/vectors/` layout and loader.
 */

pub mod credential_scenario;
pub mod did_web;
pub mod resolver;
pub mod vectors;
