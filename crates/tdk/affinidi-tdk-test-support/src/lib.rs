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
 * # Fixtures
 *
 * - [`did_web`] / [`resolver`] — in-process did:web / did:webvh mock server with
 *   fault injection, plus an injectable `StaticResolver`.
 * - [`determinism`] — seeded `did:peer` generation (same seed → same identity).
 * - [`didcomm_fuzz`] — deterministic DIDComm envelope fixtures + seed corpus for
 *   coverage-guided fuzzing of the `unpack`/`decrypt` entry points.
 * - [`credential_scenario`] — issuer/holder/verifier `CredentialScenario` for
 *   SD-JWT VC, with the [`mdoc_scenario`] and [`oid4vp`] flows layered on top.
 * - [`vectors`] — shared `tests/vectors/` layout and loader.
 *
 * The embedded-mediator fixtures (`TestMediator` / `TestEnvironment` /
 * `TestTopology`) live in the sibling `affinidi-messaging-test-mediator` crate.
 * A copy-paste cookbook covering both crates plus the language-agnostic
 * `docker-compose.test.yml` path is in
 * [`docs/testing/cookbook.md`](https://github.com/affinidi/affinidi-tdk-rs/blob/main/docs/testing/cookbook.md).
 *
 * # Stability
 *
 * This is a `0.x` testing crate: minor releases may evolve the API, but breaking
 * changes get a minor bump and a `CHANGELOG` entry, and the fixture config and
 * error enums are `#[non_exhaustive]` so new variants land additively. Each
 * module carries a runnable, CI-compiled doc example of its happy path.
 */

pub mod credential_scenario;
pub mod determinism;
pub mod did_web;
pub mod didcomm_fuzz;
pub mod mdoc_scenario;
pub mod oid4vp;
pub mod resolver;
pub mod vectors;
