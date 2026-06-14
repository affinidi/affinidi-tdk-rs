# Affinidi Messaging Mediator Config

## Changelog history

## 14th June 2026

### 0.1.2 — non_exhaustive ConfigError (W7 sweep)

- `ConfigError` is now `#[non_exhaustive]` (ADR-0003) so new variants land
  additively. Patch bump keeps the `0.1` pin valid; consumers that `match` it
  must add a `_` wildcard arm. No behaviour change.

## 12th June 2026

### 0.1.1 — Config loading + validation (simplification T18, part b)

- Adds the `env` module (config-file reading + env-var overrides:
  `read_config_file`, `apply_env_overrides`) and the `validate` module (the pure
  boot-time invariant checks: DID syntax, JWT-expiry ordering, TLS file presence,
  and the legal-but-suspicious-combo warnings), both moved out of the mediator
  binary. The mediator now re-uses them; its `validate_config(&Config)` is a thin
  orchestrator that maps results to `MediatorError` and logs warnings.
- New lean `ConfigError` (thiserror) for `read_config_file` instead of the
  mediator's server-tier `MediatorError`. The relay warning is decoupled from the
  mediator's `authz` module (uses the `MediatorACLSet` SEND_FORWARDED bit
  accessor directly), so validation needs only the lean ACL types. The crate
  stays off the server stack (added deps: toml, thiserror, tracing — all lean).

### 0.1.0 — Initial release (simplification T18, part a)

- New crate holding the mediator's raw TOML configuration **schema** — the
  `ConfigRaw` root and its `*ConfigRaw` / plain-serde sub-structs, extracted from
  `affinidi-messaging-mediator`'s `src/common/config/`. The mediator re-exports
  these types and keeps all runtime resolution; the goal is one schema shared
  with the `mediator-setup` wizard.
- Dependency-light by design: serde + the lean (`default-features = false`) tier
  of `affinidi-messaging-mediator-common` (only for the always-available ACL
  types used by validation). The raw `DatabaseConfigRaw` is defined in this crate
  rather than imported from mediator-common's `server`-gated `database` module,
  so the crate builds and publishes against any 0.15.x without needing that
  module un-gated. No server/runtime dependencies.
- A golden test parses the shipped `conf/mediator.toml` into `ConfigRaw`.
