# Affinidi Messaging Mediator Config

## Changelog history

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
  of `affinidi-messaging-mediator-common` (for `DatabaseConfigRaw`). No
  server/runtime dependencies.
- A golden test parses the shipped `conf/mediator.toml` into `ConfigRaw`.
