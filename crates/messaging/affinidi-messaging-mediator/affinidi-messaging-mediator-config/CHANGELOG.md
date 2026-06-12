# Affinidi Messaging Mediator Config

## Changelog history

## 12th June 2026

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
