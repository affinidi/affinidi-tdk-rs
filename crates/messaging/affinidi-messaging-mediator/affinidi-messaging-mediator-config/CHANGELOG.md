# Affinidi Messaging Mediator Config

## Unreleased (0.2.2) — the four documented-but-unread environment overrides

`conf/mediator.toml` documented `PROCESSOR_FORWARDING_RELAY_MODE` and
`PROCESSOR_FORWARDING_RELAY_TRUSTED_MEDIATORS`, but `apply_env_overrides` read
neither. A containerised deployment setting relay mode by environment was
silently running the file's value — `blind`, the default — with no warning, and
an operator's peer allowlist was silently empty (accept any peer). Both are
relay *security* posture, so failing open and quietly is the wrong direction.

Now applied, along with two more that were never wired: `max_hops` and
`server.local_endpoints`.

| Field | Environment variable |
|---|---|
| `server.local_endpoints` | `LOCAL_ENDPOINTS` (comma-separated) |
| `processors.forwarding.max_hops` | `PROCESSOR_FORWARDING_MAX_HOPS` |
| `processors.forwarding.relay_mode` | `PROCESSOR_FORWARDING_RELAY_MODE` |
| `processors.forwarding.relay_trusted_mediators` | `PROCESSOR_FORWARDING_RELAY_TRUSTED_MEDIATORS` |

`local_endpoints` is the first `Vec<String>` field to take an override, so
`env_override_list!` splits on commas via a new `split_list` helper: entries are
trimmed, empties dropped, and an empty value clears the list (which is how an
operator turns off a TOML-configured allowlist from the environment).

Additive: a deployment that sets none of these behaves exactly as before.

## 8th August 2026 (0.2.1)

Adds the optional `[didcomm_v1]` section (`DidCommV1ConfigRaw`): `enabled` and
`allow_unauthenticated_forwards`, both defaulting to `false`. Additive and
`#[serde(default)]`, so an existing `mediator.toml` parses unchanged. See the
mediator's changelog for what the knobs do and why the second one exists.

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
