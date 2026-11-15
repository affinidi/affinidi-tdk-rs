# Affinidi Task Utils

## [0.1.1] - 2026-11-15

Workspace lint and dependency housekeeping. No API or behaviour change.

- Dependency versions now come from the root `[workspace.dependencies]`
  for the external crates shared by five or more workspace members
  (#1070). The published manifest still names concrete requirements; the
  resolved dependency graph and every feature selection are unchanged.
- Now inherits the workspace lints (`[lints] workspace = true`, #1064):
  `unsafe_code` is denied and the workspace clippy lints apply.

## Changelog history

## [0.1.0] - 2026-06-13

initial release (W15)

- `TaskSupervisor`: spawn long-lived `tokio` tasks with restart-on-failure
  (capped exponential backoff, 1s → 60s), an observable `HealthRegistry`
  (`Running` / `Restarting` / `Stopped` + restart count + last error), and
  clean `CancellationToken`-driven shutdown.
- Extracted from the Affinidi messaging mediator's in-tree supervisor so the
  same "restart-and-degrade, never fail-fast" policy can be reused across the
  workspace (mediator, DID-resolver cache server and SDK).
- Re-exports `tokio_util::sync::CancellationToken`.
