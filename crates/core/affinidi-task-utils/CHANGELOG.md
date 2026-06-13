# Affinidi Task Utils

## Changelog history

## 13th June 2026

### 0.1.0 — initial release (W15)

- `TaskSupervisor`: spawn long-lived `tokio` tasks with restart-on-failure
  (capped exponential backoff, 1s → 60s), an observable `HealthRegistry`
  (`Running` / `Restarting` / `Stopped` + restart count + last error), and
  clean `CancellationToken`-driven shutdown.
- Extracted from the Affinidi messaging mediator's in-tree supervisor so the
  same "restart-and-degrade, never fail-fast" policy can be reused across the
  workspace (mediator, DID-resolver cache server and SDK).
- Re-exports `tokio_util::sync::CancellationToken`.
