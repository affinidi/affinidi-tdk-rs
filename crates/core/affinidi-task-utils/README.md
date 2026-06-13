# affinidi-task-utils

Background-task supervision for long-lived `tokio` tasks.

Spawn a long-lived background task through a `TaskSupervisor` instead of a bare
`tokio::spawn` and a silent task death becomes a *detected, recovered, and
observable* event:

- **Restart on failure** — a task that returns `Err(_)` or panics is restarted
  with capped exponential backoff (1s → 60s). The supervisor never gives up:
  the process keeps serving while the fault is logged with its restart history
  ("restart-and-degrade, never fail-fast").
- **Health registry** — each task's state (`Running` / `Restarting` /
  `Stopped`), restart count, last error, and last-transition time are recorded
  in a concurrently-readable `HealthRegistry` a readiness handler can read.
- **Clean shutdown** — when the shared `CancellationToken` fires, the running
  task is aborted and marked `Stopped` with no restart.

```rust
use affinidi_task_utils::{CancellationToken, TaskSupervisor};

let shutdown = CancellationToken::new();
let supervisor = TaskSupervisor::new(shutdown.clone());

// `factory` is invoked once per (re)start — build fresh state each time.
supervisor.spawn("heartbeat", false, || async {
    // … periodic work …
    Ok::<(), std::io::Error>(())
});

let registry = supervisor.registry(); // hand to a readiness handler
```

`load_bearing` controls how a readiness handler should treat a non-`Running`
state: a down load-bearing component should fail readiness, a non-load-bearing
one should merely report `degraded`.

## License

Apache-2.0
