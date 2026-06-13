//! Background-task supervision.
//!
//! Every long-lived background task (statistics, forwarding processor,
//! message- and session-expiry sweeps, VTA secrets refresh) is spawned
//! through a [`TaskSupervisor`] instead of a bare `tokio::spawn`, so a silent
//! task death becomes a *detected, recovered, and observable* event:
//! restart-on-failure with capped exponential backoff, a [`HealthRegistry`]
//! the `/readyz` handler reads, and clean `CancellationToken`-driven
//! shutdown.
//!
//! The implementation lives in the workspace-shared [`affinidi_task_utils`]
//! crate so the mediator, the DID-resolver cache server, and the cache SDK
//! all share one "restart-and-degrade, never fail-fast" policy. It is
//! re-exported here for the mediator's existing
//! `crate::tasks::supervisor::…` paths.

pub use affinidi_task_utils::{ComponentHealth, ComponentState, HealthRegistry, TaskSupervisor};
