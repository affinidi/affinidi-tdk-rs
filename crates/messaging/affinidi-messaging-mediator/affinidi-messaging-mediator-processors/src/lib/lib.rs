//! Standalone background processors for the Affinidi Messaging Mediator.
//!
//! These processors run as separate processes from the mediator binary,
//! intended for horizontal scaling: drop more processor instances onto
//! additional hosts and they coordinate through Redis to share work.
//!
//! ## Redis-only by design
//!
//! Multi-process coordination relies on Redis primitives:
//! - **Forwarding processor**: Redis Streams consumer groups
//!   (`XREADGROUP` / `XACK` / `XAUTOCLAIM`) for at-least-once delivery
//!   across competing consumers.
//! - **Message expiry cleanup**: atomic `SPOP` on expiry-timeslot sets
//!   so multiple processors can drain the same timeslot without
//!   duplicating work.
//!
//! Memory and Fjall backends are single-process by definition and have
//! no equivalent multi-host coordination, so the standalone binaries
//! are not portable to those backends. The mediator's in-process tasks
//! cover the same workloads on every backend via the
//! `MediatorStore` trait — operators only need this crate when they want
//! to scale a Redis deployment horizontally.

pub mod forwarding;
pub mod message_expiry_cleanup;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Returns the duration since UNIX epoch, or `Duration::ZERO` if the system
/// clock is before the epoch (logging an error instead of panicking).
pub(crate) fn unix_epoch_now() -> Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|e| {
            tracing::error!("System clock before UNIX epoch: {e}. Returning 0.");
            Duration::ZERO
        })
}
