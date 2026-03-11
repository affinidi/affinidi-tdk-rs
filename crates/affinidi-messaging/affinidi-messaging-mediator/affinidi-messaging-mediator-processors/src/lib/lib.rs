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
