//! Safe time utilities that avoid panicking on system clock issues.
//!
//! Both helpers fall back to `0` and log an error if the system clock
//! is set before the UNIX epoch — preferable to a panic for a long-
//! running server.

use std::time::{SystemTime, UNIX_EPOCH};

/// Returns the current Unix timestamp in seconds.
#[inline]
pub fn unix_timestamp_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|e| {
            tracing::error!("System clock before UNIX epoch: {e}. Returning 0.");
            std::time::Duration::ZERO
        })
        .as_secs()
}

/// Returns the current Unix timestamp in milliseconds.
#[inline]
pub fn unix_timestamp_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|e| {
            tracing::error!("System clock before UNIX epoch: {e}. Returning 0.");
            std::time::Duration::ZERO
        })
        .as_millis()
}
