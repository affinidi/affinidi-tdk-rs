//! Safe time utilities that avoid panicking on system clock issues.

use std::time::{SystemTime, UNIX_EPOCH};

/// Returns the current Unix timestamp in seconds.
///
/// Uses `duration_since(UNIX_EPOCH)` which can only fail if the system clock
/// is set before January 1, 1970. In that pathological case, returns 0
/// and logs an error rather than panicking.
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
