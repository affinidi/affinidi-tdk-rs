//! The one wall-clock reading the delivery layer's loops use.

use std::time::{SystemTime, UNIX_EPOCH};

/// The current time in Unix milliseconds, or `None` if the system clock reads
/// before the Unix epoch.
///
/// Deliberately not `unwrap_or(0)`. A time of zero is a plausible-looking value
/// that every caller would act on — a reap cutoff, a delivery deadline, a
/// settle time — and each would be silently wrong. A caller that gets `None`
/// skips its pass (the loops), refuses the operation (`send`), or leaves the
/// field unset (a settle time), and says so.
pub(crate) fn now_unix_ms() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_millis().min(u64::MAX as u128) as u64)
}

/// [`now_unix_ms`] for a periodic loop: `None` is logged once per call, naming
/// the loop, so the skipped pass is visible.
pub(crate) fn now_for_pass(task: &str) -> Option<u64> {
    let now = now_unix_ms();
    if now.is_none() {
        tracing::warn!(
            task,
            "system clock is before the unix epoch — skipping this pass rather than acting on \
             an unreadable clock"
        );
    }
    now
}
