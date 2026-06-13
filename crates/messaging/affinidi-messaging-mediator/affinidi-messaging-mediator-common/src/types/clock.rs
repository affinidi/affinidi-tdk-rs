//! An injectable clock so expiry / TTL / session-cleanup logic can be driven by
//! a virtual clock in tests instead of waiting on real wall-clock time.
//!
//! [`Clock`] is the abstraction; [`SystemClock`] is the production implementation
//! (the real system clock) and is what the mediator wires in at startup.
//! [`TestClock`] — a manually-advanced clock — is compiled only under the
//! non-default `test-clock` feature, so it can never reach a production build.
//!
//! The trait lives in `types` (always built, no server deps) so both the
//! mediator and the client SDK can share it without pulling the server stack.

#[cfg(not(feature = "server"))]
use std::time::{SystemTime, UNIX_EPOCH};

/// A source of the current Unix time.
///
/// Production code holds an `Arc<dyn Clock>` (a [`SystemClock`]); tests inject a
/// [`TestClock`] they can advance by hand to exercise expiry paths instantly.
pub trait Clock: Send + Sync + std::fmt::Debug {
    /// The current Unix time in **seconds**.
    fn unix_secs(&self) -> u64;

    /// The current Unix time in **milliseconds**.
    fn unix_millis(&self) -> u128;
}

/// The production clock: reads the real system clock.
///
/// Falls back to `0` (logging an error) if the system clock is set before the
/// UNIX epoch — the same non-panicking behaviour as the free
/// [`unix_timestamp_secs`](crate::time::unix_timestamp_secs) helpers, which it
/// delegates to.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

#[cfg(feature = "server")]
impl Clock for SystemClock {
    fn unix_secs(&self) -> u64 {
        crate::time::unix_timestamp_secs()
    }

    fn unix_millis(&self) -> u128 {
        crate::time::unix_timestamp_millis()
    }
}

// Without the `server` feature the `time` helpers aren't compiled, so provide an
// equivalent inline implementation for lean (SDK-style) consumers.
#[cfg(not(feature = "server"))]
impl Clock for SystemClock {
    fn unix_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    fn unix_millis(&self) -> u128 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0)
    }
}

/// A manually-advanced clock for tests — **never compiled into production**
/// (gated on the `test-clock` feature).
///
/// Cheap to clone; clones share the same underlying time, so a test can hold one
/// handle, hand another to the mediator, and advance both at once. Start it at a
/// fixed instant, then [`advance_secs`](Self::advance_secs) past a token's
/// expiry to make the expiry path fire without any real time passing.
#[cfg(feature = "test-clock")]
#[derive(Debug, Clone)]
pub struct TestClock {
    /// Shared current time in milliseconds since the UNIX epoch.
    millis: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

#[cfg(feature = "test-clock")]
impl TestClock {
    /// A clock fixed at `unix_secs` seconds past the epoch.
    pub fn at_secs(unix_secs: u64) -> Self {
        Self {
            millis: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(unix_secs * 1_000)),
        }
    }

    /// A clock seeded from the real system clock (so tokens look freshly issued).
    pub fn now() -> Self {
        Self::at_secs(SystemClock.unix_secs())
    }

    /// Move the clock forward by `secs` seconds.
    pub fn advance_secs(&self, secs: u64) {
        self.advance_millis(secs * 1_000);
    }

    /// Move the clock forward by `millis` milliseconds.
    pub fn advance_millis(&self, millis: u64) {
        self.millis
            .fetch_add(millis, std::sync::atomic::Ordering::SeqCst);
    }

    /// Set the clock to exactly `unix_secs` seconds past the epoch.
    pub fn set_secs(&self, unix_secs: u64) {
        self.millis
            .store(unix_secs * 1_000, std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(feature = "test-clock")]
impl Clock for TestClock {
    fn unix_secs(&self) -> u64 {
        self.millis.load(std::sync::atomic::Ordering::SeqCst) / 1_000
    }

    fn unix_millis(&self) -> u128 {
        self.millis.load(std::sync::atomic::Ordering::SeqCst) as u128
    }
}

#[cfg(all(test, feature = "test-clock"))]
mod tests {
    use super::*;

    #[test]
    fn test_clock_advances() {
        let clock = TestClock::at_secs(1_000);
        assert_eq!(clock.unix_secs(), 1_000);
        assert_eq!(clock.unix_millis(), 1_000_000);

        clock.advance_secs(50);
        assert_eq!(clock.unix_secs(), 1_050);

        clock.advance_millis(500);
        assert_eq!(clock.unix_millis(), 1_050_500);
        assert_eq!(clock.unix_secs(), 1_050);

        clock.set_secs(42);
        assert_eq!(clock.unix_secs(), 42);
    }

    #[test]
    fn clones_share_time() {
        let a = TestClock::at_secs(100);
        let b = a.clone();
        a.advance_secs(10);
        assert_eq!(b.unix_secs(), 110, "a clone observes the advance");
    }

    #[test]
    fn system_clock_is_nonzero() {
        assert!(SystemClock.unix_secs() > 0);
    }
}
