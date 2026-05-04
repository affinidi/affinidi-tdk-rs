//! Shared helpers for the e2e integration tests.

use std::sync::Once;

/// Legacy Redis-availability gate — kept as `false` always since the
/// default `TestMediator` backend is now in-memory and tests don't
/// need Redis to run. Retained so existing call sites
/// (`if skip_if_no_redis() { return; }`) keep compiling without churn.
pub fn skip_if_no_redis() -> bool {
    false
}

static TRACING_INIT: Once = Once::new();

/// Install a single `tracing_subscriber` for all tests in the process.
/// `RUST_LOG` controls the level; default is `warn`. Idempotent — safe
/// to call from every test.
pub fn init_tracing() {
    TRACING_INIT.call_once(|| {
        let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"));
        let _ = tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .with_test_writer()
            .try_init();
    });
}
