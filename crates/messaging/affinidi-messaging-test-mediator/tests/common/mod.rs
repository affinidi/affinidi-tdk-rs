//! Shared helpers for the e2e integration tests.

use std::sync::Once;

/// Legacy Redis-availability gate — kept as `false` always since the
/// default `TestMediator` backend is now in-memory and tests don't
/// need Redis to run. Retained so existing call sites
/// (`if skip_if_no_redis() { return; }`) keep compiling without churn.
///
/// `#[allow(dead_code)]` because `tests/common/mod.rs` is built
/// separately for each integration-test binary and not every binary
/// calls this helper.
#[allow(dead_code)]
pub fn skip_if_no_redis() -> bool {
    false
}

static TRACING_INIT: Once = Once::new();

/// Install a single `tracing_subscriber` for all tests in the process.
/// `RUST_LOG` controls the level; default is `warn`. Idempotent — safe
/// to call from every test.
#[allow(dead_code)]
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

/// Read the admin's live stream until a monitor batch shows an event matching
/// `wanted`, or `deadline` passes.
#[allow(dead_code)]
pub async fn await_monitor_event(
    env: &affinidi_messaging_test_mediator::TestEnvironment,
    watcher: &affinidi_messaging_test_mediator::TestUser,
    wanted: impl Fn(&serde_json::Value) -> bool,
    deadline: std::time::Duration,
) -> Option<serde_json::Value> {
    use affinidi_messaging_sdk::protocols::trust_tasks::decode_monitor_event;
    let until = tokio::time::Instant::now() + deadline;
    while tokio::time::Instant::now() < until {
        let next = env
            .atm
            .message_pickup()
            .live_stream_next(
                &watcher.profile,
                Some(std::time::Duration::from_millis(500)),
                false,
            )
            .await
            .expect("live stream");
        let Some((message, _)) = next else { continue };
        let Some(batch) = decode_monitor_event(&message) else {
            continue;
        };
        assert!(
            batch.proof.is_some(),
            "every monitor batch is signed by the mediator"
        );
        for event in &batch.payload.events {
            let event = serde_json::to_value(event).unwrap();
            assert!(
                event.get("message").is_none(),
                "metadata only, never a body"
            );
            if wanted(&event) {
                return Some(event);
            }
        }
    }
    None
}
