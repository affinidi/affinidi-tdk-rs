//! The websocket transport's receive-leg probe, against a real mediator.
//!
//! A ping/pong proves the socket, not that the mediator is still delivering to
//! it. After inbound has been silent for the configured time, the transport
//! writes a live-delivery request straight to the socket; the mediator answers
//! through the delivery path being tested (and redelivers anything waiting).
//! No answer within the deadline means nothing reaches this socket, and the
//! transport reconnects.
//!
//! This test holds the healthy half end to end: the probe goes out on an idle
//! socket, the mediator's answer comes back, the transport consumes it rather
//! than handing it to the application, and nothing reconnects. The unhealthy
//! half — an unanswered probe forcing a reconnect — needs a mediator that
//! keeps a socket open while not delivering to it, which the test mediator has
//! no way to stage; it is covered by the `receive_leg::probe_step` unit tests.

mod common;

use std::time::Duration;

use affinidi_messaging_sdk::config::ATMConfig;
use affinidi_messaging_test_mediator::TestEnvironment;
use common::init_tracing;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_idle_socket_is_probed_and_the_answer_is_not_handed_to_the_application() {
    init_tracing();
    let config = ATMConfig::builder()
        .with_receive_probe(Some(Duration::from_secs(1)))
        .build()
        .expect("config");
    let env = TestEnvironment::spawn_with_atm_config(config)
        .await
        .expect("env");
    let bob = env.add_user("bob").await.expect("add bob");
    env.atm
        .profile_enable_websocket(&bob.profile)
        .await
        .expect("bob is live");
    let health = bob.profile.receive_health().await.expect("receive health");

    // The connect's own live-delivery answer is the application's, as before.
    // Drain it so what follows is only what the probe produced.
    while env
        .atm
        .message_pickup()
        .live_stream_next(&bob.profile, Some(Duration::from_millis(500)), true)
        .await
        .expect("live stream")
        .is_some()
    {}
    let before = health.borrow().last_data_frame_at;

    // The watchdog runs every 20s; by 45s at least one probe has gone out on
    // this silent socket and been answered.
    tokio::time::sleep(Duration::from_secs(45)).await;

    let now = health.borrow().clone();
    assert!(
        now.last_data_frame_at > before,
        "the probe's answer arrived as a data frame: {now:?} (before {before:?})"
    );
    assert_eq!(
        now.probe_reconnects, 0,
        "an answered probe forces no reconnect"
    );
    assert_eq!(
        now.probe_outstanding_since, None,
        "nothing left outstanding"
    );
    assert!(
        env.atm
            .message_pickup()
            .live_stream_next(&bob.profile, Some(Duration::from_secs(1)), true)
            .await
            .expect("live stream")
            .is_none(),
        "the probe's answer is the transport's, not the application's"
    );

    env.shutdown().await.expect("shutdown");
}
