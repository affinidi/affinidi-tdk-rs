//! End-to-end Trust Tasks round-trip: the SDK sends a `messaging/ping` Trust Task
//! to a live mediator over the DIDComm binding envelope; the mediator consumes it
//! through the Trust Tasks framework and returns a typed `ping` response.
//!
//! Exercises the whole path — `atm.trust_tasks().ping()` → pack + `/inbound` →
//! the mediator's `trust_tasks` consumer → response → the SDK's typed reply — over
//! a real in-process HTTP mediator (memory backend, no Redis).

use affinidi_messaging_test_mediator::TestEnvironment;

#[tokio::test]
async fn ping_trust_task_round_trips_through_the_mediator() {
    let env = TestEnvironment::spawn()
        .await
        .expect("spawn test environment");

    let alice = env.add_user("alice").await.expect("add alice");
    // Enable the WebSocket live-stream so the synchronous request/response
    // (`send_message` with wait) can correlate the reply by thread id.
    env.atm
        .profile_add(&alice.profile, true)
        .await
        .expect("enable websocket for alice");

    let response = env
        .atm
        .trust_tasks()
        .ping(&alice.profile, Some("nonce-42".to_string()))
        .await
        .expect("alice pings the mediator via a Trust Task");

    // The mediator reports healthy, echoes the nonce, and advertises the protocols
    // it speaks — all from the typed response, no message inspection by the caller.
    assert_eq!(response.status.to_string(), "ok");
    assert_eq!(response.nonce.as_deref(), Some("nonce-42"));
    assert!(
        response.protocols.iter().any(|p| p == "didcomm"),
        "advertises DIDComm: {:?}",
        response.protocols
    );
    assert!(
        response.protocols.iter().any(|p| p == "tsp"),
        "advertises TSP: {:?}",
        response.protocols
    );
}
