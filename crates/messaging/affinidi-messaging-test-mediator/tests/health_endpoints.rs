//! Health-endpoint wiring: `/livez` and `/readyz` component health.
//!
//! Validates the task-supervision contract end-to-end through a real
//! spawned mediator (the same `serve_internal` path the binary uses):
//! - `/livez` is process-liveness only and answers 200.
//! - `/readyz` reports the supervised background tasks under `components`,
//!   with the always-on `statistics` task running, and (when forwarding is
//!   enabled) the load-bearing `forwarding_processor` task running.
//!
//! These run on the default in-memory backend — no Redis.

mod common;

use std::time::Duration;

use affinidi_messaging_test_mediator::TestMediator;
use common::init_tracing;
use serde_json::Value;

fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("client")
}

#[tokio::test]
async fn livez_is_liveness_only_and_returns_200() {
    init_tracing();
    let mediator = TestMediator::spawn().await.expect("spawn");
    let client = http_client();

    let resp = client
        .get(format!("{}livez", mediator.endpoint()))
        .send()
        .await
        .expect("livez request");
    assert_eq!(resp.status().as_u16(), 200, "livez should be 200");

    let body: Value = resp.json().await.expect("livez json");
    assert_eq!(body["status"], "alive");

    mediator.shutdown();
    let _ = mediator.join().await;
}

#[tokio::test]
async fn readyz_reports_supervised_component_health() {
    init_tracing();
    // Forwarding on so the load-bearing `forwarding_processor` component is
    // present alongside the always-on `statistics` task.
    let mediator = TestMediator::builder()
        .enable_forwarding(true)
        .spawn()
        .await
        .expect("spawn");
    let client = http_client();

    // The supervisor populates the registry synchronously at spawn, but give
    // the tasks a moment to reach Running before asserting.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // /readyz may be 200 or 503 depending on backend-probe specifics; the
    // body carries the component health regardless of status code.
    let resp = client
        .get(format!("{}readyz", mediator.endpoint()))
        .send()
        .await
        .expect("readyz request");
    let body: Value = resp.json().await.expect("readyz json");

    let components = body["components"]
        .as_array()
        .expect("readyz body has a components array");
    assert!(
        !components.is_empty(),
        "expected supervised components to be reported, got {body}"
    );

    // Every reported component must carry the supervision fields.
    for c in components {
        assert!(c["name"].is_string(), "component missing name: {c}");
        assert!(c["state"].is_string(), "component missing state: {c}");
        assert!(
            c["load_bearing"].is_boolean(),
            "component missing load_bearing: {c}"
        );
    }

    let find = |name: &str| components.iter().find(|c| c["name"] == name).cloned();

    let stats = find("statistics").expect("statistics component present");
    assert_eq!(stats["state"], "running", "statistics should be running");
    assert_eq!(stats["load_bearing"], false);

    let fwd = find("forwarding_processor").expect("forwarding_processor component present");
    assert_eq!(
        fwd["state"], "running",
        "forwarding processor should be running"
    );
    assert_eq!(
        fwd["load_bearing"], true,
        "forwarding processor is load-bearing"
    );

    mediator.shutdown();
    let _ = mediator.join().await;
}
