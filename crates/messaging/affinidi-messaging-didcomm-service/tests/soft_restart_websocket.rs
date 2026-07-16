//! Regression test for the in-process service-teardown websocket leak.
//!
//! The SDK websocket transport runs as an independent, self-reconnecting
//! spawned task that is *not* stopped by dropping the listener's `ATM` /
//! profile — only an explicit `stop_websocket()` (a `WebSocketCommands::Stop`)
//! ends it. `connect()` already tears the old socket down on the reconnect
//! path; before the fix, the terminal-exit path (shutdown / `Never` /
//! exhausted retries) did not.
//!
//! On a process that exits (hard restart) the leak is invisible — the OS
//! reaps every task. But a *soft restart* keeps the process alive and builds
//! a fresh `DIDCommService` for the same DID. The orphaned socket from the
//! previous service keeps reconnecting to the mediator while the new service
//! opens a second channel for the same DID, and the mediator answers with an
//! endless `w.websocket.duplicate-channel` flood.
//!
//! This test reproduces that exact shape: start a service, shut it down, then
//! start a second service for the same DID (as a soft restart does) and assert
//! the second service never receives a duplicate-channel problem report.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use affinidi_messaging_didcomm::Message;
use affinidi_messaging_didcomm_service::{
    DIDCommResponse, DIDCommService, DIDCommServiceConfig, DIDCommServiceError, Extension,
    HandlerContext, ListenerConfig, ListenerEvent, MESSAGE_PICKUP_STATUS_TYPE, RestartPolicy,
    RetryConfig, Router, TRUST_PING_TYPE, handler_fn, ignore_handler, trust_ping_handler,
};
use affinidi_messaging_test_mediator::TestMediator;
use affinidi_tdk::dids::{DID, KeyType, PeerKeyRole};
use affinidi_tdk_common::profiles::TDKProfile;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

const REPORT_PROBLEM_TYPE: &str = "https://didcomm.org/report-problem/2.0/problem-report";
const LISTENER_ID: &str = "vta-main";

/// Connect gate for loaded CI runners (#611). A single `connect()` attempt
/// may legitimately spend up to 10s inside the service's `profile_add`
/// timeout, and the test's restart policy backs off 1–2s between attempts —
/// so the old flat 15s budget fit barely one and a half attempts, and one
/// slow attempt on a saturated runner failed the whole test. 60s fits about
/// five full attempts; when healthy the wait returns in well under a second,
/// so the larger budget costs nothing.
const CONNECT_BUDGET: Duration = Duration::from_secs(60);

/// Wait for the listener to connect, panicking with every lifecycle event
/// seen so far when the budget expires — so a CI failure names the actual
/// connect error(s) instead of an opaque `Timeout(Elapsed(()))`.
async fn wait_connected_or_dump_events(
    service: &DIDCommService,
    events: &mut broadcast::Receiver<ListenerEvent>,
    generation: &str,
) {
    if service
        .wait_connected(LISTENER_ID, CONNECT_BUDGET)
        .await
        .is_ok()
    {
        return;
    }
    let mut seen = Vec::new();
    loop {
        match events.try_recv() {
            Ok(event) => seen.push(format!("{event:?}")),
            Err(broadcast::error::TryRecvError::Lagged(n)) => {
                seen.push(format!("({n} earlier event(s) dropped)"));
            }
            Err(_) => break,
        }
    }
    panic!(
        "service {generation} failed to connect to the mediator within \
         {CONNECT_BUDGET:?}; lifecycle events observed: {seen:#?}"
    );
}

/// Counts `w.websocket.duplicate-channel` problem reports delivered to the
/// listener. A healthy, singly-connected listener never receives one.
async fn count_duplicate_channel(
    _ctx: HandlerContext,
    message: Message,
    Extension(counter): Extension<Arc<AtomicUsize>>,
) -> Result<Option<DIDCommResponse>, DIDCommServiceError> {
    if serde_json::to_string(&message.body)
        .unwrap_or_default()
        .contains("duplicate-channel")
    {
        counter.fetch_add(1, Ordering::SeqCst);
    }
    Ok(None)
}

fn build_router(counter: Arc<AtomicUsize>) -> Router {
    Router::new()
        .extension(counter)
        .route(TRUST_PING_TYPE, handler_fn(trust_ping_handler))
        .expect("route trust-ping")
        .route(MESSAGE_PICKUP_STATUS_TYPE, handler_fn(ignore_handler))
        .expect("route pickup-status")
        .route(REPORT_PROBLEM_TYPE, handler_fn(count_duplicate_channel))
        .expect("route problem-report")
        .fallback(handler_fn(ignore_handler))
}

fn service_config(profile: TDKProfile) -> DIDCommServiceConfig {
    DIDCommServiceConfig {
        listeners: vec![ListenerConfig {
            id: LISTENER_ID.into(),
            profile,
            restart_policy: RestartPolicy::Always {
                backoff: RetryConfig {
                    initial_delay_secs: 1,
                    max_delay_secs: 2,
                },
            },
            ..Default::default()
        }],
    }
}

#[tokio::test]
async fn soft_restart_does_not_leak_a_dueling_websocket() {
    // A single DID plays the role of the VTA across the restart.
    let (vta_did, vta_secrets) = DID::generate_did_peer(
        vec![
            (PeerKeyRole::Verification, KeyType::Ed25519),
            (PeerKeyRole::Encryption, KeyType::X25519),
        ],
        None,
    )
    .expect("generate VTA DID");

    // Pre-register the DID as a LOCAL account so the websocket upgrade is
    // allowed (the fixture's default ACL denies the LOCAL bit otherwise).
    let mediator = TestMediator::builder()
        .local_did(vta_did.clone())
        .spawn()
        .await
        .expect("spawn test mediator");
    let mediator_did = mediator.did().to_string();

    let profile = || {
        TDKProfile::new(
            "vta",
            &vta_did,
            Some(mediator_did.as_str()),
            vta_secrets.clone(),
        )
    };

    // ── First service generation ──────────────────────────────────────
    let counter1 = Arc::new(AtomicUsize::new(0));
    let shutdown1 = CancellationToken::new();
    let service1 = DIDCommService::start(
        service_config(profile()),
        build_router(counter1.clone()),
        shutdown1.clone(),
    )
    .await
    .expect("start service generation 1");
    let mut events1 = service1.subscribe();
    wait_connected_or_dump_events(&service1, &mut events1, "1").await;

    // Soft restart: tear the first service down. With the fix this stops the
    // websocket; without it, the socket is orphaned and keeps reconnecting.
    service1.shutdown().await;

    // ── Second service generation (the "restarted" VTA) ──────────────
    let counter2 = Arc::new(AtomicUsize::new(0));
    let shutdown2 = CancellationToken::new();
    let service2 = DIDCommService::start(
        service_config(profile()),
        build_router(counter2.clone()),
        shutdown2.clone(),
    )
    .await
    .expect("start service generation 2");
    let mut events2 = service2.subscribe();
    wait_connected_or_dump_events(&service2, &mut events2, "2").await;

    // Give any orphaned socket several reconnect cycles (initial backoff is
    // 1s, capped at 2s) to start a duplicate-channel war. Poll so the test
    // fails fast on the buggy path instead of always sleeping the full window.
    for _ in 0..16 {
        if counter2.load(Ordering::SeqCst) > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    let dup_count = counter2.load(Ordering::SeqCst);

    shutdown2.cancel();
    service2.shutdown().await;
    mediator.shutdown();

    assert_eq!(
        dup_count, 0,
        "restarted service received {dup_count} duplicate-channel problem report(s) — \
         the previous generation's websocket was orphaned and kept reconnecting"
    );
}
