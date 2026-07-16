//! Regression test for multiplexed TSP receive over the shared live-stream
//! websocket.
//!
//! A `Protocols::BOTH` service opens ONE mediator websocket (the mediator allows
//! one per DID) and pulls both DIDComm and TSP frames via
//! `MessagePickup::live_stream_next_frame`. This test proves that a TSP message
//! sent to the service is actually delivered to its `TspHandler` — i.e. that a
//! TSP frame arriving on the live-stream is classified and surfaced as
//! `InboundFrame::Tsp`, not silently dropped.
//!
//! Before the fix this hung: the frame reached the socket but was never routed
//! to the `TspHandler`.

#![cfg(feature = "tsp")]

use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use affinidi_messaging_didcomm_service::{
    DIDCommService, DIDCommServiceConfig, DIDCommServiceError, HandlerContext, ListenerConfig,
    Protocols, Router, TspHandler, TspResponse, handler_fn, ignore_handler,
};
use affinidi_messaging_test_mediator::TestEnvironment;
use affinidi_tdk_common::profiles::TDKProfile;
use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

const LISTENER_ID: &str = "svc";

/// `(payload, sender_vid)` pairs recorded by [`RecordingTspHandler`].
type ReceivedFrames = Arc<Mutex<Vec<(Vec<u8>, String)>>>;

/// Records every TSP payload + sender the service receives.
struct RecordingTspHandler {
    received: ReceivedFrames,
}

#[async_trait]
impl TspHandler for RecordingTspHandler {
    async fn handle(
        &self,
        _ctx: HandlerContext,
        payload: Vec<u8>,
        sender_vid: String,
    ) -> Result<Option<TspResponse>, DIDCommServiceError> {
        self.received.lock().unwrap().push((payload, sender_vid));
        Ok(None)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tsp_frame_is_delivered_over_the_multiplexed_live_stream() {
    let env = TestEnvironment::spawn().await.expect("spawn test mediator");

    // Mint the service's identity on the mediator (registered LOCAL ALLOW_ALL).
    let service = env
        .mediator
        .add_user("service")
        .await
        .expect("mint service identity");
    let mediator_did = env.mediator.did().to_string();
    let profile = TDKProfile::new(
        "svc",
        &service.did,
        Some(mediator_did.as_str()),
        service.secrets.clone(),
    );

    // Start a Protocols::BOTH service: one socket, DIDComm + TSP multiplexed.
    let received = Arc::new(Mutex::new(Vec::new()));
    let config = DIDCommServiceConfig {
        listeners: vec![ListenerConfig {
            id: LISTENER_ID.into(),
            profile,
            protocols: Protocols::BOTH,
            ..Default::default()
        }],
    };
    let router = Router::new().fallback(handler_fn(ignore_handler));
    let shutdown = CancellationToken::new();
    let service_handle = DIDCommService::start_with_tsp(
        config,
        router,
        RecordingTspHandler {
            received: received.clone(),
        },
        shutdown.clone(),
    )
    .await
    .expect("start service");
    service_handle
        // 60s, not 15s: one connect attempt can spend 10s in the service's
        // `profile_add` timeout on a loaded CI runner, so a flat 15s budget
        // fits barely one retry (#611). Returns immediately when healthy.
        .wait_connected(LISTENER_ID, Duration::from_secs(60))
        .await
        .expect("service connects to mediator");

    // A client sends a TSP message to the service through the mediator.
    let client = env.add_user("client").await.expect("add client");
    let payload = b"hello over tsp".to_vec();
    env.atm
        .tsp()
        .send(&client.profile, &service.did, &payload)
        .await
        .expect("client sends TSP to the service");

    // The service must receive it on its single multiplexed live-stream socket.
    for _ in 0..40 {
        if !received.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    let got = received.lock().unwrap().clone();
    assert!(
        !got.is_empty(),
        "service never received the TSP frame over live_stream_next_frame — \
         the multiplexed TSP frame was dropped"
    );
    assert_eq!(got[0].0, payload, "payload round-trips");
    assert_eq!(
        got[0].1, client.did,
        "authenticated sender VID is the client"
    );

    shutdown.cancel();
    service_handle.shutdown().await;
    env.shutdown().await.ok();
}
