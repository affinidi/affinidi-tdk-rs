//! Regression test: the delivery-layer `DidCommTransport` must surface an inbound
//! **TSP** frame off the multiplexed pickup socket.
//!
//! A TSP frame is handed to the adapter's `tsp_to_inbound` as the **qb64** stored
//! string (base64url of qb2 — `-E…` *text*), so it must `atm.tsp().unpack(profile,
//! packed)` (base64url-decodes first), NOT `unpack_bytes(packed.as_bytes())`.
//! Before sdk 0.18.59 (#627) it did the latter, fed the ASCII `-E…` bytes into the
//! CESR parser, failed with `missing -E envelope wrapper`, and dropped the frame —
//! so the VTA never answered TSP trust-pings. On the old code this times out; on
//! the fix it passes. Drives the SDK's `DidCommTransport` directly — the coverage
//! gap that let the bug ship.
//!
//! Mirrors `tsp_live_stream` (the framework-path regression): receiver minted with
//! `env.mediator.add_user` (a DIDComm-only did:peer — TSP is delivered over the
//! mediator's pickup socket the transport reads), connected via the framework's
//! `from_tdk_profile` + `profile_add(_, true)` sequence, and — crucially — the
//! inbound consumer is polling BEFORE the client sends (`live_stream_next_frame`
//! is live-only, so a frame delivered before the stream is polled is missed).

#![cfg(feature = "tsp")]

use std::sync::Arc;
use std::time::Duration;

use affinidi_messaging_core::{Inbound, MessageTransport, Protocol};
use affinidi_messaging_sdk::DidCommTransport;
use affinidi_messaging_test_mediator::TestEnvironment;
use affinidi_tdk::common::TDKSharedState;
use affinidi_tdk::common::config::TDKConfig;
use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::config::ATMConfig;
use affinidi_tdk::messaging::profiles::ATMProfile;
use affinidi_tdk::secrets_resolver::SecretsResolver;
use affinidi_tdk_common::profiles::TDKProfile;
use futures_util::StreamExt;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn didcomm_transport_surfaces_inbound_tsp_frame() {
    let env = TestEnvironment::spawn().await.expect("spawn test mediator");
    let service = env
        .mediator
        .add_user("service")
        .await
        .expect("service identity");
    let client = env.add_user("client").await.expect("client identity");
    let mediator_did = env.mediator.did().to_string();

    // Stand the service up as the framework listener's `connect()` does (its own
    // fresh TDK — a separate connection from `env.atm` — secrets seeded before
    // ATM::new, profile via `from_tdk_profile` + `profile_add(_, true)`), then wrap
    // it in `DidCommTransport`.
    let tdk_profile = TDKProfile::new(
        "svc",
        &service.did,
        Some(mediator_did.as_str()),
        service.secrets.clone(),
    );
    let service_tdk = Arc::new(
        TDKSharedState::new(TDKConfig::builder().build().expect("tdk config"))
            .await
            .expect("service TDK"),
    );
    for secret in service.secrets.clone() {
        service_tdk.secrets_resolver().insert(secret).await;
    }
    let service_atm = ATM::new(
        ATMConfig::builder().build().expect("atm config"),
        service_tdk,
    )
    .await
    .expect("service ATM");
    let atm_profile = ATMProfile::from_tdk_profile(&service_atm, &tdk_profile)
        .await
        .expect("service profile from tdk profile");
    let service_profile = service_atm
        .profile_add(&atm_profile, true)
        .await
        .expect("profile_add (connect websocket)");
    let transport = DidCommTransport::new(service_atm.clone(), service_profile.clone())
        .await
        .expect("bind DidCommTransport");

    // Start consuming BEFORE the send: `live_stream_next_frame` is live-only, so a
    // frame delivered before the stream is being polled would be missed. Skip the
    // DIDComm control frames (e.g. `messagepickup/3.0/status`) and return the first
    // TSP one. Before the qb64/qb2 unpack fix the TSP frame NEVER surfaces (dropped
    // as "missing -E envelope wrapper") and this task never completes.
    let recv: tokio::task::JoinHandle<Option<Inbound>> = tokio::spawn(async move {
        let mut inbound = transport.inbound();
        loop {
            match inbound.next().await {
                Some(item) if item.message.protocol == Protocol::TSP => break Some(item),
                Some(_) => continue,
                None => break None,
            }
        }
    });

    // Give the live-stream a moment to subscribe, then the client sends a TSP
    // message to the service through the mediator.
    tokio::time::sleep(Duration::from_secs(2)).await;
    let payload = b"hello over tsp (adapter)".to_vec();
    env.atm
        .tsp()
        .send(&client.profile, &service.did, &payload)
        .await
        .expect("client sends TSP to the service");

    let got = tokio::time::timeout(Duration::from_secs(30), recv)
        .await
        .expect("DidCommTransport yields the inbound TSP frame within 30s")
        .expect("receive task panicked")
        .expect("inbound stream ended before any TSP frame arrived");

    assert_eq!(got.message.payload, payload, "payload round-trips");
    assert_eq!(
        got.message.sender.as_deref(),
        Some(client.did.as_str()),
        "authenticated sender VID is the client"
    );
    assert!(
        got.message.verified,
        "a TSP sender is cryptographically authenticated"
    );
}
