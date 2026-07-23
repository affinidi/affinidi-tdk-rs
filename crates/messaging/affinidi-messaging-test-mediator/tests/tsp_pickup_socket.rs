//! TSP frames delivered over the **message-pickup** websocket must survive the
//! gap between polls.
//!
//! A TSP frame arriving on the pickup socket is handed back *packed* (it can't
//! be DIDComm-unpacked). That path used to deliver it only if a `Next` request
//! happened to be outstanding at that exact instant, or a direct channel was
//! attached; otherwise it was dropped on the floor with a `debug!` line. The
//! DIDComm branch caches an unmatched message, but a packed frame has no place
//! in that cache, so it had nowhere to go.
//!
//! A polling consumer (`live_stream_next_frame` in a loop) always leaves a gap
//! between one poll returning and the next being registered. A frame landing in
//! that gap was silently lost — which reads to the operator as an intermittent
//! transport: the send succeeded, the mediator delivered, and the frame simply
//! never appeared.
//!
//! The sleep below is the whole point of this test: it guarantees the frame
//! arrives with no `Next` outstanding.
#![cfg(feature = "tsp")]

use std::time::Duration;

use affinidi_messaging_sdk::protocols::message_pickup::InboundFrame;
use affinidi_messaging_test_mediator::TestEnvironment;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tsp_frame_arriving_between_polls_is_not_dropped() {
    let env = TestEnvironment::spawn()
        .await
        .expect("spawn test environment");

    let alice = env.add_user("alice").await.expect("add alice");
    let bob = env.add_user("bob").await.expect("add bob");

    // Bob listens on the message-pickup socket (live delivery on) — NOT the
    // raw-TSP socket.
    env.atm
        .profile_enable_websocket(&bob.profile)
        .await
        .expect("bob enables the pickup websocket");

    let payload = b"a TSP frame that lands between polls";
    env.atm
        .tsp()
        .send(&alice.profile, &bob.did, payload)
        .await
        .expect("alice sends a TSP message to bob");

    // Let the frame arrive while Bob is NOT polling. This is what used to lose
    // it: with no `Next` outstanding the packed branch had nowhere to put it.
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Now poll. Enabling live delivery also produces a `messagepickup/3.0/status`
    // DIDComm frame, so keep pulling until the TSP frame shows up rather than
    // judging on whatever comes first.
    let mut tsp_frame: Option<String> = None;
    for _ in 0..5 {
        match env
            .atm
            .message_pickup()
            .live_stream_next_frame(&bob.profile, Some(Duration::from_secs(2)), true)
            .await
            .expect("live_stream_next_frame must not error")
        {
            Some(InboundFrame::Tsp(raw)) => {
                tsp_frame = Some(*raw);
                break;
            }
            Some(_other) => continue, // the status frame; keep going
            None => continue,
        }
    }

    let frame = tsp_frame.expect(
        "the TSP frame was delivered by the mediator but never surfaced — it arrived while no \
         `Next` was outstanding and was dropped",
    );

    // It really is Alice's message, not just any frame.
    let qb2 = env.atm.tsp().decode(&frame).expect("frame decodes to qb2");
    let (recovered, sender) = env
        .atm
        .tsp()
        .unpack_bytes(&bob.profile, &qb2)
        .await
        .expect("bob unpacks the cached TSP frame");
    assert_eq!(recovered, payload, "payload round-trips");
    assert_eq!(sender, alice.did, "sender VID is recovered");

    env.shutdown().await.expect("shutdown");
}

/// **A consumer that falls behind must not lose frames.**
///
/// The packed queue holds TSP frames that arrived with no `Next` outstanding.
/// It used to sit outside the socket-read backpressure guard, so the only way
/// to honour its bound was to discard the oldest frame — and a discarded packed
/// frame is unrecoverable: under delete-on-send the mediator dropped its copy
/// the moment it wrote it, so there is nothing left to redeliver.
///
/// Now both caches share one policy: when either is full the select loop stops
/// reading the socket, and nothing is ever discarded. A consumer that stalls
/// stalls its own connection instead of silently losing messages.
///
/// This sends comfortably more than `fetch_cache_limit_count` (100 by default)
/// before polling at all, so the queue provably passes its limit while the
/// consumer is idle, then drains and checks that every frame survived.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_slow_consumer_does_not_lose_packed_frames() {
    const FRAMES: usize = 130;

    let env = TestEnvironment::spawn()
        .await
        .expect("spawn test environment");

    let alice = env.add_user("alice").await.expect("add alice");
    let bob = env.add_user("bob").await.expect("add bob");

    env.atm
        .profile_enable_websocket(&bob.profile)
        .await
        .expect("bob enables the pickup websocket");

    // Fill well past the cache limit while Bob polls for nothing at all.
    //
    // Paced: the mediator rate-limits inbound at 100 req/s per IP with a burst
    // of 50, so an unthrottled loop gets a 429 around frame 58. The pause is
    // about the sender's rate limit, not the behaviour under test — Bob is
    // still not polling throughout.
    for i in 0..FRAMES {
        let payload = format!("frame-{i:04}").into_bytes();
        env.atm
            .tsp()
            .send(&alice.profile, &bob.did, &payload)
            .await
            .unwrap_or_else(|e| panic!("alice sends frame {i}: {e}"));
        tokio::time::sleep(Duration::from_millis(15)).await;
    }

    // Let the backlog settle so the queue is genuinely over its limit and the
    // read arm has had to back off.
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Now drain. Every frame must still be there.
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for _ in 0..(FRAMES * 3) {
        match env
            .atm
            .message_pickup()
            .live_stream_next_frame(&bob.profile, Some(Duration::from_secs(5)), true)
            .await
            .expect("live_stream_next_frame must not error")
        {
            Some(InboundFrame::Tsp(raw)) => {
                let qb2 = env.atm.tsp().decode(&raw).expect("frame decodes");
                let (payload, _) = env
                    .atm
                    .tsp()
                    .unpack_bytes(&bob.profile, &qb2)
                    .await
                    .expect("unpack");
                seen.insert(String::from_utf8(payload).expect("utf8 payload"));
            }
            Some(_other) => continue, // the status frame
            None => break,            // nothing left within the budget
        }
        if seen.len() == FRAMES {
            break;
        }
    }

    let missing: Vec<String> = (0..FRAMES)
        .map(|i| format!("frame-{i:04}"))
        .filter(|f| !seen.contains(f))
        .collect();
    assert!(
        missing.is_empty(),
        "{} of {FRAMES} frames were lost while the consumer was not polling \
         (first few: {:?}). Discarding a packed frame is unrecoverable — the \
         mediator no longer holds it.",
        missing.len(),
        &missing[..missing.len().min(5)]
    );

    env.shutdown().await.expect("shutdown");
}
