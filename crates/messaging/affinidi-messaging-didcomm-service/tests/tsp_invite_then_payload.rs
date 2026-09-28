//! Regression test: a TSP payload sent right behind a relationship invite is
//! delivered, not dropped.
//!
//! The listener hands each inbound frame to its own task. Before the fix
//! nothing ordered those tasks, so the payload's frame could be unpacked before
//! the invite's frame had been recorded; the relationship gate (Rev 3 §7.2.2)
//! then saw no relationship and discarded the payload. Only a peer's first
//! exchange was exposed, since after that the relationship already exists.
//!
//! The race is made deterministic by giving the service a relationship store
//! whose writes are slow, so recording an invite takes long enough that an
//! unordered payload always overtakes it. The fix orders one sender's frames
//! through unpack; the second test checks that a slow peer does not hold up a
//! different one.

#![cfg(feature = "tsp")]

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use affinidi_messaging_didcomm_service::{
    DIDCommService, DIDCommServiceConfig, DIDCommServiceError, HandlerContext, ListenerConfig,
    Protocols, Router, TspHandler, TspResponse, handler_fn, ignore_handler,
};
use affinidi_messaging_sdk::errors::ATMError;
use affinidi_messaging_sdk::protocols::tsp::{
    InMemoryRelationshipStore, PeerCapability, RelationshipState, RelationshipStore, ThreadDigests,
};
use affinidi_messaging_test_mediator::TestEnvironment;
use affinidi_tdk_common::profiles::TDKProfile;
use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

const LISTENER_ID: &str = "svc";

/// How long a slowed relationship-state write takes.
const SLOW_WRITE: Duration = Duration::from_millis(1500);

/// Which peers' relationship writes are slowed.
#[derive(Clone)]
enum Slow {
    Everyone,
    Only(Arc<Mutex<HashSet<String>>>),
}

/// An in-memory relationship store whose `set` is slow for chosen peers.
struct SlowWriteStore {
    inner: InMemoryRelationshipStore,
    slow: Slow,
}

impl SlowWriteStore {
    fn is_slow(&self, their_vid: &str) -> bool {
        match &self.slow {
            Slow::Everyone => true,
            Slow::Only(vids) => vids.lock().unwrap().contains(their_vid),
        }
    }
}

#[async_trait]
impl RelationshipStore for SlowWriteStore {
    async fn get(&self, our_vid: &str, their_vid: &str) -> Result<RelationshipState, ATMError> {
        self.inner.get(our_vid, their_vid).await
    }

    async fn set(
        &self,
        our_vid: &str,
        their_vid: &str,
        state: RelationshipState,
    ) -> Result<(), ATMError> {
        if self.is_slow(their_vid) {
            tokio::time::sleep(SLOW_WRITE).await;
        }
        self.inner.set(our_vid, their_vid, state).await
    }

    async fn get_capability(
        &self,
        our_vid: &str,
        their_vid: &str,
    ) -> Result<Option<PeerCapability>, ATMError> {
        self.inner.get_capability(our_vid, their_vid).await
    }

    async fn set_capability(
        &self,
        our_vid: &str,
        their_vid: &str,
        capability: PeerCapability,
    ) -> Result<(), ATMError> {
        self.inner
            .set_capability(our_vid, their_vid, capability)
            .await
    }

    async fn thread_digests(
        &self,
        our_vid: &str,
        their_vid: &str,
    ) -> Result<ThreadDigests, ATMError> {
        self.inner.thread_digests(our_vid, their_vid).await
    }

    async fn set_thread_digests(
        &self,
        our_vid: &str,
        their_vid: &str,
        digests: ThreadDigests,
    ) -> Result<(), ATMError> {
        self.inner
            .set_thread_digests(our_vid, their_vid, digests)
            .await
    }

    async fn reply_path(&self, our_vid: &str, their_vid: &str) -> Result<Vec<String>, ATMError> {
        self.inner.reply_path(our_vid, their_vid).await
    }

    async fn set_reply_path(
        &self,
        our_vid: &str,
        their_vid: &str,
        path: Vec<String>,
    ) -> Result<(), ATMError> {
        self.inner.set_reply_path(our_vid, their_vid, path).await
    }
}

/// `(payload, sender_vid)` pairs the service's handler received.
type Received = Arc<Mutex<Vec<(Vec<u8>, String)>>>;

struct RecordingTspHandler {
    received: Received,
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

struct Fixture {
    env: TestEnvironment,
    service_did: String,
    received: Received,
    shutdown: CancellationToken,
    handle: DIDCommService,
}

async fn start(slow: Slow) -> Fixture {
    let env = TestEnvironment::spawn_with_direct_delivery()
        .await
        .expect("spawn test mediator");
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

    let store: Arc<dyn RelationshipStore> = Arc::new(SlowWriteStore {
        inner: InMemoryRelationshipStore::default(),
        slow,
    });
    let received: Received = Arc::new(Mutex::new(Vec::new()));
    let config = DIDCommServiceConfig {
        listeners: vec![ListenerConfig {
            id: LISTENER_ID.into(),
            profile,
            protocols: Protocols::BOTH,
            relationship_store: Some(store),
            ..Default::default()
        }],
    };
    let shutdown = CancellationToken::new();
    let handle = DIDCommService::start_with_tsp(
        config,
        Router::new().fallback(handler_fn(ignore_handler)),
        RecordingTspHandler {
            received: received.clone(),
        },
        shutdown.clone(),
    )
    .await
    .expect("start service");
    handle
        .wait_connected(LISTENER_ID, Duration::from_secs(60))
        .await
        .expect("service connects to mediator");

    Fixture {
        env,
        service_did: service.did,
        received,
        shutdown,
        handle,
    }
}

impl Fixture {
    fn has(&self, payload: &[u8], sender: &str) -> bool {
        self.received
            .lock()
            .unwrap()
            .iter()
            .any(|(p, s)| p == payload && s == sender)
    }

    async fn wait_for(&self, payload: &[u8], sender: &str, within: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + within;
        while tokio::time::Instant::now() < deadline {
            if self.has(payload, sender) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        self.has(payload, sender)
    }

    async fn stop(self) {
        self.shutdown.cancel();
        self.handle.shutdown().await;
        self.env.shutdown().await.ok();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_payload_sent_right_after_an_invite_is_delivered() {
    let fx = start(Slow::Everyone).await;

    // Several fresh peers, each on its first exchange: invite, then the payload
    // straight away without waiting for the service to record the invite.
    for i in 0..5 {
        let client = fx
            .env
            .add_user(&format!("client-{i}"))
            .await
            .expect("add client");
        fx.env
            .atm
            .tsp()
            .form_relationship(&client.profile, &fx.service_did)
            .await
            .expect("client invites the service");
        let payload = format!("first message from client {i}").into_bytes();
        fx.env
            .atm
            .tsp()
            .send(&client.profile, &fx.service_did, &payload)
            .await
            .expect("client sends TSP to the service");

        assert!(
            fx.wait_for(&payload, &client.did, Duration::from_secs(20))
                .await,
            "client {i}'s payload, sent right behind its invite, was dropped"
        );
    }

    fx.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_slow_peer_does_not_hold_up_another_peer() {
    let slow_vids = Arc::new(Mutex::new(HashSet::new()));
    let fx = start(Slow::Only(slow_vids.clone())).await;

    let slow = fx.env.add_user("slow").await.expect("add slow client");
    let quick = fx.env.add_user("quick").await.expect("add quick client");
    slow_vids.lock().unwrap().insert(slow.did.clone());

    let slow_payload = b"from the slow peer".to_vec();
    let quick_payload = b"from the quick peer".to_vec();

    // The slow peer's invite takes SLOW_WRITE to record, and its payload is
    // queued behind it. The quick peer's frames arrive after both and must not
    // wait for them.
    fx.env
        .atm
        .tsp()
        .form_relationship(&slow.profile, &fx.service_did)
        .await
        .expect("slow client invites");
    fx.env
        .atm
        .tsp()
        .send(&slow.profile, &fx.service_did, &slow_payload)
        .await
        .expect("slow client sends");
    fx.env
        .atm
        .tsp()
        .form_relationship(&quick.profile, &fx.service_did)
        .await
        .expect("quick client invites");
    fx.env
        .atm
        .tsp()
        .send(&quick.profile, &fx.service_did, &quick_payload)
        .await
        .expect("quick client sends");

    assert!(
        fx.wait_for(&quick_payload, &quick.did, Duration::from_secs(20))
            .await,
        "the quick peer's payload was not delivered"
    );
    assert!(
        !fx.has(&slow_payload, &slow.did),
        "the quick peer's payload should have arrived while the slow peer's invite \
         was still being recorded — the peers were serialised against each other"
    );
    assert!(
        fx.wait_for(&slow_payload, &slow.did, Duration::from_secs(20))
            .await,
        "the slow peer's payload, sent right behind its invite, was dropped"
    );

    fx.stop().await;
}
