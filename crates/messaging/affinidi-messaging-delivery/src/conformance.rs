//! A reusable **`MessageTransport` conformance suite** (design §11).
//!
//! The delivery layer's guarantees are transport-agnostic, so they are tested
//! **parameterized over the wire**: a caller implements [`ConformanceWire`] for
//! its transport plus a control surface, and [`run_all`] drives the delivery
//! layer over a fresh transport per case and asserts every guarantee. Run it
//! against the DIDComm wire (phase 1), TSP (phase 4), and REST-fallback always;
//! the in-crate [`MockWire`] is the reference (and the baseline that always
//! runs).
//!
//! The seven checks mirror the §11 list:
//! - **truthful send** — a dropped send is `Err`, never a false `Ok`;
//! - **connection-truth** — `connection_state()` re-falsifies on drop/reconnect;
//! - **demux** — concurrent `request()`s each get their own reply; an unsolicited
//!   push mid-request reaches `subscribe()`, not a waiter, and is not lost;
//! - **dedup** — two `Guaranteed` sends with one idempotency key make one entry;
//! - **accept-then-die** — a hop-accepted entry with no evidence settles
//!   `Unconfirmed` at window expiry, never a false `Delivered`;
//! - **outbox-drain** — a hop-id that drains from the sender's outbox settles
//!   `Delivered`;
//! - **layer receipt** — an inbound receipt settles the matching entry
//!   `Delivered`.
//!
//! Gated behind the `conformance` feature (and `test`) so it is not compiled
//! into a normal build; the assertions `panic!` on failure by design.

#![cfg(any(test, feature = "conformance"))]

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use affinidi_messaging_core::{
    ConnState, Inbound, InboundAck, MessageTransport, MessagingError, Protocol, ReceivedMessage,
    SendReceipt, TransportKind,
};
use futures_util::stream::{self, BoxStream, StreamExt};
use tokio::sync::{mpsc, watch};

use crate::outbox::{InMemoryOutboxStore, OutboxState, OutboxStore};
use crate::receipt::Receipt;
use crate::service::{Delivery, MessagingService, Sent};
use crate::{drain_once, poll_outbox_drain, sweep_confirmations};

/// The control surface a conforming wire hands the suite so it can drive
/// scenarios deterministically: bring the wire up/down, inject an inbound
/// frame, and set what the sender's outbox currently holds.
#[async_trait::async_trait]
pub trait WireControl: Send + Sync {
    /// Bring the wire **up** (sends succeed, `connection_state → Connected`) or
    /// **down** (sends `Err`, `connection_state → Disconnected`).
    async fn set_up(&self, up: bool);
    /// Deliver `inbound` as if it arrived on the wire (into the dispatcher).
    async fn deliver(&self, inbound: Inbound);
    /// Set the hop-ids currently held in the sender's own outbox (drives the
    /// `outbox_message_ids()` signal for the outbox-drain check).
    async fn set_outbox_ids(&self, ids: Vec<String>);
}

/// A wire under test. `fresh` builds a brand-new transport + its control for a
/// single conformance case (each case gets an isolated wire).
#[async_trait::async_trait]
pub trait ConformanceWire: Send + Sync {
    async fn fresh(&self) -> (Arc<dyn MessageTransport>, Arc<dyn WireControl>);
}

/// Run the whole §11 suite against `wire`. Panics on the first failed check.
pub async fn run_all(wire: &dyn ConformanceWire) {
    assert_truthful_send(wire).await;
    assert_connection_truth(wire).await;
    assert_demux(wire).await;
    assert_dedup(wire).await;
    assert_accept_then_die(wire).await;
    assert_outbox_drain(wire).await;
    assert_layer_receipt(wire).await;
}

fn guaranteed(key: &str, deliver_by: Duration) -> Delivery {
    Delivery::Guaranteed {
        idempotency_key: Some(key.to_string()),
        ordering_key: None,
        deliver_by,
    }
}

/// **Truthful send:** a send while the wire is down is `Err`, never a false
/// `Ok`; once the wire is up it succeeds.
pub async fn assert_truthful_send(wire: &dyn ConformanceWire) {
    let (transport, ctrl) = wire.fresh().await;
    let svc = MessagingService::new(transport, Arc::new(InMemoryOutboxStore::new()));

    ctrl.set_up(false).await;
    let dropped = svc.send("did:x", b"m".to_vec(), Delivery::BestEffort).await;
    assert!(
        dropped.is_err(),
        "truthful send: a BestEffort send on a down wire must be Err, not a false Ok"
    );

    ctrl.set_up(true).await;
    let ok = svc.send("did:x", b"m".to_vec(), Delivery::BestEffort).await;
    assert!(
        matches!(ok, Ok(Sent::Accepted)),
        "truthful send: a send on an up wire is Accepted"
    );
}

/// **Connection-truth:** `connection_state()` transitions to `Disconnected` on a
/// drop and back to `Connected` on reconnect — never a boot-time latch.
pub async fn assert_connection_truth(wire: &dyn ConformanceWire) {
    let (transport, ctrl) = wire.fresh().await;
    let mut cs = transport.connection_state();

    ctrl.set_up(false).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), cs.changed()).await;
    assert_eq!(
        *cs.borrow(),
        ConnState::Disconnected,
        "connection-truth: state goes Disconnected on a drop"
    );

    ctrl.set_up(true).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), cs.changed()).await;
    assert_eq!(
        *cs.borrow(),
        ConnState::Connected,
        "connection-truth: state goes Connected again on reconnect (re-falsifiable)"
    );
}

/// **Demux:** two concurrent `request()`s each get their own reply (delivered
/// out of order), and an unsolicited push arriving mid-request reaches
/// `subscribe()` rather than being stolen by a waiter or lost.
pub async fn assert_demux(wire: &dyn ConformanceWire) {
    let (transport, ctrl) = wire.fresh().await;
    let svc = Arc::new(MessagingService::new(
        transport,
        Arc::new(InMemoryOutboxStore::new()),
    ));
    let mut sub = svc.subscribe();

    let (s1, s2) = (svc.clone(), svc.clone());
    let r1 = tokio::spawn(async move {
        s1.request("did:x", b"a".to_vec(), "t1", Duration::from_secs(5))
            .await
    });
    let r2 = tokio::spawn(async move {
        s2.request("did:x", b"b".to_vec(), "t2", Duration::from_secs(5))
            .await
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Replies out of order, plus an unsolicited push in between.
    ctrl.deliver(inbound("for-t2", Some("t2"))).await;
    ctrl.deliver(inbound("push", None)).await;
    ctrl.deliver(inbound("for-t1", Some("t1"))).await;

    assert_eq!(
        r1.await.unwrap().unwrap().id,
        "for-t1",
        "demux: request t1 gets its own reply"
    );
    assert_eq!(
        r2.await.unwrap().unwrap().id,
        "for-t2",
        "demux: request t2 gets its own reply"
    );
    let push = tokio::time::timeout(Duration::from_secs(2), sub.next())
        .await
        .expect("demux: the unsolicited push reaches subscribe()")
        .expect("demux: subscribe yields the push");
    assert_eq!(
        push.message.id, "push",
        "demux: the push is not lost or stolen"
    );
}

/// **Dedup:** two `Guaranteed` sends carrying the same idempotency key produce a
/// single outbox entry (at-least-once retry is safe because the anchor dedups).
pub async fn assert_dedup(wire: &dyn ConformanceWire) {
    let (transport, _ctrl) = wire.fresh().await;
    let outbox = Arc::new(InMemoryOutboxStore::new());
    let svc = MessagingService::new(transport, outbox.clone());

    svc.send(
        "did:x",
        b"first".to_vec(),
        guaranteed("k", Duration::from_secs(60)),
    )
    .await
    .unwrap();
    svc.send(
        "did:x",
        b"second".to_vec(),
        guaranteed("k", Duration::from_secs(60)),
    )
    .await
    .unwrap();

    // Exactly one entry keyed "k".
    let all_due = outbox.due(u64::MAX / 2).await.unwrap();
    let for_k = all_due.iter().filter(|e| e.idempotency_key == "k").count();
    assert_eq!(for_k, 1, "dedup: same idempotency key → one outbox entry");
}

/// **Accept-then-die:** an entry that hop-accepts but gets no end-to-end
/// evidence settles `Unconfirmed` at window expiry — never a false `Delivered`.
pub async fn assert_accept_then_die(wire: &dyn ConformanceWire) {
    let (transport, ctrl) = wire.fresh().await;
    let outbox = Arc::new(InMemoryOutboxStore::new());
    let svc = MessagingService::new(transport.clone(), outbox.clone());
    ctrl.set_up(true).await;

    svc.send(
        "did:x",
        b"m".to_vec(),
        guaranteed("k", Duration::from_millis(1)),
    )
    .await
    .unwrap();
    let e = outbox.get("k").await.unwrap().unwrap();

    // Drain hop-accepts it → Sent (durably queued at the hop, NOT delivered).
    drain_once(outbox.as_ref(), transport.as_ref(), e.created_at_ms)
        .await
        .unwrap();
    assert_eq!(
        outbox.get("k").await.unwrap().unwrap().state,
        OutboxState::Sent,
        "accept-then-die: hop-accept is Sent, not Delivered"
    );

    // Window passes with no evidence → Unconfirmed, never Delivered.
    sweep_confirmations(outbox.as_ref(), e.deliver_by_ms + 1)
        .await
        .unwrap();
    assert_eq!(
        outbox.get("k").await.unwrap().unwrap().state,
        OutboxState::Unconfirmed,
        "accept-then-die: window expiry with no evidence settles Unconfirmed"
    );
}

/// **Outbox-drain:** a `Sent` entry whose hop-id was observed in the sender's
/// outbox and then drained (recipient picked up) settles `Delivered`.
pub async fn assert_outbox_drain(wire: &dyn ConformanceWire) {
    let (transport, ctrl) = wire.fresh().await;
    let outbox = Arc::new(InMemoryOutboxStore::new());
    let svc = MessagingService::new(transport.clone(), outbox.clone());
    ctrl.set_up(true).await;

    svc.send(
        "did:x",
        b"m".to_vec(),
        guaranteed("k", Duration::from_secs(60)),
    )
    .await
    .unwrap();
    let e = outbox.get("k").await.unwrap().unwrap();
    drain_once(outbox.as_ref(), transport.as_ref(), e.created_at_ms)
        .await
        .unwrap();
    let hop = outbox
        .get("k")
        .await
        .unwrap()
        .unwrap()
        .hop_id
        .expect("outbox-drain: a Sent entry records its hop-id");

    // Present in the outbox → observed (awaiting pickup), still Sent.
    ctrl.set_outbox_ids(vec![hop.clone()]).await;
    poll_outbox_drain(transport.as_ref(), outbox.as_ref())
        .await
        .unwrap();
    assert_eq!(
        outbox.get("k").await.unwrap().unwrap().state,
        OutboxState::Sent,
        "outbox-drain: still Sent while present in the outbox"
    );

    // Drained after being observed → recipient picked up → Delivered.
    ctrl.set_outbox_ids(vec![]).await;
    poll_outbox_drain(transport.as_ref(), outbox.as_ref())
        .await
        .unwrap();
    assert_eq!(
        outbox.get("k").await.unwrap().unwrap().state,
        OutboxState::Delivered,
        "outbox-drain: drain after observation settles Delivered"
    );
}

/// **Layer receipt:** an inbound receipt confirming a `Sent` entry's key settles
/// it `Delivered` — end-to-end evidence with no application reply.
pub async fn assert_layer_receipt(wire: &dyn ConformanceWire) {
    let (transport, ctrl) = wire.fresh().await;
    let outbox = Arc::new(InMemoryOutboxStore::new());
    let svc = MessagingService::new(transport.clone(), outbox.clone());
    ctrl.set_up(true).await;

    svc.send(
        "did:x",
        b"m".to_vec(),
        guaranteed("k", Duration::from_secs(60)),
    )
    .await
    .unwrap();
    let e = outbox.get("k").await.unwrap().unwrap();
    drain_once(outbox.as_ref(), transport.as_ref(), e.created_at_ms)
        .await
        .unwrap();
    assert_eq!(
        outbox.get("k").await.unwrap().unwrap().state,
        OutboxState::Sent
    );

    // A layer receipt for "k" arrives → the dispatcher confirms it.
    let mut receipt = inbound("receipt", None);
    receipt.message.payload = Receipt::new("k").encode();
    ctrl.deliver(receipt).await;

    // Give the dispatcher a moment to consume + confirm.
    let mut delivered = false;
    for _ in 0..50 {
        if svc.delivery_state("k").await.unwrap() == Some(OutboxState::Delivered) {
            delivered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        delivered,
        "layer receipt: an inbound receipt settles the matching entry Delivered"
    );
}

/// A minimal inbound message for the demux/receipt cases.
fn inbound(id: &str, thid: Option<&str>) -> Inbound {
    Inbound {
        message: ReceivedMessage {
            id: id.to_string(),
            sender: Some("did:example:alice".to_string()),
            recipient: "did:example:bob".to_string(),
            payload: b"{}".to_vec(),
            protocol: Protocol::DIDComm,
            verified: true,
            encrypted: true,
        },
        thread_id: thid.map(str::to_string),
        ack: InboundAck(format!("ack-{id}")),
    }
}

// ── Reference wire (the always-available baseline) ───────────────────────────

/// The reference [`ConformanceWire`]: an in-memory controllable transport that
/// satisfies the whole suite. A real wire (DIDComm/TSP) mirrors this contract.
pub struct MockWire;

struct MockShared {
    fail_send: AtomicBool,
    conn_tx: watch::Sender<ConnState>,
    conn_rx: watch::Receiver<ConnState>,
    inbound_tx: mpsc::UnboundedSender<Inbound>,
    inbound_rx: Mutex<Option<mpsc::UnboundedReceiver<Inbound>>>,
    outbox_ids: Mutex<Option<Vec<String>>>,
}

struct MockTransport {
    shared: Arc<MockShared>,
}

struct MockControl {
    shared: Arc<MockShared>,
}

#[async_trait::async_trait]
impl ConformanceWire for MockWire {
    async fn fresh(&self) -> (Arc<dyn MessageTransport>, Arc<dyn WireControl>) {
        let (conn_tx, conn_rx) = watch::channel(ConnState::Connected);
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
        let shared = Arc::new(MockShared {
            fail_send: AtomicBool::new(false),
            conn_tx,
            conn_rx,
            inbound_tx,
            inbound_rx: Mutex::new(Some(inbound_rx)),
            outbox_ids: Mutex::new(Some(Vec::new())),
        });
        (
            Arc::new(MockTransport {
                shared: shared.clone(),
            }),
            Arc::new(MockControl { shared }),
        )
    }
}

#[async_trait::async_trait]
impl WireControl for MockControl {
    async fn set_up(&self, up: bool) {
        self.shared.fail_send.store(!up, Ordering::SeqCst);
        let _ = self.shared.conn_tx.send(if up {
            ConnState::Connected
        } else {
            ConnState::Disconnected
        });
    }
    async fn deliver(&self, inbound: Inbound) {
        let _ = self.shared.inbound_tx.send(inbound);
    }
    async fn set_outbox_ids(&self, ids: Vec<String>) {
        *self.shared.outbox_ids.lock().unwrap() = Some(ids);
    }
}

fn hop_id_of(packed: &[u8]) -> String {
    let mut h = DefaultHasher::new();
    packed.hash(&mut h);
    format!("hop-{:016x}", h.finish())
}

#[async_trait::async_trait]
impl MessageTransport for MockTransport {
    fn kind(&self) -> TransportKind {
        TransportKind::Didcomm
    }

    async fn send(&self, _dest: &str, packed: Vec<u8>) -> Result<SendReceipt, MessagingError> {
        if self.shared.fail_send.load(Ordering::SeqCst) {
            return Err(MessagingError::Transport("wire is down".into()));
        }
        Ok(SendReceipt {
            via: TransportKind::Didcomm,
            hop_id: Some(hop_id_of(&packed)),
        })
    }

    fn connection_state(&self) -> watch::Receiver<ConnState> {
        self.shared.conn_rx.clone()
    }

    fn inbound(&self) -> BoxStream<'static, Inbound> {
        match self.shared.inbound_rx.lock().unwrap().take() {
            Some(rx) => Box::pin(stream::unfold(rx, |mut rx| async move {
                rx.recv().await.map(|item| (item, rx))
            })),
            None => Box::pin(stream::empty()),
        }
    }

    async fn ack(&self, _ack: InboundAck) -> Result<(), MessagingError> {
        Ok(())
    }

    async fn outbox_message_ids(&self) -> Result<Option<Vec<String>>, MessagingError> {
        Ok(self.shared.outbox_ids.lock().unwrap().clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mock_wire_satisfies_the_conformance_suite() {
        run_all(&MockWire).await;
    }
}
