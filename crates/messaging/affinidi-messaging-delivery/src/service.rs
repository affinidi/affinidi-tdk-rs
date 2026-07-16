//! The `MessagingService` front-end — the API services call — over one
//! transport + outbox, with a single inbound dispatcher.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use affinidi_messaging_core::{
    ConnState, Inbound, MessageTransport, MessagingError, ReceivedMessage,
};
use futures_util::stream::{self, BoxStream, StreamExt};
use tokio::sync::{broadcast, oneshot, watch};
use tokio::task::JoinHandle;

use crate::confirm::confirm_delivered;
use crate::outbox::{Key, OutboxEntry, OutboxState, OutboxStore};
use crate::receipt::{self, Receipt, ReceiptPacker};

/// The delivery guarantee for a [`MessagingService::send`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Delivery {
    /// Fire-and-forget: send once, surface the hop result, do NOT persist. For
    /// non-critical, self-healing traffic (heartbeats, pings, presence).
    BestEffort,
    /// Delivery-critical: write to the durable outbox and retry until acked or
    /// the window expires. For credential issuance, consent/step-up pushes,
    /// registry writes, webvh publishes.
    Guaranteed {
        /// Dedup anchor; `None` derives a unique key from the destination.
        idempotency_key: Option<Key>,
        /// `None` = drain in parallel; `Some(k)` = per-`k` FIFO.
        ordering_key: Option<Key>,
        /// The delivery window — the acceptable recovery time before the entry
        /// settles visibly (never a silent success).
        deliver_by: Duration,
    },
}

/// The outcome of a send. Distinguishes handed-off from confirmed, so a caller
/// can no longer log a merely-queued message as "delivered".
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Sent {
    /// Hop-accepted (`BestEffort`) or durably queued (`Guaranteed`) — handed
    /// off, **not** confirmed delivered.
    Accepted,
    /// Positive end-to-end evidence received. Emitted once §5a confirmation
    /// lands; a `Guaranteed` send returns `Accepted` until then.
    Delivered,
    /// The delivery window passed with no evidence possible — a truthful "we
    /// can't know".
    Unconfirmed,
}

/// Aggregated messaging connectivity for a health endpoint — read off the
/// transport's live `connection_state()`, never a boot-time latch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MessagingStatus {
    /// The transport is connected.
    Connected,
    /// The transport is down or reconnecting.
    Disconnected,
}

type WaiterMap = Arc<Mutex<HashMap<String, oneshot::Sender<ReceivedMessage>>>>;

/// Buffered unsolicited inbound messages per subscriber before a slow consumer
/// starts lagging (and losing the oldest — at-least-once, dedup on the key).
const SUBSCRIBE_BUFFER: usize = 256;

static KEY_SEQ: AtomicU64 = AtomicU64::new(0);

/// The delivery-layer front-end over one transport + outbox.
///
/// Owns a **single inbound dispatcher**: it reads the transport's `inbound()`
/// exactly once, routes replies (matched by thread id) to `request` waiters and
/// everything else to `subscribe`, and acks each message **once, after handoff**
/// — never in a per-caller loop, never before handoff.
pub struct MessagingService {
    transport: Arc<dyn MessageTransport>,
    outbox: Arc<dyn OutboxStore>,
    waiters: WaiterMap,
    subscribers: broadcast::Sender<Inbound>,
    conn_state: watch::Receiver<ConnState>,
    _dispatcher: JoinHandle<()>,
}

impl MessagingService {
    /// Build the service over `transport` + `outbox` and start the inbound
    /// dispatcher. Must be called inside a Tokio runtime.
    ///
    /// The layer-receipt **consume** half is always active — an inbound receipt
    /// confirms its matching outbox entry `Sent → Delivered` (§5a). To also
    /// **emit** receipts for messages this service receives, build with
    /// [`with_receipts`](Self::with_receipts).
    pub fn new(transport: Arc<dyn MessageTransport>, outbox: Arc<dyn OutboxStore>) -> Self {
        Self::build(transport, outbox, None)
    }

    /// Build the service and, additionally, **emit** a fire-and-forget layer
    /// receipt (§5a) for every unsolicited message it durably receives, using
    /// `receipt_packer` to encrypt the receipt to the sender. This is what lets
    /// a peer's `Guaranteed` outbox entry settle `Delivered` with no
    /// application-protocol reply.
    pub fn with_receipts(
        transport: Arc<dyn MessageTransport>,
        outbox: Arc<dyn OutboxStore>,
        receipt_packer: Arc<dyn ReceiptPacker>,
    ) -> Self {
        Self::build(transport, outbox, Some(receipt_packer))
    }

    fn build(
        transport: Arc<dyn MessageTransport>,
        outbox: Arc<dyn OutboxStore>,
        receipt_packer: Option<Arc<dyn ReceiptPacker>>,
    ) -> Self {
        let waiters: WaiterMap = Arc::new(Mutex::new(HashMap::new()));
        let (subscribers, _) = broadcast::channel(SUBSCRIBE_BUFFER);
        let conn_state = transport.connection_state();

        let dispatcher = tokio::spawn(run_dispatcher(
            transport.clone(),
            outbox.clone(),
            waiters.clone(),
            subscribers.clone(),
            receipt_packer,
        ));

        Self {
            transport,
            outbox,
            waiters,
            subscribers,
            conn_state,
            _dispatcher: dispatcher,
        }
    }

    /// Send `packed` to `to` with the chosen delivery guarantee.
    ///
    /// - `BestEffort`: one truthful `transport.send()`; `Ok(Accepted)` on
    ///   hop-accept, `Err` if the frame wasn't transmitted. No outbox row.
    /// - `Guaranteed`: enqueue a durable outbox entry (the drain sends + retries)
    ///   and return `Accepted` (queued). Confirmation upgrades it to `Delivered`
    ///   via the outbox once §5a lands.
    pub async fn send(
        &self,
        to: &str,
        packed: Vec<u8>,
        delivery: Delivery,
    ) -> Result<Sent, MessagingError> {
        match delivery {
            Delivery::BestEffort => {
                self.transport.send(to, packed).await?;
                Ok(Sent::Accepted)
            }
            Delivery::Guaranteed {
                idempotency_key,
                ordering_key,
                deliver_by,
            } => {
                let now = now_unix_ms();
                let key = idempotency_key.unwrap_or_else(|| default_key(to, now));
                let mut entry = OutboxEntry::new(
                    key,
                    to,
                    packed,
                    now,
                    now.saturating_add(deliver_by.as_millis() as u64),
                );
                entry.ordering_key = ordering_key;
                self.outbox.put(entry).await.map_err(|e| {
                    MessagingError::Transport(format!("outbox enqueue failed: {e}"))
                })?;
                Ok(Sent::Accepted)
            }
        }
    }

    /// Send `packed` and await a reply correlated by `correlation_thid` — the
    /// thread id the caller minted on the outgoing message — up to `timeout`.
    ///
    /// Concurrent `request`s are safe: each registers a waiter keyed by its own
    /// thread id, and the dispatcher fans replies to the right one; no shared-
    /// session serialization.
    pub async fn request(
        &self,
        to: &str,
        packed: Vec<u8>,
        correlation_thid: &str,
        timeout: Duration,
    ) -> Result<ReceivedMessage, MessagingError> {
        let (tx, rx) = oneshot::channel();
        // Register the waiter BEFORE sending so a fast reply can't race ahead.
        self.waiters
            .lock()
            .expect("waiters mutex")
            .insert(correlation_thid.to_string(), tx);

        if let Err(e) = self.transport.send(to, packed).await {
            self.remove_waiter(correlation_thid);
            return Err(e);
        }

        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(message)) => Ok(message),
            Ok(Err(_recv)) => Err(MessagingError::Transport(
                "request waiter dropped before a reply arrived".to_string(),
            )),
            Err(_elapsed) => {
                self.remove_waiter(correlation_thid);
                Err(MessagingError::Transport(format!(
                    "request timed out after {timeout:?} (thid {correlation_thid})"
                )))
            }
        }
    }

    /// Subscribe to inbound messages NOT claimed by a `request` waiter
    /// (unsolicited pushes, server-initiated requests). Each subscriber gets its
    /// own stream. Delivery is at-least-once — a consumer must dedup on the
    /// message's idempotency key.
    pub fn subscribe(&self) -> BoxStream<'static, Inbound> {
        let rx = self.subscribers.subscribe();
        Box::pin(stream::unfold(rx, |mut rx| async move {
            loop {
                match rx.recv().await {
                    Ok(item) => return Some((item, rx)),
                    // A slow subscriber that fell behind: skip the gap, keep going.
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => return None,
                }
            }
        }))
    }

    /// The one status a health endpoint reads, off the transport's live
    /// connection signal.
    pub fn status(&self) -> MessagingStatus {
        match *self.conn_state.borrow() {
            ConnState::Connected => MessagingStatus::Connected,
            _ => MessagingStatus::Disconnected,
        }
    }

    /// Record end-to-end delivery evidence for a `Guaranteed` send:
    /// its outbox entry transitions `Sent → Delivered` (§5a).
    ///
    /// Call this from an evidence source — a layer-receipt recognizer, or a
    /// protocol-reply handler that knows the reply confirms `idempotency_key`.
    /// Idempotent: `Ok(true)` if it transitioned an entry, `Ok(false)` if there
    /// was no matching `Sent` entry (unknown or already terminal).
    pub async fn confirm(&self, idempotency_key: &str) -> Result<bool, MessagingError> {
        crate::confirm::confirm_delivered(self.outbox.as_ref(), idempotency_key)
            .await
            .map_err(|e| MessagingError::Transport(format!("confirm failed: {e}")))
    }

    /// The current outbox state of a `Guaranteed` send (`Queued` / `Sent` /
    /// `Delivered` / `Unconfirmed` / `Failed`), or `None` if the key was never
    /// enqueued. Callers poll this to learn a delivery outcome after `send`
    /// returned `Accepted`. (A `BestEffort` send has no outbox entry.)
    pub async fn delivery_state(
        &self,
        idempotency_key: &str,
    ) -> Result<Option<OutboxState>, MessagingError> {
        Ok(self
            .outbox
            .get(idempotency_key)
            .await
            .map_err(|e| MessagingError::Transport(format!("outbox read failed: {e}")))?
            .map(|entry| entry.state))
    }

    fn remove_waiter(&self, thid: &str) {
        self.waiters.lock().expect("waiters mutex").remove(thid);
    }
}

/// The single inbound dispatcher: read `inbound()` once, then for each message
/// either
/// 1. **consume** it as a layer receipt — confirm its outbox entry `Sent →
///    Delivered` (§5a) and never surface it to the application; or
/// 2. **route** it to a matching `request` waiter (by thread id) or to
///    `subscribe`, emitting a fire-and-forget receipt for unsolicited traffic
///    when a packer is configured;
///
/// then ack it once after handoff.
async fn run_dispatcher(
    transport: Arc<dyn MessageTransport>,
    outbox: Arc<dyn OutboxStore>,
    waiters: WaiterMap,
    subscribers: broadcast::Sender<Inbound>,
    receipt_packer: Option<Arc<dyn ReceiptPacker>>,
) {
    let mut inbound = transport.inbound();
    while let Some(item) = inbound.next().await {
        let ack = item.ack.clone();

        // 1. A layer receipt is consumed by the layer, not the application: it
        //    confirms the matching outbox entry Sent → Delivered. A receipt for
        //    an unknown/terminal key is a harmless no-op (spurious/duplicate).
        if let Some(key) = receipt::receipt_of(&item.message) {
            match confirm_delivered(outbox.as_ref(), &key).await {
                Ok(true) => {
                    tracing::debug!(idempotency_key = %key, "layer receipt confirmed delivery")
                }
                Ok(false) => {}
                Err(e) => tracing::warn!(error = %e, "failed to apply layer receipt"),
            }
            if let Err(e) = transport.ack(ack).await {
                tracing::warn!(error = %e, "failed to ack layer receipt");
            }
            continue;
        }

        // 2. Protocol-reply evidence (§5a): a peer replying *in the thread* of one
        //    of our Guaranteed sends proves it received the original — you cannot
        //    reply in-thread to a message you never got. So an inbound whose
        //    thread id matches a `Sent` outbox entry confirms it `Delivered`,
        //    with no application ack of our own. Idempotent: a no-op when no
        //    `Sent` entry matches, and harmless if a layer receipt already
        //    confirmed the same entry. The reply is still ordinary application
        //    traffic — it is also routed below.
        let confirmed_our_send = match item.thread_id.as_deref() {
            Some(thid) => match confirm_delivered(outbox.as_ref(), thid).await {
                Ok(confirmed) => {
                    if confirmed {
                        tracing::debug!(idempotency_key = %thid, "protocol reply confirmed delivery");
                    }
                    confirmed
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to apply protocol-reply evidence");
                    false
                }
            },
            None => false,
        };

        // 3. Route application traffic.
        let waiter = item
            .thread_id
            .clone()
            .and_then(|thid| waiters.lock().expect("waiters mutex").remove(&thid));

        match waiter {
            // A reply for an in-flight request → its waiter. A reply is its own
            // evidence (the protocol-reply source); we do NOT also receipt it.
            Some(tx) => {
                let _ = tx.send(item.message);
            }
            // Unsolicited → subscribers (dropped if none are listening). If we
            // run the layer (a packer is configured) AND this is a fresh inbound
            // rather than a reply to our own Guaranteed send, emit a fire-and-
            // forget receipt echoing the correlation so *that* sender's outbox
            // entry settles Delivered. A message that just confirmed one of our
            // sends is a reply, not a fresh Guaranteed push, so it needs no
            // receipt from us (its thread id is the original thread, not the
            // reply's own key — a receipt would be a no-op on the peer anyway).
            None => {
                if !confirmed_our_send
                    && let Some(packer) = receipt_packer.as_ref()
                    && let (Some(to), Some(confirms)) =
                        (item.message.sender.clone(), item.thread_id.clone())
                {
                    spawn_receipt(transport.clone(), packer.clone(), to, confirms);
                }
                let _ = subscribers.send(item);
            }
        }

        // Ack once, HERE, after handoff — never in a per-caller loop and never
        // before the message has been routed.
        if let Err(e) = transport.ack(ack).await {
            tracing::warn!(error = %e, "failed to ack inbound message after handoff");
        }
    }
}

/// Pack and send a fire-and-forget layer receipt confirming `confirms` back to
/// `to`, on a detached task so a slow pack/send never stalls the dispatcher. A
/// pack or send failure is only logged: the receipt is self-healing (the
/// sender's delivery window expires and it re-sends; the receiver re-emits).
fn spawn_receipt(
    transport: Arc<dyn MessageTransport>,
    packer: Arc<dyn ReceiptPacker>,
    to: String,
    confirms: String,
) {
    tokio::spawn(async move {
        let body = Receipt::new(confirms).encode();
        match packer.pack_receipt(&to, body).await {
            Ok(packed) => {
                if let Err(e) = transport.send(&to, packed).await {
                    tracing::debug!(error = %e, to = %to, "layer receipt send failed (self-healing on window expiry)");
                }
            }
            Err(e) => tracing::warn!(error = %e, to = %to, "failed to pack layer receipt"),
        }
    });
}

/// A unique default idempotency key for a `Guaranteed` send with none supplied.
fn default_key(to: &str, now_ms: u64) -> Key {
    let seq = KEY_SEQ.fetch_add(1, Ordering::Relaxed);
    format!("{to}:{now_ms}:{seq}")
}

/// Current wall-clock time in Unix milliseconds.
fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outbox::{InMemoryOutboxStore, OutboxState};
    use affinidi_messaging_core::{
        InboundAck, Protocol, ReceivedMessage, SendReceipt, TransportKind,
    };
    use std::sync::atomic::AtomicBool;
    use tokio::sync::mpsc;

    /// A controllable transport: records sends + acks, feeds `inbound()` from an
    /// mpsc the test pushes into, and exposes a settable connection state.
    struct MockTransport {
        inbound_rx: Mutex<Option<mpsc::UnboundedReceiver<Inbound>>>,
        sent: Mutex<Vec<(String, Vec<u8>)>>,
        acked: Mutex<Vec<String>>,
        conn_rx: watch::Receiver<ConnState>,
        fail_send: AtomicBool,
    }

    struct MockHandles {
        transport: Arc<MockTransport>,
        inbound_tx: mpsc::UnboundedSender<Inbound>,
        conn_tx: watch::Sender<ConnState>,
    }

    fn mock() -> MockHandles {
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
        let (conn_tx, conn_rx) = watch::channel(ConnState::Connected);
        let transport = Arc::new(MockTransport {
            inbound_rx: Mutex::new(Some(inbound_rx)),
            sent: Mutex::new(Vec::new()),
            acked: Mutex::new(Vec::new()),
            conn_rx,
            fail_send: AtomicBool::new(false),
        });
        MockHandles {
            transport,
            inbound_tx,
            conn_tx,
        }
    }

    #[async_trait::async_trait]
    impl MessageTransport for MockTransport {
        fn kind(&self) -> TransportKind {
            TransportKind::Didcomm
        }
        async fn send(&self, dest: &str, packed: Vec<u8>) -> Result<SendReceipt, MessagingError> {
            if self.fail_send.load(Ordering::SeqCst) {
                return Err(MessagingError::Transport("mock send failed".into()));
            }
            self.sent.lock().unwrap().push((dest.to_string(), packed));
            Ok(SendReceipt {
                via: TransportKind::Didcomm,
                hop_id: None,
            })
        }
        fn connection_state(&self) -> watch::Receiver<ConnState> {
            self.conn_rx.clone()
        }
        fn inbound(&self) -> BoxStream<'static, Inbound> {
            match self.inbound_rx.lock().unwrap().take() {
                Some(rx) => Box::pin(stream::unfold(rx, |mut rx| async move {
                    rx.recv().await.map(|item| (item, rx))
                })),
                None => Box::pin(stream::empty()),
            }
        }
        async fn ack(&self, ack: InboundAck) -> Result<(), MessagingError> {
            self.acked.lock().unwrap().push(ack.0);
            Ok(())
        }
    }

    fn inbound(id: &str, thid: Option<&str>, ack: &str) -> Inbound {
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
            ack: InboundAck(ack.to_string()),
        }
    }

    #[tokio::test]
    async fn best_effort_send_transmits_once() {
        let h = mock();
        let svc = MessagingService::new(h.transport.clone(), Arc::new(InMemoryOutboxStore::new()));

        let sent = svc
            .send("did:example:bob", b"packed".to_vec(), Delivery::BestEffort)
            .await
            .unwrap();
        assert_eq!(sent, Sent::Accepted);
        assert_eq!(h.transport.sent.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn guaranteed_send_enqueues_to_the_outbox() {
        let h = mock();
        let outbox = Arc::new(InMemoryOutboxStore::new());
        let svc = MessagingService::new(h.transport.clone(), outbox.clone());

        let sent = svc
            .send(
                "did:example:bob",
                b"packed".to_vec(),
                Delivery::Guaranteed {
                    idempotency_key: Some("k-1".to_string()),
                    ordering_key: None,
                    deliver_by: Duration::from_secs(60),
                },
            )
            .await
            .unwrap();
        assert_eq!(sent, Sent::Accepted);
        // Enqueued, not sent directly (the drain owns sending).
        assert!(h.transport.sent.lock().unwrap().is_empty());
        let entry = outbox.get("k-1").await.unwrap().unwrap();
        assert_eq!(entry.state, OutboxState::Queued);
        assert_eq!(entry.dest_did, "did:example:bob");
    }

    #[tokio::test]
    async fn request_receives_its_reply_by_thread_id_and_acks() {
        let h = mock();
        let svc = Arc::new(MessagingService::new(
            h.transport.clone(),
            Arc::new(InMemoryOutboxStore::new()),
        ));

        let svc2 = svc.clone();
        let req = tokio::spawn(async move {
            svc2.request(
                "did:example:bob",
                b"req".to_vec(),
                "thread-1",
                Duration::from_secs(5),
            )
            .await
        });

        // Let the request register its waiter + send, then deliver the reply.
        tokio::time::sleep(Duration::from_millis(50)).await;
        h.inbound_tx
            .send(inbound("reply-msg", Some("thread-1"), "queue-1"))
            .unwrap();

        let reply = req.await.unwrap().unwrap();
        assert_eq!(reply.id, "reply-msg");
        // The dispatcher acked the reply after handoff.
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(h.transport.acked.lock().unwrap().as_slice(), &["queue-1"]);
    }

    #[tokio::test]
    async fn concurrent_requests_dont_steal_each_others_replies() {
        let h = mock();
        let svc = Arc::new(MessagingService::new(
            h.transport.clone(),
            Arc::new(InMemoryOutboxStore::new()),
        ));

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
        // Deliver replies out of order.
        h.inbound_tx
            .send(inbound("for-t2", Some("t2"), "q2"))
            .unwrap();
        h.inbound_tx
            .send(inbound("for-t1", Some("t1"), "q1"))
            .unwrap();

        assert_eq!(r1.await.unwrap().unwrap().id, "for-t1");
        assert_eq!(r2.await.unwrap().unwrap().id, "for-t2");
    }

    #[tokio::test]
    async fn unsolicited_message_goes_to_subscribe_and_is_acked() {
        let h = mock();
        let svc = MessagingService::new(h.transport.clone(), Arc::new(InMemoryOutboxStore::new()));
        let mut sub = svc.subscribe();

        // No matching waiter → routed to subscribers.
        h.inbound_tx
            .send(inbound("push-1", None, "q-push"))
            .unwrap();

        let got = tokio::time::timeout(Duration::from_secs(2), sub.next())
            .await
            .expect("subscribe yields the push")
            .expect("stream item");
        assert_eq!(got.message.id, "push-1");
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(h.transport.acked.lock().unwrap().as_slice(), &["q-push"]);
    }

    #[tokio::test]
    async fn status_tracks_the_transport_connection_state() {
        let h = mock();
        let svc = MessagingService::new(h.transport.clone(), Arc::new(InMemoryOutboxStore::new()));
        assert_eq!(svc.status(), MessagingStatus::Connected);

        h.conn_tx.send(ConnState::Disconnected).unwrap();
        assert_eq!(svc.status(), MessagingStatus::Disconnected);

        h.conn_tx.send(ConnState::Connected).unwrap();
        assert_eq!(svc.status(), MessagingStatus::Connected);
    }

    // ── Layer-receipt evidence (§5a) ─────────────────────────────────────

    /// A trivial packer: records who it packed for and wraps the body so the
    /// test can prove the receipt reached the transport.
    struct MockPacker {
        packed_for: Mutex<Vec<String>>,
    }
    impl MockPacker {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                packed_for: Mutex::new(Vec::new()),
            })
        }
    }
    #[async_trait::async_trait]
    impl ReceiptPacker for MockPacker {
        async fn pack_receipt(&self, to: &str, body: Vec<u8>) -> Result<Vec<u8>, MessagingError> {
            self.packed_for.lock().unwrap().push(to.to_string());
            Ok(body) // "packed" == the raw receipt body, for assertion
        }
    }

    /// An inbound whose payload IS a layer receipt confirming `confirms`.
    fn inbound_receipt(confirms: &str, ack: &str) -> Inbound {
        let mut item = inbound("receipt-msg", None, ack);
        item.message.payload = Receipt::new(confirms).encode();
        item
    }

    async fn sent_entry(outbox: &InMemoryOutboxStore, key: &str) {
        let mut e = OutboxEntry::new(key, "did:example:bob", vec![1], 1_000, 61_000);
        e.state = OutboxState::Sent;
        outbox.put(e).await.unwrap();
    }

    #[tokio::test]
    async fn a_layer_receipt_confirms_its_outbox_entry_and_is_not_routed() {
        let h = mock();
        let outbox = Arc::new(InMemoryOutboxStore::new());
        sent_entry(&outbox, "k").await; // a Guaranteed send awaiting evidence
        let svc = MessagingService::new(h.transport.clone(), outbox.clone());
        let mut sub = svc.subscribe();

        // A receipt for "k" arrives.
        h.inbound_tx
            .send(inbound_receipt("k", "q-receipt"))
            .unwrap();

        // The outbox entry settles Delivered (consumed by the layer)…
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            outbox.get("k").await.unwrap().unwrap().state,
            OutboxState::Delivered
        );
        // …the receipt is acked…
        assert_eq!(h.transport.acked.lock().unwrap().as_slice(), &["q-receipt"]);
        // …and never surfaced to the application.
        assert!(
            tokio::time::timeout(Duration::from_millis(100), sub.next())
                .await
                .is_err(),
            "a layer receipt must not reach subscribers"
        );
    }

    #[tokio::test]
    async fn a_receipt_for_an_unknown_key_is_a_harmless_noop() {
        let h = mock();
        let outbox = Arc::new(InMemoryOutboxStore::new());
        let svc = MessagingService::new(h.transport.clone(), outbox.clone());
        let _sub = svc.subscribe();

        h.inbound_tx
            .send(inbound_receipt("never-sent", "q"))
            .unwrap();

        // Nothing to confirm, but it's still consumed + acked, not an error.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(outbox.get("never-sent").await.unwrap().is_none());
        assert_eq!(h.transport.acked.lock().unwrap().as_slice(), &["q"]);
    }

    #[tokio::test]
    async fn an_unsolicited_message_emits_a_receipt_when_a_packer_is_configured() {
        let h = mock();
        let packer = MockPacker::new();
        let svc = MessagingService::with_receipts(
            h.transport.clone(),
            Arc::new(InMemoryOutboxStore::new()),
            packer.clone(),
        );
        let mut sub = svc.subscribe();

        // Unsolicited (no matching waiter), with a sender + correlation thid.
        h.inbound_tx
            .send(inbound("push-1", Some("corr-key"), "q-push"))
            .unwrap();

        // Still delivered to the app…
        let got = tokio::time::timeout(Duration::from_secs(2), sub.next())
            .await
            .expect("subscribe yields the push")
            .expect("stream item");
        assert_eq!(got.message.id, "push-1");

        // …and a receipt was packed for the sender and sent back to it,
        // echoing the correlation as the confirmed key.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            packer.packed_for.lock().unwrap().as_slice(),
            &["did:example:alice"]
        );
        let sent = h.transport.sent.lock().unwrap();
        let (dest, body) = sent.last().expect("a receipt was sent");
        assert_eq!(dest, "did:example:alice");
        assert_eq!(receipt::receipt_key(body).as_deref(), Some("corr-key"));
    }

    #[tokio::test]
    async fn a_reply_to_a_request_is_not_receipted() {
        let h = mock();
        let packer = MockPacker::new();
        let svc = Arc::new(MessagingService::with_receipts(
            h.transport.clone(),
            Arc::new(InMemoryOutboxStore::new()),
            packer.clone(),
        ));

        let svc2 = svc.clone();
        let req = tokio::spawn(async move {
            svc2.request("did:x", b"req".to_vec(), "thread-1", Duration::from_secs(5))
                .await
        });

        tokio::time::sleep(Duration::from_millis(50)).await;
        // The reply matches the in-flight request's waiter.
        h.inbound_tx
            .send(inbound("reply", Some("thread-1"), "q-reply"))
            .unwrap();
        assert_eq!(req.await.unwrap().unwrap().id, "reply");

        // A reply is its own (protocol-reply) evidence — no layer receipt emitted.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            packer.packed_for.lock().unwrap().is_empty(),
            "a request reply must not trigger a layer receipt"
        );
    }

    #[tokio::test]
    async fn no_receipt_is_emitted_without_a_packer() {
        let h = mock();
        let svc = MessagingService::new(h.transport.clone(), Arc::new(InMemoryOutboxStore::new()));
        let _sub = svc.subscribe();

        h.inbound_tx
            .send(inbound("push-1", Some("corr"), "q-push"))
            .unwrap();

        // Consume-only service: the push is delivered + acked, but nothing is
        // sent back (no emit half).
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(h.transport.sent.lock().unwrap().is_empty());
    }

    // ── Protocol-reply evidence (§5a) ────────────────────────────────────

    #[tokio::test]
    async fn a_reply_in_thread_confirms_a_guaranteed_send_and_still_delivers() {
        let h = mock();
        let outbox = Arc::new(InMemoryOutboxStore::new());
        sent_entry(&outbox, "thid-x").await; // a Guaranteed send awaiting evidence
        let svc = MessagingService::new(h.transport.clone(), outbox.clone());
        let mut sub = svc.subscribe();

        // A peer replies in the thread of our send (thid == the idempotency key).
        h.inbound_tx
            .send(inbound("the-reply", Some("thid-x"), "q-reply"))
            .unwrap();

        // The reply is evidence → the outbox entry settles Delivered…
        let got = tokio::time::timeout(Duration::from_secs(2), sub.next())
            .await
            .expect("subscribe yields the reply")
            .expect("stream item");
        // …and is STILL delivered to the application (it is a real message).
        assert_eq!(got.message.id, "the-reply");
        assert_eq!(
            outbox.get("thid-x").await.unwrap().unwrap().state,
            OutboxState::Delivered
        );
    }

    #[tokio::test]
    async fn a_reply_confirming_our_send_is_not_receipted() {
        let h = mock();
        let outbox = Arc::new(InMemoryOutboxStore::new());
        sent_entry(&outbox, "thid-x").await;
        let packer = MockPacker::new();
        let svc =
            MessagingService::with_receipts(h.transport.clone(), outbox.clone(), packer.clone());
        let _sub = svc.subscribe();

        h.inbound_tx
            .send(inbound("the-reply", Some("thid-x"), "q-reply"))
            .unwrap();

        tokio::time::sleep(Duration::from_millis(50)).await;
        // Confirmed our send (protocol reply)…
        assert_eq!(
            outbox.get("thid-x").await.unwrap().unwrap().state,
            OutboxState::Delivered
        );
        // …and, being a reply to our own send, is NOT itself receipted.
        assert!(
            packer.packed_for.lock().unwrap().is_empty(),
            "a reply confirming our send must not trigger a receipt"
        );
    }

    #[tokio::test]
    async fn confirm_upgrades_a_sent_guaranteed_send_to_delivered() {
        let h = mock();
        let outbox = Arc::new(InMemoryOutboxStore::new());
        let svc = MessagingService::new(h.transport.clone(), outbox.clone());

        // Guaranteed send → Queued.
        svc.send(
            "did:x",
            b"m".to_vec(),
            Delivery::Guaranteed {
                idempotency_key: Some("k".to_string()),
                ordering_key: None,
                deliver_by: Duration::from_secs(60),
            },
        )
        .await
        .unwrap();
        assert_eq!(
            svc.delivery_state("k").await.unwrap(),
            Some(OutboxState::Queued)
        );

        // Simulate the drain hop-accepting it (Queued → Sent).
        let mut e = outbox.get("k").await.unwrap().unwrap();
        e.state = OutboxState::Sent;
        outbox.put(e).await.unwrap();
        assert_eq!(
            svc.delivery_state("k").await.unwrap(),
            Some(OutboxState::Sent)
        );

        // Evidence arrives → Delivered (idempotent).
        assert!(svc.confirm("k").await.unwrap());
        assert!(!svc.confirm("k").await.unwrap());
        assert_eq!(
            svc.delivery_state("k").await.unwrap(),
            Some(OutboxState::Delivered)
        );

        // An unknown key has no delivery state.
        assert_eq!(svc.delivery_state("unknown").await.unwrap(), None);
    }
}
