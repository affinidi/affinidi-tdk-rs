//! Transport-agnostic connection vocabulary and the [`MessageTransport`] wire
//! contract shared by messaging transports (DIDComm today, TSP and REST later).
//! Kept here in `affinidi-messaging-core` — the protocol-agnostic base of the
//! messaging stack — so every transport and the delivery layer above them speak
//! the same words, and a transport implemented here is safe for the delivery
//! layer to build reliability on.

use crate::error::MessagingError;
use crate::types::ReceivedMessage;
use futures_util::stream::BoxStream;
use serde::{Deserialize, Serialize};
use tokio::sync::watch;

/// Re-falsifiable connection / reachability state of a messaging transport.
///
/// A conforming transport MUST publish a transition on **every** drop and
/// **every** (re)connect for the life of the process — this is not a boot-time
/// latch (rule R6.2). Transports carry it over a [`tokio::sync::watch`] channel
/// they own, so the delivery layer, health endpoints, and retry loops all
/// observe the *same* latest value rather than each inferring connectivity.
///
/// [`tokio::sync::watch`]: https://docs.rs/tokio/latest/tokio/sync/watch/index.html
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ConnState {
    /// Establishing the first connection; no successful connect yet.
    Connecting,
    /// Connected to the next hop (mediator / relay) — sends can be attempted.
    Connected,
    /// The connection has dropped; the transport is retrying or idle. A send
    /// attempted now is not on the wire.
    Disconnected,
}

/// Which wire a [`MessageTransport`] speaks, for status and telemetry.
///
/// This is the *transport* axis (how bytes travel), distinct from
/// [`crate::types::Protocol`] (the crypto envelope). `Rest` reuses a did-signed
/// HTTPS POST and has no crypto `Protocol` of its own, which is why the two
/// axes are separate enums.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum TransportKind {
    /// DIDComm over a mediator (websocket or REST `/inbound`).
    Didcomm,
    /// Trust Spanning Protocol via the sender's mediator.
    Tsp,
    /// Last-resort did-signed HTTPS POST to a peer that speaks neither.
    Rest,
}

/// Proof that a transport accepted a frame at its **next hop** — a mediator or
/// TSP relay accept, a REST `2xx`.
///
/// This is *hop acceptance*, **not** end-to-end delivery: the hop can accept a
/// frame and then fail — permanently, or past any window we would accept —
/// before routing it to the recipient. End-to-end delivery is proven *above*
/// the transport (an application-level ack, or the delivery layer's outbox),
/// and is never inferred from a `SendReceipt`. Conflating the two is exactly
/// the "logged delivered for a dropped send" bug this layer exists to remove.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendReceipt {
    /// Which transport accepted the frame.
    pub via: TransportKind,
    /// The hop's identifier for the accepted frame, when it returns one (e.g. a
    /// mediator queue-id). Correlates a later delivery confirmation; `None` when
    /// the hop returns no id.
    pub hop_id: Option<String>,
}

/// An opaque, transport-scoped acknowledgement handle for exactly one
/// [`Inbound`]. The delivery layer passes it back to [`MessageTransport::ack`]
/// once the message is durably handed off. Its contents are transport-specific
/// (DIDComm: the mediator queue-id / message hash; TSP and REST define their
/// own) and callers must treat it as opaque.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundAck(pub String);

/// An inbound message the transport has received but has **not yet
/// acknowledged** to its source (e.g. still queued at the mediator).
///
/// The delivery layer above decides when to [`MessageTransport::ack`] — only
/// **after** the message is durably handed off — so a host teardown between
/// receipt and persistence cannot lose it (never ack-before-handoff). Delivery
/// of each `Inbound` to the layer is exactly-once from the transport's side;
/// at-least-once and dedup are the layer's concern.
#[derive(Debug, Clone)]
pub struct Inbound {
    /// The received, unpacked message (sender proven per `message.verified`).
    pub message: ReceivedMessage,
    /// Thread id for correlation / demux (DIDComm `thid`), when present.
    pub thread_id: Option<String>,
    /// Handle to acknowledge this exact delivery once it is durably handled.
    pub ack: InboundAck,
}

/// A wire that can carry a packed message to a peer and surface inbound ones,
/// **conformant** to the guarantees the delivery layer builds reliability on.
///
/// The six cross-service delivery findings all reduce to the DIDComm wire
/// failing to surface two things: a *truthful* send result and a
/// *re-falsifiable* connection state. This trait makes surfacing them
/// mandatory, so a conforming wire cannot have those bugs — and TSP/REST
/// inherit the guarantees by implementing the same contract.
///
/// Packing/unpacking is **not** part of this trait — it is the crypto concern
/// of [`crate::traits::MessagingProtocol`]. A transport takes already-packed
/// bytes (as produced by `MessagingProtocol::pack`) and moves them.
///
/// Object-safe: the delivery layer holds an `Arc<dyn MessageTransport>`.
#[async_trait::async_trait]
pub trait MessageTransport: Send + Sync {
    /// The transport's identity, for status/telemetry.
    fn kind(&self) -> TransportKind;

    /// Send one already-packed message to `dest`.
    ///
    /// **Requirement 1 — truthful result.** Resolves `Ok(SendReceipt)` ONLY
    /// when the bytes are accepted by the next hop (mediator `/inbound` 2xx, TSP
    /// relay accept, REST 2xx). If the wire is down, reconnecting, or the send
    /// errors, this returns `Err` — **never** `Ok` for a dropped frame. The
    /// receipt is hop-acceptance, not end-to-end delivery (see [`SendReceipt`]).
    async fn send(&self, dest: &str, packed: Vec<u8>) -> Result<SendReceipt, MessagingError>;

    /// A re-falsifiable connection/reachability signal for this transport.
    ///
    /// **Requirement 2 — the value MUST change on every drop and every
    /// reconnect**, for the life of the process. It is NOT a boot-time latch.
    /// Observers read the latest [`ConnState`] and see every transition.
    fn connection_state(&self) -> watch::Receiver<ConnState>;

    /// The inbound stream of received (unpacked) messages, each still
    /// un-acknowledged at the source so the layer owns ack timing.
    ///
    /// **Requirement 3 — never ack-before-handoff.** The transport yields each
    /// [`Inbound`] without deleting it from its source; the layer calls
    /// [`MessageTransport::ack`] only after a durable handoff.
    fn inbound(&self) -> BoxStream<'static, Inbound>;

    /// Acknowledge (and let the transport settle/delete) an inbound message
    /// **after** it has been durably handed off. Acking after handoff is what
    /// makes at-least-once delivery safe: an un-acked message is redelivered
    /// rather than lost.
    async fn ack(&self, ack: InboundAck) -> Result<(), MessagingError>;

    /// The hop-ids still held in the **sender's own outbox** — the transport's
    /// "not yet picked up" signal (§5a outbox-drain evidence).
    ///
    /// A hop-and-hold transport (DIDComm/TSP via a mediator) keeps a sent
    /// message in the sender's outbox until the recipient acks pickup, then
    /// deletes it. So a [`SendReceipt::hop_id`] that has **drained** from this
    /// set — after first appearing in it — is the transport-level evidence that
    /// the recipient took delivery. The delivery layer polls this.
    ///
    /// The default returns `None`: a transport that gives no such signal (a
    /// stateless REST POST) simply offers no outbox-drain evidence.
    async fn outbox_message_ids(&self) -> Result<Option<Vec<String>>, MessagingError> {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::stream;
    use std::sync::Arc;

    /// A do-nothing transport, purely to prove the trait is implementable and
    /// object-safe (the delivery layer will hold an `Arc<dyn MessageTransport>`).
    struct NoopTransport {
        conn: watch::Sender<ConnState>,
    }

    #[async_trait::async_trait]
    impl MessageTransport for NoopTransport {
        fn kind(&self) -> TransportKind {
            TransportKind::Didcomm
        }
        async fn send(&self, _dest: &str, _packed: Vec<u8>) -> Result<SendReceipt, MessagingError> {
            Ok(SendReceipt {
                via: TransportKind::Didcomm,
                hop_id: None,
            })
        }
        fn connection_state(&self) -> watch::Receiver<ConnState> {
            self.conn.subscribe()
        }
        fn inbound(&self) -> BoxStream<'static, Inbound> {
            Box::pin(stream::empty())
        }
        async fn ack(&self, _ack: InboundAck) -> Result<(), MessagingError> {
            Ok(())
        }
    }

    #[test]
    fn message_transport_is_object_safe_and_implementable() {
        let (tx, _rx) = watch::channel(ConnState::Connecting);
        // Coercion to `dyn` proves object-safety; building it proves every
        // method (including the `async` ones) has a valid signature.
        let t: Arc<dyn MessageTransport> = Arc::new(NoopTransport { conn: tx });
        assert_eq!(t.kind(), TransportKind::Didcomm);
        assert_eq!(*t.connection_state().borrow(), ConnState::Connecting);
        // The inbound stream is a valid `BoxStream<'static, Inbound>`.
        let _stream = t.inbound();
    }
}
