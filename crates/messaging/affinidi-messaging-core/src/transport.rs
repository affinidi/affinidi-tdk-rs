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
#[non_exhaustive]
pub struct Inbound {
    /// The received, unpacked message (sender proven per `message.verified`).
    pub message: ReceivedMessage,
    /// Thread id for correlation / demux (DIDComm `thid`), when present.
    pub thread_id: Option<String>,
    /// Handle to acknowledge this exact delivery once it is durably handled.
    pub ack: InboundAck,
    /// What this message *is* — application data, or a request about the
    /// relationship itself. See [`InboundKind`].
    pub kind: InboundKind,
}

impl Inbound {
    /// An application message — the overwhelmingly common case.
    ///
    /// A constructor rather than a struct literal because [`Inbound`] is
    /// `#[non_exhaustive]`: the type has grown once and will again, and every
    /// previous growth was a source break for every consumer.
    pub fn new(message: ReceivedMessage, thread_id: Option<String>, ack: InboundAck) -> Self {
        Self {
            message,
            thread_id,
            ack,
            kind: InboundKind::Application,
        }
    }

    /// Mark what this message is. Chained onto [`Inbound::new`].
    #[must_use]
    pub fn with_kind(mut self, kind: InboundKind) -> Self {
        self.kind = kind;
        self
    }

    /// Whether this is a request about the relationship rather than traffic
    /// over it — the messages a consumer must answer as *policy*, not route as
    /// data.
    pub fn is_relationship_control(&self) -> bool {
        matches!(self.kind, InboundKind::RelationshipControl { .. })
    }
}

/// What an [`Inbound`] turned out to be.
///
/// # Why a transport-level type has to say this
///
/// A protocol can carry two things that look identical to a wire and mean
/// opposite things to the layer above: data *over* a relationship, and a
/// request *about* one. TSP Rev 3 §7.2 is the case that forced this — an
/// endpoint drops an application message from a VID it holds no relationship
/// with, so the control exchange is a precondition of all traffic rather than
/// an optional courtesy.
///
/// Without this field the two are indistinguishable by the time they reach a
/// consumer, and the transport is left making an authorization decision it has
/// no standing to make. The split is deliberate and worth stating:
///
/// * **Recording** an inbound control message is *framework* behaviour. It is
///   what admits the messages that follow, it is not a grant of anything, and
///   a transport that skipped it would make every later message vanish. The
///   transport does this before the consumer ever sees the message.
/// * **Answering** it — accept, refuse, ignore — is *policy*. It depends on an
///   ACL the transport cannot see, so it belongs to the consumer.
///
/// The failure mode when this is got wrong is silence, which is why it earns a
/// type rather than a convention: §7.2.2 says *drop*, so an endpoint that
/// records nothing looks exactly like a transport that accepts connections and
/// never replies. Nothing goes back to the peer and nothing appears in a log.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum InboundKind {
    /// Ordinary traffic for the consumer's protocol handler.
    #[default]
    Application,
    /// A request about the relationship itself, already recorded by the
    /// transport and awaiting the consumer's decision.
    ///
    /// Carries what answering requires, because the consumer cannot recover it
    /// from the sender alone — both `accept_relationship` and
    /// `cancel_relationship` need the digest, and nothing stores it.
    RelationshipControl {
        /// What the peer asked for.
        request: RelationshipRequest,
        /// The digest an answer must echo back (TSP `TSP_Digest`, §7.2.2).
        /// For a cancellation, the relationship digest the cancellation named.
        thread_digest: [u8; 32],
        /// A §7.3 answer to a cancellation is still owed by the consumer.
        ///
        /// A cancellation of a relationship held in both directions is
        /// answered with a cancellation back. A transport that sends that
        /// answer itself reports `false` once it has; `true` means the answer
        /// was due and the transport could not send it. `false` for
        /// everything else.
        reply_expected: bool,
        /// A VID this request introduces (TSP §7.2.5 referral), already
        /// verified by the transport — an unverified referral never reaches a
        /// consumer. `None` when the request introduces nobody.
        ///
        /// Worth a policy decision of its own: accepting an invite that
        /// introduces a VID is agreeing to two things, not one.
        introduces: Option<String>,
    },
}

/// What a peer asked for about a relationship.
///
/// Deliberately smaller than any one protocol's control taxonomy: a referral
/// is an attachment on an invite rather than a fourth kind, so it rides
/// [`InboundKind::RelationshipControl::introduces`] instead of a variant here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RelationshipRequest {
    /// The peer proposes a relationship (TSP `XRFI`).
    Invite,
    /// The peer accepted one we proposed (TSP `XRFA`).
    Accept,
    /// The peer is ending one (TSP `XRFD`).
    Cancel,
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

    /// Where each of `hop_ids` stands, as the sender's mediator records it, in
    /// the order asked (`messaging/message/status/0.1`).
    ///
    /// Stronger evidence than [`outbox_message_ids`](Self::outbox_message_ids).
    /// "Gone from the outbox" cannot tell a recipient's pickup from an expiry,
    /// and a recipient that collects before the first poll never appears at
    /// all. A mediator that keeps receipts says which it was. The delivery
    /// layer prefers this and falls back to the outbox listing when it answers
    /// `None`.
    ///
    /// The default returns `None`: no such signal (a stateless transport, or a
    /// mediator that predates receipts).
    async fn outbox_status(
        &self,
        _hop_ids: &[String],
    ) -> Result<Option<Vec<OutboxStatus>>, MessagingError> {
        Ok(None)
    }
}

/// Where a sent message stands at the sender's mediator.
///
/// # Why this exists
///
/// A message leaves the sender's outbox in the same way whether the recipient
/// took it or the mediator discarded it, so the outbox alone can only say
/// "gone". The removal reason is what separates delivery from loss, and it is
/// decided by who removed the message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum OutboxStatus {
    /// Held for the recipient, not yet handed over.
    Queued,
    /// Handed to the recipient, not yet removed by it. Not yet evidence of
    /// collection: the recipient may still fail to process it.
    Delivered,
    /// Removed by the recipient. Evidence of delivery.
    Collected,
    /// Removed by the sender.
    Withdrawn,
    /// Removed by the mediator before the recipient took it: expired, or the
    /// account was removed. Evidence of loss.
    Discarded,
    /// The mediator holds neither the message nor a receipt for it. No
    /// evidence either way.
    Unknown,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Protocol;
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

    fn a_message() -> ReceivedMessage {
        ReceivedMessage {
            id: "frame-1".to_string(),
            sender: Some("did:example:alice".to_string()),
            recipient: "did:example:bob".to_string(),
            payload: Vec::new(),
            protocol: Protocol::TSP,
            verified: true,
            encrypted: true,
        }
    }

    /// The default is application data, so a transport that says nothing about
    /// kind cannot silently present a relationship request as traffic.
    ///
    /// The direction matters: defaulting the other way would make every
    /// existing transport's messages look like control and route none of them.
    #[test]
    fn an_unmarked_message_is_application_data() {
        let inbound = Inbound::new(a_message(), None, InboundAck("ack-1".into()));
        assert_eq!(inbound.kind, InboundKind::Application);
        assert!(!inbound.is_relationship_control());
    }

    /// A relationship request carries what answering it requires.
    ///
    /// Not a formality: `accept_relationship` and `cancel_relationship` both
    /// need the thread digest, and nothing on the recorded relationship stores
    /// it — so a consumer handed only the sender could decide what to do and
    /// still have no way to say it.
    #[test]
    fn a_relationship_request_carries_what_answering_it_needs() {
        let inbound = Inbound::new(a_message(), None, InboundAck("ack-2".into())).with_kind(
            InboundKind::RelationshipControl {
                request: RelationshipRequest::Invite,
                thread_digest: [7u8; 32],
                reply_expected: false,
                introduces: None,
            },
        );

        assert!(inbound.is_relationship_control());
        let InboundKind::RelationshipControl {
            request,
            thread_digest,
            ..
        } = inbound.kind
        else {
            panic!("expected a relationship request, got {:?}", inbound.kind);
        };
        assert_eq!(request, RelationshipRequest::Invite);
        assert_eq!(
            thread_digest, [7u8; 32],
            "the digest an accept must echo has to survive the trip to the consumer",
        );
    }

    /// An invite that introduces a VID is distinguishable from one that does
    /// not, because accepting it agrees to two things rather than one.
    #[test]
    fn a_referral_is_visible_to_the_consumer() {
        let plain = InboundKind::RelationshipControl {
            request: RelationshipRequest::Invite,
            thread_digest: [0u8; 32],
            reply_expected: false,
            introduces: None,
        };
        let introducing = InboundKind::RelationshipControl {
            request: RelationshipRequest::Invite,
            thread_digest: [0u8; 32],
            reply_expected: false,
            introduces: Some("did:example:carol".to_string()),
        };
        assert_ne!(
            plain, introducing,
            "a referral must not be invisible beside an ordinary invite",
        );
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
