//! `DidCommTransport` — a [`MessageTransport`] over the DIDComm ATM wire.
//!
//! Binds the now-conformant SDK (truthful send, a live `watch<ConnState>`
//! connection signal, ack-after-handoff) to the transport-agnostic contract in
//! `affinidi-messaging-core`, so the delivery layer can build reliability on
//! DIDComm through the same trait it will use for TSP and REST.

use std::sync::Arc;
use std::time::Duration;

use affinidi_messaging_core::{
    ConnState, Inbound, InboundAck, MessageTransport, MessagingError, Protocol, ReceivedMessage,
    SendReceipt, TransportKind,
};
use affinidi_messaging_didcomm::Message;
use futures_util::stream::{self, BoxStream};
use tokio::sync::watch;

use crate::messages::compat::UnpackMetadata;
use crate::{ATM, profiles::ATMProfile};

/// How long each inbound `live_stream_next` poll waits for a message before
/// looping — also the reconnect-retry cadence.
const INBOUND_POLL_WAIT: Duration = Duration::from_secs(10);
/// Backoff after a transient inbound error (e.g. a websocket reconnect) so the
/// stream doesn't spin.
const INBOUND_ERROR_BACKOFF: Duration = Duration::from_millis(500);

/// A [`MessageTransport`] over the DIDComm ATM wire for one profile.
///
/// Construct with [`DidCommTransport::new`] (async — it captures the profile's
/// connection-state signal once). `send` is truthful: an untransmitted frame is
/// an `Err`, never a false `Ok` (SDK ≥ 0.18.52). `inbound` yields messages the
/// transport has **not** acked; the caller acks via [`MessageTransport::ack`]
/// only after a durable handoff.
pub struct DidCommTransport {
    atm: ATM,
    profile: Arc<ATMProfile>,
    conn_state: watch::Receiver<ConnState>,
}

impl DidCommTransport {
    /// Bind a transport to `profile`'s DIDComm websocket wire.
    ///
    /// Errors if the profile has no websocket transport running (enable it with
    /// `profile_enable_websocket` first). The connection-state receiver is
    /// captured here and tracks socket reconnects for the life of the transport
    /// task; a full task teardown + restart would need a fresh
    /// `DidCommTransport`.
    pub async fn new(atm: ATM, profile: Arc<ATMProfile>) -> Result<Self, MessagingError> {
        let conn_state = profile.connection_state().await.ok_or_else(|| {
            MessagingError::Transport(
                "profile has no websocket transport (enable it before binding a DidCommTransport)"
                    .to_string(),
            )
        })?;
        Ok(Self {
            atm,
            profile,
            conn_state,
        })
    }
}

#[async_trait::async_trait]
impl MessageTransport for DidCommTransport {
    fn kind(&self) -> TransportKind {
        TransportKind::Didcomm
    }

    async fn send(&self, _dest: &str, packed: Vec<u8>) -> Result<SendReceipt, MessagingError> {
        // The packed JWE already encodes the recipient; the ATM routes it via
        // the profile's mediator, so `dest` is informational here.
        let packed = String::from_utf8(packed)
            .map_err(|e| MessagingError::Transport(format!("packed message is not UTF-8: {e}")))?;
        // Fire-and-forget at the transport: the delivery layer's outbox owns
        // end-to-end confirmation, so we don't wait for a reply. `msg_id` is only
        // used for reply correlation (unused when not waiting), so a fresh id is
        // fine. `send_message` is truthful — `Err` if the frame wasn't written.
        let msg_id = uuid::Uuid::new_v4().to_string();
        self.atm
            .send_message(&self.profile, &packed, &msg_id, false, false)
            .await
            .map(|_| SendReceipt {
                via: TransportKind::Didcomm,
                hop_id: None,
            })
            .map_err(|e| MessagingError::Transport(format!("didcomm send failed: {e}")))
    }

    fn connection_state(&self) -> watch::Receiver<ConnState> {
        self.conn_state.clone()
    }

    fn inbound(&self) -> BoxStream<'static, Inbound> {
        let atm = self.atm.clone();
        let profile = self.profile.clone();
        // Own the ATM + profile so the stream is `'static`; re-borrow per poll.
        // `auto_delete = false` so the mediator keeps its copy until the caller
        // acks after a durable handoff (never ack-before-handoff).
        Box::pin(stream::unfold(
            (atm, profile),
            |(atm, profile)| async move {
                loop {
                    match atm
                        .message_pickup()
                        .live_stream_next(&profile, Some(INBOUND_POLL_WAIT), false)
                        .await
                    {
                        Ok(Some((message, meta))) => {
                            if let Some(inbound) = to_inbound(message, &meta) {
                                return Some((inbound, (atm, profile)));
                            }
                            // Un-mappable frame: skip and keep polling.
                        }
                        // Poll window elapsed with no message — poll again.
                        Ok(None) => {}
                        Err(_) => {
                            // Transient (e.g. websocket reconnecting). Back off so we
                            // don't spin; the stream stays alive across reconnects.
                            tokio::time::sleep(INBOUND_ERROR_BACKOFF).await;
                        }
                    }
                }
            },
        ))
    }

    async fn ack(&self, ack: InboundAck) -> Result<(), MessagingError> {
        self.atm
            .delete_message_background(&self.profile, &ack.0)
            .await
            .map_err(|e| MessagingError::Transport(format!("ack (delete) failed: {e}")))
    }
}

/// Map a DIDComm plaintext message + unpack metadata to the neutral [`Inbound`]
/// the delivery layer consumes. `None` if the message can't be serialised
/// (should not happen for a valid unpacked message).
fn to_inbound(message: Message, meta: &UnpackMetadata) -> Option<Inbound> {
    let payload = message.to_json().ok()?;
    let recipient = message
        .to
        .as_ref()
        .and_then(|v| v.first())
        .cloned()
        .unwrap_or_default();
    let received = ReceivedMessage {
        id: message.id.clone(),
        sender: message.from.clone(),
        recipient,
        payload,
        protocol: Protocol::DIDComm,
        verified: meta.authenticated,
        encrypted: meta.encrypted,
    };
    Some(Inbound {
        message: received,
        thread_id: message.thid.clone(),
        ack: InboundAck(meta.sha256_hash.clone()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn to_inbound_maps_didcomm_message_and_meta() {
        let message = Message::build(
            "urn:uuid:msg-1".to_string(),
            "https://example.org/test/1.0".to_string(),
            json!({ "hello": "world" }),
        )
        .from("did:example:alice".to_string())
        .to("did:example:bob".to_string())
        .thid("urn:uuid:thread-9".to_string())
        .finalize();

        let meta = UnpackMetadata {
            authenticated: true,
            encrypted: true,
            sha256_hash: "queue-id-abc".to_string(),
            ..Default::default()
        };

        let inbound = to_inbound(message, &meta).expect("valid message maps to Inbound");

        assert_eq!(inbound.message.id, "urn:uuid:msg-1");
        assert_eq!(inbound.message.sender.as_deref(), Some("did:example:alice"));
        assert_eq!(inbound.message.recipient, "did:example:bob");
        assert_eq!(inbound.message.protocol, Protocol::DIDComm);
        assert!(inbound.message.verified, "meta.authenticated → verified");
        assert!(inbound.message.encrypted, "meta.encrypted → encrypted");
        // Thread id for demux, and the ack carries the mediator queue-id so the
        // caller can ack this exact delivery after handoff.
        assert_eq!(inbound.thread_id.as_deref(), Some("urn:uuid:thread-9"));
        assert_eq!(inbound.ack, InboundAck("queue-id-abc".to_string()));
        // Payload is the full plaintext message JSON (parseable downstream).
        assert!(!inbound.message.payload.is_empty());
    }
}
