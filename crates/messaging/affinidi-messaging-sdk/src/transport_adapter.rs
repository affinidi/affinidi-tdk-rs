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
use sha256::digest;
use tokio::sync::watch;

use crate::messages::Folder;
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

    async fn send(&self, dest: &str, packed: Vec<u8>) -> Result<SendReceipt, MessagingError> {
        let packed = String::from_utf8(packed)
            .map_err(|e| MessagingError::Transport(format!("packed message is not UTF-8: {e}")))?;
        // Deliver to `dest` by **forwarding** the packed message through the
        // recipient's mediator (a DIDComm routing/2.0 `forward` envelope). A bare
        // `send_message` only pushes bytes to our own mediator and does NOT wrap a
        // forward, so a standard mediator never routes it to the recipient — the
        // message is silently undelivered. (`send_message` "worked" for a
        // same-DID self-send, which is why this went unnoticed until a real
        // cross-DID round trip.) Fire-and-forget: the delivery layer's outbox
        // owns end-to-end confirmation, so we don't wait for a response.
        // `forward_and_send_message` is truthful — `Err` if the frame wasn't
        // written.
        let msg_id = uuid::Uuid::new_v4().to_string();
        let mediator_did = self
            .profile
            .inner
            .mediator
            .as_ref()
            .as_ref()
            .map(|m| m.did.clone())
            .ok_or_else(|| {
                MessagingError::Transport("profile has no mediator to forward through".to_string())
            })?;
        // `hop_id` correlates a later outbox-drain confirmation (§5a). It is the
        // `sha256` of the inner packed frame; the outbox-drain path must key on
        // the same value the mediator exposes in `Folder::Outbox` for a forwarded
        // message (re-validate before Guaranteed/outbox-drain relies on it).
        let hop_id = digest(packed.as_str());
        self.atm
            .forward_and_send_message(
                &self.profile,
                false,
                &packed,
                Some(&msg_id),
                &mediator_did,
                dest,
                None,
                None,
                false,
            )
            .await
            .map(|_| SendReceipt {
                via: TransportKind::Didcomm,
                hop_id: Some(hop_id),
            })
            .map_err(|e| MessagingError::Transport(format!("didcomm forward+send failed: {e}")))
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

    async fn outbox_message_ids(&self) -> Result<Option<Vec<String>>, MessagingError> {
        // The mediator holds a sent message in the sender's `Outbox` until the
        // recipient acks pickup, then deletes it; each row's `msg_id` is the
        // `sha256(packed)` this transport returns as a `SendReceipt::hop_id`. So
        // a hop-id that has drained from this list is the recipient's pickup.
        let list = self
            .atm
            .list_messages(&self.profile, Folder::Outbox)
            .await
            .map_err(|e| MessagingError::Transport(format!("list outbox failed: {e}")))?;
        Ok(Some(list.into_iter().map(|m| m.msg_id).collect()))
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
    // Anti-spoof: the plaintext `from` header is sender-controlled, so trust it
    // ONLY when it matches the DID of the key that actually authcrypted the
    // envelope. An attacker can authcrypt with their own key (so `authenticated`
    // is true) while claiming a victim's `from`; that mismatch yields NO
    // authenticated sender. So `sender` (and the `verified` flag derived from
    // it) mean "cryptographically-bound sender" — safe for a consumer to use for
    // authorization without re-deriving the check.
    let sender = authenticated_sender(&message, meta);
    let verified = sender.is_some();
    let received = ReceivedMessage {
        id: message.id.clone(),
        sender,
        recipient,
        payload,
        protocol: Protocol::DIDComm,
        verified,
        encrypted: meta.encrypted,
    };
    Some(Inbound {
        message: received,
        thread_id: message.thid.clone(),
        ack: InboundAck(meta.sha256_hash.clone()),
    })
}

/// The cryptographically-authenticated sender DID of an authcrypt message, or
/// `None` when the message is anonymous, not authenticated, or its plaintext
/// `from` does not match the key that encrypted it (a spoof attempt).
///
/// This is the binding the DIDComm authcrypt model guarantees: the sender is
/// the owner of `encrypted_from_kid`, not whoever the (unprotected) `from`
/// header names. Requiring `from == DID(encrypted_from_kid)` rejects a message
/// authcrypted by one key but claiming another party's `from`.
fn authenticated_sender(message: &Message, meta: &UnpackMetadata) -> Option<String> {
    if !meta.authenticated || meta.anonymous_sender {
        return None;
    }
    let kid = meta.encrypted_from_kid.as_deref()?;
    // The DID that owns the authcrypt key (strip the `#key` fragment).
    let key_did = kid.split_once('#').map(|(did, _)| did).unwrap_or(kid);
    match message.from.as_deref() {
        Some(from) if from == key_did => Some(from.to_string()),
        _ => None,
    }
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
            // `from` matches the authcrypt key's DID → a genuine sender.
            encrypted_from_kid: Some("did:example:alice#key-1".to_string()),
            sha256_hash: "queue-id-abc".to_string(),
            ..Default::default()
        };

        let inbound = to_inbound(message, &meta).expect("valid message maps to Inbound");

        assert_eq!(inbound.message.id, "urn:uuid:msg-1");
        assert_eq!(inbound.message.sender.as_deref(), Some("did:example:alice"));
        assert_eq!(inbound.message.recipient, "did:example:bob");
        assert_eq!(inbound.message.protocol, Protocol::DIDComm);
        assert!(
            inbound.message.verified,
            "authcrypt key DID matches `from` → verified"
        );
        assert!(inbound.message.encrypted, "meta.encrypted → encrypted");
        // Thread id for demux, and the ack carries the mediator queue-id so the
        // caller can ack this exact delivery after handoff.
        assert_eq!(inbound.thread_id.as_deref(), Some("urn:uuid:thread-9"));
        assert_eq!(inbound.ack, InboundAck("queue-id-abc".to_string()));
        // Payload is the full plaintext message JSON (parseable downstream).
        assert!(!inbound.message.payload.is_empty());
    }

    fn msg_from(from: &str) -> Message {
        Message::build(
            "m".to_string(),
            "https://example.org/t/1.0".to_string(),
            json!({}),
        )
        .from(from.to_string())
        .to("did:example:bob".to_string())
        .finalize()
    }

    #[test]
    fn spoofed_from_is_not_an_authenticated_sender() {
        // Authcrypted by mallory's key, but the plaintext `from` claims alice.
        // The mismatch must NOT yield an authenticated sender (no false trust).
        let message = msg_from("did:example:alice");
        let meta = UnpackMetadata {
            authenticated: true,
            encrypted: true,
            encrypted_from_kid: Some("did:example:mallory#key-1".to_string()),
            sha256_hash: "q".to_string(),
            ..Default::default()
        };
        let inbound = to_inbound(message, &meta).unwrap();
        assert_eq!(inbound.message.sender, None, "spoofed from → no sender");
        assert!(!inbound.message.verified, "spoofed from → not verified");
    }

    #[test]
    fn anonymous_and_unauthenticated_have_no_sender() {
        let message = msg_from("did:example:alice");
        // Anonymous (anoncrypt): authenticated=false / anonymous_sender=true.
        let anon = UnpackMetadata {
            authenticated: false,
            encrypted: true,
            anonymous_sender: true,
            encrypted_from_kid: None,
            sha256_hash: "q".to_string(),
            ..Default::default()
        };
        let inbound = to_inbound(message, &anon).unwrap();
        assert_eq!(inbound.message.sender, None);
        assert!(!inbound.message.verified);
    }
}
