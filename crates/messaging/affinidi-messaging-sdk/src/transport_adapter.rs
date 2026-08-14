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

use crate::errors::ATMError;
use crate::messages::Folder;
use crate::messages::compat::UnpackMetadata;
use crate::protocols::message_pickup::InboundFrame;
use crate::{ATM, profiles::ATMProfile};

/// How long each inbound `live_stream_next` poll waits for a message before
/// looping — also the reconnect-retry cadence.
const INBOUND_POLL_WAIT: Duration = Duration::from_secs(10);
/// Backoff after a transient inbound error (e.g. a websocket reconnect) so the
/// stream doesn't spin.
const INBOUND_ERROR_BACKOFF: Duration = Duration::from_millis(500);

/// Attempts (including the first) at unpacking one inbound TSP frame before it
/// is treated as undeliverable.
///
/// Deliberately small: the inbound stream is **sequential**, so every retry here
/// stalls all other inbound traffic for this profile. Matches the trust
/// registry's own TSP retry budget (`trust-registry`'s `UNPACK_MAX_ATTEMPTS`),
/// which faces the identical failure and settled on the same number.
#[cfg(feature = "tsp")]
const TSP_UNPACK_MAX_ATTEMPTS: u32 = 3;
/// Backoff before the second unpack attempt; doubles up to
/// [`TSP_UNPACK_MAX_BACKOFF`].
#[cfg(feature = "tsp")]
const TSP_UNPACK_INITIAL_BACKOFF: Duration = Duration::from_millis(200);
/// Ceiling on the unpack backoff, bounding the stall a poison frame can impose
/// on the shared inbound stream.
#[cfg(feature = "tsp")]
const TSP_UNPACK_MAX_BACKOFF: Duration = Duration::from_millis(800);

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
        //
        // The **frame** variant surfaces BOTH DIDComm and TSP frames off the one
        // socket — a mediator multiplexes both to a single DID, and a consumer
        // (e.g. the VTA) receives both. `Inbound.message.protocol` tags which, so
        // the delivery layer routes each frame to its handler; without this a
        // DIDComm-only `live_stream_next` would silently drop inbound TSP.
        Box::pin(stream::unfold(
            (atm, profile),
            |(atm, profile)| async move {
                loop {
                    match atm
                        .message_pickup()
                        .live_stream_next_frame(&profile, Some(INBOUND_POLL_WAIT), false)
                        .await
                    {
                        Ok(Some(frame)) => {
                            if let Some(inbound) = frame_to_inbound(&atm, &profile, frame).await {
                                return Some((inbound, (atm, profile)));
                            }
                            // Un-mappable / unsupported frame: skip and keep polling.
                        }
                        // Poll window elapsed with no message — poll again.
                        Ok(None) => {}
                        Err(e) if is_terminal_inbound_error(&e) => {
                            // The profile has no transport and will never grow one
                            // on its own (see `is_terminal_inbound_error`). End the
                            // stream so the consumer learns the transport is gone;
                            // backing off here instead meant an endless 2Hz poll
                            // against a torn-down profile, one warning per attempt,
                            // for the life of the process.
                            tracing::warn!(
                                profile = %profile.inner.alias,
                                error = %e,
                                "inbound stream ending: this profile has no live websocket transport",
                            );
                            return None;
                        }
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

/// Is this inbound-poll error one the stream can never recover from?
///
/// [`ATMError::ProfileError`] means the profile has no mediator at all, or its
/// `ws_channel_tx` slot is empty. That slot is only ever emptied by an explicit
/// teardown — `stop_websocket` or `cleanup_failed_websocket` — and **never** by
/// a reconnect, which happens inside the transport task and keeps the same
/// command sender. So nothing short of a fresh `profile_enable_websocket` can
/// refill it, and that installs a new transport with a new stream anyway.
///
/// Everything else (a socket reconnecting, a transient mediator fault) is
/// recoverable, and the stream must stay alive across it.
fn is_terminal_inbound_error(err: &ATMError) -> bool {
    matches!(err, ATMError::ProfileError(_))
}

/// Is this TSP unpack failure worth retrying, or is the frame poison?
///
/// Mirrors the trust registry's classification of the same failure, so the two
/// ends of a TSP hop agree on what "transient" means:
///
/// - [`ATMError::DIDError`] — resolving the sender's VID (or our own DID)
///   failed. The overwhelmingly common transient case.
/// - [`ATMError::TransportError`] / [`ATMError::Disconnected`] /
///   [`ATMError::TDKError`] — network or resolver-cache trouble underneath.
/// - Everything else — notably [`ATMError::MsgReceiveError`] (envelope parse,
///   wrong recipient, decrypt/verify failure) and [`ATMError::SecretsError`]
///   (our own key material missing) — is a deterministic property of the bytes
///   or of local configuration. Retrying identical input cannot change it.
#[cfg(feature = "tsp")]
fn is_transient_unpack_error(err: &ATMError) -> bool {
    matches!(
        err,
        ATMError::DIDError(_)
            | ATMError::TransportError(_)
            | ATMError::Disconnected(_)
            | ATMError::TDKError(_)
    )
}

/// Map an [`InboundFrame`] (DIDComm or TSP, multiplexed on the one socket) to
/// the neutral [`Inbound`]. A DIDComm frame arrives already unpacked; a TSP
/// frame is unpacked here (see [`tsp_to_inbound`]).
async fn frame_to_inbound(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    frame: InboundFrame,
) -> Option<Inbound> {
    match frame {
        InboundFrame::DidComm(message, meta) => to_inbound(*message, &meta),
        InboundFrame::Tsp(packed) => tsp_to_inbound(atm, profile, &packed).await,
    }
}

/// Map an inbound TSP frame to the neutral [`Inbound`]. `atm.tsp().unpack`
/// authenticates the sender (resolves + verifies the VID), so `sender` is the
/// cryptographically-authenticated VID and `verified` is `true`. `protocol` is
/// [`Protocol::TSP`] so the consumer routes it to its TSP handler.
#[cfg(feature = "tsp")]
async fn tsp_to_inbound(atm: &ATM, profile: &Arc<ATMProfile>, packed: &str) -> Option<Inbound> {
    // The mediator keys a stored TSP frame on `sha256(packed)` — the id the frame
    // stream would delete on ack, so it is the ack handle here too.
    let ack = digest(packed);
    // The multiplexed pickup socket (`live_stream_next_frame`) surfaces a TSP
    // frame as the **qb64** stored string — base64url of qb2, i.e. `-E…` *text* —
    // NOT raw qb2. Use `unpack`, which base64url-decodes first. Feeding
    // `packed.as_bytes()` to `unpack_bytes` (which expects raw qb2) would push the
    // ASCII `'-','E',…` bytes straight into the CESR parser and fail with "missing
    // -E envelope wrapper", so every inbound TSP frame — e.g. a trust-ping — is
    // silently skipped and never answered. Mirrors the framework listener's
    // `dispatch_tsp` (the raw-TSP `connect_websocket` path yields already-decoded
    // qb2 and correctly uses `unpack_bytes`; this DIDComm-multiplexed path does not).
    let mut backoff = TSP_UNPACK_INITIAL_BACKOFF;
    let mut attempt = 1;
    let (payload, sender) = loop {
        match atm.tsp().unpack(profile, packed).await {
            Ok(v) => break v,
            Err(e) if is_transient_unpack_error(&e) && attempt < TSP_UNPACK_MAX_ATTEMPTS => {
                // A resolver hiccup must not cost us the frame. Retry in-process
                // rather than waiting for the next redelivery — the bytes are
                // still in hand, and the stream is sequential, so the budget is
                // deliberately tight.
                tracing::warn!(
                    error = %e,
                    attempt,
                    "failed to unpack inbound TSP frame — retrying in {backoff:?}",
                );
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(TSP_UNPACK_MAX_BACKOFF);
                attempt += 1;
            }
            Err(e) => {
                // Out of attempts, or bytes that can never unpack.
                //
                // Delete the frame. This stream polls with `auto_delete = false`,
                // so the mediator still holds it, and a frame that never becomes
                // an `Inbound` never reaches the delivery layer that would ack it
                // — the ack handle computed above is the only chance anyone gets
                // to release it. Left alone it is redelivered on every reconnect
                // and every restart until the mediator's own expiry, which is how
                // a single unresolvable sender turns into a permanent boot-time
                // error on the receiving node.
                //
                // The tradeoff is deliberate and it is not free: a resolver
                // outage lasting longer than the retry budget will discard a
                // frame that would have been valid. Logged at error level, with
                // the sender the envelope claims and the frame id, so the loss is
                // auditable rather than silent.
                tracing::error!(
                    error = %e,
                    attempts = attempt,
                    frame = %ack,
                    "cannot unpack an inbound TSP frame — deleting it from the mediator so it \
                     stops being redelivered",
                );
                if let Err(delete_err) = atm.delete_message_background(profile, &ack).await {
                    tracing::warn!(
                        error = %delete_err,
                        frame = %ack,
                        "could not delete the undeliverable TSP frame — it will be redelivered",
                    );
                }
                return None;
            }
        }
    };
    let received = ReceivedMessage {
        // TSP frames carry no DIDComm message id; the frame hash is a stable id.
        id: ack.clone(),
        sender: Some(sender),
        recipient: profile.inner.did.clone(),
        payload,
        protocol: Protocol::TSP,
        verified: true,
        encrypted: true,
    };
    Some(Inbound {
        message: received,
        // TSP correlation is out of band, not the DIDComm `thid` demux.
        thread_id: None,
        ack: InboundAck(ack),
    })
}

/// Fallback when the `tsp` feature is off: an inbound TSP frame can't be
/// unpacked (no `atm.tsp()`), so it is skipped rather than dropping the whole
/// stream.
///
/// **Reachable, and reached in production.** This used to carry the note "a
/// DIDComm-only build never advertises TSP, so this is unreachable in
/// practice" — but a build does not control what its operator's DID document
/// advertises. One advertised `#tsp` against a binary compiled without the
/// feature, and because frame *classification* was gated on that same feature,
/// the frame never got here: it went to the DIDComm unpacker and surfaced as a
/// JSON parse error naming nothing relevant. Classification is unconditional
/// now (see [`crate::tsp_wire`]), so this arm runs and can say what happened.
///
/// The message names the transport, why this build cannot read it, and both
/// remedies — a rejection an operator can act on, rather than one that reads
/// like a corrupt message.
#[cfg(not(feature = "tsp"))]
async fn tsp_to_inbound(_atm: &ATM, _profile: &Arc<ATMProfile>, packed: &str) -> Option<Inbound> {
    tracing::error!(
        bytes = packed.len(),
        "received a well-formed inbound TSP frame, but this build of \
         affinidi-messaging-sdk was compiled without the `tsp` feature and cannot unpack it — \
         dropping. The frame is not corrupt; this binary simply has no TSP support. Either \
         rebuild with `--features tsp`, or stop advertising a `TSPTransport` service in this \
         DID's document so senders fall back to a transport this build serves."
    );
    None
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
    fn only_a_dead_profile_ends_the_inbound_stream() {
        // The case this exists for: `ProfileError` means the profile's websocket
        // channel slot is empty, and only an explicit teardown empties it — a
        // reconnect keeps the same sender. Retrying it is an endless 2Hz poll
        // against a transport that will never come back, one warning per attempt.
        assert!(is_terminal_inbound_error(&ATMError::ProfileError(
            "No WebSocket channel set for profile".into()
        )));

        // Everything else must keep the stream alive — a socket reconnecting is
        // precisely what the backoff path is for, and ending the stream there
        // would drop inbound traffic on every blip.
        assert!(!is_terminal_inbound_error(&ATMError::TransportError(
            "websocket reconnecting".into()
        )));
        assert!(!is_terminal_inbound_error(&ATMError::Disconnected(
            "socket closed".into()
        )));
        assert!(!is_terminal_inbound_error(&ATMError::MsgReceiveError(
            "bad frame".into()
        )));
    }

    #[cfg(feature = "tsp")]
    #[test]
    fn resolver_failures_are_retried_and_bad_bytes_are_not() {
        // A momentary resolver outage must not cost us a frame we still hold.
        assert!(is_transient_unpack_error(&ATMError::DIDError(
            "couldn't resolve TSP VID did:web:peer".into()
        )));
        assert!(is_transient_unpack_error(&ATMError::TransportError(
            "connection reset".into()
        )));
        assert!(is_transient_unpack_error(&ATMError::TDKError(
            "resolver cache miss".into()
        )));

        // Bytes that cannot decrypt or parse will never succeed however often we
        // try, and our own key material being absent is local misconfiguration.
        // Retrying either just delays the delete.
        assert!(!is_transient_unpack_error(&ATMError::MsgReceiveError(
            "couldn't unpack TSP message: bad signature".into()
        )));
        assert!(!is_transient_unpack_error(&ATMError::SecretsError(
            "no Ed25519 authentication key".into()
        )));
    }

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
