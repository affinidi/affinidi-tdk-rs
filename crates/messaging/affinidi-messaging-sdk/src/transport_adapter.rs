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
#[cfg(feature = "tsp")]
use affinidi_messaging_core::{InboundKind, RelationshipRequest};
use affinidi_messaging_didcomm::Message;
#[cfg(feature = "tsp")]
use affinidi_tsp::message::control::ControlType;
use futures_util::stream::{self, BoxStream};
use sha256::digest;
use tokio::sync::watch;

use crate::errors::ATMError;
use crate::messages::Folder;
use crate::messages::compat::UnpackMetadata;
use crate::protocols::message_pickup::InboundFrame;
#[cfg(feature = "tsp")]
use crate::protocols::tsp::InboundTsp;
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
            .map_err(|e| transport_error("didcomm forward+send failed", e))
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
            .map_err(|e| transport_error("ack (delete) failed", e))
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
            .map_err(|e| transport_error("list outbox failed", e))?;
        Ok(Some(list.into_iter().map(|m| m.msg_id).collect()))
    }
}

/// Carry an ATM failure across the [`MessageTransport`] boundary.
///
/// An HTTP status — the mediator's `429` on the send, or on the authentication
/// in front of it — becomes [`MessagingError::HttpStatus`], so the status, the
/// refusing service and `Retry-After` survive through `MessagingService` rather
/// than being flattened into text. `what` is prefixed onto its context.
/// Everything else stays [`MessagingError::Transport`], as before.
fn transport_error(what: &str, err: ATMError) -> MessagingError {
    match err.http_status() {
        Some(status) => {
            let context = format!("{what}: {}", status.context);
            MessagingError::from(status.clone().with_context(context))
        }
        None => MessagingError::Transport(format!("{what}: {err}")),
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

/// Map an inbound TSP frame to the neutral [`Inbound`]. `unpack_message`
/// authenticates the sender (resolves + verifies the VID), so `sender` is the
/// cryptographically-authenticated VID and `verified` is `true`. `protocol` is
/// [`Protocol::TSP`] so the consumer routes it to its TSP handler.
///
/// # Why `unpack_message` and not `unpack`
///
/// `unpack` returns `(payload, sender)` and **cannot say what kind of message
/// arrived**. The SDK says so itself where it refuses to return a padding
/// message through that signature: "this signature has no way to say so …
/// `unpack_message` is the API that can actually express the distinction."
///
/// Using it here meant a TSP **control** message — an invite, an accept, a
/// cancellation — was unpacked as though it were application data and its frame
/// contents handed to the consumer, which could only fail to parse them. Worse,
/// nothing ever called `record_incoming_control`, so no relationship was ever
/// recorded, so §7.2.2 discarded every application message that followed. The
/// endpoint went silent and said nothing about why, which is the exact failure
/// [`InboundKind`] documents.
///
/// So this recognises all four kinds, records control messages (framework
/// behaviour), and leaves *answering* them to the consumer (policy).
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
    // `unpack_message` takes raw qb2; the pickup socket hands us the **qb64**
    // stored string (base64url of qb2, i.e. `-E…` as text). Feeding the string
    // straight in would push the ASCII `'-','E',…` bytes into the CESR parser
    // and fail with "missing -E envelope wrapper" on every frame. `unpack` used
    // to hide this by decoding internally; doing it here is the cost of an API
    // that can name the message kind.
    //
    // Decoded once, outside the retry loop: a base64url failure is a property
    // of the bytes and will not become true on a second attempt.
    let qb2 = match atm.tsp().decode(packed) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(
                error = %e,
                frame = %ack,
                "inbound TSP frame is not valid base64url — releasing it",
            );
            release_frame(atm, profile, &ack).await;
            return None;
        }
    };

    let mut backoff = TSP_UNPACK_INITIAL_BACKOFF;
    let mut attempt = 1;
    let unpacked = loop {
        match atm.tsp().unpack_message(profile, &qb2).await {
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
    // Each kind is answered here or handed up; none may fall through to the
    // application path, which is what the old `unpack` forced on all four.
    //
    // Exhaustive with no catch-all, and it compiles because `InboundTsp` is
    // defined in *this* crate — `#[non_exhaustive]` binds other crates, not its
    // own. So a kind added later is a compile error here rather than something
    // that quietly takes the application path, which is the defect this
    // function exists to fix.
    let (payload, sender) = match unpacked {
        InboundTsp::Application { payload, sender } => (payload, sender),

        InboundTsp::Control {
            control,
            sender,
            thread_digest,
        } => {
            // Record it. This is the whole fix: recording is what admits the
            // application messages that follow, because
            // `RelationshipState::admits_application_message` is true for any
            // recorded relationship and not only a completed one (§7.2.2 with
            // §3.6). Nothing has to *accept* for traffic to flow.
            //
            // Then surface it. Recording is framework behaviour; *answering*
            // is policy, and depends on an ACL this layer cannot see.
            //
            // A refusal to record is not surfaced. It means a protocol rule
            // rejected the message — a cancellation for a relationship we do
            // not hold, or the losing side of the §7.2.3 invite race — so
            // there is no relationship for a consumer to make a decision
            // about, and handing it one to answer would invite a reply to a
            // message TSP has already discarded.
            let incoming = match atm
                .tsp()
                .record_incoming_control(profile, &sender, &control)
                .await
            {
                Ok(incoming) => {
                    tracing::debug!(
                        sender = %sender,
                        state = ?incoming.state,
                        frame = %ack,
                        "recorded an inbound TSP control message",
                    );
                    incoming
                }
                Err(e) => {
                    tracing::debug!(
                        error = %e,
                        sender = %sender,
                        frame = %ack,
                        "inbound TSP control message not recorded — a protocol rule refused it \
                         (a cancellation for a relationship we do not hold, or the losing side \
                         of the §7.2.3 invite race)",
                    );
                    release_frame(atm, profile, &ack).await;
                    return None;
                }
            };

            let request = match control.control_type {
                ControlType::RelationshipFormingInvite => RelationshipRequest::Invite,
                ControlType::RelationshipFormingAccept => RelationshipRequest::Accept,
                ControlType::RelationshipCancel => RelationshipRequest::Cancel,
            };
            // `record_incoming_control` verifies a referral's signature before
            // returning `Ok`, so reading it here cannot surface an unvouched-for
            // VID to a consumer.
            let introduces = control.referral.as_ref().map(|r| r.new_vid.clone());

            // A control message carries no user data, and §3.6's
            // user-data-alongside-an-invite is delivered by TSP as its own
            // application message. An empty payload is therefore the honest
            // representation rather than a placeholder.
            let received = ReceivedMessage {
                id: ack.clone(),
                sender: Some(sender),
                recipient: profile.inner.did.clone(),
                payload: Vec::new(),
                protocol: Protocol::TSP,
                verified: true,
                encrypted: true,
            };
            return Some(Inbound::new(received, None, InboundAck(ack)).with_kind(
                InboundKind::RelationshipControl {
                    request,
                    thread_digest,
                    reply_expected: incoming.reply_expected,
                    introduces,
                },
            ));
        }

        InboundTsp::UpperLayerControl { sender, .. } => {
            // `XCTL`: the sender marked it control for a layer above TSP. This
            // adapter serves no such layer, so it is dropped — but dropped *by
            // name*, not as unrecognised user data.
            tracing::debug!(
                sender = %sender,
                frame = %ack,
                "ignoring an upper-layer TSP control message (XCTL); this transport has no \
                 upper layer to route it to",
            );
            release_frame(atm, profile, &ack).await;
            return None;
        }

        InboundTsp::Padding { sender } => {
            // §9.4: discard silently. "Silently" is about not answering the
            // peer, not about leaving it in the mailbox — it still has to be
            // released, which is why the SDK reports padding rather than
            // swallowing it.
            tracing::trace!(sender = %sender, frame = %ack, "discarding a TSP padding message");
            release_frame(atm, profile, &ack).await;
            return None;
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
    // TSP correlation is out of band, not the DIDComm `thid` demux.
    Some(Inbound::new(received, None, InboundAck(ack)))
}

/// Release a frame the delivery layer will never ack, because it never becomes
/// an [`Inbound`].
///
/// The pickup stream polls with `auto_delete = false`, so the mediator still
/// holds anything that returns `None` above. Left alone it is redelivered on
/// every reconnect and every restart until the mediator's own expiry — which is
/// how one padding message becomes a permanent boot-time loop.
#[cfg(feature = "tsp")]
async fn release_frame(atm: &ATM, profile: &Arc<ATMProfile>, ack: &str) {
    if let Err(e) = atm.delete_message_background(profile, ack).await {
        tracing::warn!(
            error = %e,
            frame = %ack,
            "could not release a handled TSP frame — it will be redelivered",
        );
    }
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
    Some(Inbound::new(
        received,
        message.thid.clone(),
        InboundAck(meta.sha256_hash.clone()),
    ))
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

    /// A mediator 429 on the send keeps its type across the transport boundary.
    #[test]
    fn a_send_http_status_survives_as_a_typed_messaging_error() {
        use crate::errors::HttpStatusError;
        let err = transport_error(
            "didcomm forward+send failed",
            ATMError::from(HttpStatusError::from_parts(
                "send DIDComm message",
                429,
                Some("mediator"),
                Some("4"),
                "",
            )),
        );
        assert!(err.is_rate_limited(), "{err:?}");
        let status = err.http_status().unwrap();
        assert_eq!(status.rate_limit_source.as_deref(), Some("mediator"));
        assert_eq!(status.retry_after_secs, Some(4));
        assert_eq!(
            status.context,
            "didcomm forward+send failed: send DIDComm message"
        );
    }

    /// So does one from the authentication in front of the send, including
    /// after the retry loop gave up.
    #[test]
    fn an_authentication_http_status_survives_as_a_typed_messaging_error() {
        use affinidi_did_authentication::errors::DIDAuthError;
        let auth = DIDAuthError::RetriesExhausted {
            attempts: 3,
            last: Box::new(DIDAuthError::from(
                crate::errors::HttpStatusError::from_parts(
                    "authentication request",
                    429,
                    Some("mediator"),
                    Some("2"),
                    "",
                ),
            )),
        };
        let atm = ATMError::from(auth);
        assert!(matches!(atm, ATMError::DIDAuth(_)));
        assert!(atm.is_rate_limited());
        assert!(
            atm.to_string().starts_with("Authentication error: "),
            "{atm}"
        );

        let err = transport_error("didcomm forward+send failed", atm);
        assert!(err.is_rate_limited(), "{err:?}");
        assert_eq!(err.http_status().unwrap().retry_after_secs, Some(2));
    }

    #[test]
    fn other_failures_stay_transport_strings() {
        let err = transport_error(
            "ack (delete) failed",
            ATMError::TransportError("socket closed".into()),
        );
        let MessagingError::Transport(text) = &err else {
            panic!("expected Transport, got {err:?}");
        };
        assert!(text.starts_with("ack (delete) failed: "), "{text}");
        assert!(err.http_status().is_none());
    }

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
