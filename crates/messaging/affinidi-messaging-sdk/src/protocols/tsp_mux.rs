//! DID multiplexing on a **raw-TSP** socket: the `tsp-mux` WebSocket
//! subprotocol (`messaging/mux/event/0.1`, "Raw-TSP sockets").
//!
//! One raw-TSP socket, authenticated as the profile (the *principal*),
//! carries live delivery for every member DID that granted the principal
//! `receive` (or was attached to this connection). Open it with
//! [`TspOps::connect_websocket_mux`](super::tsp::TspOps::connect_websocket_mux).
//!
//! What arrives on it is demultiplexed here, by one owner (R1.7):
//!
//! - **Mux events.** A TSP Direct message from the mediator's VID to the
//!   principal's whose payload is a `messaging/mux/event` document. Opened
//!   with the principal's keys, checked (the TSP sender and the document's
//!   `issuer` are the profile's mediator, its `recipient` is the principal)
//!   and handed over typed, as [`TspMuxFrame::Event`].
//! - **Data frames.** Everything else. Its cleartext receiver VID names the
//!   member (or the principal) it is for: it is handed over **unopened**, as
//!   [`TspMuxFrame::Data`], so the application opens it with that member's
//!   keys ([`TspOps::unpack_bytes`](super::tsp::TspOps::unpack_bytes) with the
//!   member's profile).
//!
//! `tsp-mux` implies `tsp-ack`: the mediator keeps each delivered frame until
//! it is acknowledged ([`TspMuxWebSocket::ack`]). Acks are authorised against
//! each member's `delete` scope, so an ack can be refused for one member and
//! succeed for another; [`TspMuxAck`] reports each frame's outcome.
//!
//! Nothing reconnects here. A dropped socket ends [`TspMuxWebSocket::recv`]
//! (with the mediator's close reason when it gave one), and the caller decides
//! what to do (R6.2). On a new connection the member set is rebuilt from that
//! connection's `ready` and `attached` events; nothing carries over.

use std::sync::Arc;
use std::time::Duration;

use affinidi_tsp::MetaEnvelope;
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use serde_json::Value;
use tracing::{debug, warn};
use trust_tasks_rs::TrustTask;

use super::mux::{EVENT_TYPE, MuxEvent, MuxEventKind, MuxReady, event_is_well_formed};
use super::tsp::{TspOps, TspWsStream};
use crate::ATM;
use crate::errors::ATMError;
use crate::messages::DeleteMessageRequest;
use crate::profiles::ATMProfile;

/// The WebSocket subprotocol that asks for a mux connection on a raw-TSP
/// socket. Offered after `tsp` and `tsp-ack`, in that order.
pub const TSP_MUX_SUBPROTOCOL: &str = "tsp-mux";

/// The client's offer, in the order the spec requires: an older mediator
/// reflects the list and so selects `tsp`, which this client reads as "mux
/// unavailable".
const MUX_OFFER: [&str; 3] = ["tsp", "tsp-ack", TSP_MUX_SUBPROTOCOL];

/// How long to wait for the `ready` event after the upgrade. The mediator
/// admits the principal's stored grants (a DID resolution each) before it
/// sends `ready`, so this is generous.
pub const MUX_READY_TIMEOUT: Duration = Duration::from_secs(30);

/// The mediator deletes at most this many ids per request.
const MAX_ACK_BATCH: usize = 100;

/// Lowercase hex SHA-256 of a frame's exact bytes: the `frameId` a `refused`
/// event names. [`TspMuxWebSocket::send`] returns it for each frame sent.
pub fn frame_id(qb2: &[u8]) -> String {
    sha256::digest(qb2)
}

/// The mediator's message id for a delivered frame: SHA-256 of the stored
/// body, which for a TSP message is `base64url(qb2)`. What
/// [`TspMuxWebSocket::ack`] deletes, and what [`TspMuxAck`] reports by.
pub fn message_id(qb2: &[u8]) -> String {
    sha256::digest(BASE64_URL_SAFE_NO_PAD.encode(qb2))
}

/// One frame received on a `tsp-mux` socket.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum TspMuxFrame {
    /// A `messaging/mux/event` from the mediator (`attached`, `detached`,
    /// `refused`; the first `ready` is consumed by the handshake and kept in
    /// [`TspMuxWebSocket::ready`]). Events are live only: never stored, so
    /// never acknowledged. Use [`MuxRefused::from_event`] for a `refused`
    /// one and [`MuxEvent::dids`] for `attached` / `detached`.
    ///
    /// [`MuxRefused::from_event`]: super::mux::MuxRefused::from_event
    Event(Box<MuxEvent>),
    /// A delivered TSP message, unopened.
    Data {
        /// The VID the frame is addressed to, from its cleartext envelope: a
        /// member DID, or the principal. Open the frame with that DID's keys.
        receiver: String,
        /// The sender VID from the cleartext envelope. **Not authenticated**
        /// until the frame is opened.
        sender: String,
        /// The raw qb2 frame, exactly as received; pass it to
        /// [`TspMuxWebSocket::ack`] once handled.
        frame: Vec<u8>,
    },
    /// A binary frame that is not a parseable TSP envelope, so it names no
    /// receiver. Handed over rather than dropped; the mediator holds it until
    /// it is acknowledged like any other.
    Unreadable {
        /// The raw frame.
        frame: Vec<u8>,
        /// Why its envelope did not parse.
        error: String,
    },
}

/// The outcome of [`TspMuxWebSocket::ack`], frame by frame, as the mediator
/// reported it. A frame is listed as acked only if the mediator said it
/// deleted it (R1.1).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct TspMuxAck {
    /// Message ids ([`message_id`]) the mediator deleted.
    pub acked: Vec<String>,
    /// Message ids it did not delete, with its reason. A member without the
    /// `delete` scope lands here: its frames stay in its inbox and are
    /// delivered again on the next connection.
    pub refused: Vec<(String, String)>,
}

impl TspMuxAck {
    /// Whether every frame was acknowledged.
    pub fn is_complete(&self) -> bool {
        self.refused.is_empty()
    }

    /// Fold the mediator's answer for `requested` into the result. An id the
    /// answer does not mention, or names as both deleted and failed, counts
    /// as not acknowledged.
    fn settle(&mut self, requested: &[String], success: &[String], errors: &[(String, String)]) {
        for id in requested {
            let failed = errors.iter().find(|(e, _)| e == id);
            match (success.contains(id), failed) {
                (true, None) => self.acked.push(id.clone()),
                (_, Some((_, reason))) => self.refused.push((id.clone(), reason.clone())),
                (false, None) => self.refused.push((
                    id.clone(),
                    "the mediator did not report this id as deleted".to_string(),
                )),
            }
        }
    }
}

/// Acknowledges frames of one `tsp-mux` socket. Cloneable, so one task can
/// ack while another reads ([`TspMuxWebSocket::acker`]). Acks go over REST,
/// authenticated as the socket's own session: the mediator authorises a
/// member's deletes against the members of that session.
#[derive(Clone)]
pub struct TspMuxAcker {
    atm: ATM,
    rest_endpoint: String,
    access_token: String,
}

impl std::fmt::Debug for TspMuxAcker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TspMuxAcker")
            .field("rest_endpoint", &self.rest_endpoint)
            .finish_non_exhaustive()
    }
}

impl TspMuxAcker {
    /// Acknowledge (delete) delivered frames. See [`TspMuxWebSocket::ack`].
    pub async fn ack(&self, frames: &[&[u8]]) -> Result<TspMuxAck, ATMError> {
        let ids: Vec<String> = frames.iter().map(|f| message_id(f)).collect();
        self.ack_ids(&ids).await
    }

    /// Acknowledge by message id ([`message_id`]).
    pub async fn ack_ids(&self, ids: &[String]) -> Result<TspMuxAck, ATMError> {
        let mut out = TspMuxAck::default();
        for chunk in ids.chunks(MAX_ACK_BATCH) {
            let request = DeleteMessageRequest {
                message_ids: chunk.to_vec(),
            };
            match self
                .atm
                .delete_messages_with_token(&self.rest_endpoint, &self.access_token, &request)
                .await
            {
                Ok(r) => out.settle(chunk, &r.success, &r.errors),
                // An earlier batch may have gone through; report it rather
                // than lose it, and the rest as not acknowledged.
                Err(e) if !out.acked.is_empty() || !out.refused.is_empty() => {
                    let reason = format!("ack request failed: {e}");
                    let done = out.acked.len() + out.refused.len();
                    out.refused
                        .extend(ids[done..].iter().map(|id| (id.clone(), reason.clone())));
                    return Ok(out);
                }
                Err(e) => return Err(e),
            }
        }
        Ok(out)
    }
}

/// Opens a frame the mediator sealed to the principal: `(payload, sender)`,
/// verified and decrypted. A seam, so the demultiplexer is testable without
/// a resolver.
#[async_trait::async_trait]
pub(crate) trait EventOpener: Send + Sync {
    async fn open(&self, qb2: &[u8]) -> Result<(Vec<u8>, String), ATMError>;
}

/// The SDK's opener: the principal's keys from the secrets resolver, the
/// mediator's from its DID. The relationship gate is not applied: a mux event
/// is transport control from the mediator this socket authenticated to, not
/// an application message from a peer.
struct AtmOpener {
    atm: ATM,
    principal: String,
}

#[async_trait::async_trait]
impl EventOpener for AtmOpener {
    async fn open(&self, qb2: &[u8]) -> Result<(Vec<u8>, String), ATMError> {
        let meta = MetaEnvelope::parse(qb2)
            .map_err(|e| ATMError::MsgReceiveError(format!("couldn't parse TSP envelope: {e}")))?;
        let unpacked = self
            .atm
            .tsp()
            .unpack_with_fresh_key_state(&self.principal, &meta.sender, qb2)
            .await?;
        if unpacked.message_type != affinidi_tsp::MessageType::Direct || unpacked.control.is_some()
        {
            return Err(ATMError::MsgReceiveError(
                "not a TSP Direct message".to_string(),
            ));
        }
        Ok((unpacked.payload, unpacked.sender))
    }
}

/// The single demultiplexer of one socket (R1.7).
pub(crate) struct Demux {
    pub(crate) principal: String,
    pub(crate) mediator: String,
    pub(crate) opener: Arc<dyn EventOpener>,
}

impl Demux {
    /// Sort one binary frame into an event or a data frame. Returns `None`
    /// for an event that must be ignored (malformed, or not addressed to this
    /// principal by this mediator; spec consumer rule 1 and "Members per
    /// kind").
    pub(crate) async fn classify(&self, frame: Vec<u8>) -> Option<TspMuxFrame> {
        let meta = match MetaEnvelope::parse(&frame) {
            Ok(m) => m,
            Err(e) => {
                return Some(TspMuxFrame::Unreadable {
                    frame,
                    error: e.to_string(),
                });
            }
        };
        if meta.receiver == self.principal && meta.sender == self.mediator {
            match self.opener.open(&frame).await {
                Ok((payload, sender)) => match self.event(&payload, &sender) {
                    EventCheck::Event(e) => return Some(TspMuxFrame::Event(e)),
                    EventCheck::Ignore => return None,
                    EventCheck::NotAnEvent => {}
                },
                Err(e) => {
                    // Something from the mediator we cannot open (a stale
                    // key, a control message): not an event we can trust, but
                    // still a stored frame, so it goes to the caller.
                    debug!(error = %e, "a frame from the mediator did not open as a mux event");
                }
            }
        }
        Some(TspMuxFrame::Data {
            receiver: meta.receiver,
            sender: meta.sender,
            frame,
        })
    }

    fn event(&self, payload: &[u8], sender: &str) -> EventCheck {
        let Ok(doc) = serde_json::from_slice::<Value>(payload) else {
            return EventCheck::NotAnEvent;
        };
        if doc.get("type").and_then(Value::as_str) != Some(EVENT_TYPE) {
            return EventCheck::NotAnEvent;
        }
        if sender != self.mediator
            || doc.get("issuer").and_then(Value::as_str) != Some(self.mediator.as_str())
        {
            warn!(
                sender,
                "ignoring a mux event not issued by this profile's mediator"
            );
            return EventCheck::Ignore;
        }
        if doc.get("recipient").and_then(Value::as_str) != Some(self.principal.as_str()) {
            warn!("ignoring a mux event addressed to someone else");
            return EventCheck::Ignore;
        }
        match serde_json::from_value::<TrustTask<MuxEvent>>(doc) {
            Ok(task) if event_is_well_formed(&task.payload) => {
                EventCheck::Event(Box::new(task.payload))
            }
            Ok(task) => {
                warn!(event = %task.payload.event, "ignoring a malformed mux event");
                EventCheck::Ignore
            }
            Err(e) => {
                warn!(error = %e, "ignoring a mux event that does not parse");
                EventCheck::Ignore
            }
        }
    }
}

enum EventCheck {
    Event(Box<MuxEvent>),
    Ignore,
    NotAnEvent,
}

/// The next frame off the socket that matters: a binary frame, or the end.
/// `Ok(None)` when the stream ended without a close frame; `Err` on a close
/// frame (with the mediator's reason) or a transport error.
async fn next_binary(ws: &mut TspWsStream) -> Result<Option<Vec<u8>>, ATMError> {
    use futures_util::StreamExt;
    use tokio_tungstenite::tungstenite::Message;
    loop {
        match ws.next().await {
            Some(Ok(Message::Binary(bytes))) => return Ok(Some(bytes.to_vec())),
            Some(Ok(Message::Close(frame))) => {
                return Err(ATMError::TransportError(match frame {
                    Some(frame) if !frame.reason.is_empty() => format!(
                        "tsp-mux websocket closed by the mediator: {} ({})",
                        frame.reason, frame.code
                    ),
                    Some(frame) => {
                        format!(
                            "tsp-mux websocket closed by the mediator: code {}",
                            frame.code
                        )
                    }
                    None => "tsp-mux websocket closed by the mediator (no reason given)".into(),
                }));
            }
            None => return Ok(None),
            Some(Ok(_)) => continue,
            Some(Err(e)) => {
                return Err(ATMError::TransportError(format!(
                    "tsp-mux websocket receive error: {e}"
                )));
            }
        }
    }
}

/// Whether the mediator's selection makes this a mux socket. Only `tsp-mux`
/// does; `tsp` or `tsp-ack` means the mediator will not multiplex (older, or
/// mux disabled), and there is no silent fallback to a plain socket.
pub(crate) fn check_selection(selected: Option<&str>) -> Result<(), ATMError> {
    match selected {
        Some(TSP_MUX_SUBPROTOCOL) => Ok(()),
        other => Err(ATMError::ConfigError(format!(
            "the mediator did not accept a DID-multiplexing raw-TSP connection: it selected \
             {other:?}, not `{TSP_MUX_SUBPROTOCOL}` (mux unavailable or disabled)"
        ))),
    }
}

/// Selection proves nothing on its own (an older mediator may echo tokens):
/// the connection is a mux connection once its first frame is a valid `ready`
/// event from the mediator. Anything else first, or nothing in time, fails.
pub(crate) async fn await_ready(
    ws: &mut TspWsStream,
    demux: &Demux,
    wait: Duration,
) -> Result<MuxReady, ATMError> {
    let first = match tokio::time::timeout(wait, next_binary(ws)).await {
        Err(_) => {
            return Err(ATMError::TransportError(format!(
                "tsp-mux: no `ready` event from the mediator within {wait:?}"
            )));
        }
        Ok(Ok(Some(frame))) => frame,
        Ok(Ok(None)) => {
            return Err(ATMError::TransportError(
                "tsp-mux: the socket ended before the mediator sent `ready`".into(),
            ));
        }
        Ok(Err(e)) => return Err(e),
    };
    match demux.classify(first).await {
        Some(TspMuxFrame::Event(event)) if event.event == MuxEventKind::Ready => {
            MuxReady::from_event(&event).ok_or_else(|| {
                ATMError::TransportError("tsp-mux: the `ready` event is malformed".into())
            })
        }
        _ => Err(ATMError::TransportError(
            "tsp-mux: the mediator's first frame was not a `ready` event; not a mux connection"
                .into(),
        )),
    }
}

/// An open `tsp-mux` socket. See the [module docs](self).
pub struct TspMuxWebSocket {
    ws: TspWsStream,
    demux: Demux,
    ready: MuxReady,
    acker: TspMuxAcker,
}

impl std::fmt::Debug for TspMuxWebSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TspMuxWebSocket")
            .field("principal", &self.demux.principal)
            .field("mediator", &self.demux.mediator)
            .field("ready", &self.ready)
            .finish_non_exhaustive()
    }
}

impl TspMuxWebSocket {
    /// This connection's `ready` event: its session id and mux nonce (for
    /// [`sign_attach`](super::mux::sign_attach)), its limits and how many
    /// durable notices wait in the principal's inbox. It belongs to this
    /// connection alone.
    pub fn ready(&self) -> &MuxReady {
        &self.ready
    }

    /// The principal: the DID this socket is authenticated as.
    pub fn principal(&self) -> &str {
        &self.demux.principal
    }

    /// Receive the next frame: a mux event or a data frame (see
    /// [`TspMuxFrame`]). Pings and text frames are skipped, as are events the
    /// spec says to ignore (malformed, or not from this mediator to this
    /// principal).
    ///
    /// When the socket goes away it is finished, and the caller is told:
    /// `Err` with the mediator's close code and reason when it sent a close
    /// frame, `Ok(None)` when the stream ended without one. Nothing
    /// reconnects; the members are not reachable through this socket any
    /// more, and frames not acknowledged are delivered again on the next
    /// connection.
    pub async fn recv(&mut self) -> Result<Option<TspMuxFrame>, ATMError> {
        loop {
            let Some(frame) = next_binary(&mut self.ws).await? else {
                return Ok(None);
            };
            if let Some(frame) = self.demux.classify(frame).await {
                return Ok(Some(frame));
            }
        }
    }

    /// Send a raw qb2 TSP frame, as the principal or as a member that granted
    /// `send`. Returns its [`frame_id`]: a `refused` event naming that id
    /// means the mediator refused it (the socket stays open). Without one the
    /// mediator accepted it; `Ok` here means only that it was written.
    pub async fn send(&mut self, frame: &[u8]) -> Result<String, ATMError> {
        use futures_util::SinkExt;
        use tokio_tungstenite::tungstenite::Message;
        self.ws
            .send(Message::Binary(frame.to_vec().into()))
            .await
            .map_err(|e| ATMError::TransportError(format!("tsp-mux websocket send error: {e}")))?;
        Ok(frame_id(frame))
    }

    /// Acknowledge delivered frames (`Data` / `Unreadable`), releasing the
    /// mediator's copies. Call once each is safely handled. Returns the
    /// mediator's answer per frame: acks for a member without `delete` scope
    /// are refused, and those frames stay in its inbox. `Err` when the
    /// request itself failed (nothing is known to be acknowledged).
    pub async fn ack(&self, frames: &[&[u8]]) -> Result<TspMuxAck, ATMError> {
        self.acker.ack(frames).await
    }

    /// A handle that acknowledges frames of this socket from another task.
    pub fn acker(&self) -> TspMuxAcker {
        self.acker.clone()
    }

    /// Close the socket gracefully.
    pub async fn close(mut self) -> Result<(), ATMError> {
        self.ws
            .close(None)
            .await
            .map_err(|e| ATMError::TransportError(format!("tsp-mux websocket close error: {e}")))
    }
}

impl TspOps<'_> {
    /// Open the mediator's raw-TSP WebSocket as a **DID-multiplexing**
    /// connection (`tsp-mux`): the profile is the principal, and the socket
    /// also carries live delivery for every member DID that granted it
    /// `receive` (stored grants are admitted on connect).
    ///
    /// Offers `tsp`, `tsp-ack`, `tsp-mux` in that order and succeeds only if
    /// the mediator selected `tsp-mux` **and** its first frame is a valid
    /// `ready` event. A mediator that selects `tsp` or `tsp-ack` does not
    /// multiplex, and this fails; there is no silent fallback (use
    /// [`connect_websocket_acked`](TspOps::connect_websocket_acked) for a
    /// plain socket).
    ///
    /// Delivery is delete-to-ack (`tsp-mux` implies `tsp-ack`); see
    /// [`TspMuxWebSocket::ack`]. Members' frames arrive unopened, tagged with
    /// their receiver; the member's keys are needed to open them.
    pub async fn connect_websocket_mux(
        &self,
        profile: &Arc<ATMProfile>,
    ) -> Result<TspMuxWebSocket, ATMError> {
        let (principal, mediator) = profile.dids()?;
        let (principal, mediator) = (principal.to_string(), mediator.to_string());
        let Some(rest_endpoint) = profile.get_mediator_rest_endpoint() else {
            return Err(ATMError::ConfigError(format!(
                "Profile ({}) has no mediator REST endpoint, which tsp-mux acks need",
                profile.inner.alias
            )));
        };
        let raw = self.open_raw_socket(profile, &MUX_OFFER).await?;
        let mut ws = raw.ws;
        if let Err(e) = check_selection(raw.selected.as_deref()) {
            let _ = ws.close(None).await;
            return Err(e);
        }
        let demux = Demux {
            principal: principal.clone(),
            mediator,
            opener: Arc::new(AtmOpener {
                atm: self.atm.clone(),
                principal,
            }),
        };
        let ready = match await_ready(&mut ws, &demux, MUX_READY_TIMEOUT).await {
            Ok(r) => r,
            Err(e) => {
                let _ = ws.close(None).await;
                return Err(e);
            }
        };
        Ok(TspMuxWebSocket {
            ws,
            demux,
            ready,
            acker: TspMuxAcker {
                atm: self.atm.clone(),
                rest_endpoint,
                access_token: raw.access_token,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_tsp::PrivateVid;
    use affinidi_tsp::message::direct;
    use futures_util::SinkExt;
    use serde_json::json;
    use tokio::net::TcpListener;
    use tokio_tungstenite::tungstenite::{
        Message,
        handshake::server::{Request, Response},
        http::HeaderValue,
    };

    const MEDIATOR: &str = "did:example:mediator";
    const PRINCIPAL: &str = "did:example:phone";
    const WORK: &str = "did:example:work";
    const NONCE: &str = "Zk3xQ0b9Rw7mT2pN4vYc8LsH1eJ6aUdG5oWiKfB0nXq";

    struct Keys {
        mediator: PrivateVid,
        principal: PrivateVid,
        work: PrivateVid,
        sender: PrivateVid,
    }

    fn keys() -> Keys {
        Keys {
            mediator: PrivateVid::generate(MEDIATOR),
            principal: PrivateVid::generate(PRINCIPAL),
            work: PrivateVid::generate(WORK),
            sender: PrivateVid::generate("did:example:sender"),
        }
    }

    /// Opens with the principal's key, trusting the sender's key it knows of.
    struct TestOpener {
        principal_decryption: [u8; 32],
        known: Vec<(String, [u8; 32])>,
    }

    #[async_trait::async_trait]
    impl EventOpener for TestOpener {
        async fn open(&self, qb2: &[u8]) -> Result<(Vec<u8>, String), ATMError> {
            let meta = MetaEnvelope::parse(qb2).unwrap();
            let (_, vk) = self
                .known
                .iter()
                .find(|(d, _)| *d == meta.sender)
                .ok_or_else(|| ATMError::MsgReceiveError("unknown sender".into()))?;
            let u = direct::unpack(qb2, &self.principal_decryption, vk)
                .map_err(|e| ATMError::MsgReceiveError(e.to_string()))?;
            Ok((u.payload, u.sender))
        }
    }

    fn demux(k: &Keys) -> Demux {
        Demux {
            principal: PRINCIPAL.into(),
            mediator: MEDIATOR.into(),
            opener: Arc::new(TestOpener {
                principal_decryption: k.principal.decryption_key,
                known: vec![
                    (MEDIATOR.into(), k.mediator.verifying_key),
                    ("did:example:sender".into(), k.sender.verifying_key),
                ],
            }),
        }
    }

    fn seal(from: &PrivateVid, to: &PrivateVid, payload: &[u8]) -> Vec<u8> {
        direct::pack(
            payload,
            affinidi_tsp::MessageType::Direct,
            &from.id,
            &to.id,
            &from.signing_key,
            &to.encryption_key,
        )
        .unwrap()
        .bytes
    }

    fn event_doc(issuer: &str, recipient: &str, payload: Value) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "id": "urn:uuid:3a4b5c6d-7e8f-4a9b-8c0d-1e2f3a4b5c01",
            "type": EVENT_TYPE,
            "issuer": issuer,
            "recipient": recipient,
            "issuedAt": "2026-11-09T09:00:01Z",
            "payload": payload,
        }))
        .unwrap()
    }

    fn ready_payload() -> Value {
        json!({
            "event": "ready", "sessionId": "ses_7Hq2xV9mK3pL", "muxNonce": NONCE,
            "maxDidsPerConnection": 1000, "maxGrantLifetimeSeconds": 2592000,
            "pendingNotices": 1,
        })
    }

    fn ready_frame(k: &Keys) -> Vec<u8> {
        seal(
            &k.mediator,
            &k.principal,
            &event_doc(MEDIATOR, PRINCIPAL, ready_payload()),
        )
    }

    /// A one-shot mediator: selects `selected` and writes `frames`, then
    /// holds the socket open until the client goes.
    async fn serve(selected: Option<&'static str>, frames: Vec<Message>) -> TspWsStream {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            // The handshake callback's error type is tungstenite's, not ours.
            #[allow(clippy::result_large_err)]
            let callback = |req: &Request, mut resp: Response| {
                let offered = req
                    .headers()
                    .get("sec-websocket-protocol")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or_default()
                    .to_string();
                assert!(
                    offered.ends_with("tsp, tsp-ack, tsp-mux"),
                    "offer order: {offered}"
                );
                if let Some(p) = selected {
                    resp.headers_mut()
                        .insert("sec-websocket-protocol", HeaderValue::from_static(p));
                }
                Ok(resp)
            };
            let mut ws = tokio_tungstenite::accept_hdr_async(tcp, callback)
                .await
                .unwrap();
            for f in frames {
                ws.send(f).await.unwrap();
            }
            use futures_util::StreamExt;
            while ws.next().await.is_some() {}
        });
        let mut req = tokio_tungstenite::tungstenite::ClientRequestBuilder::new(
            format!("ws://{addr}/ws").parse().unwrap(),
        )
        .with_sub_protocol("bearer.t");
        for p in MUX_OFFER {
            req = req.with_sub_protocol(p);
        }
        let (ws, resp) = tokio_tungstenite::connect_async(req).await.unwrap();
        let got = resp
            .headers()
            .get("sec-websocket-protocol")
            .and_then(|v| v.to_str().ok());
        assert_eq!(got, selected);
        ws
    }

    /// The handshake as `connect_websocket_mux` runs it after the upgrade.
    async fn handshake(
        selected: Option<&'static str>,
        frames: Vec<Message>,
        k: &Keys,
    ) -> Result<MuxReady, ATMError> {
        let mut ws = serve(selected, frames).await;
        check_selection(selected)?;
        await_ready(&mut ws, &demux(k), Duration::from_millis(500)).await
    }

    #[tokio::test]
    async fn selected_tsp_mux_and_a_ready_event_is_a_mux_connection() {
        let k = keys();
        let ready = handshake(
            Some("tsp-mux"),
            vec![
                Message::Ping(vec![].into()),
                Message::Binary(ready_frame(&k).into()),
            ],
            &k,
        )
        .await
        .expect("a mux connection");
        assert_eq!(ready.session_id, "ses_7Hq2xV9mK3pL");
        assert_eq!(ready.mux_nonce, NONCE);
        assert_eq!(ready.max_dids_per_connection, Some(1000));
        assert_eq!(ready.pending_notices, Some(1));
    }

    #[tokio::test]
    async fn a_selected_tsp_or_tsp_ack_is_mux_unavailable() {
        let k = keys();
        for selected in ["tsp", "tsp-ack"] {
            // Even with a `ready`-looking frame behind it: selection decides.
            let err = handshake(
                Some(selected),
                vec![Message::Binary(ready_frame(&k).into())],
                &k,
            )
            .await
            .unwrap_err();
            assert!(
                matches!(err, ATMError::ConfigError(ref m) if m.contains("mux unavailable")),
                "{selected}: {err}"
            );
        }
    }

    #[tokio::test]
    async fn no_ready_is_not_a_mux_connection() {
        let k = keys();
        // Nothing at all.
        let err = handshake(Some("tsp-mux"), vec![], &k).await.unwrap_err();
        assert!(err.to_string().contains("no `ready`"), "{err}");

        // A data frame first: a mediator echoing tokens it does not implement.
        let data = seal(&k.sender, &k.principal, b"hello");
        let err = handshake(Some("tsp-mux"), vec![Message::Binary(data.into())], &k)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not a `ready`"), "{err}");

        // An `attached` event first.
        let attached = seal(
            &k.mediator,
            &k.principal,
            &event_doc(
                MEDIATOR,
                PRINCIPAL,
                json!({"event": "attached", "dids": [{"did": WORK, "reason": "connect",
                       "scope": ["receive"], "deliveryActive": true}]}),
            ),
        );
        assert!(
            handshake(Some("tsp-mux"), vec![Message::Binary(attached.into())], &k)
                .await
                .is_err()
        );

        // The socket closed before `ready`, with the mediator's reason.
        let err = handshake(
            Some("tsp-mux"),
            vec![Message::Close(Some(
                tokio_tungstenite::tungstenite::protocol::CloseFrame {
                    code: 1011.into(),
                    reason: "mux connection could not be established".into(),
                },
            ))],
            &k,
        )
        .await
        .unwrap_err();
        assert!(
            err.to_string().contains("could not be established"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn events_and_data_frames_are_demultiplexed() {
        let k = keys();
        let d = demux(&k);

        // A mux event: typed, with its reason.
        let detached = seal(
            &k.mediator,
            &k.principal,
            &event_doc(
                MEDIATOR,
                PRINCIPAL,
                json!({"event": "detached", "dids": [{"did": WORK, "reason": "connectionFull"}]}),
            ),
        );
        match d.classify(detached).await {
            Some(TspMuxFrame::Event(e)) => {
                assert_eq!(e.event, MuxEventKind::Detached);
                assert_eq!(
                    e.dids[0].reason,
                    super::super::mux::MemberChangeReason::ConnectionFull
                );
            }
            other => panic!("expected an event, got {other:?}"),
        }

        // A member's frame: unopened, tagged with its receiver.
        let for_work = seal(&k.sender, &k.work, b"for work");
        match d.classify(for_work.clone()).await {
            Some(TspMuxFrame::Data {
                receiver,
                sender,
                frame,
            }) => {
                assert_eq!(receiver, WORK);
                assert_eq!(sender, "did:example:sender");
                assert_eq!(frame, for_work, "handed over exactly as received");
            }
            other => panic!("expected data, got {other:?}"),
        }

        // A frame for the principal from someone else is data too.
        let for_me = seal(&k.sender, &k.principal, b"for the principal");
        assert!(matches!(
            d.classify(for_me).await,
            Some(TspMuxFrame::Data { receiver, .. }) if receiver == PRINCIPAL
        ));

        // From the mediator but not a mux event (say, a Trust Task response):
        // data, unopened.
        let other_doc = seal(
            &k.mediator,
            &k.principal,
            &serde_json::to_vec(
                &json!({"type": "https://trusttasks.org/spec/messaging/ping/0.2#response"}),
            )
            .unwrap(),
        );
        assert!(matches!(
            d.classify(other_doc.clone()).await,
            Some(TspMuxFrame::Data { frame, .. }) if frame == other_doc
        ));

        // Not TSP at all: handed over, never dropped.
        assert!(matches!(
            d.classify(b"not tsp".to_vec()).await,
            Some(TspMuxFrame::Unreadable { .. })
        ));
    }

    #[tokio::test]
    async fn events_not_from_this_mediator_to_this_principal_are_ignored() {
        let k = keys();
        let d = demux(&k);
        // `issuer` is not the mediator.
        let wrong_issuer = seal(
            &k.mediator,
            &k.principal,
            &event_doc("did:example:other", PRINCIPAL, ready_payload()),
        );
        assert!(d.classify(wrong_issuer).await.is_none());
        // `recipient` is not the principal (consumer rule 1).
        let wrong_recipient = seal(
            &k.mediator,
            &k.principal,
            &event_doc(MEDIATOR, WORK, ready_payload()),
        );
        assert!(d.classify(wrong_recipient).await.is_none());
        // Malformed for its kind: `refused` without `code`.
        let malformed = seal(
            &k.mediator,
            &k.principal,
            &event_doc(
                MEDIATOR,
                PRINCIPAL,
                json!({"event": "refused", "frameId": "0".repeat(64)}),
            ),
        );
        assert!(d.classify(malformed).await.is_none());
        // An event document sent by someone other than the mediator is not
        // opened as one: it is data for the caller.
        let forged = seal(
            &k.sender,
            &k.principal,
            &event_doc(MEDIATOR, PRINCIPAL, ready_payload()),
        );
        assert!(matches!(
            d.classify(forged).await,
            Some(TspMuxFrame::Data { .. })
        ));
    }

    #[tokio::test]
    async fn a_refused_event_is_typed() {
        let k = keys();
        let d = demux(&k);
        let bad = seal(&k.sender, &k.work, b"refused");
        let id = frame_id(&bad);
        assert_eq!(id.len(), 64);
        assert!(
            id.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        );
        let refused = seal(
            &k.mediator,
            &k.principal,
            &event_doc(
                MEDIATOR,
                PRINCIPAL,
                json!({"event": "refused", "frameId": id, "code": "authorization.acl.denied",
                       "sender": "did:example:sender", "receiver": WORK,
                       "reason": "not admitted"}),
            ),
        );
        let Some(TspMuxFrame::Event(e)) = d.classify(refused).await else {
            panic!("expected an event");
        };
        let r = super::super::mux::MuxRefused::from_event(&e).expect("a refusal");
        assert_eq!(r.frame_id, frame_id(&bad));
        assert_eq!(r.code, "authorization.acl.denied");
        assert_eq!(r.sender.as_deref(), Some("did:example:sender"));
        assert_eq!(r.receiver.as_deref(), Some(WORK));
        assert_eq!(r.reason.as_deref(), Some("not admitted"));
        assert!(MuxReady::from_event(&e).is_none());
    }

    #[test]
    fn ack_results_follow_the_mediator_frame_by_frame() {
        let ids: Vec<String> = ["a", "b", "c", "d"].iter().map(|s| s.to_string()).collect();
        let mut ack = TspMuxAck::default();
        ack.settle(
            &ids,
            &["a".into(), "d".into()],
            &[
                ("b".into(), "no delete scope".into()),
                ("d".into(), "conflict".into()),
            ],
        );
        assert_eq!(ack.acked, vec!["a".to_string()]);
        assert_eq!(
            ack.refused,
            vec![
                ("b".to_string(), "no delete scope".to_string()),
                (
                    "c".to_string(),
                    "the mediator did not report this id as deleted".to_string()
                ),
                ("d".to_string(), "conflict".to_string()),
            ]
        );
        assert!(!ack.is_complete());
    }

    #[test]
    fn message_id_is_the_stored_body_hash() {
        let frame = b"\xd4qb2";
        assert_eq!(
            message_id(frame),
            sha256::digest(BASE64_URL_SAFE_NO_PAD.encode(frame))
        );
        assert_ne!(message_id(frame), frame_id(frame));
    }
}
