//! DID multiplexing on a **raw-TSP** socket: the `tsp-mux` WebSocket
//! subprotocol (`messaging/mux/event/0.1`, "Raw-TSP sockets").
//!
//! One raw-TSP socket, authenticated as the profile (the *principal*),
//! carries live delivery for every member DID that granted the principal
//! `receive` (or was attached to this connection). Open it with
//! [`TspOps::connect_websocket_mux`](super::tsp::TspOps::connect_websocket_mux).
//!
//! A task owns the socket and demultiplexes what arrives on it, as the one
//! owner (R1.7):
//!
//! - **Mux events.** A TSP Direct message from the mediator's VID to the
//!   principal's whose payload is a `messaging/mux/event` document. Opened
//!   with the principal's keys, checked (the TSP sender and the document's
//!   `issuer` are the profile's mediator, its `recipient` is the principal)
//!   and handed over typed, as [`TspMuxFrame::Event`].
//! - **Notices.** A `messaging/mux/notice` from the mediator, verified (its
//!   proof, and its issuer is the mediator), as [`TspMuxFrame::Notice`].
//!   Acknowledge it once handled, as any frame.
//! - **Answers to Trust Tasks.** A mux Trust Task sent on this socket
//!   ([`TspMuxSender::request`]) gets its answer here, matched by thread id,
//!   and never reaches [`TspMuxWebSocket::recv`]; a stored answer is
//!   acknowledged by the socket itself. An answer to a request this socket
//!   did not make (one sent another way, waiting on its own reply) is left
//!   alone for its owner.
//! - **Data frames.** Everything else. Its cleartext receiver VID names the
//!   member (or the principal) it is for: it is handed over **unopened**, as
//!   [`TspMuxFrame::Data`], so the application opens it with that member's
//!   keys ([`TspOps::unpack_bytes`](super::tsp::TspOps::unpack_bytes) with the
//!   member's profile).
//!
//! `tsp-mux` implies `tsp-ack`: the mediator keeps each delivered frame until
//! it is acknowledged ([`TspMuxWebSocket::ack`]), with `messaging/mux/ack` on
//! the socket itself, so the instance holding the connection answers. Acks
//! are authorised against each member's `delete` scope, so an ack can be
//! refused for one member and succeed for another; [`TspMuxAck`] reports each
//! frame's outcome.
//!
//! Sending, requests and acks go through a [`TspMuxSender`], which is cheap to
//! clone, so one task can send while another waits on
//! [`recv`](TspMuxWebSocket::recv).
//!
//! **Reconnecting.** A socket from
//! [`connect_websocket_mux`](super::tsp::TspOps::connect_websocket_mux) does
//! not reconnect: a dropped socket ends [`TspMuxWebSocket::recv`] (with the
//! mediator's close reason when it gave one), fails every request still
//! waiting, and turns [`TspMuxWebSocket::state`] to [`TspMuxState::Closed`];
//! the caller decides what to do (R6.2).
//!
//! One from
//! [`connect_websocket_mux_managed`](super::tsp::TspOps::connect_websocket_mux_managed)
//! reconnects by itself, with backoff ([`TspMuxReconnect`]). While it is down
//! the state is [`TspMuxState::Reconnecting`], requests still waiting fail,
//! and sends fail at once rather than queue. Once a new connection's `ready`
//! arrives the state is `Open` again and [`TspMuxWebSocket::recv`] returns
//! [`TspMuxFrame::Reconnected`]. It stops only when the client closes or
//! drops it, when the mediator no longer accepts `tsp-mux`, or when a newer
//! connection for the same DID replaced it (then `recv` fails and the state
//! is `Closed`): taking the connection back would replace the newer one, and
//! the two would fight.
//!
//! Each connection is new to the mediator, so nothing carries over: the
//! member set is rebuilt from the new connection's `ready` and `attached`
//! events (stored grants are admitted again; members attached with
//! statements must be attached again, signed for the new `ready`), and frames
//! not acknowledged before the drop are delivered again.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use affinidi_tsp::MetaEnvelope;
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use serde_json::Value;
use tracing::{debug, warn};

use trust_tasks_proof::affinidi::ProofPurposeResolver;

use super::mux::{
    EVENT_TYPE, MuxEvent, MuxEventKind, MuxMembers, MuxNotice, MuxReady, MuxRefused, check_event,
};
use super::tsp::{TspOps, TspWsStream};
use crate::ATM;
use crate::errors::ATMError;
use crate::profiles::ATMProfile;
use tokio::sync::{mpsc, oneshot, watch};
use trust_tasks_rs::TrustTask;

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

/// `messaging/mux/ack`'s answer type: pushed to the socket, never stored, so
/// it is the one answer the socket does not acknowledge.
const ACK_RESPONSE_TYPE: &str = "https://trusttasks.org/spec/messaging/mux/ack/0.1#response";

/// Frames read off the socket and not yet taken by [`TspMuxWebSocket::recv`].
const FRAME_BUFFER: usize = 64;

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
    /// A durable `messaging/mux/notice` from the mediator, verified (its
    /// proof, and its issuer is the mediator): grants suspended, revoked or
    /// expiring, or delegations present. Act on it, then acknowledge `frame`.
    Notice {
        /// The verified notice.
        notice: Box<TrustTask<MuxNotice>>,
        /// The raw frame, for [`TspMuxWebSocket::ack`].
        frame: Vec<u8>,
    },
    /// A managed socket ([`TspOps::connect_websocket_mux_managed`]) is
    /// connected again after a drop. This is a new connection: its `ready`
    /// (a new session id and mux nonce, for attach statements) replaces the
    /// old one, and the member set starts again from it. Stored grants come
    /// back as an `attached` event; members attached with statements must be
    /// attached again. Frames not acknowledged before the drop are delivered
    /// again, so handle a repeat by its [`message_id`].
    ///
    /// [`TspOps::connect_websocket_mux_managed`]: super::tsp::TspOps::connect_websocket_mux_managed
    Reconnected {
        /// The new connection's `ready` event.
        ready: Box<MuxReady>,
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

/// Acknowledges frames of one `tsp-mux` socket from another task
/// ([`TspMuxWebSocket::acker`]): the [`TspMuxSender`]'s acks, on their own.
#[derive(Clone, Debug)]
pub struct TspMuxAcker {
    sender: TspMuxSender,
}

impl TspMuxAcker {
    /// Acknowledge (delete) delivered frames. See [`TspMuxWebSocket::ack`].
    pub async fn ack(&self, frames: &[&[u8]]) -> Result<TspMuxAck, ATMError> {
        self.sender.ack(frames).await
    }

    /// Acknowledge by message id ([`message_id`]).
    pub async fn ack_ids(&self, ids: &[String]) -> Result<TspMuxAck, ATMError> {
        self.sender.ack_ids(ids).await
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
    /// Checks an event's proof, when it carries one.
    pub(crate) resolver: Arc<dyn ProofPurposeResolver>,
}

impl Demux {
    /// Sort one binary frame into an event or a data frame. Returns `None`
    /// for an event that must be ignored (malformed, or not addressed to this
    /// principal by this mediator; spec consumer rule 1 and "Members per
    /// kind"). An answer to a Trust Task is handed over as data here; the
    /// socket task routes it ([`sort`](Self::sort)).
    pub(crate) async fn classify(&self, frame: Vec<u8>) -> Option<TspMuxFrame> {
        match self.sort(frame).await {
            Sorted::Frame(f) => Some(f),
            Sorted::Answer { frame, .. } => {
                let meta = MetaEnvelope::parse(&frame).ok()?;
                Some(TspMuxFrame::Data {
                    receiver: meta.receiver,
                    sender: meta.sender,
                    frame,
                })
            }
            Sorted::Ignore => None,
        }
    }

    /// Sort one binary frame: an event, a notice, a Trust Task answer, or
    /// data.
    pub(crate) async fn sort(&self, frame: Vec<u8>) -> Sorted {
        let meta = match MetaEnvelope::parse(&frame) {
            Ok(m) => m,
            Err(e) => {
                return Sorted::Frame(TspMuxFrame::Unreadable {
                    frame,
                    error: e.to_string(),
                });
            }
        };
        if meta.receiver == self.principal && meta.sender == self.mediator {
            match self.opener.open(&frame).await {
                Ok((payload, sender)) => match self.event(&payload, &sender).await {
                    EventCheck::Event(e) => return Sorted::Frame(TspMuxFrame::Event(e)),
                    EventCheck::Ignore => return Sorted::Ignore,
                    EventCheck::NotAnEvent => {
                        if let Ok(doc) = serde_json::from_slice::<Value>(&payload) {
                            if let Some(thread_id) = answer_thread(&doc) {
                                return Sorted::Answer {
                                    thread_id,
                                    doc,
                                    frame,
                                };
                            }
                            if doc.get("type").and_then(Value::as_str) == Some(NOTICE_TYPE) {
                                match super::mux::verify_notice_doc(
                                    self.resolver.clone(),
                                    &doc,
                                    &self.mediator,
                                )
                                .await
                                {
                                    Ok(notice) => {
                                        return Sorted::Frame(TspMuxFrame::Notice {
                                            notice: Box::new(notice),
                                            frame,
                                        });
                                    }
                                    // Stored all the same, so it goes to the
                                    // caller as data rather than vanishing.
                                    Err(e) => warn!(error = %e, "a mux notice did not verify"),
                                }
                            }
                        }
                    }
                },
                Err(e) => {
                    // Something from the mediator we cannot open (a stale
                    // key, a control message): not an event we can trust, but
                    // still a stored frame, so it goes to the caller.
                    debug!(error = %e, "a frame from the mediator did not open as a mux event");
                }
            }
        }
        Sorted::Frame(TspMuxFrame::Data {
            receiver: meta.receiver,
            sender: meta.sender,
            frame,
        })
    }

    /// An opened frame's payload as an event: checked as
    /// [`verify_mux_event`](super::mux::verify_mux_event) checks one, after
    /// the TSP envelope's signature showed the mediator sent it.
    async fn event(&self, payload: &[u8], sender: &str) -> EventCheck {
        let Ok(doc) = serde_json::from_slice::<Value>(payload) else {
            return EventCheck::NotAnEvent;
        };
        if doc.get("type").and_then(Value::as_str) != Some(EVENT_TYPE) {
            return EventCheck::NotAnEvent;
        }
        if sender != self.mediator {
            warn!(
                sender,
                "ignoring a mux event not sent by this profile's mediator"
            );
            return EventCheck::Ignore;
        }
        match check_event(&self.resolver, &doc, &self.mediator, &self.principal).await {
            Ok(event) => EventCheck::Event(Box::new(event)),
            Err(e) => {
                warn!(error = %e, "ignoring a mux event");
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

/// How [`Demux::sort`] sorted a frame.
pub(crate) enum Sorted {
    /// For the application.
    Frame(TspMuxFrame),
    /// A Trust Task answer from the mediator to the principal, for whoever
    /// asked.
    Answer {
        thread_id: String,
        doc: Value,
        frame: Vec<u8>,
    },
    /// An event to ignore.
    Ignore,
}

/// The thread a Trust Task answer replies to: a `#response` document, or a
/// Trust Task error, carrying `threadId`.
fn answer_thread(doc: &Value) -> Option<String> {
    let thread = doc.get("threadId").and_then(Value::as_str)?;
    let ty = doc.get("type").and_then(Value::as_str)?;
    (ty.contains("#response") || ty.contains("/trust-task-error/")).then(|| thread.to_string())
}

const NOTICE_TYPE: &str = "https://trusttasks.org/spec/messaging/mux/notice/0.1";

/// What came off the socket.
enum Incoming {
    /// A binary frame.
    Frame(Vec<u8>),
    /// The stream ended without a close frame.
    Ended,
    /// The mediator closed the socket, or the transport failed. `replaced`
    /// is decided from the close frame itself (see [`is_replacement`]), never
    /// from error text.
    Closed { error: ATMError, replaced: bool },
}

/// Whether the mediator closed this socket because a newer connection for
/// the same DID took its place: close code 1008 (policy) with exactly the
/// mediator's reason. Text that only contains the words does not count.
fn is_replacement(frame: &tokio_tungstenite::tungstenite::protocol::CloseFrame) -> bool {
    use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
    frame.code == CloseCode::Policy && frame.reason.as_str() == REPLACED_REASON
}

/// The next frame off the socket that matters: a binary frame, the end, or a
/// close (with the mediator's reason) or transport error.
async fn next_incoming(ws: &mut TspWsStream) -> Incoming {
    use futures_util::StreamExt;
    use tokio_tungstenite::tungstenite::Message;
    loop {
        match ws.next().await {
            Some(Ok(Message::Binary(bytes))) => return Incoming::Frame(bytes.to_vec()),
            Some(Ok(Message::Close(frame))) => {
                let replaced = frame.as_ref().is_some_and(is_replacement);
                let error = ATMError::TransportError(match frame {
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
                });
                return Incoming::Closed { error, replaced };
            }
            None => return Incoming::Ended,
            Some(Ok(_)) => continue,
            Some(Err(e)) => {
                return Incoming::Closed {
                    error: ATMError::TransportError(format!(
                        "tsp-mux websocket receive error: {e}"
                    )),
                    replaced: false,
                };
            }
        }
    }
}

/// [`next_incoming`] for the handshake: `Ok(None)` when the stream ended
/// without a close frame; `Err` on a close frame or a transport error.
async fn next_binary(ws: &mut TspWsStream) -> Result<Option<Vec<u8>>, ATMError> {
    match next_incoming(ws).await {
        Incoming::Frame(bytes) => Ok(Some(bytes)),
        Incoming::Ended => Ok(None),
        Incoming::Closed { error, .. } => Err(error),
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

/// Whether a `tsp-mux` connection is open (R6.2): watch it with
/// [`TspMuxWebSocket::state`] or [`TspMuxSender::state`].
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum TspMuxState {
    /// The socket is open.
    Open,
    /// A managed socket is down and connecting again: `attempt` counts the
    /// tries since it dropped (1 for the first), `reason` says why it dropped
    /// or why the last try failed. Requests and sends fail meanwhile.
    Reconnecting {
        /// Tries since the drop, starting at 1.
        attempt: u32,
        /// Why the socket dropped, or the last try failed.
        reason: String,
    },
    /// The socket is gone for good, and why: the mediator's close reason, a
    /// transport error, the client closing it, or (for a managed socket) the
    /// mediator no longer accepting `tsp-mux`. Nothing reconnects from here.
    Closed {
        /// What ended it.
        reason: String,
    },
}

/// How a managed `tsp-mux` socket
/// ([`TspOps::connect_websocket_mux_managed`](super::tsp::TspOps::connect_websocket_mux_managed))
/// paces its reconnects. The defaults match the SDK's DIDComm WebSocket:
/// 1 s doubling to 60 s, and a connection that stayed up 30 s counts as
/// healthy, so the next drop reconnects at once. Each wait is jittered by
/// ±15 %, so many clients dropped together do not return together, and is
/// never shorter than a refusing server's `Retry-After` (within the cap).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct TspMuxReconnect {
    /// The wait after the first failed try.
    pub initial_delay: Duration,
    /// The longest wait between tries.
    pub max_delay: Duration,
    /// How long a connection must stay up for the next drop to reconnect at
    /// once, instead of where the backoff left off.
    pub stable_after: Duration,
}

impl Default for TspMuxReconnect {
    fn default() -> Self {
        Self {
            initial_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(60),
            stable_after: Duration::from_secs(30),
        }
    }
}

impl TspMuxReconnect {
    /// Backoff from `initial` doubling to `max` (at least `initial`).
    pub fn with_delays(mut self, initial: Duration, max: Duration) -> Self {
        self.initial_delay = initial;
        self.max_delay = max.max(initial);
        self
    }

    /// How long a connection must stay up to reset the backoff.
    pub fn with_stable_after(mut self, stable_after: Duration) -> Self {
        self.stable_after = stable_after;
        self
    }

    /// The wait before the next try, after one that waited `current`.
    fn escalate(&self, current: Duration) -> Duration {
        if current.is_zero() {
            self.initial_delay
        } else {
            (current * 2).min(self.max_delay)
        }
    }
}

/// `d` jittered by ±15 %; zero stays zero.
fn jittered(d: Duration) -> Duration {
    use rand::RngExt;
    if d.is_zero() {
        return d;
    }
    d.mul_f64(rand::rng().random_range(0.85..1.15))
}

/// Opens a raw-TSP socket offering `tsp-mux`: the mediator's selection and the
/// stream. The SDK's dials through the profile's mediator; tests dial a local
/// server.
#[async_trait::async_trait]
pub(crate) trait Dialer: Send + Sync {
    async fn dial(&self) -> Result<(TspWsStream, Option<String>), ATMError>;
}

struct AtmDialer {
    atm: ATM,
    profile: Arc<ATMProfile>,
}

#[async_trait::async_trait]
impl Dialer for AtmDialer {
    async fn dial(&self) -> Result<(TspWsStream, Option<String>), ATMError> {
        let raw = self
            .atm
            .tsp()
            .open_raw_socket(&self.profile, &MUX_OFFER)
            .await?;
        Ok((raw.ws, raw.selected))
    }
}

/// Dial, check the selection and wait for `ready`: a mux connection, or why
/// not. The socket is closed on failure.
async fn open_mux(
    dialer: &dyn Dialer,
    demux: &Demux,
    wait: Duration,
) -> Result<(TspWsStream, MuxReady), ATMError> {
    let (mut ws, selected) = dialer.dial().await?;
    if let Err(e) = check_selection(selected.as_deref()) {
        let _ = ws.close(None).await;
        return Err(e);
    }
    match await_ready(&mut ws, demux, wait).await {
        Ok(ready) => Ok((ws, ready)),
        Err(e) => {
            let _ = ws.close(None).await;
            Err(e)
        }
    }
}

/// The reason the mediator closes a socket with (code 1008) when a newer
/// connection for the same DID took its place. A managed socket stops on it:
/// connecting again would replace the newer connection in turn, and the two
/// would take it from each other for ever. The mediator decides delivery
/// anyway, so this gives a hostile one nothing it lacks; matching the code
/// and the exact reason keeps any other close or error from stopping it.
const REPLACED_REASON: &str = "replaced by a newer connection";

/// Whether a failed reconnect is final: the mediator (or the profile) no
/// longer offers a mux connection at all. Anything else is tried again.
fn is_final(e: &ATMError) -> bool {
    matches!(e, ATMError::ConfigError(_))
}

/// Answers to requests that failed with a dropped socket, by thread id: a
/// stored one arrives on the next connection, and is acknowledged there.
const ABANDONED_KEPT: usize = 64;

/// What the socket task is asked to do.
enum Outgoing {
    Frame {
        bytes: Vec<u8>,
        done: oneshot::Sender<Result<(), ATMError>>,
    },
    Close {
        done: oneshot::Sender<()>,
    },
}

/// A Trust Task sent on the socket, waiting for its answer.
struct Pending {
    /// The request frame's [`frame_id`], which a `refused` event names.
    frame_id: String,
    answer: oneshot::Sender<Result<Value, ATMError>>,
}

/// What every handle to one connection shares.
struct Shared {
    atm: ATM,
    profile: Arc<ATMProfile>,
    principal: String,
    mediator: String,
    out: mpsc::Sender<Outgoing>,
    /// By thread id.
    pending: std::sync::Mutex<HashMap<String, Pending>>,
    /// Thread ids of requests failed by a drop (newest last, bounded).
    abandoned: std::sync::Mutex<std::collections::VecDeque<String>>,
    state: watch::Sender<TspMuxState>,
    /// The current connection's `ready`: `None` while it is down or gone.
    ready: watch::Sender<Option<MuxReady>>,
}

impl Shared {
    fn closed_error(&self) -> ATMError {
        match &*self.state.borrow() {
            TspMuxState::Closed { reason } => {
                ATMError::TransportError(format!("tsp-mux connection closed: {reason}"))
            }
            TspMuxState::Reconnecting { reason, .. } => {
                ATMError::Disconnected(format!("tsp-mux connection down, reconnecting: {reason}"))
            }
            TspMuxState::Open => ATMError::TransportError("tsp-mux connection closed".into()),
        }
    }

    /// The socket dropped and a new one is on its way: say so, and fail every
    /// request still waiting. Its answer, if the mediator stores it, comes on
    /// the next connection; it is remembered so that answer is acknowledged.
    /// An ack's answer is never stored, so whether a failed ack went through
    /// is not known: acking again is safe.
    fn lose(&self, reason: &str) {
        self.ready.send_replace(None);
        self.state.send_replace(TspMuxState::Reconnecting {
            attempt: 1,
            reason: reason.to_string(),
        });
        let waiting: Vec<(String, Pending)> =
            self.pending.lock().expect("pending map").drain().collect();
        let mut abandoned = self.abandoned.lock().expect("abandoned list");
        for (thread, p) in waiting {
            let _ = p.answer.send(Err(ATMError::Disconnected(format!(
                "tsp-mux connection dropped before the answer came ({reason}); the request \
                 may still have been acted on"
            ))));
            abandoned.push_back(thread);
        }
        while abandoned.len() > ABANDONED_KEPT {
            abandoned.pop_front();
        }
    }

    /// The connection ended: say so, and fail every request still waiting.
    fn finish(&self, reason: String) {
        self.ready.send_replace(None);
        self.state.send_replace(TspMuxState::Closed {
            reason: reason.clone(),
        });
        let waiting: Vec<Pending> = self
            .pending
            .lock()
            .expect("pending map")
            .drain()
            .map(|(_, p)| p)
            .collect();
        for p in waiting {
            let _ = p.answer.send(Err(ATMError::TransportError(format!(
                "tsp-mux connection closed before the answer came: {reason}"
            ))));
        }
    }
}

/// Sends on one `tsp-mux` connection: raw frames, mux Trust Tasks (answered
/// on the socket), and acknowledgements. Cheap to clone; every clone talks to
/// the same socket, and fails once it has closed.
#[derive(Clone)]
pub struct TspMuxSender {
    shared: Arc<Shared>,
}

/// [`TspMuxSender`] as the wire a grant keeper talks on.
struct TspGrantWire(TspMuxSender);

impl super::mux_grant_keep::GrantWire for TspGrantWire {
    async fn grant(
        &self,
        statements: Vec<Value>,
    ) -> Result<crate::tasks::messaging::mux::grant::v0_1::Response, ATMError> {
        self.0.grant(statements).await
    }
    async fn list(
        &self,
        cursor: Option<String>,
    ) -> Result<crate::tasks::messaging::mux::list::v0_1::Response, ATMError> {
        self.0.list(false, cursor, None).await
    }
}

impl std::fmt::Debug for TspMuxSender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TspMuxSender")
            .field("principal", &self.shared.principal)
            .field("state", &*self.shared.state.borrow())
            .finish_non_exhaustive()
    }
}

impl TspMuxSender {
    /// Send a raw qb2 TSP frame, as the principal or as a member that granted
    /// `send`. Returns its [`frame_id`]: a `refused` event naming that id
    /// means the mediator refused it (the socket stays open). Without one the
    /// mediator accepted it; `Ok` here means only that it was written.
    pub async fn send(&self, frame: &[u8]) -> Result<String, ATMError> {
        let (done, written) = oneshot::channel();
        self.shared
            .out
            .send(Outgoing::Frame {
                bytes: frame.to_vec(),
                done,
            })
            .await
            .map_err(|_| self.shared.closed_error())?;
        written.await.map_err(|_| self.shared.closed_error())??;
        Ok(frame_id(frame))
    }

    /// Send a mux Trust Task (`messaging/mux/*`) on this socket, signed as
    /// the principal and sealed to the mediator, and wait for its answer,
    /// which this socket routes here by thread id. A request the mediator
    /// refuses is answered by a `refused` event naming the request frame, and
    /// fails here with its code. Times out after 15 s, as a Trust Task sent
    /// over TSP does.
    ///
    /// `attach` and `detach` act on the connection they arrive on, so this is
    /// the only way to send them for a `tsp-mux` connection.
    pub async fn request<P, R>(&self, payload: Value) -> Result<TrustTask<R>, ATMError>
    where
        P: trust_tasks_rs::Payload + serde::de::DeserializeOwned + serde::Serialize,
        R: serde::de::DeserializeOwned,
    {
        let mut task = super::trust_tasks::mux_task::<P>(&self.shared.profile, payload)?;
        task.issued_at = Some(chrono::Utc::now());
        let thread_id = task.id.clone();
        let body = serde_json::to_value(&task)
            .map_err(|e| ATMError::MsgSendError(format!("couldn't serialise Trust Task: {e}")))?;
        let body = self
            .shared
            .atm
            .trust_tasks()
            .sign(&self.shared.principal, body)
            .await?;
        let bytes = serde_json::to_vec(&body)
            .map_err(|e| ATMError::MsgSendError(format!("couldn't serialise Trust Task: {e}")))?;
        let frame = self
            .shared
            .atm
            .tsp()
            .pack(&self.shared.profile, &self.shared.mediator, &bytes)
            .await?;
        let (answer, answered) = oneshot::channel();
        self.shared.pending.lock().expect("pending map").insert(
            thread_id.clone(),
            Pending {
                frame_id: frame_id(&frame),
                answer,
            },
        );
        let forget = || {
            self.shared
                .pending
                .lock()
                .expect("pending map")
                .remove(&thread_id);
        };
        if let Err(e) = self.send(&frame).await {
            forget();
            return Err(e);
        }
        let timeout = super::trust_tasks::TSP_REPLY_TIMEOUT;
        match tokio::time::timeout(timeout, answered).await {
            Ok(Ok(Ok(doc))) => super::trust_tasks::decode_body(&doc),
            Ok(Ok(Err(e))) => Err(e),
            Ok(Err(_)) => Err(self.shared.closed_error()),
            Err(_) => {
                forget();
                Err(ATMError::MsgReceiveError(format!(
                    "no answer from the mediator on the tsp-mux socket within {}s",
                    timeout.as_secs()
                )))
            }
        }
    }

    /// Acknowledge (delete) delivered frames. See [`TspMuxWebSocket::ack`].
    pub async fn ack(&self, frames: &[&[u8]]) -> Result<TspMuxAck, ATMError> {
        let ids: Vec<String> = frames.iter().map(|f| message_id(f)).collect();
        self.ack_ids(&ids).await
    }

    /// Acknowledge by message id ([`message_id`]), with `messaging/mux/ack`
    /// on the socket, in batches of 100.
    pub async fn ack_ids(&self, ids: &[String]) -> Result<TspMuxAck, ATMError> {
        use crate::tasks::messaging::mux::ack::v0_1::Payload;
        let mut out = TspMuxAck::default();
        for chunk in ids.chunks(MAX_ACK_BATCH) {
            match self
                .request::<Payload, Value>(serde_json::json!({ "messageIds": chunk }))
                .await
            {
                Ok(answer) => {
                    let acked: Vec<String> = answer.payload["acked"]
                        .as_array()
                        .map(|a| {
                            a.iter()
                                .filter_map(Value::as_str)
                                .map(str::to_string)
                                .collect()
                        })
                        .unwrap_or_default();
                    let refused: Vec<(String, String)> = answer.payload["refused"]
                        .as_array()
                        .map(|a| {
                            a.iter()
                                .filter_map(|r| {
                                    Some((
                                        r["messageId"].as_str()?.to_string(),
                                        r["reason"].as_str().unwrap_or("refused").to_string(),
                                    ))
                                })
                                .collect()
                        })
                        .unwrap_or_default();
                    out.settle(chunk, &acked, &refused);
                }
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

    /// `messaging/mux/attach` on this connection: `statements` are attach
    /// statements ([`sign_attach`](super::mux::sign_attach)) bound to this
    /// connection's `ready`.
    pub async fn attach(
        &self,
        statements: Vec<Value>,
    ) -> Result<crate::tasks::messaging::mux::attach::v0_1::Response, ATMError> {
        use crate::tasks::messaging::mux::attach::v0_1::{Payload, Response};
        Ok(self
            .request::<Payload, Response>(serde_json::json!({ "attachments": statements }))
            .await?
            .payload)
    }

    /// `messaging/mux/detach` on this connection.
    pub async fn detach(
        &self,
        dids: Vec<String>,
    ) -> Result<crate::tasks::messaging::mux::detach::v0_1::Response, ATMError> {
        use crate::tasks::messaging::mux::detach::v0_1::{Payload, Response};
        Ok(self
            .request::<Payload, Response>(serde_json::json!({ "dids": dids }))
            .await?
            .payload)
    }

    /// `messaging/mux/grant` on this socket: store grant statements
    /// ([`sign_grant`](super::mux::sign_grant)). Each is accepted or refused
    /// on its own. The counterpart of `TrustTasksOps::mux_grant`.
    pub async fn grant(
        &self,
        statements: Vec<Value>,
    ) -> Result<crate::tasks::messaging::mux::grant::v0_1::Response, ATMError> {
        use crate::tasks::messaging::mux::grant::v0_1::{Payload, Response};
        Ok(self
            .request::<Payload, Response>(serde_json::json!({ "grants": statements }))
            .await?
            .payload)
    }

    /// `messaging/mux/list` on this socket: the grants the principal holds,
    /// or (`as_member`) those on its own DID. One page; pass the previous
    /// page's `nextCursor` as `cursor` to continue.
    pub async fn list(
        &self,
        as_member: bool,
        cursor: Option<String>,
        limit: Option<u64>,
    ) -> Result<crate::tasks::messaging::mux::list::v0_1::Response, ATMError> {
        use crate::tasks::messaging::mux::list::v0_1::{Payload, Response};
        Ok(self
            .request::<Payload, Response>(super::trust_tasks::mux_list_payload(
                as_member, cursor, limit,
            ))
            .await?
            .payload)
    }

    /// `messaging/mux/update` on this socket: narrow a grant (smaller scope
    /// and/or earlier expiry). Widening needs a new grant.
    pub async fn update(
        &self,
        grant_id: &str,
        scope: Option<&[super::mux::MuxCapability]>,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<crate::tasks::messaging::mux::update::v0_1::Response, ATMError> {
        use crate::tasks::messaging::mux::update::v0_1::{Payload, Response};
        Ok(self
            .request::<Payload, Response>(super::trust_tasks::mux_update_payload(
                grant_id, scope, expires_at,
            ))
            .await?
            .payload)
    }

    /// `messaging/mux/revoke` on this socket. As principal, `dids` are member
    /// DIDs to drop; as member (`as_member`), principals to remove.
    /// `grant_ids` name grants directly either way.
    pub async fn revoke(
        &self,
        as_member: bool,
        grant_ids: Vec<String>,
        dids: Vec<String>,
    ) -> Result<crate::tasks::messaging::mux::revoke::v0_1::Response, ATMError> {
        use crate::tasks::messaging::mux::revoke::v0_1::{Payload, Response};
        Ok(self
            .request::<Payload, Response>(super::trust_tasks::mux_revoke_payload(
                as_member, grant_ids, dids,
            ))
            .await?
            .payload)
    }

    /// `messaging/mux/revoke-all` on this socket, with a statement from
    /// [`sign_revoke_all`](super::mux::sign_revoke_all).
    pub async fn revoke_all(
        &self,
        statement: Value,
    ) -> Result<crate::tasks::messaging::mux::revoke_all::v0_1::Response, ATMError> {
        use crate::tasks::messaging::mux::revoke_all::v0_1::{Payload, Response};
        Ok(self
            .request::<Payload, Response>(serde_json::json!({ "revocation": statement }))
            .await?
            .payload)
    }

    /// Whether the connection is open, as a watch: it changes once, to
    /// [`TspMuxState::Closed`], when the socket goes.
    pub fn state(&self) -> watch::Receiver<TspMuxState> {
        self.shared.state.subscribe()
    }

    /// The current connection's `ready` (session id and attach nonce), as a
    /// watch: `None` while the socket is down or closed, and a new value on
    /// every reconnect of a managed socket.
    pub fn ready(&self) -> watch::Receiver<Option<MuxReady>> {
        self.shared.ready.subscribe()
    }

    /// Keep `members` attached to this connection across reconnects
    /// (`reattach_on_reconnect`, opt-in): sign fresh attach statements with
    /// this socket's `ATM` for each new connection, attach them on the
    /// socket, and attach again before they expire. Stops when the returned
    /// handle is dropped. See [`super::mux_keep`].
    pub fn keep_attached(
        &self,
        members: Vec<super::mux_keep::MuxKeepAttach>,
    ) -> Result<super::mux_keep::MuxKeepAttached, ATMError> {
        let sender = self.clone();
        super::mux_keep::spawn_keep(
            self.shared.atm.clone(),
            self.shared.principal.clone(),
            self.shared.mediator.clone(),
            members,
            self.ready(),
            move |statements| {
                let sender = sender.clone();
                async move {
                    let r = sender.attach(statements).await?;
                    serde_json::to_value(&r)
                        .map_err(|e| ATMError::MsgReceiveError(format!("attach answer: {e}")))
                }
            },
        )
    }

    /// Keep stored grants to this socket's principal renewed and recreated,
    /// as each member opted into (`auto_renew` / `auto_recreate`, both off by
    /// default): grants and lists go on this socket, signed with this
    /// socket's `ATM`. Hand the socket's `TspMuxFrame::Notice`s to
    /// [`MuxGrantKeeper::handle_notice`](super::mux_grant_keep::MuxGrantKeeper::handle_notice)
    /// before acknowledging them. Stops when the returned handle is dropped.
    /// See [`super::mux_grant_keep`].
    pub fn keep_grants(
        &self,
        members: Vec<super::mux_grant_keep::MuxGrantKeep>,
    ) -> Result<super::mux_grant_keep::MuxGrantKeeper, ATMError> {
        super::mux_grant_keep::spawn_grant_keep(
            self.shared.atm.clone(),
            self.shared.principal.clone(),
            self.shared.mediator.clone(),
            members,
            self.ready(),
            TspGrantWire(self.clone()),
        )
    }
}

/// Why [`pump`] stopped.
enum Ended {
    /// The client closed or dropped the socket: stop for good.
    Client(String),
    /// The socket went away: the reason, the error to hand `recv` when
    /// nothing reconnects, and whether the mediator said a newer connection
    /// replaced it.
    Lost {
        reason: String,
        error: Option<ATMError>,
        replaced: bool,
    },
}

/// Serve one socket until it ends: read and sort every frame, write what the
/// senders send, and route Trust Task answers to their requests.
async fn pump(
    ws: &mut TspWsStream,
    demux: &Demux,
    shared: &Arc<Shared>,
    out: &mut mpsc::Receiver<Outgoing>,
    frames: &mpsc::Sender<Result<TspMuxFrame, ATMError>>,
) -> Ended {
    use futures_util::SinkExt;
    use tokio_tungstenite::tungstenite::Message;
    loop {
        tokio::select! {
            incoming = next_incoming(ws) => match incoming {
                Incoming::Frame(frame) => match demux.sort(frame).await {
                    Sorted::Frame(f) => {
                        if let TspMuxFrame::Event(e) = &f
                            && let Some(refused) = MuxRefused::from_event(e)
                        {
                            refuse_pending(shared, &refused);
                        }
                        if frames.send(Ok(f)).await.is_err() {
                            let _ = ws.close(None).await;
                            return Ended::Client("dropped by the client".into());
                        }
                    }
                    Sorted::Answer { thread_id, doc, frame } => {
                        answer_pending(shared, &thread_id, doc, frame);
                    }
                    Sorted::Ignore => {}
                },
                Incoming::Ended => {
                    return Ended::Lost {
                        reason: "the socket ended without a close frame".into(),
                        error: None,
                        replaced: false,
                    };
                }
                Incoming::Closed { error, replaced } => {
                    return Ended::Lost {
                        reason: error.to_string(),
                        error: Some(error),
                        replaced,
                    };
                }
            },
            cmd = out.recv() => match cmd {
                Some(Outgoing::Frame { bytes, done }) => {
                    let written = ws
                        .send(Message::Binary(bytes.into()))
                        .await
                        .map_err(|e| ATMError::TransportError(format!("tsp-mux websocket send error: {e}")));
                    let _ = done.send(written);
                }
                Some(Outgoing::Close { done }) => {
                    let _ = ws.close(None).await;
                    shared.finish("closed by the client".into());
                    let _ = done.send(());
                    return Ended::Client("closed by the client".into());
                }
                // `Shared` holds a sender for as long as this task runs, so
                // this does not happen; stop cleanly if it does.
                None => {
                    let _ = ws.close(None).await;
                    return Ended::Client("closed by the client".into());
                }
            },
            _ = frames.closed() => {
                let _ = ws.close(None).await;
                return Ended::Client("dropped by the client".into());
            }
        }
    }
}

/// How a managed socket connects again.
struct Redial {
    dialer: Arc<dyn Dialer>,
    policy: TspMuxReconnect,
    ready_wait: Duration,
}

/// The task that owns the connection: [`pump`] on each socket, and, for a
/// managed one, connecting again with backoff when a socket goes (R6.2: the
/// state says which).
async fn run(
    mut ws: TspWsStream,
    demux: Demux,
    shared: Arc<Shared>,
    mut out: mpsc::Receiver<Outgoing>,
    frames: mpsc::Sender<Result<TspMuxFrame, ATMError>>,
    redial: Option<Redial>,
) {
    let mut up_since = tokio::time::Instant::now();
    let mut delay = Duration::ZERO;
    loop {
        let (mut reason, error, replaced) =
            match pump(&mut ws, &demux, &shared, &mut out, &frames).await {
                Ended::Client(reason) => {
                    shared.finish(reason);
                    return;
                }
                Ended::Lost {
                    reason,
                    error,
                    replaced,
                } => (reason, error, replaced),
            };
        let Some(redial) = redial.as_ref().filter(|_| !replaced) else {
            if replaced && redial.is_some() {
                warn!(principal = %shared.principal, "tsp-mux socket replaced by a newer connection; not reconnecting");
            }
            shared.finish(reason);
            if let Some(e) = error {
                let _ = frames.send(Err(e)).await;
            }
            return;
        };
        warn!(principal = %shared.principal, %reason, "tsp-mux socket dropped; reconnecting");
        shared.lose(&reason);
        // Let go of the dead socket now (answering a close the mediator sent),
        // not when the next one is up.
        let _ = tokio::time::timeout(Duration::from_secs(1), ws.close(None)).await;
        drop(ws);
        delay = if up_since.elapsed() >= redial.policy.stable_after {
            Duration::ZERO
        } else {
            redial.policy.escalate(delay)
        };
        let mut attempt: u32 = 1;
        loop {
            shared.state.send_replace(TspMuxState::Reconnecting {
                attempt,
                reason: reason.clone(),
            });
            let wait = jittered(delay);
            let tried = {
                let dial = async {
                    tokio::time::sleep(wait).await;
                    open_mux(redial.dialer.as_ref(), &demux, redial.ready_wait).await
                };
                tokio::pin!(dial);
                loop {
                    tokio::select! {
                        tried = &mut dial => break Some(tried),
                        cmd = out.recv() => match cmd {
                            // Not queued for later: a frame sent now would go
                            // out on a connection the sender has not seen.
                            Some(Outgoing::Frame { done, .. }) => {
                                let _ = done.send(Err(shared.closed_error()));
                            }
                            Some(Outgoing::Close { done }) => {
                                shared.finish("closed by the client".into());
                                let _ = done.send(());
                                break None;
                            }
                            None => break None,
                        },
                        _ = frames.closed() => break None,
                    }
                }
            };
            let Some(tried) = tried else {
                // Closed or dropped by the client while down.
                shared.finish("closed by the client".into());
                return;
            };
            match tried {
                Ok((new_ws, ready)) => {
                    ws = new_ws;
                    up_since = tokio::time::Instant::now();
                    shared.ready.send_replace(Some(ready.clone()));
                    shared.state.send_replace(TspMuxState::Open);
                    debug!(principal = %shared.principal, session = %ready.session_id, "tsp-mux reconnected");
                    if frames
                        .send(Ok(TspMuxFrame::Reconnected {
                            ready: Box::new(ready),
                        }))
                        .await
                        .is_err()
                    {
                        let _ = ws.close(None).await;
                        shared.finish("dropped by the client".into());
                        return;
                    }
                    break;
                }
                Err(e) if is_final(&e) => {
                    warn!(principal = %shared.principal, "tsp-mux not reconnecting: {e}");
                    shared.finish(e.to_string());
                    let _ = frames.send(Err(e)).await;
                    return;
                }
                Err(e) => {
                    debug!(principal = %shared.principal, attempt, "tsp-mux reconnect failed: {e}");
                    delay = redial.policy.escalate(delay);
                    if let Some(after) = e.http_status().and_then(|s| s.retry_after_secs) {
                        delay = delay.max(Duration::from_secs(after).min(redial.policy.max_delay));
                    }
                    reason = e.to_string();
                    attempt = attempt.saturating_add(1);
                }
            }
        }
    }
}

/// A `refused` event naming a request this socket sent: that request fails
/// with the mediator's code.
fn refuse_pending(shared: &Shared, refused: &MuxRefused) {
    let mut pending = shared.pending.lock().expect("pending map");
    let Some(thread) = pending
        .iter()
        .find(|(_, p)| p.frame_id == refused.frame_id)
        .map(|(t, _)| t.clone())
    else {
        return;
    };
    if let Some(p) = pending.remove(&thread) {
        let _ = p.answer.send(Err(ATMError::MsgSendError(format!(
            "the mediator refused the Trust Task: {}{}",
            refused.code,
            refused
                .reason
                .as_deref()
                .map(|r| format!(" ({r})"))
                .unwrap_or_default()
        ))));
    }
}

/// An answer for a request this socket sent goes to it, and a stored one is
/// acknowledged, by this socket, so nothing else consumes it (R1.7). An
/// answer for any other request is left for its owner, unacknowledged.
fn answer_pending(shared: &Arc<Shared>, thread_id: &str, doc: Value, frame: Vec<u8>) {
    let pending = shared
        .pending
        .lock()
        .expect("pending map")
        .remove(thread_id);
    let stored = doc.get("type").and_then(Value::as_str) != Some(ACK_RESPONSE_TYPE);
    let Some(p) = pending else {
        let mut abandoned = shared.abandoned.lock().expect("abandoned list");
        if let Some(at) = abandoned.iter().position(|t| t == thread_id) {
            // Asked on a socket that dropped before the answer came: this
            // connection made the request, so it consumes the answer.
            abandoned.remove(at);
            drop(abandoned);
            debug!(
                thread_id,
                "the answer to a request failed by a drop; acknowledged"
            );
            if stored {
                ack_answer(shared, frame);
            }
        } else {
            debug!(
                thread_id,
                "a Trust Task answer for a request not made on this socket; left for its owner"
            );
        }
        return;
    };
    let _ = p.answer.send(Ok(doc));
    if stored {
        ack_answer(shared, frame);
    }
}

/// Acknowledge a stored Trust Task answer this socket consumed.
fn ack_answer(shared: &Arc<Shared>, frame: Vec<u8>) {
    let sender = TspMuxSender {
        shared: Arc::clone(shared),
    };
    tokio::spawn(async move {
        match sender.ack_ids(&[message_id(&frame)]).await {
            Ok(a) if a.is_complete() => {}
            Ok(a) => debug!(refused = ?a.refused, "a Trust Task answer was not acknowledged"),
            Err(e) => debug!("a Trust Task answer was not acknowledged: {e}"),
        }
    });
}

/// An open `tsp-mux` socket. See the [module docs](self).
pub struct TspMuxWebSocket {
    frames: mpsc::Receiver<Result<TspMuxFrame, ATMError>>,
    sender: TspMuxSender,
    ready: MuxReady,
    members: MuxMembers,
}

impl std::fmt::Debug for TspMuxWebSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TspMuxWebSocket")
            .field("principal", &self.sender.shared.principal)
            .field("mediator", &self.sender.shared.mediator)
            .field("ready", &self.ready)
            .finish_non_exhaustive()
    }
}

impl TspMuxWebSocket {
    /// This connection's `ready` event: its session id and mux nonce (for
    /// [`sign_attach`](super::mux::sign_attach)), its limits and how many
    /// durable notices wait in the principal's inbox. It belongs to this
    /// connection alone; on a managed socket, [`recv`](Self::recv) replaces it
    /// when it returns [`TspMuxFrame::Reconnected`].
    pub fn ready(&self) -> &MuxReady {
        &self.ready
    }

    /// This connection's member set, kept from its `attached` and `detached`
    /// events as [`recv`](Self::recv) reads them: which member DIDs it
    /// carries, with what scope, and whether each one's live traffic comes
    /// here now. It starts empty at `ready`; the stored grants admitted on
    /// connect arrive as the first `attached` event. When
    /// [`MuxReady::pending_notices`] is above zero, read the principal's
    /// notices ([`TspMuxFrame::Notice`]) before trusting it (consumer rule 3).
    pub fn members(&self) -> &MuxMembers {
        &self.members
    }

    /// The principal: the DID this socket is authenticated as.
    pub fn principal(&self) -> &str {
        &self.sender.shared.principal
    }

    /// Receive the next frame: a mux event, a notice or a data frame (see
    /// [`TspMuxFrame`]). Pings and text frames are skipped, as are events the
    /// spec says to ignore (malformed, or not from this mediator to this
    /// principal), and answers to Trust Tasks, which go to their requests.
    ///
    /// When the socket goes away it is finished, and the caller is told:
    /// `Err` with the mediator's close code and reason when it sent a close
    /// frame, `Ok(None)` when the stream ended without one. The members are
    /// not reachable through this socket any more, and frames not
    /// acknowledged are delivered again on the next connection.
    ///
    /// A managed socket instead waits through a drop and returns
    /// [`TspMuxFrame::Reconnected`] once connected again, having taken its
    /// `ready` and started the member set again from it. It ends only as
    /// [`TspMuxState::Closed`] says.
    pub async fn recv(&mut self) -> Result<Option<TspMuxFrame>, ATMError> {
        match self.frames.recv().await {
            None => Ok(None),
            Some(Err(e)) => Err(e),
            Some(Ok(frame)) => {
                match &frame {
                    TspMuxFrame::Event(event) => {
                        self.members.apply(event);
                    }
                    TspMuxFrame::Reconnected { ready } => {
                        self.ready = (**ready).clone();
                        self.members = MuxMembers::connected();
                    }
                    _ => {}
                }
                Ok(Some(frame))
            }
        }
    }

    /// Send a raw qb2 TSP frame. See [`TspMuxSender::send`].
    pub async fn send(&self, frame: &[u8]) -> Result<String, ATMError> {
        self.sender.send(frame).await
    }

    /// Acknowledge delivered frames (`Data`, `Notice`, `Unreadable`),
    /// releasing the mediator's copies, with `messaging/mux/ack` on this
    /// socket. Call once each is safely handled. Returns the mediator's
    /// answer per frame: acks for a member without `delete` scope are refused
    /// (`notPermitted`), and those frames stay in its inbox. `Err` when the
    /// request itself failed (nothing is known to be acknowledged).
    pub async fn ack(&self, frames: &[&[u8]]) -> Result<TspMuxAck, ATMError> {
        self.sender.ack(frames).await
    }

    /// A handle that acknowledges frames of this socket from another task.
    pub fn acker(&self) -> TspMuxAcker {
        TspMuxAcker {
            sender: self.sender.clone(),
        }
    }

    /// A handle that sends on this socket from another task: frames, mux
    /// Trust Tasks and acks.
    pub fn sender(&self) -> TspMuxSender {
        self.sender.clone()
    }

    /// Whether the connection is open (R6.2). See [`TspMuxSender::state`].
    pub fn state(&self) -> watch::Receiver<TspMuxState> {
        self.sender.state()
    }

    /// Close the socket gracefully. Requests still waiting fail.
    pub async fn close(self) -> Result<(), ATMError> {
        let (done, closed) = oneshot::channel();
        if self
            .sender
            .shared
            .out
            .send(Outgoing::Close { done })
            .await
            .is_ok()
        {
            let _ = closed.await;
        }
        Ok(())
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
    /// their receiver; the member's keys are needed to open them. A task owns
    /// the socket from here; send through [`TspMuxWebSocket::sender`].
    pub async fn connect_websocket_mux(
        &self,
        profile: &Arc<ATMProfile>,
    ) -> Result<TspMuxWebSocket, ATMError> {
        self.connect_mux(profile, None).await
    }

    /// [`connect_websocket_mux`](Self::connect_websocket_mux), kept connected:
    /// when the socket drops, it connects again by itself, paced by
    /// `reconnect`, until the client closes or drops it. The first connection
    /// must succeed, as for `connect_websocket_mux`; this fails as that does.
    ///
    /// While it is down, [`TspMuxWebSocket::state`] is
    /// [`TspMuxState::Reconnecting`], sends and requests fail at once
    /// (`ATMError::Disconnected`), and requests that were waiting fail. Each
    /// new connection is announced by [`TspMuxFrame::Reconnected`] from
    /// [`TspMuxWebSocket::recv`]. It gives up (state `Closed`, `recv` fails)
    /// only when the mediator no longer accepts `tsp-mux`, or when a newer
    /// connection for the same DID replaced this one. See the
    /// [module docs](super::tsp_mux) for what carries over (nothing).
    pub async fn connect_websocket_mux_managed(
        &self,
        profile: &Arc<ATMProfile>,
        reconnect: TspMuxReconnect,
    ) -> Result<TspMuxWebSocket, ATMError> {
        self.connect_mux(profile, Some(reconnect)).await
    }

    async fn connect_mux(
        &self,
        profile: &Arc<ATMProfile>,
        reconnect: Option<TspMuxReconnect>,
    ) -> Result<TspMuxWebSocket, ATMError> {
        let (principal, mediator) = profile.dids()?;
        let (principal, mediator) = (principal.to_string(), mediator.to_string());
        let demux = Demux {
            principal: principal.clone(),
            mediator: mediator.clone(),
            opener: Arc::new(AtmOpener {
                atm: self.atm.clone(),
                principal: principal.clone(),
            }),
            resolver: super::mux::proof_resolver(self.atm),
        };
        let dialer: Arc<dyn Dialer> = Arc::new(AtmDialer {
            atm: self.atm.clone(),
            profile: Arc::clone(profile),
        });
        let (ws, ready) = open_mux(dialer.as_ref(), &demux, MUX_READY_TIMEOUT).await?;
        let redial = reconnect.map(|policy| Redial {
            dialer,
            policy,
            ready_wait: MUX_READY_TIMEOUT,
        });
        Ok(start(
            self.atm.clone(),
            Arc::clone(profile),
            ws,
            demux,
            ready,
            redial,
        ))
    }
}

/// Hand an open mux connection to its task.
fn start(
    atm: ATM,
    profile: Arc<ATMProfile>,
    ws: TspWsStream,
    demux: Demux,
    ready: MuxReady,
    redial: Option<Redial>,
) -> TspMuxWebSocket {
    let (out_tx, out_rx) = mpsc::channel(16);
    let (frames_tx, frames_rx) = mpsc::channel(FRAME_BUFFER);
    let (state, _) = watch::channel(TspMuxState::Open);
    let (ready_tx, _) = watch::channel(Some(ready.clone()));
    let shared = Arc::new(Shared {
        atm,
        profile,
        principal: demux.principal.clone(),
        mediator: demux.mediator.clone(),
        out: out_tx,
        pending: std::sync::Mutex::new(HashMap::new()),
        abandoned: std::sync::Mutex::new(std::collections::VecDeque::new()),
        state,
        ready: ready_tx,
    });
    tokio::spawn(run(
        ws,
        demux,
        Arc::clone(&shared),
        out_rx,
        frames_tx,
        redial,
    ));
    TspMuxWebSocket {
        frames: frames_rx,
        sender: TspMuxSender { shared },
        ready,
        members: MuxMembers::connected(),
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

    async fn demux(k: &Keys) -> Demux {
        demux_for(MEDIATOR, k).await
    }

    async fn demux_for(mediator: &str, k: &Keys) -> Demux {
        use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
        let client = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .unwrap();
        Demux {
            principal: PRINCIPAL.into(),
            mediator: mediator.into(),
            opener: Arc::new(TestOpener {
                principal_decryption: k.principal.decryption_key,
                known: vec![
                    (mediator.into(), k.mediator.verifying_key),
                    ("did:example:sender".into(), k.sender.verifying_key),
                ],
            }),
            resolver: Arc::new(trust_tasks_proof::affinidi::CachedDidResolver::new(
                Arc::new(client),
            )),
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
        await_ready(&mut ws, &demux(k).await, Duration::from_millis(500)).await
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
        let d = demux(&k).await;

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
        let d = demux(&k).await;
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
        let d = demux(&k).await;
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

    /// An event's proof, when it has one, must verify (the spec recommends
    /// one; the TSP envelope already shows the mediator sent it).
    #[tokio::test]
    async fn an_event_with_a_proof_that_fails_is_ignored() {
        use affinidi_secrets_resolver::secrets::Secret;
        use trust_tasks_proof::affinidi::{SignOptions, sign_trust_task};
        let seed = [9u8; 32];
        let mb = Secret::generate_ed25519(None, Some(&seed))
            .get_public_keymultibase()
            .unwrap();
        let mediator = format!("did:key:{mb}");
        let secret = Secret::generate_ed25519(Some(&format!("{mediator}#{mb}")), Some(&seed));
        let mut k = keys();
        k.mediator = PrivateVid::generate(&mediator);
        let d = demux_for(&mediator, &k).await;

        let doc: Value =
            serde_json::from_slice(&event_doc(&mediator, PRINCIPAL, ready_payload())).unwrap();
        let signed = sign_trust_task(&doc, &secret, SignOptions::new())
            .await
            .unwrap();
        let sealed =
            |doc: &Value| seal(&k.mediator, &k.principal, &serde_json::to_vec(doc).unwrap());

        assert!(matches!(
            d.classify(sealed(&signed)).await,
            Some(TspMuxFrame::Event(e)) if e.event == MuxEventKind::Ready
        ));
        let mut forged = signed.clone();
        forged["payload"]["muxNonce"] = json!("B".repeat(43));
        assert!(d.classify(sealed(&forged)).await.is_none());
    }

    #[tokio::test]
    async fn the_socket_keeps_its_member_set() {
        let k = keys();
        let d = demux(&k).await;
        let mut members = MuxMembers::connected();
        let event = |payload: Value| {
            seal(
                &k.mediator,
                &k.principal,
                &event_doc(MEDIATOR, PRINCIPAL, payload),
            )
        };
        for frame in [
            event(json!({"event": "attached", "dids": [
                {"did": WORK, "reason": "connect", "scope": ["receive", "pickup"],
                 "deliveryActive": true, "grantId": "g1"},
                {"did": "did:example:home", "reason": "connect", "scope": ["receive"],
                 "deliveryActive": true}]})),
            event(json!({"event": "detached", "dids": [
                {"did": "did:example:home", "reason": "expired"}]})),
            seal(&k.sender, &k.work, b"data does not change the set"),
        ] {
            if let Some(TspMuxFrame::Event(e)) = d.classify(frame).await {
                members.apply(&e);
            }
        }
        assert_eq!(members.len(), 1);
        assert!(members.is_reachable(WORK));
        assert!(!members.is_reachable("did:example:home"));
        assert_eq!(members.get(WORK).unwrap().grant_id.as_deref(), Some("g1"));
    }

    /// A Trust Task answer from the mediator (a `#response` or a Trust Task
    /// error, with `threadId`) is sorted out for its request; without a
    /// thread, or from anyone else, it is data.
    #[tokio::test]
    async fn trust_task_answers_are_sorted_out_by_thread() {
        let k = keys();
        let d = demux(&k).await;
        let doc = |v: Value| seal(&k.mediator, &k.principal, &serde_json::to_vec(&v).unwrap());
        let answer = doc(json!({
            "type": "https://trusttasks.org/spec/messaging/mux/ack/0.1#response",
            "threadId": "urn:uuid:1",
            "payload": {"acked": [], "refused": []},
        }));
        match d.sort(answer.clone()).await {
            Sorted::Answer {
                thread_id, frame, ..
            } => {
                assert_eq!(thread_id, "urn:uuid:1");
                assert_eq!(frame, answer);
            }
            _ => panic!("expected an answer"),
        }
        let error = doc(json!({
            "type": "https://trusttasks.org/spec/trust-task-error/0.6",
            "threadId": "urn:uuid:2",
            "payload": {"code": "messaging/mux:notMuxConnection"},
        }));
        assert!(
            matches!(d.sort(error).await, Sorted::Answer { thread_id, .. } if thread_id == "urn:uuid:2")
        );
        // No thread: not an answer.
        let unthreaded = doc(json!({
            "type": "https://trusttasks.org/spec/messaging/ping/0.2#response",
        }));
        assert!(matches!(
            d.sort(unthreaded).await,
            Sorted::Frame(TspMuxFrame::Data { .. })
        ));
        // From a peer, though it looks like one: data, unopened.
        let forged = seal(
            &k.sender,
            &k.principal,
            &serde_json::to_vec(&json!({
                "type": "https://trusttasks.org/spec/messaging/mux/ack/0.1#response",
                "threadId": "urn:uuid:1",
            }))
            .unwrap(),
        );
        assert!(matches!(
            d.sort(forged).await,
            Sorted::Frame(TspMuxFrame::Data { .. })
        ));
    }

    /// A notice from the mediator is handed over verified, as a notice; one
    /// whose proof fails is still handed over, as data, since it is stored.
    #[tokio::test]
    async fn notices_are_verified_and_typed() {
        use affinidi_secrets_resolver::secrets::Secret;
        use trust_tasks_proof::affinidi::{SignOptions, sign_trust_task};
        let seed = [7u8; 32];
        let mb = Secret::generate_ed25519(None, Some(&seed))
            .get_public_keymultibase()
            .unwrap();
        let mediator = format!("did:key:{mb}");
        let secret = Secret::generate_ed25519(Some(&format!("{mediator}#{mb}")), Some(&seed));
        let mut k = keys();
        k.mediator = PrivateVid::generate(&mediator);
        let d = demux_for(&mediator, &k).await;
        let notice = json!({
            "id": "urn:uuid:9a8b7c6d-5e4f-4a3b-9c2d-1e0f9a8b7c01",
            "type": NOTICE_TYPE,
            "issuer": mediator,
            "recipient": PRINCIPAL,
            "issuedAt": "2026-11-12T09:00:00Z",
            "payload": {"notice": "grantsRevoked", "revocations": [
                {"did": WORK, "grantIds": ["g1"], "reason": "revokedByMember",
                 "revokedAt": "2026-11-12T08:59:00Z"}]},
        });
        let signed = sign_trust_task(&notice, &secret, SignOptions::new())
            .await
            .unwrap();
        let sealed =
            |doc: &Value| seal(&k.mediator, &k.principal, &serde_json::to_vec(doc).unwrap());
        let frame = sealed(&signed);
        match d.sort(frame.clone()).await {
            Sorted::Frame(TspMuxFrame::Notice { notice, frame: f }) => {
                assert_eq!(f, frame);
                assert_eq!(
                    serde_json::to_value(&notice.payload).unwrap()["notice"],
                    "grantsRevoked"
                );
            }
            _ => panic!("expected a notice"),
        }
        let mut forged = signed.clone();
        forged["payload"]["revocations"][0]["did"] = json!("did:example:other");
        assert!(matches!(
            d.sort(sealed(&forged)).await,
            Sorted::Frame(TspMuxFrame::Data { .. })
        ));
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

    // ─── managed reconnect ──────────────────────────────────────────────────

    use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;

    /// What a fake mediator does with one accepted connection.
    struct Conn {
        selected: &'static str,
        frames: Vec<Message>,
        /// Close with this code and reason after the frames; `None` holds it
        /// open.
        close: Option<(CloseCode, &'static str)>,
    }

    /// Dials the fake mediator, offering `tsp-mux`.
    struct LocalDialer {
        addr: std::net::SocketAddr,
    }

    #[async_trait::async_trait]
    impl Dialer for LocalDialer {
        async fn dial(&self) -> Result<(TspWsStream, Option<String>), ATMError> {
            let mut req = tokio_tungstenite::tungstenite::ClientRequestBuilder::new(
                format!("ws://{}/ws", self.addr).parse().unwrap(),
            )
            .with_sub_protocol("bearer.t");
            for p in MUX_OFFER {
                req = req.with_sub_protocol(p);
            }
            let (ws, resp) = tokio_tungstenite::connect_async(req)
                .await
                .map_err(|e| ATMError::TransportError(format!("dial: {e}")))?;
            let selected = resp
                .headers()
                .get("sec-websocket-protocol")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            Ok((ws, selected))
        }
    }

    /// A mediator that serves `conns` in turn, one per accepted connection,
    /// and counts the connections it accepted.
    async fn serve_each(
        conns: Vec<Conn>,
    ) -> (Arc<LocalDialer>, Arc<std::sync::atomic::AtomicUsize>) {
        use futures_util::StreamExt;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio_tungstenite::tungstenite::protocol::CloseFrame;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&accepted);
        tokio::spawn(async move {
            for conn in conns {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                count.fetch_add(1, Ordering::SeqCst);
                let selected = conn.selected;
                #[allow(clippy::result_large_err)]
                let callback = move |_: &Request, mut resp: Response| {
                    resp.headers_mut()
                        .insert("sec-websocket-protocol", HeaderValue::from_static(selected));
                    Ok(resp)
                };
                let mut ws = tokio_tungstenite::accept_hdr_async(tcp, callback)
                    .await
                    .unwrap();
                for f in conn.frames {
                    let _ = ws.send(f).await;
                }
                if let Some((code, reason)) = conn.close {
                    let _ = ws
                        .close(Some(CloseFrame {
                            code,
                            reason: reason.into(),
                        }))
                        .await;
                }
                tokio::spawn(async move { while ws.next().await.is_some() {} });
            }
            // Refuse anything after the script: keep accepting and dropping.
            while let Ok((tcp, _)) = listener.accept().await {
                count.fetch_add(1, Ordering::SeqCst);
                drop(tcp);
            }
        });
        (Arc::new(LocalDialer { addr }), accepted)
    }

    async fn test_atm() -> ATM {
        use affinidi_tdk_common::{TDKSharedState, config::TDKConfig};
        let tdk = Arc::new(
            TDKSharedState::new(TDKConfig::headless().unwrap())
                .await
                .unwrap(),
        );
        ATM::new(crate::config::ATMConfig::builder().build().unwrap(), tdk)
            .await
            .unwrap()
    }

    fn test_profile() -> Arc<ATMProfile> {
        Arc::new(ATMProfile {
            inner: Arc::new(crate::profiles::ATMProfileInner {
                did: PRINCIPAL.into(),
                alias: "phone".into(),
                mediator: Arc::new(None),
            }),
        })
    }

    /// Open a socket on the fake mediator as `connect_mux` does, managed when
    /// `policy` is given.
    async fn open_on(
        dialer: Arc<LocalDialer>,
        k: &Keys,
        policy: Option<TspMuxReconnect>,
    ) -> TspMuxWebSocket {
        let demux = demux(k).await;
        let (ws, ready) = open_mux(dialer.as_ref(), &demux, Duration::from_secs(2))
            .await
            .expect("first connection");
        let redial = policy.map(|policy| Redial {
            dialer: dialer as Arc<dyn Dialer>,
            policy,
            ready_wait: Duration::from_secs(2),
        });
        start(test_atm().await, test_profile(), ws, demux, ready, redial)
    }

    async fn state_becomes(
        state: &mut watch::Receiver<TspMuxState>,
        want: impl Fn(&TspMuxState) -> bool,
    ) -> TspMuxState {
        timeout(Duration::from_secs(5), async {
            loop {
                if want(&state.borrow_and_update()) {
                    return state.borrow().clone();
                }
                state.changed().await.expect("state sender alive");
            }
        })
        .await
        .expect("state reached in time")
    }

    use tokio::time::timeout;

    /// A managed socket that the mediator closes says why it is down, refuses
    /// sends while it is, reconnects after its backoff, and announces the new
    /// connection with its `ready` (R6.2).
    #[tokio::test]
    async fn a_managed_socket_reconnects_and_says_so() {
        let k = keys();
        let (dialer, accepted) = serve_each(vec![
            Conn {
                selected: "tsp-mux",
                frames: vec![Message::Binary(ready_frame(&k).into())],
                close: Some((CloseCode::Away, "instance shutting down")),
            },
            Conn {
                selected: "tsp-mux",
                frames: vec![Message::Binary(ready_frame(&k).into())],
                close: None,
            },
        ])
        .await;
        let policy = TspMuxReconnect::default()
            .with_delays(Duration::from_millis(300), Duration::from_secs(1));
        let mut sock = open_on(dialer, &k, Some(policy)).await;
        let ready_watch = sock.sender().ready();
        assert!(ready_watch.borrow().is_some(), "ready while open");
        let mut state = sock.state();
        let down = state_becomes(&mut state, |s| {
            matches!(s, TspMuxState::Reconnecting { .. })
        })
        .await;
        assert!(
            matches!(&down, TspMuxState::Reconnecting { attempt: 1, reason } if reason.contains("instance shutting down")),
            "{down:?}"
        );
        assert!(ready_watch.borrow().is_none(), "no ready while down");
        let err = sock.send(b"while down").await.unwrap_err();
        assert!(matches!(err, ATMError::Disconnected(_)), "{err}");

        let frame = timeout(Duration::from_secs(5), sock.recv())
            .await
            .expect("reconnected in time")
            .expect("no error")
            .expect("a frame");
        let TspMuxFrame::Reconnected { ready } = frame else {
            panic!("expected Reconnected, got {frame:?}");
        };
        assert_eq!(ready.mux_nonce, NONCE);
        assert_eq!(sock.ready(), &*ready);
        assert_eq!(
            ready_watch.borrow().as_ref(),
            Some(&*ready),
            "the new ready, for re-attaching"
        );
        assert_eq!(*sock.state().borrow(), TspMuxState::Open);
        assert_eq!(accepted.load(std::sync::atomic::Ordering::SeqCst), 2);
        sock.close().await.unwrap();
    }

    /// A managed socket replaced by a newer connection for the same DID stops
    /// rather than take the connection back.
    #[tokio::test]
    async fn a_replaced_managed_socket_does_not_reconnect() {
        let k = keys();
        let (dialer, accepted) = serve_each(vec![Conn {
            selected: "tsp-mux",
            frames: vec![Message::Binary(ready_frame(&k).into())],
            close: Some((CloseCode::Policy, REPLACED_REASON)),
        }])
        .await;
        let policy = TspMuxReconnect::default()
            .with_delays(Duration::from_millis(20), Duration::from_millis(50));
        let mut sock = open_on(dialer, &k, Some(policy)).await;
        let err = timeout(Duration::from_secs(5), sock.recv())
            .await
            .unwrap()
            .unwrap_err();
        assert!(
            err.to_string().contains("replaced by a newer connection"),
            "{err}"
        );
        assert!(matches!(*sock.state().borrow(), TspMuxState::Closed { .. }));
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(accepted.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    /// Only the mediator's own replacement close stops a managed socket: code
    /// 1008 with exactly its reason. Other codes, or text that merely holds
    /// the words, do not.
    #[test]
    fn only_the_exact_replacement_close_counts() {
        use tokio_tungstenite::tungstenite::protocol::CloseFrame;
        let close = |code, reason: &str| CloseFrame {
            code,
            reason: reason.to_string().into(),
        };
        assert!(is_replacement(&close(CloseCode::Policy, REPLACED_REASON)));
        assert!(!is_replacement(&close(CloseCode::Away, REPLACED_REASON)));
        assert!(!is_replacement(&close(CloseCode::Normal, REPLACED_REASON)));
        assert!(!is_replacement(&close(
            CloseCode::Policy,
            "x: replaced by a newer connection (forwarded)"
        )));
        assert!(!is_replacement(&close(CloseCode::Policy, "")));
    }

    /// A close that only looks like a replacement (another code, or the words
    /// inside other text) is an ordinary drop: the managed socket reconnects.
    #[tokio::test]
    async fn a_lookalike_replacement_close_still_reconnects() {
        let k = keys();
        let (dialer, accepted) = serve_each(vec![
            Conn {
                selected: "tsp-mux",
                frames: vec![Message::Binary(ready_frame(&k).into())],
                close: Some((CloseCode::Away, REPLACED_REASON)),
            },
            Conn {
                selected: "tsp-mux",
                frames: vec![Message::Binary(ready_frame(&k).into())],
                close: Some((
                    CloseCode::Policy,
                    "upstream: replaced by a newer connection",
                )),
            },
            Conn {
                selected: "tsp-mux",
                frames: vec![Message::Binary(ready_frame(&k).into())],
                close: None,
            },
        ])
        .await;
        let policy = TspMuxReconnect::default()
            .with_delays(Duration::from_millis(20), Duration::from_millis(50));
        let mut sock = open_on(dialer, &k, Some(policy)).await;
        for _ in 0..2 {
            let frame = timeout(Duration::from_secs(5), sock.recv())
                .await
                .unwrap()
                .unwrap();
            assert!(
                matches!(frame, Some(TspMuxFrame::Reconnected { .. })),
                "{frame:?}"
            );
        }
        assert_eq!(*sock.state().borrow(), TspMuxState::Open);
        assert_eq!(accepted.load(std::sync::atomic::Ordering::SeqCst), 3);
        sock.close().await.unwrap();
    }

    /// When the mediator stops selecting `tsp-mux`, a managed socket gives up:
    /// `recv` says why and the state is `Closed`.
    #[tokio::test]
    async fn a_managed_socket_stops_when_mux_is_no_longer_offered() {
        let k = keys();
        let (dialer, _) = serve_each(vec![
            Conn {
                selected: "tsp-mux",
                frames: vec![Message::Binary(ready_frame(&k).into())],
                close: Some((CloseCode::Away, "bye")),
            },
            Conn {
                selected: "tsp",
                frames: vec![],
                close: None,
            },
        ])
        .await;
        let policy = TspMuxReconnect::default()
            .with_delays(Duration::from_millis(20), Duration::from_millis(50));
        let mut sock = open_on(dialer, &k, Some(policy)).await;
        let err = timeout(Duration::from_secs(5), sock.recv())
            .await
            .expect("in time")
            .unwrap_err();
        assert!(err.to_string().contains("mux unavailable"), "{err}");
        assert!(matches!(*sock.state().borrow(), TspMuxState::Closed { .. }));
    }

    /// A failed try backs off and counts its attempts; a later one succeeds.
    #[tokio::test]
    async fn failed_tries_are_counted_until_one_connects() {
        let k = keys();
        let (dialer, accepted) = serve_each(vec![
            Conn {
                selected: "tsp-mux",
                frames: vec![Message::Binary(ready_frame(&k).into())],
                close: Some((CloseCode::Away, "bye")),
            },
            // Upgraded but never sends `ready`, then goes.
            Conn {
                selected: "tsp-mux",
                frames: vec![],
                close: Some((CloseCode::Away, "not ready")),
            },
            Conn {
                selected: "tsp-mux",
                frames: vec![Message::Binary(ready_frame(&k).into())],
                close: None,
            },
        ])
        .await;
        let policy = TspMuxReconnect::default()
            .with_delays(Duration::from_millis(20), Duration::from_millis(100));
        let mut sock = open_on(dialer, &k, Some(policy)).await;
        let mut state = sock.state();
        let second = state_becomes(
            &mut state,
            |s| matches!(s, TspMuxState::Reconnecting { attempt, .. } if *attempt >= 2),
        )
        .await;
        assert!(
            matches!(second, TspMuxState::Reconnecting { attempt: 2, .. }),
            "{second:?}"
        );
        let frame = timeout(Duration::from_secs(5), sock.recv())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(
            matches!(frame, TspMuxFrame::Reconnected { .. }),
            "{frame:?}"
        );
        assert_eq!(accepted.load(std::sync::atomic::Ordering::SeqCst), 3);
        sock.close().await.unwrap();
    }

    /// A plain socket does not reconnect: the close ends `recv` with the
    /// mediator's reason, and nothing dials again.
    #[tokio::test]
    async fn a_plain_socket_does_not_reconnect() {
        let k = keys();
        let (dialer, accepted) = serve_each(vec![Conn {
            selected: "tsp-mux",
            frames: vec![Message::Binary(ready_frame(&k).into())],
            close: Some((CloseCode::Away, "instance shutting down")),
        }])
        .await;
        let mut sock = open_on(dialer, &k, None).await;
        let err = timeout(Duration::from_secs(5), sock.recv())
            .await
            .unwrap()
            .unwrap_err();
        assert!(err.to_string().contains("instance shutting down"), "{err}");
        assert!(matches!(*sock.state().borrow(), TspMuxState::Closed { .. }));
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(accepted.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    /// Closing a managed socket while it is down stops it for good.
    #[tokio::test]
    async fn closing_while_down_stops_reconnecting() {
        let k = keys();
        let (dialer, accepted) = serve_each(vec![Conn {
            selected: "tsp-mux",
            frames: vec![Message::Binary(ready_frame(&k).into())],
            close: Some((CloseCode::Away, "bye")),
        }])
        .await;
        let policy =
            TspMuxReconnect::default().with_delays(Duration::from_secs(2), Duration::from_secs(2));
        let sock = open_on(dialer, &k, Some(policy)).await;
        let mut state = sock.state();
        state_becomes(&mut state, |s| {
            matches!(s, TspMuxState::Reconnecting { .. })
        })
        .await;
        sock.close().await.unwrap();
        let closed = state_becomes(&mut state, |s| matches!(s, TspMuxState::Closed { .. })).await;
        assert_eq!(
            closed,
            TspMuxState::Closed {
                reason: "closed by the client".into()
            }
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(accepted.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    /// A request failed by a drop is remembered, so its stored answer, when
    /// it comes on the next connection, is this socket's to consume (R1.7),
    /// not left for an owner that no longer waits.
    #[tokio::test]
    async fn an_answer_to_a_request_failed_by_a_drop_is_consumed() {
        let k = keys();
        let (dialer, _) = serve_each(vec![Conn {
            selected: "tsp-mux",
            frames: vec![Message::Binary(ready_frame(&k).into())],
            close: None,
        }])
        .await;
        let sock = open_on(dialer, &k, None).await;
        let shared = Arc::clone(&sock.sender.shared);
        let (answer, answered) = oneshot::channel();
        shared.pending.lock().unwrap().insert(
            "urn:uuid:t1".into(),
            Pending {
                frame_id: "f1".into(),
                answer,
            },
        );
        shared.lose("network gone");
        let failed = answered.await.unwrap().unwrap_err();
        assert!(matches!(failed, ATMError::Disconnected(_)), "{failed}");
        assert!(matches!(
            *shared.state.borrow(),
            TspMuxState::Reconnecting { attempt: 1, .. }
        ));
        assert_eq!(
            shared.abandoned.lock().unwrap().iter().collect::<Vec<_>>(),
            ["urn:uuid:t1"]
        );
        answer_pending(
            &shared,
            "urn:uuid:t1",
            json!({ "type": "https://trusttasks.org/spec/messaging/mux/attach/0.1#response" }),
            b"frame".to_vec(),
        );
        assert!(shared.abandoned.lock().unwrap().is_empty(), "consumed");
    }

    #[test]
    fn the_backoff_doubles_to_its_cap_and_jitter_stays_in_band() {
        let p = TspMuxReconnect::default();
        let mut d = Duration::ZERO;
        let mut seen = Vec::new();
        for _ in 0..9 {
            d = p.escalate(d);
            seen.push(d.as_secs());
        }
        assert_eq!(seen, [1, 2, 4, 8, 16, 32, 60, 60, 60]);
        assert_eq!(jittered(Duration::ZERO), Duration::ZERO);
        for _ in 0..1000 {
            let j = jittered(Duration::from_secs(10)).as_secs_f64();
            assert!((8.5..11.5).contains(&j), "{j}");
        }
        let p =
            TspMuxReconnect::default().with_delays(Duration::from_secs(5), Duration::from_secs(1));
        assert_eq!(
            p.max_delay,
            Duration::from_secs(5),
            "max is at least initial"
        );
    }
}
