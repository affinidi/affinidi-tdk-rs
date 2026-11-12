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
//! Nothing reconnects here. A dropped socket ends [`TspMuxWebSocket::recv`]
//! (with the mediator's close reason when it gave one), fails every request
//! still waiting, and turns [`TspMuxWebSocket::state`] to
//! [`TspMuxState::Closed`]; the caller decides what to do (R6.2). On a new
//! connection the member set is rebuilt from that connection's `ready` and
//! `attached` events; nothing carries over.

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

/// Whether a `tsp-mux` connection is open (R6.2): watch it with
/// [`TspMuxWebSocket::state`] or [`TspMuxSender::state`].
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum TspMuxState {
    /// The socket is open.
    Open,
    /// The socket is gone, and why: the mediator's close reason, a transport
    /// error, or the client closing it. Nothing reconnects.
    Closed {
        /// What ended it.
        reason: String,
    },
}

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
    state: watch::Sender<TspMuxState>,
}

impl Shared {
    fn closed_error(&self) -> ATMError {
        match &*self.state.borrow() {
            TspMuxState::Closed { reason } => {
                ATMError::TransportError(format!("tsp-mux connection closed: {reason}"))
            }
            TspMuxState::Open => ATMError::TransportError("tsp-mux connection closed".into()),
        }
    }

    /// The connection ended: say so, and fail every request still waiting.
    fn finish(&self, reason: String) {
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

    /// Whether the connection is open, as a watch: it changes once, to
    /// [`TspMuxState::Closed`], when the socket goes.
    pub fn state(&self) -> watch::Receiver<TspMuxState> {
        self.shared.state.subscribe()
    }
}

/// The task that owns one socket: it reads and sorts every frame, writes what
/// the senders send, and routes Trust Task answers to their requests.
async fn run(
    mut ws: TspWsStream,
    demux: Demux,
    shared: Arc<Shared>,
    mut out: mpsc::Receiver<Outgoing>,
    frames: mpsc::Sender<Result<TspMuxFrame, ATMError>>,
) {
    use futures_util::SinkExt;
    use tokio_tungstenite::tungstenite::Message;
    loop {
        tokio::select! {
            incoming = next_binary(&mut ws) => match incoming {
                Ok(Some(frame)) => match demux.sort(frame).await {
                    Sorted::Frame(f) => {
                        if let TspMuxFrame::Event(e) = &f
                            && let Some(refused) = MuxRefused::from_event(e)
                        {
                            refuse_pending(&shared, &refused);
                        }
                        if frames.send(Ok(f)).await.is_err() {
                            // The application dropped the socket.
                            let _ = ws.close(None).await;
                            shared.finish("dropped by the client".into());
                            return;
                        }
                    }
                    Sorted::Answer { thread_id, doc, frame } => {
                        answer_pending(&shared, &thread_id, doc, frame);
                    }
                    Sorted::Ignore => {}
                },
                Ok(None) => {
                    shared.finish("the socket ended without a close frame".into());
                    return;
                }
                Err(e) => {
                    shared.finish(e.to_string());
                    let _ = frames.send(Err(e)).await;
                    return;
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
                    return;
                }
                // `Shared` holds a sender for as long as this task runs, so
                // this does not happen; stop cleanly if it does.
                None => {
                    let _ = ws.close(None).await;
                    shared.finish("closed by the client".into());
                    return;
                }
            },
            _ = frames.closed() => {
                let _ = ws.close(None).await;
                shared.finish("dropped by the client".into());
                return;
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
    let Some(p) = pending else {
        debug!(
            thread_id,
            "a Trust Task answer for a request not made on this socket; left for its owner"
        );
        return;
    };
    let stored = doc.get("type").and_then(Value::as_str) != Some(ACK_RESPONSE_TYPE);
    let _ = p.answer.send(Ok(doc));
    if stored {
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
    /// connection alone.
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
    /// frame, `Ok(None)` when the stream ended without one. Nothing
    /// reconnects; the members are not reachable through this socket any
    /// more, and frames not acknowledged are delivered again on the next
    /// connection.
    pub async fn recv(&mut self) -> Result<Option<TspMuxFrame>, ATMError> {
        match self.frames.recv().await {
            None => Ok(None),
            Some(Err(e)) => Err(e),
            Some(Ok(frame)) => {
                if let TspMuxFrame::Event(event) = &frame {
                    self.members.apply(event);
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
        let (principal, mediator) = profile.dids()?;
        let (principal, mediator) = (principal.to_string(), mediator.to_string());
        let raw = self.open_raw_socket(profile, &MUX_OFFER).await?;
        let mut ws = raw.ws;
        if let Err(e) = check_selection(raw.selected.as_deref()) {
            let _ = ws.close(None).await;
            return Err(e);
        }
        let demux = Demux {
            principal: principal.clone(),
            mediator: mediator.clone(),
            opener: Arc::new(AtmOpener {
                atm: self.atm.clone(),
                principal: principal.clone(),
            }),
            resolver: super::mux::proof_resolver(self.atm),
        };
        let ready = match await_ready(&mut ws, &demux, MUX_READY_TIMEOUT).await {
            Ok(r) => r,
            Err(e) => {
                let _ = ws.close(None).await;
                return Err(e);
            }
        };
        let (out_tx, out_rx) = mpsc::channel(16);
        let (frames_tx, frames_rx) = mpsc::channel(FRAME_BUFFER);
        let (state, _) = watch::channel(TspMuxState::Open);
        let shared = Arc::new(Shared {
            atm: self.atm.clone(),
            profile: Arc::clone(profile),
            principal,
            mediator,
            out: out_tx,
            pending: std::sync::Mutex::new(HashMap::new()),
            state,
        });
        tokio::spawn(run(ws, demux, Arc::clone(&shared), out_rx, frames_tx));
        Ok(TspMuxWebSocket {
            frames: frames_rx,
            sender: TspMuxSender { shared },
            ready,
            members: MuxMembers::connected(),
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
}
