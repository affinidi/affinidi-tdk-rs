/*!
 * WebSocket transport implementation for Affinidi Messaging SDK.
 */

use super::{
    ReceiveHealth, WebSocketResponses,
    receive_leg::{
        CONSUMER_STALL_AFTER, ProbeStep, UnpackFailure, UnpackSightings, classify_unpack_failure,
        consumer_stalled, frame_hint, probe_step, unpack_failure_disposition,
    },
    ws_cache::MessageCache,
};
use crate::{ATM, SharedState, errors::ATMError, profiles::ATMProfile};
use affinidi_messaging_core::ConnState;
use ahash::{HashMap, HashMapExt};
use futures_util::{SinkExt, StreamExt};
use rand::RngExt;
use std::{collections::VecDeque, sync::Arc, time::Duration};
use tokio::{
    net::TcpStream,
    select,
    sync::{
        broadcast,
        mpsc::{self, Receiver, Sender},
        oneshot, watch,
    },
    task::JoinHandle,
    time::{Interval, interval_at},
};
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream,
    tungstenite::{Bytes, ClientRequestBuilder, Message, error::ProtocolError, http::Uri},
};
use tracing::{Instrument, Level, debug, error, info, span, warn};

type WebSocket = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// How long a socket must stay up before we treat the connection as proven.
///
/// Longer than the 20s watchdog interval, so a "stable" connection is one that
/// completed at least one ping/pong round-trip. See
/// [`WebSocketTransport::on_disconnected`] for why this gate exists.
const STABLE_CONNECTION: Duration = Duration::from_secs(30);

/// How long a control write — a ping, or the close frame of a socket we are
/// giving up on — may take.
///
/// Both write and flush. On a socket whose peer is gone (the half-open socket a
/// laptop wakes up holding) that flush may have nobody to drain it, and the
/// transport task must not park on a frame nobody will read.
const SOCKET_WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// How long the transport task waits for one inbound frame to unpack.
///
/// The unpack runs inline on the transport task and resolves DIDs over the
/// network. Unbounded, a hung resolver stalled the whole socket — reads, sends,
/// the watchdog — behind one frame (R1.2). A timed-out unpack is a transient
/// failure: the frame is left at the mediator for redelivery.
const UNPACK_TIMEOUT: Duration = Duration::from_secs(20);

/// How long the transport task waits to pack a receive-leg probe (packing can
/// resolve the mediator's DID).
const PROBE_PACK_TIMEOUT: Duration = Duration::from_secs(10);

/// The Message Pickup 3.0 status type — the mediator's answer to a probe.
const STATUS_TYPE: &str = "https://didcomm.org/messagepickup/3.0/status";

/// What the 20s watchdog does on a tick.
#[derive(Debug, PartialEq, Eq)]
enum WatchdogStep {
    /// Nothing outstanding: send a ping.
    Ping,
    /// The last ping went a whole interval with no frame back: the socket is
    /// dead even if the OS still thinks it is open.
    Dead,
    /// A ping is outstanding but reads are paused (inbound caches full), so a
    /// pong could not have been read. Not evidence either way; keep waiting.
    Wait,
}

/// The watchdog's decision, split out so the rule can be tested without a
/// socket.
///
/// The missed-pong check is what detects a half-open socket — the peer gone
/// with no FIN or RST ever arriving, as after sleep or a network change. The
/// OS can keep such a socket "open" for a very long time, and without this the
/// transport sits `Connected` on it, receiving nothing.
fn watchdog_step(awaiting_pong: bool, reads_paused: bool) -> WatchdogStep {
    match (awaiting_pong, reads_paused) {
        (false, _) => WatchdogStep::Ping,
        (true, false) => WatchdogStep::Dead,
        (true, true) => WatchdogStep::Wait,
    }
}

/// Close a socket within [`SOCKET_WRITE_TIMEOUT`]; the result is ignored either way.
async fn close_bounded(web_socket: &mut WebSocket) {
    if tokio::time::timeout(SOCKET_WRITE_TIMEOUT, web_socket.close(None))
        .await
        .is_err()
    {
        debug!("WebSocket close did not complete within {SOCKET_WRITE_TIMEOUT:?}; dropping it");
    }
}

/// A standalone task that manages the WebSocket connection to a mediator for a DID Profile
pub(crate) struct WebSocketTransport {
    /// The ATM Profile that this WebSocket connection is associated with
    pub(crate) profile: Arc<ATMProfile>,

    /// SDK Shared state
    shared: Arc<SharedState>,

    /// WebSocket Stream when connected
    web_socket: Option<WebSocket>,

    /// connect_delay_timer
    connect_delay_timer: Option<Interval>,

    /// Delay in seconds for the connection attempts
    /// Used to backoff the connection attempts
    connect_delay: u8,

    /// Counter tracking Websocket Ping/Pong responses
    /// Used to help with detecting when a websocket connection is lost
    awaiting_pong: bool,

    /// When the current socket was established. `None` while disconnected.
    /// Read by [`Self::on_disconnected`] to decide whether the connection
    /// lived long enough to earn a backoff reset.
    connected_at: Option<tokio::time::Instant>,

    /// Unix-seconds expiry of the access token the current socket was opened
    /// with. The mediator force-closes the socket at this time, so we use it
    /// to proactively refresh the token and reconnect *before* expiry rather
    /// than waiting to be kicked. `None` until the first successful connect.
    access_expires_at: Option<u64>,

    /// Cache of inbound messages awaiting to be sent to the SDK
    /// If a MPSC delivery channel is enabled, then this cache isn't used
    inbound_cache: MessageCache,

    /// Possible to send messages to the SDK via a MPSC channel
    /// This bypasses the cache
    direct_channel: Option<broadcast::Sender<WebSocketResponses>>,

    /// Tracks number of next message requests from the SDK
    next_requests: HashMap<u32, oneshot::Sender<WebSocketResponses>>,
    next_requests_list: VecDeque<u32>,

    /// Inbound frames that are handed back **packed** (TSP frames, and every
    /// frame when `skip_unpack_messages` is set) and arrived with nowhere to go.
    ///
    /// These cannot live in [`Self::inbound_cache`], which is keyed by unpacked
    /// DIDComm message id. Without a home of their own they were dropped: the
    /// packed path delivered a frame only if a `Next` request happened to be
    /// outstanding at that instant, or a direct channel was attached. A polling
    /// consumer (`live_stream_next_frame`) leaves microsecond-wide gaps between
    /// one poll returning and the next being registered, and a frame landing in
    /// that gap was gone — the send succeeded, the mediator delivered, and the
    /// consumer waited forever. Queue them here instead and let the next `Next`
    /// drain the queue.
    ///
    /// Bounded by the same count/byte limits as [`Self::inbound_cache`], and
    /// with the same policy: when it fills, the socket-read arm of the select
    /// loop stops reading (backpressure) rather than the cache discarding
    /// anything. See [`Self::packed_cache_is_full`].
    packed_cache: VecDeque<String>,

    /// Running total of `packed_cache`'s payload bytes, so fullness can be
    /// judged without walking the queue.
    packed_cache_bytes: u64,

    /// Latched when `packed_cache` exceeds either limit; cleared once the
    /// consumer has drained it back under both. Mirrors `MessageCache`'s
    /// `cache_full` so the two caches behave identically.
    packed_cache_full: bool,

    /// Skip calling toggle_live_delivery during connection setup
    skip_toggle_live_delivery: bool,

    /// Skip unpacking messages - return them as packed strings instead
    skip_unpack_messages: bool,

    /// When the last Text/Binary frame arrived, or the socket connected —
    /// whichever is later. Drives the receive-leg probe; see
    /// [`super::receive_leg::probe_step`].
    last_data_frame_at: tokio::time::Instant,

    /// The outstanding receive-leg probe: its message id and when it was
    /// written. Cleared by any inbound data frame.
    probe: Option<(String, tokio::time::Instant)>,

    /// Ids of recent probes, so their answers can be recognised and consumed
    /// here rather than handed to the application. Bounded (a handful).
    probe_ids: VecDeque<String>,

    /// When the caches last went from empty to holding frames.
    held_since: Option<tokio::time::Instant>,

    /// When a consumer last took a frame.
    last_take_at: Option<tokio::time::Instant>,

    /// Frames that failed to unpack transiently, counted per mediator id.
    unpack_sightings: UnpackSightings,

    /// The current receive-leg health, and where it is published.
    health: ReceiveHealth,
    health_tx: watch::Sender<ReceiveHealth>,

    /// Re-falsifiable connection-state signal. A transition is published on
    /// every successful (re)connect (`Connected`) and every drop
    /// (`Disconnected`), so observers see live connectivity rather than a
    /// boot-time latch. The matching `Receiver` is handed to the caller by
    /// `start`/`start_with_options` and stored on the `Mediator`.
    conn_state_tx: watch::Sender<ConnState>,
}

/// WebSocket Commands
pub(crate) enum WebSocketCommands {
    /// Stop the WebSocket Connection and shutdown the task
    Stop,

    /// Request to send a notifcation (true) if already connected or when next connects if not connected
    NotifyConnection(oneshot::Sender<bool>),

    /// Send a message to the mediator. The `oneshot` reports the ACTUAL write
    /// result: `Ok(())` once the frame is written to the socket, `Err(reason)`
    /// if the socket is disconnected (reconnect window) or the write fails — so
    /// the caller never sees success for a frame that was not transmitted (R1.1).
    SendMessage(String, oneshot::Sender<Result<(), String>>),

    /// Send inbound messages to a MPSC Channel
    EnableInboundChannel(broadcast::Sender<WebSocketResponses>),

    /// Disable the inbound messages channel
    DisableInboundChannel,

    /// Get Next Message (will intercept before the InbOundChannel)
    /// U32: Unique ID for this request
    Next(u32, oneshot::Sender<WebSocketResponses>),

    /// Cancel this Next request
    CancelNext(u32),

    /// Get a specific message from the cache - will only respond if the message is found
    GetMessage(String, oneshot::Sender<WebSocketResponses>),

    /// If SDK timesout, then cancel the GetMessage request
    CancelGetMessage(String),

    /// Drop the current socket and connect again at once (no backoff). See
    /// [`crate::profiles::ATMProfile::reconnect_websocket`].
    Reconnect,
}

impl WebSocketTransport {
    /// Creates a new WebSocketTransport instance, it auto starts the websocket connection
    /// Returns a Future JoinHandle for this task and a Sender for sending commands to the task
    pub(crate) async fn start(
        profile: Arc<ATMProfile>,
        shared: Arc<SharedState>,
        direct_channel: Option<broadcast::Sender<WebSocketResponses>>,
    ) -> (
        JoinHandle<()>,
        Sender<WebSocketCommands>,
        watch::Receiver<ConnState>,
    ) {
        Self::start_with_options(profile, shared, direct_channel, false, false).await
    }

    pub(crate) async fn start_with_options(
        profile: Arc<ATMProfile>,
        shared: Arc<SharedState>,
        direct_channel: Option<broadcast::Sender<WebSocketResponses>>,
        skip_toggle_live_delivery: bool,
        skip_unpack_messages: bool,
    ) -> (
        JoinHandle<()>,
        Sender<WebSocketCommands>,
        watch::Receiver<ConnState>,
    ) {
        let (task_tx, mut task_rx) = mpsc::channel::<WebSocketCommands>(32);
        let (conn_state_tx, conn_state_rx) = watch::channel(ConnState::Connecting);
        let (health_tx, health_rx) = watch::channel(ReceiveHealth::default());
        // Install the receive-health view before the task can publish to it, so
        // a caller that reads it right after `start` never sees `None`.
        if let Some(mediator) = profile.inner.mediator.as_ref().as_ref() {
            mediator
                .ws_receive_health_rx
                .write()
                .await
                .replace(health_rx);
        }
        let handle = tokio::spawn(async move {
            let mut websocket = WebSocketTransport::new(
                profile,
                shared,
                direct_channel,
                skip_toggle_live_delivery,
                skip_unpack_messages,
                conn_state_tx,
                health_tx,
            );
            websocket.run(&mut task_rx).await;
        });
        (handle, task_tx, conn_state_rx)
    }

    fn new(
        profile: Arc<ATMProfile>,
        shared: Arc<SharedState>,
        direct_channel: Option<broadcast::Sender<WebSocketResponses>>,
        skip_toggle_live_delivery: bool,
        skip_unpack_messages: bool,
        conn_state_tx: watch::Sender<ConnState>,
        health_tx: watch::Sender<ReceiveHealth>,
    ) -> Self {
        WebSocketTransport {
            inbound_cache: MessageCache {
                fetch_cache_limit_count: shared.config.fetch_cache_limit_count,
                fetch_cache_limit_bytes: shared.config.fetch_cache_limit_bytes,
                ..Default::default()
            },
            profile,
            shared,
            web_socket: None,
            connect_delay_timer: None,
            connect_delay: 0,
            awaiting_pong: false,
            connected_at: None,
            access_expires_at: None,
            direct_channel,
            next_requests: HashMap::new(),
            next_requests_list: VecDeque::new(),
            packed_cache: VecDeque::new(),
            packed_cache_bytes: 0,
            packed_cache_full: false,
            skip_toggle_live_delivery,
            skip_unpack_messages,
            last_data_frame_at: tokio::time::Instant::now(),
            probe: None,
            probe_ids: VecDeque::new(),
            held_since: None,
            last_take_at: None,
            unpack_sightings: UnpackSightings::default(),
            health: ReceiveHealth::default(),
            health_tx,
            conn_state_tx,
        }
    }

    /// Starts the WebSocket Connection and management to the mediator
    async fn run(&mut self, task_rx: &mut Receiver<WebSocketCommands>) {
        let _span = span!(Level::DEBUG, "websocket_run", profile = %self.profile.inner.alias);

        async move {
            // ATM utility for this connection
            let atm = ATM {
                inner: self.shared.clone(),
            };

            // Set up a watchdog to ping the mediator every 20 seconds
            let mut watchdog = interval_at(
                tokio::time::Instant::now() + Duration::from_secs(20),
                Duration::from_secs(20),
            );

            let mut notify_connection: Option<oneshot::Sender<bool>> = None;

            // Armed on each successful connect; drives a proactive token
            // refresh + reconnect before the mediator closes the socket at
            // access-token expiry.
            let mut refresh_deadline: Option<tokio::time::Instant> = None;

            loop {
                if self.web_socket.is_none() && self.connect_delay_timer.is_none() {
                    debug!("WebSocket not connected, starting connection attempt in {} seconds", self.connect_delay);
                    if self.connect_delay == 0 {
                        // Tick immediately
                        self.connect_delay_timer = Some(tokio::time::interval(Duration::from_secs(1)));
                    } else {
                        // Apply ±15% jitter so many clients disconnected at
                        // once don't reconnect in lock-step (thundering herd).
                        let delay = jittered_backoff(self.connect_delay);
                        self.connect_delay_timer = Some(tokio::time::interval_at(
                            tokio::time::Instant::now() + delay,
                            delay,
                        ));
                    }
                }

                select! {
                    Some(_) = WebSocketTransport::conditional_reconnect_delay(&mut self.connect_delay_timer), if self.web_socket.is_none() => {
                        debug!("Attempt to reconnect");
                        self.web_socket = self._handle_connection(&atm).await;
                        if self.web_socket.is_some() {
                            // Single success site for the first connect AND every
                            // reconnect — publish the live connection signal here.
                            let _ = self.conn_state_tx.send(ConnState::Connected);
                            // A fresh socket starts its silence clock now, with
                            // no probe out: the connect itself re-enabled live
                            // delivery, which is what a probe would have asked.
                            self.last_data_frame_at = tokio::time::Instant::now();
                            self.probe = None;
                            // Arm the proactive-refresh timer for this socket.
                            refresh_deadline = self.refresh_deadline();
                            if notify_connection.is_some() {
                                let _ = notify_connection.unwrap().send(true);
                                notify_connection = None;
                            }
                        }
                    },
                    Some(_) = Self::conditional_refresh(refresh_deadline), if self.web_socket.is_some() => {
                        debug!("Access token nearing expiry; refreshing and reconnecting");
                        refresh_deadline = None; // re-armed on the next connect
                        if let Ok((profile_did, mediator_did)) = self.profile.dids() {
                            // Mint a fresh access token via the refresh-token
                            // flow (mediator re-checks the DID is still allowed
                            // to connect) so the reconnect below carries a token
                            // good for another full lifetime.
                            if let Err(e) = self
                                .shared
                                .tdk_common
                                .authentication()
                                .refresh(profile_did.to_string(), mediator_did.to_string())
                                .await
                            {
                                warn!("Proactive token refresh failed ({e}); reconnecting to re-authenticate");
                            }
                        }
                        // Reconnect immediately (no backoff) so the new socket
                        // uses the fresh token before the old one expires.
                        if let Some(web_socket) = self.web_socket.as_mut() {
                            close_bounded(web_socket).await;
                        }
                        self.web_socket = None;
                        self.fail_pending_requests();
                        // Self-initiated reconnect (not a failure): keep the
                        // immediate retry, but clear the stability marker so the
                        // fresh socket has to earn its own reset.
                        self.connected_at = None;
                        self.connect_delay = 0;
                        self.connect_delay_timer = None;
                    },
                    _ = watchdog.tick(), if self.web_socket.is_some() => {
                        let reads_paused =
                            self.inbound_cache.is_full() || self.packed_cache_is_full();
                        let dead = match watchdog_step(self.awaiting_pong, reads_paused) {
                            WatchdogStep::Wait => false,
                            WatchdogStep::Dead => {
                                warn!("Missed Pong, closing connection");
                                true
                            }
                            WatchdogStep::Ping => match self.web_socket.as_mut() {
                                Some(web_socket) => {
                                    // `awaiting_pong` used to be cleared here and
                                    // never set, which left the missed-pong check
                                    // above unreachable: a half-open socket was
                                    // never detected. Any inbound frame clears it.
                                    match tokio::time::timeout(
                                        SOCKET_WRITE_TIMEOUT,
                                        web_socket.send(Message::Ping(Bytes::new())),
                                    )
                                    .await
                                    {
                                        Ok(Ok(())) => {
                                            self.awaiting_pong = true;
                                            false
                                        }
                                        Ok(Err(e)) => {
                                            warn!("WebSocket ping failed ({e}); closing connection");
                                            true
                                        }
                                        Err(_) => {
                                            warn!("WebSocket ping could not be written; closing connection");
                                            true
                                        }
                                    }
                                }
                                None => false,
                            },
                        };
                        if dead {
                            if let Some(web_socket) = self.web_socket.as_mut() {
                                close_bounded(web_socket).await;
                            }
                            self.web_socket = None;
                            self.awaiting_pong = false;
                            self.fail_pending_requests();
                            self.on_disconnected();
                        } else {
                            self.check_receive_leg(&atm).await;
                        }
                    },
                    cmd = task_rx.recv() => {
                        match cmd {
                            Some(WebSocketCommands::NotifyConnection(sender)) => {
                                if self.web_socket.is_some() {
                                    let _ = sender.send(self.web_socket.is_some());
                                } else {
                                    notify_connection = Some(sender);
                                }
                            },
                            Some(WebSocketCommands::SendMessage(msg, reply)) => {
                                let result = if let Some(web_socket) = self.web_socket.as_mut() {
                                    debug!("Sending message to websocket");
                                    match web_socket.send(Message::text(msg)).await {
                                        Ok(_) => {
                                            debug!("Message sent");
                                            Ok(())
                                        }
                                        Err(e) => {
                                            error!("Error sending message: {:?}", e);
                                            Err(format!("websocket write failed: {e}"))
                                        }
                                    }
                                } else {
                                    // The socket is `None` for the whole reconnect
                                    // window — the frame was NOT transmitted. Report
                                    // the failure instead of silently dropping it and
                                    // letting the caller believe it was sent (R1.1).
                                    warn!("SendMessage while websocket disconnected; not transmitted");
                                    Err("websocket is not connected".to_string())
                                };
                                let _ = reply.send(result);
                            },
                            Some(WebSocketCommands::Stop) => {
                                debug!("Stopping WebSocket connection");
                                if let Some(web_socket) = self.web_socket.as_mut() {
                                    close_bounded(web_socket).await;
                                }
                                break;
                            },
                            Some(WebSocketCommands::EnableInboundChannel(sender)) => {
                                debug!("Enabling direct channel");
                                self.direct_channel = Some(sender);
                            },
                            Some(WebSocketCommands::DisableInboundChannel) => {
                                debug!("Disabling direct channel");
                                self.direct_channel = None;
                            },
                            Some(WebSocketCommands::Next(id, sender)) => {
                                debug!("Next message requested");
                                // Packed frames first: they are strictly older than
                                // anything a later poll could produce, and they have no
                                // other way out — the DIDComm cache is keyed by unpacked
                                // message id and cannot hold them.
                                // A `Next` is the consumer showing up, whether or
                                // not there is anything to take.
                                self.last_take_at = Some(tokio::time::Instant::now());
                                if let Some(packed) = self.pop_packed() {
                                    debug!("Serving packed message from cache");
                                    let _ = sender.send(WebSocketResponses::PackedMessageReceived(Box::new(packed)));
                                } else if let Some((message, metadata)) = self.inbound_cache.next() {
                                    let _ = sender.send(WebSocketResponses::MessageReceived(Box::new(message), Box::new(metadata)));
                                } else {
                                    self.next_requests.insert(id, sender);
                                    self.next_requests_list.push_back(id);
                                }
                            },
                            Some(WebSocketCommands::CancelNext(id)) => {
                                debug!("Next message cancelled");
                                self.next_requests.remove(&id);
                                self.next_requests_list.retain(|&x| x != id);

                            },
                            Some(WebSocketCommands::GetMessage(id, sender)) => {
                                self.last_take_at = Some(tokio::time::Instant::now());
                                if let Some((sender, message, metadata)) = self.inbound_cache.get_or_add_wanted(&id, sender) {
                                    debug!("Message found in cache");
                                    let _ = sender.send(WebSocketResponses::MessageReceived(Box::new(message), Box::new(metadata)));
                                } else {
                                    debug!("Message ({}) not found in cache, added to wanted list", id);
                                }
                            }
                            Some(WebSocketCommands::Reconnect) => {
                                debug!("Reconnect requested");
                                if let Some(web_socket) = self.web_socket.as_mut() {
                                    close_bounded(web_socket).await;
                                }
                                self.web_socket = None;
                                self.awaiting_pong = false;
                                self.fail_pending_requests();
                                // Asked for, not a failure: immediate retry, and
                                // the fresh socket earns its own stability.
                                self.connected_at = None;
                                self.connect_delay = 0;
                                self.connect_delay_timer = None;
                            }
                            Some(WebSocketCommands::CancelGetMessage(id)) => {
                                // Drop the registration so a reply that arrives
                                // later is not handed to a receiver nobody holds.
                                self.inbound_cache.wanted_list.remove(&id);
                                debug!("Get message cancelled");
                            }
                            None => break,
                        }
                    },
                    // Read only while BOTH inbound queues have room. The packed
                    // queue was previously outside this guard, which left
                    // discarding a frame as the only way to honour its bound —
                    // unrecoverable, since delete-on-send means the mediator no
                    // longer holds it. One policy for both caches: stop reading,
                    // never discard.
                    Some(msg) = WebSocketTransport::conditional_websocket(&mut self.web_socket), if !self.inbound_cache.is_full() && !self.packed_cache_is_full() => {
                        self.handle_inbound_message(&atm, msg).await;
                    }
                }
                self.track_held_frames();
            }
            debug!("WebSocket connection stopped");
        }
        .instrument(_span)
        .await;
    }

    // Helper function that conditionally checks if the websocket is connected
    // Allows the use of an Option on the select! macro in the main loop
    async fn conditional_websocket(
        web_socket: &mut Option<WebSocket>,
    ) -> Option<
        Result<tokio_tungstenite::tungstenite::Message, tokio_tungstenite::tungstenite::Error>,
    > {
        if let Some(ws) = web_socket.as_mut() {
            ws.next().await
        } else {
            None
        }
    }

    // Helper function that conditionally checks if reconnecting is needed
    // Allows the use of an Option on the select! macro in the main loop
    async fn conditional_reconnect_delay(delay: &mut Option<Interval>) -> Option<()> {
        if let Some(delay) = delay.as_mut() {
            delay.tick().await;
            Some(())
        } else {
            None
        }
    }

    /// Proactive token-refresh deadline for the freshly-connected socket:
    /// fire at ~80% of the access token's remaining lifetime, leaving the
    /// last ~20% as budget to refresh the token and reconnect *before* the
    /// mediator force-closes the socket at expiry. `None` if expiry is unknown.
    fn refresh_deadline(&self) -> Option<tokio::time::Instant> {
        let expires_at = self.access_expires_at?;
        // Wall-clock TTL read goes through the injected clock; the deadline
        // itself is still scheduled on the tokio monotonic timer below.
        let now = self.shared.config.clock().unix_secs();
        let ttl = expires_at.saturating_sub(now);
        Some(tokio::time::Instant::now() + Duration::from_secs(refresh_after_secs(ttl)))
    }

    // Sleeps until the proactive-refresh deadline, if one is armed. Mirrors the
    // other `conditional_*` helpers so the `select!` branch simply never fires
    // when no deadline is set.
    async fn conditional_refresh(deadline: Option<tokio::time::Instant>) -> Option<()> {
        if let Some(deadline) = deadline {
            tokio::time::sleep_until(deadline).await;
            Some(())
        } else {
            None
        }
    }

    // Handles the inbound messages from the websocket
    async fn handle_inbound_message(
        &mut self,
        atm: &ATM,
        inbound: Result<Message, tokio_tungstenite::tungstenite::Error>,
    ) {
        // Any frame from the peer proves the socket is alive, not only a pong —
        // a mediator busy streaming may answer the ping behind its messages.
        if inbound.is_ok() {
            self.awaiting_pong = false;
        }
        // A data frame is evidence the mediator is delivering to this socket —
        // stronger than a pong, which only proves the socket. It answers any
        // outstanding receive-leg probe.
        if matches!(inbound, Ok(Message::Text(_) | Message::Binary(_))) {
            self.last_data_frame_at = tokio::time::Instant::now();
            if self.probe.take().is_some() {
                debug!("Receive-leg probe answered");
            }
            self.health.last_data_frame_at = Some(self.shared.config.clock().unix_secs());
            self.health.probe_outstanding_since = None;
            self.publish_health();
        }
        match inbound {
            Ok(ws_msg) => match ws_msg {
                Message::Text(text) => {
                    debug!("Received inbound text message",);
                    self.process_inbound_didcomm_message(atm, text.to_string())
                        .await;
                }
                Message::Binary(data) => {
                    warn!("Received inbound binary message");
                    self.process_inbound_didcomm_message(
                        atm,
                        String::from_utf8_lossy(&data).to_string(),
                    )
                    .await;
                }
                Message::Ping(data) => {
                    debug!("Received ping message, sending pong");
                    if let Some(web_socket) = self.web_socket.as_mut() {
                        let _ = web_socket.send(Message::Pong(data)).await;
                    }
                }
                Message::Pong(_) => {
                    debug!("Received pong message");
                    self.awaiting_pong = false;
                }
                Message::Close(frame) => {
                    // The close frame is the mediator's only chance to say WHY,
                    // and discarding it (this arm was `Close(_)`) is what made a
                    // refused duplicate connection indistinguishable from a
                    // network fault: the socket simply vanished, the loop
                    // reconnected, and the pair looped. The mediator now states
                    // a distinct reason per cause, so surface it.
                    //
                    // WARN, not DEBUG: a server that closed us deliberately is
                    // the one disconnect an operator needs to see, and the
                    // reason text is the difference between "check your network"
                    // and "you have this open twice".
                    match &frame {
                        Some(frame) => warn!(
                            code = u16::from(frame.code),
                            reason = %frame.reason,
                            "WebSocket closed by the mediator"
                        ),
                        None => {
                            warn!("WebSocket closed by the mediator with no reason given")
                        }
                    }
                    self.web_socket = None;
                    self.fail_pending_requests();
                    self.on_disconnected();
                }
                _ => {
                    warn!("Received unknown message type: {:?}", ws_msg);
                }
            },
            Err(tokio_tungstenite::tungstenite::Error::Protocol(
                ProtocolError::ResetWithoutClosingHandshake,
            )) => {
                // Connection Dropped
                warn!("WebSocket connection dropped");
                self.web_socket = None;
                self.fail_pending_requests();
                self.on_disconnected();
            }
            Err(e) => {
                error!("Generic websocket error: {:?}", e);
                self.web_socket = None;
                self.fail_pending_requests();
                self.on_disconnected();
            }
        }
    }

    /// Queue a packed frame, updating the byte total and the full latch.
    fn push_packed(&mut self, message: String) {
        self.packed_cache_bytes += message.len() as u64;
        self.packed_cache.push_back(message);
        if self.packed_cache.len() as u32 > self.shared.config.fetch_cache_limit_count
            || self.packed_cache_bytes > self.shared.config.fetch_cache_limit_bytes
        {
            self.packed_cache_full = true;
        }
        debug!(
            "Cached packed message ({} queued, {} bytes)",
            self.packed_cache.len(),
            self.packed_cache_bytes
        );
    }

    /// Take the oldest queued packed frame, clearing the full latch once the
    /// queue is back under both limits.
    fn pop_packed(&mut self) -> Option<String> {
        let message = self.packed_cache.pop_front()?;
        self.packed_cache_bytes = self.packed_cache_bytes.saturating_sub(message.len() as u64);
        if self.packed_cache_full
            && (self.packed_cache.len() as u32) <= self.shared.config.fetch_cache_limit_count
            && self.packed_cache_bytes <= self.shared.config.fetch_cache_limit_bytes
        {
            self.packed_cache_full = false;
        }
        Some(message)
    }

    /// Whether the packed queue has hit its limits and the socket should stop
    /// being read until the consumer catches up.
    fn packed_cache_is_full(&self) -> bool {
        self.packed_cache_full
    }

    async fn process_inbound_didcomm_message(&mut self, atm: &ATM, message: String) {
        debug!("Received text message ({})", message);

        // A TSP message can't be DIDComm-unpacked. The live-stream frame is
        // self-describing (CESR qb64), so sniff it and deliver TSP frames packed
        // — the consumer unpacks them via `atm.tsp()`. Without this a TSP frame
        // would fail the DIDComm `unpack` below and be silently dropped.
        //
        // Classification is **not** gated on the `tsp` feature, and that is
        // load-bearing. It used to be, which meant a build without the feature
        // did not merely fail to handle a TSP frame — it failed to *recognise*
        // one, sent it to the DIDComm unpacker, and surfaced the whole thing as
        // `Cannot parse message as JSON ... invalid number at line 1 column 2`
        // (CESR qb64 opens with `-`). That named neither TSP nor the missing
        // feature, and it short-circuited the two `cfg(not(feature = "tsp"))`
        // warnings written for this exact case: both sit *downstream* of
        // classification, so gating classification made them unreachable.
        //
        // Recognising a frame needs one byte; only unpacking needs the TSP
        // stack. Every consumer path already handles a packed frame it did not
        // ask for — the DIDComm-only streams warn by name and delete it (no
        // redelivery loop), and `transport_adapter::tsp_to_inbound`'s non-`tsp`
        // arm now actually runs and says what arrived and why it can't be read.
        // If skip_unpack_messages is true, send the packed message directly
        if deliver_packed(self.skip_unpack_messages, &message) {
            // A packed frame has exactly three possible homes, tried in order:
            // an outstanding `Next` request, the direct channel, or the packed
            // cache. It must reach one of them — every arm that gives up on the
            // frame has to hand it to the next arm rather than let it fall off
            // the end, which is how these frames used to vanish.
            let mut message = message;

            // 1. Outstanding `Next` requests. A waiter whose receiver has gone
            //    away (its poll timed out between our `pop_front` and this
            //    `send`) hands the frame back, so we try the next waiter rather
            //    than losing it to a race we just lost.
            while let Some(next_request) = self.next_requests_list.pop_front() {
                let Some(sender) = self.next_requests.remove(&next_request) else {
                    error!(
                        "Next message requestor ({next_request}) not found - bug in the SDK - trying the next waiter"
                    );
                    continue;
                };
                match sender.send(WebSocketResponses::PackedMessageReceived(Box::new(message))) {
                    Ok(()) => {
                        debug!("Next message found, sending to requestor packed");
                        self.last_take_at = Some(tokio::time::Instant::now());
                        return;
                    }
                    Err(WebSocketResponses::PackedMessageReceived(returned)) => {
                        debug!("Next requestor ({next_request}) is gone; re-homing the frame");
                        message = *returned;
                    }
                    // `send` returns the value we passed, which is the variant
                    // constructed one line above.
                    Err(_) => unreachable!("oneshot returns the value it was given"),
                }
            }

            // 2. The direct channel, when one is attached and has receivers.
            //    `send` fails only when every receiver has dropped, which makes
            //    the channel no better than no channel for this frame.
            if let Some(direct_channel) = self.direct_channel.as_mut() {
                match direct_channel
                    .send(WebSocketResponses::PackedMessageReceived(Box::new(message)))
                {
                    Ok(_) => {
                        debug!("Sending message to direct channel packed");
                        self.last_take_at = Some(tokio::time::Instant::now());
                        return;
                    }
                    Err(returned) => {
                        let WebSocketResponses::PackedMessageReceived(returned) = returned.0 else {
                            unreachable!("broadcast returns the value it was given")
                        };
                        debug!("Direct channel has no receivers; caching the packed frame");
                        message = *returned;
                    }
                }
            }

            // 3. Cache it for the next `Next`.
            //
            //    Never dropped to make room. This cache exists precisely because
            //    a dropped packed frame is unrecoverable — under delete-on-send
            //    the mediator has already forgotten it — so discarding here to
            //    honour a memory bound would reintroduce the bug in a quieter
            //    form. Instead the queue is allowed to reach its limit and the
            //    socket-read arm stops reading, which is the same backpressure
            //    the DIDComm cache applies. A consumer that has stopped
            //    consuming stalls its own connection rather than silently losing
            //    messages.
            self.push_packed(message);
            return;
        }

        let unpacked = match tokio::time::timeout(UNPACK_TIMEOUT, atm.unpack(&message)).await {
            Ok(result) => result,
            Err(_) => Err(ATMError::TransportError(format!(
                "unpacking the inbound frame did not complete within {UNPACK_TIMEOUT:?}"
            ))),
        };
        match unpacked {
            Ok((message, metadata)) => {
                // The answer to our own receive-leg probe. Already counted as
                // evidence of delivery when its frame arrived; it is ours, not
                // the application's, and the mediator does not store it, so
                // there is nothing to hand on or delete.
                if message.typ == STATUS_TYPE
                    && message
                        .thid
                        .as_deref()
                        .is_some_and(|thid| self.probe_ids.iter().any(|id| id == thid))
                {
                    debug!("Consumed the mediator's answer to a receive-leg probe");
                    return;
                }

                // An unpacked message has the same rule as a packed frame above:
                // every home that turns it away hands it to the next, and it ends
                // in the cache rather than falling off the end. Each `send` below
                // used to be `let _ =`. A waiter whose poll had just timed out
                // (its receiver dropped before its cancel reached this task) took
                // the message with it, so a `live_stream_next` loop polling in
                // windows silently lost about one message in twenty, and a
                // `live_stream_get` that gave up a moment early lost its reply for
                // good.
                let (mut message, mut metadata) = (message, metadata);

                // 1. A `live_stream_get` waiting on this thread.
                if let Some(sender) = self.inbound_cache.message_wanted(&message) {
                    match sender.send(WebSocketResponses::MessageReceived(
                        Box::new(message),
                        Box::new(metadata),
                    )) {
                        Ok(()) => {
                            debug!("Message is wanted, sent to requestor");
                            self.last_take_at = Some(tokio::time::Instant::now());
                            return;
                        }
                        Err(WebSocketResponses::MessageReceived(m, md)) => {
                            debug!("Wanted-message requestor is gone; re-homing the message");
                            (message, metadata) = (*m, *md);
                        }
                        Err(_) => unreachable!("oneshot returns the value it was given"),
                    }
                }

                // 2. Outstanding `Next` requests, oldest first. A gone waiter
                //    hands the message back and the next one is tried.
                while let Some(next_request) = self.next_requests_list.pop_front() {
                    let Some(sender) = self.next_requests.remove(&next_request) else {
                        error!(
                            "Next message requestor ({next_request}) not found - bug in the SDK - trying the next waiter"
                        );
                        continue;
                    };
                    match sender.send(WebSocketResponses::MessageReceived(
                        Box::new(message),
                        Box::new(metadata),
                    )) {
                        Ok(()) => {
                            debug!("Next message found, sent to requestor");
                            self.last_take_at = Some(tokio::time::Instant::now());
                            return;
                        }
                        Err(WebSocketResponses::MessageReceived(m, md)) => {
                            debug!(
                                "Next requestor ({next_request}) is gone; re-homing the message"
                            );
                            (message, metadata) = (*m, *md);
                        }
                        Err(_) => unreachable!("oneshot returns the value it was given"),
                    }
                }

                // 3. The direct channel, when one is attached and has receivers.
                if let Some(direct_channel) = self.direct_channel.as_mut() {
                    match direct_channel.send(WebSocketResponses::MessageReceived(
                        Box::new(message),
                        Box::new(metadata),
                    )) {
                        Ok(_) => {
                            debug!("Sent message to direct channel");
                            self.last_take_at = Some(tokio::time::Instant::now());
                            return;
                        }
                        Err(broadcast::error::SendError(WebSocketResponses::MessageReceived(
                            m,
                            md,
                        ))) => {
                            debug!("Direct channel has no receivers; caching the message");
                            (message, metadata) = (*m, *md);
                        }
                        Err(_) => unreachable!("broadcast returns the value it was given"),
                    }
                }

                // 4. Cache it for the next `Next` / `Get`.
                debug!("Caching message");
                self.inbound_cache.insert(message, metadata);
            }
            Err(e) => {
                // The mediator ids a message by `sha256(packed message)` and
                // live-delivers those exact bytes, so `sha256(&message)` is the
                // mediator message id — the id the pickup drain reports, and
                // the one a delete names.
                let id = sha256::digest(&message);
                // Reported first, whatever happens next, so a consumer can
                // observe or quarantine the frame.
                crate::protocols::message_pickup::emit_unprocessable(
                    atm,
                    Some(id.clone()),
                    message.clone(),
                    e.to_string(),
                );
                self.handle_unprocessable(atm, &id, &message, &e);
            }
        }
    }

    /// Decide what happens to an inbound DIDComm frame that could not be
    /// unpacked: delete it from the mediator, or leave it for redelivery.
    ///
    /// # Why it is deleted at all (R1.6)
    ///
    /// R1.6 says ack (delete) only after durable handoff, and this frame was
    /// never handed off. It is deleted anyway, deliberately: it never *can* be
    /// handed off. A mediator keeps a message until its recipient deletes it
    /// and counts it against the **sender's** per-recipient queue
    /// (`limits.queue.peer`, default 50) until then. Left alone, every poison
    /// frame was redelivered on every reconnect and every redelivery request,
    /// and stayed in the sender's quota for its whole lifetime — enough of them
    /// and the sender could no longer reach this DID at all, while this side
    /// logged one error per delivery and looked healthy. The TSP adapter
    /// already deletes undeliverable frames for the same reason, and the pickup
    /// drain already deleted DIDComm ones; only the live stream kept them.
    ///
    /// A transient failure (a resolver or network hiccup, or the unpack timing
    /// out) is **not** treated as poison: the frame stays at the mediator and
    /// is offered again, and is only deleted once it has failed
    /// [`super::receive_leg::TRANSIENT_UNPACK_SIGHTINGS`] times — a
    /// "transient" failure that repeats on every redelivery is not transient.
    /// The cost is that a resolver outage spanning three redeliveries discards
    /// a frame that would have unpacked; it is logged at WARN with what can be
    /// read off the envelope, so the loss is auditable rather than silent.
    /// `with_delete_unprocessable(false)` keeps every frame instead.
    fn handle_unprocessable(&mut self, atm: &ATM, id: &str, raw: &str, err: &ATMError) {
        let class = classify_unpack_failure(err);
        let sightings = self
            .unpack_sightings
            .record(id, tokio::time::Instant::now());
        let config = &self.shared.config;
        let delete = unpack_failure_disposition(
            class,
            sightings,
            config.delete_unprocessable(),
            config.purge_policy_rejected_messages(),
        );
        let hint = frame_hint(raw);
        let sender = hint.sender.as_deref().unwrap_or("<not named>");
        let kind = hint.kind.as_deref().unwrap_or("<unknown>");

        if !delete {
            let reason = if !config.delete_unprocessable() {
                "deletion of unprocessable frames is disabled"
            } else if class == UnpackFailure::PolicyRejected {
                "policy rejects are retained (purge_policy_rejected_messages = false)"
            } else {
                "failure may be transient; left at the mediator for redelivery"
            };
            warn!(
                profile = %self.profile.inner.alias,
                frame = %id,
                envelope = hint.envelope,
                sender,
                kind,
                class = ?class,
                sightings,
                error = %err,
                "could not unpack an inbound message — {reason}"
            );
            self.health.unprocessable_retained = self.unpack_sightings.len() as u32;
            self.publish_health();
            return;
        }

        // Never park the transport task on the deletion handler: a full queue
        // leaves the frame for redelivery, where this runs again.
        if atm.try_delete_message_background(&self.profile, id) {
            warn!(
                profile = %self.profile.inner.alias,
                frame = %id,
                envelope = hint.envelope,
                sender,
                kind,
                class = ?class,
                sightings,
                error = %err,
                "deleting an inbound message this profile cannot unpack, so it stops being \
                 redelivered and stops counting against its sender's mediator queue"
            );
            self.unpack_sightings.forget(id);
            self.health.unprocessable_deleted += 1;
        } else {
            warn!(
                profile = %self.profile.inner.alias,
                frame = %id,
                sender,
                "could not queue the deletion of an unprocessable inbound message (deletion \
                 handler busy) — it will be redelivered and tried again"
            );
        }
        self.health.unprocessable_retained = self.unpack_sightings.len() as u32;
        self.publish_health();
    }

    /// Frames held in the caches, waiting for the application.
    fn held_frames(&self) -> usize {
        self.inbound_cache.total_count as usize + self.packed_cache.len()
    }

    /// Keep `held_since` in step with the caches. Run once per loop turn.
    fn track_held_frames(&mut self) {
        let held = self.held_frames();
        match (held, self.held_since) {
            (0, Some(_)) => self.held_since = None,
            (n, None) if n > 0 => self.held_since = Some(tokio::time::Instant::now()),
            _ => {}
        }
        if self.health.held_frames != held as u32 {
            self.health.held_frames = held as u32;
            self.publish_health();
        }
    }

    fn publish_health(&self) {
        self.health_tx.send_if_modified(|current| {
            if *current == self.health {
                false
            } else {
                *current = self.health.clone();
                true
            }
        });
    }

    /// The receive-leg checks, run on each watchdog tick while connected: is
    /// the application still taking frames, and is the mediator still
    /// delivering?
    async fn check_receive_leg(&mut self, atm: &ATM) {
        let now = tokio::time::Instant::now();

        // 1. Consumer stall. Reported, not "fixed" by reconnecting: a reconnect
        //    cannot make an application read, and the mediator's redelivery on
        //    connect would only duplicate frames into the packed cache. The
        //    remedy is in the consumer; the signal is what this layer owes it.
        let held = self.held_frames();
        let stalled = consumer_stalled(
            held,
            self.held_since,
            self.last_take_at,
            now,
            CONSUMER_STALL_AFTER,
        );
        match (stalled, self.health.consumer_stalled_since.is_some()) {
            (true, false) => {
                warn!(
                    profile = %self.profile.inner.alias,
                    held,
                    reads_paused = self.inbound_cache.is_full() || self.packed_cache_is_full(),
                    "inbound messages are not being collected: {held} held for more than {}s \
                     with none taken. Nothing is being deleted at the mediator, so this DID's \
                     inbox is filling and peers writing to it will start being refused \
                     (limits.queue.peer)",
                    CONSUMER_STALL_AFTER.as_secs()
                );
                self.health.consumer_stalled_since = Some(self.shared.config.clock().unix_secs());
                self.publish_health();
            }
            (false, true) => {
                info!(
                    profile = %self.profile.inner.alias,
                    "inbound messages are being collected again"
                );
                self.health.consumer_stalled_since = None;
                self.publish_health();
            }
            _ => {}
        }

        // 2. Receive-leg probe.
        let quiet = held == 0 && !self.inbound_cache.is_full() && !self.packed_cache_is_full();
        let step = probe_step(
            self.shared.config.receive_probe_after(),
            now,
            self.last_data_frame_at,
            self.probe.as_ref().map(|(_, sent)| *sent),
            quiet,
        );
        match step {
            ProbeStep::Idle | ProbeStep::Wait => {}
            ProbeStep::Send => self.send_probe(atm, now).await,
            ProbeStep::Dead => {
                let mediator = self
                    .profile
                    .dids()
                    .map(|(_, m)| m.to_string())
                    .unwrap_or_default();
                let waited = self
                    .probe
                    .as_ref()
                    .map(|(_, sent)| now.saturating_duration_since(*sent).as_secs())
                    .unwrap_or_default();
                warn!(
                    profile = %self.profile.inner.alias,
                    mediator = %mediator,
                    "mediator socket is up but nothing is being delivered to it (live-delivery \
                     probe unanswered for {waited}s); reconnecting"
                );
                self.probe = None;
                self.health.probe_outstanding_since = None;
                self.health.probe_reconnects += 1;
                self.publish_health();
                if let Some(web_socket) = self.web_socket.as_mut() {
                    close_bounded(web_socket).await;
                }
                self.web_socket = None;
                self.awaiting_pong = false;
                self.fail_pending_requests();
                self.on_disconnected();
            }
        }
    }

    /// Write a receive-leg probe — a live-delivery-change(true) — straight to
    /// the socket. Never via `ATM::send_message`: that queues a command for this
    /// very task and waits for a reply only this task could produce (#611).
    async fn send_probe(&mut self, atm: &ATM, now: tokio::time::Instant) {
        let packed = tokio::time::timeout(
            PROBE_PACK_TIMEOUT,
            crate::protocols::message_pickup::MessagePickup::packed_live_delivery_change(
                atm,
                &self.profile,
                true,
            ),
        )
        .await;
        let (frame, msg_id) = match packed {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => {
                debug!("Could not pack a receive-leg probe ({e}); trying next tick");
                return;
            }
            Err(_) => {
                debug!("Packing a receive-leg probe timed out; trying next tick");
                return;
            }
        };
        let Some(web_socket) = self.web_socket.as_mut() else {
            return;
        };
        match tokio::time::timeout(SOCKET_WRITE_TIMEOUT, web_socket.send(Message::text(frame)))
            .await
        {
            Ok(Ok(())) => {
                debug!("Receive-leg probe sent (inbound silent)");
                self.probe = Some((msg_id.clone(), now));
                self.probe_ids.push_back(msg_id);
                while self.probe_ids.len() > 4 {
                    self.probe_ids.pop_front();
                }
                self.health.probe_outstanding_since = Some(self.shared.config.clock().unix_secs());
                self.publish_health();
            }
            // A socket that cannot take a write is for the ping watchdog to
            // judge; it will on its next tick.
            Ok(Err(e)) => debug!("Receive-leg probe write failed ({e})"),
            Err(_) => debug!("Receive-leg probe write timed out"),
        }
    }

    /// Notify every in-flight request waiter that the connection was lost.
    ///
    /// Called on each disconnect transition so callers (`live_stream_get` /
    /// `live_stream_next`) return immediately instead of blocking until their
    /// own timeout elapses. These requests are gone — the mediator never saw
    /// them, or their response was lost with the socket — so they will not be
    /// answered on the reconnected socket.
    fn fail_pending_requests(&mut self) {
        // Every websocket drop funnels through here (missed pong, server close,
        // reset, socket error, forced token-refresh reconnect), so this is the
        // single place that publishes the `Disconnected` transition. The
        // reconnect loop republishes `Connected` on the next successful connect.
        let _ = self.conn_state_tx.send(ConnState::Disconnected);

        let mut notified = 0usize;

        // Pending `Next` waiters
        for (_, sender) in self.next_requests.drain() {
            let _ = sender.send(WebSocketResponses::Disconnected);
            notified += 1;
        }
        self.next_requests_list.clear();

        // Pending `GetMessage` (wanted) waiters
        for sender in self.inbound_cache.drain_wanted() {
            let _ = sender.send(WebSocketResponses::Disconnected);
            notified += 1;
        }

        if notified > 0 {
            debug!(
                count = notified,
                "Failed in-flight requests after websocket disconnect"
            );
        }
    }

    /// Record that the live socket went away, and pick the next reconnect delay.
    ///
    /// A socket that survived [`STABLE_CONNECTION`] proved the endpoint healthy,
    /// so its loss earns an immediate retry. A socket that died young did *not*.
    ///
    /// This distinction is load-bearing: resetting the backoff on connect alone
    /// makes a connect-then-immediately-closed cycle unthrottled, because every
    /// attempt "succeeds" before being killed. That is exactly what happens when
    /// two clients for the same DID duel over the mediator's one-socket-per-DID
    /// slot — each eviction is preceded by a successful connect, so the delay
    /// never escalates past the first step and the pair reconnect at ~1 Hz
    /// forever. Escalating on short-lived connections lets the duel decay to the
    /// 60s cap instead.
    fn on_disconnected(&mut self) {
        let connected_for = self.connected_at.map(|since| since.elapsed());
        self.connected_at = None;

        let next = delay_after_disconnect(self.connect_delay, connected_for);
        if next > self.connect_delay {
            debug!(
                connect_delay = next,
                "Short-lived websocket connection; escalating reconnect backoff"
            );
        }
        self.connect_delay = next;
        self.connect_delay_timer = None;
    }

    /// Calculate exponential backoff delay: 0→1→2→4→8→16→32→60s (capped).
    /// Jitter is applied separately at timer-creation time
    /// ([`jittered_backoff`]) so this base sequence stays deterministic.
    fn backoff_delay(&mut self) {
        self.connect_delay = escalate_delay(self.connect_delay);
        self.connect_delay_timer = None;
    }

    // Wrapper that handles all of the logic of setting up a connection to the mediator
    async fn _handle_connection(&mut self, atm: &ATM) -> Option<WebSocket> {
        debug!("Starting websocket connection");

        let mut web_socket = match self._create_socket().await {
            Ok(ws) => ws,
            Err(e) => {
                error!("Error creating websocket connection: {:?}", e);
                self.backoff_delay();
                if let Some(retry_after) = e.http_status().and_then(|s| s.retry_after_secs) {
                    self.connect_delay = honour_retry_after(self.connect_delay, retry_after);
                }
                return None;
            }
        };

        debug!("Websocket connected. Next enable live streaming");

        // Do toggle_live_delivery on this socket if not skipped
        if self.skip_toggle_live_delivery {
            debug!("Skipping toggle_live_delivery as requested");
            // NB: the backoff is deliberately NOT reset here — connecting is not
            // the same as staying connected. `on_disconnected` resets it once
            // this socket has survived `STABLE_CONNECTION`.
            self.connect_delay_timer = None;
            self.connected_at = Some(tokio::time::Instant::now());
            self.awaiting_pong = false;
            Some(web_socket)
        } else {
            // Pack the live-delivery-change frame and write it DIRECTLY to the
            // socket we are holding. This code runs on the transport task
            // itself, so it must not go through `ATM::send_message`: that
            // enqueues a `SendMessage` command into this task's own channel and
            // awaits a reply that only this (currently busy) task could
            // produce — a deadlock that timed out every connect attempt (#611).
            let send_result =
                match crate::protocols::message_pickup::MessagePickup::packed_live_delivery_change(
                    atm,
                    &self.profile,
                    true,
                )
                .await
                {
                    Ok((frame, _msg_id)) => {
                        web_socket.send(Message::text(frame)).await.map_err(|e| {
                            ATMError::TransportError(format!("websocket write failed: {e}"))
                        })
                    }
                    Err(e) => Err(e),
                };
            match send_result {
                Ok(()) => {
                    debug!("Live streaming enabled");
                    // See the sibling branch: the backoff reset belongs to
                    // `on_disconnected`, not to a bare successful connect.
                    self.connect_delay_timer = None;
                    self.connected_at = Some(tokio::time::Instant::now());
                    self.awaiting_pong = false;
                    Some(web_socket)
                }
                Err(e) => {
                    error!("Error enabling live streaming: {:?}", e);
                    close_bounded(&mut web_socket).await;
                    self.backoff_delay();
                    None
                }
            }
        }
    }

    // Responsible for creating a websocket connection to the mediator
    async fn _create_socket(&mut self) -> Result<WebSocket, ATMError> {
        let (profile_did, mediator_did) = self.profile.dids()?;
        // Check if authenticated
        let tokens = self
            .shared
            .tdk_common
            .authentication()
            .authenticate(profile_did.to_string(), mediator_did.to_string(), 3, None)
            .await?;
        // Remember when this token expires so we can refresh+reconnect before
        // the mediator force-closes the socket at expiry.
        self.access_expires_at = Some(tokens.access_expires_at);

        debug!("Creating websocket connection");
        // Create a custom websocket request, turn this into a client_request
        // Allows adding custom headers later

        let Some(mediator) = &*self.profile.inner.mediator else {
            return Err(ATMError::ConfigError(format!(
                "Profile ({}) is missing a valid mediator configuration!",
                self.profile.inner.alias
            )));
        };

        let Some(address) = &mediator.websocket_endpoint else {
            return Err(ATMError::ConfigError(format!(
                "Profile ({}) is missing a valid websocket endpoint!",
                self.profile.inner.alias
            )));
        };

        let uri: Uri = match address.parse() {
            Ok(uri) => uri,
            Err(err) => {
                error!(
                    "Mediator {}: Invalid ServiceEndpoint address {}: {}",
                    mediator.did, address, err
                );
                return Err(ATMError::TransportError(format!(
                    "Mediator {}: Invalid ServiceEndpoint address {}: {}",
                    mediator.did, address, err
                )));
            }
        };

        let host = uri.host().unwrap_or_default().to_string();
        let port = uri
            .port_u16()
            .unwrap_or(if uri.scheme_str() == Some("wss") {
                443
            } else {
                80
            });

        let builder = ClientRequestBuilder::new(uri)
            .with_header("Authorization", ["Bearer ", &tokens.access_token].concat());

        let (web_socket, _) = super::proxy::connect_websocket(builder, &host, port)
            .await
            .map_err(|e| match e {
                // Keep a refused upgrade typed, so a caller can see it was
                // rate-limited and by whom.
                ATMError::HttpStatus(status) => {
                    let mut status = *status;
                    status.context = format!(
                        "Profile '{}' → mediator {} websocket: {}",
                        self.profile.inner.alias, mediator.did, status.context
                    );
                    ATMError::from(status.with_url(address.as_str()))
                }
                e => ATMError::TransportError(format!(
                    "Profile '{}' → mediator {} websocket {} ({}:{}): {}",
                    self.profile.inner.alias, mediator.did, address, host, port, e
                )),
            })?;

        debug!("Completed websocket connection");

        Ok(web_socket)
    }
}

impl std::fmt::Debug for WebSocketTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebSocketTransport")
            .field("profile", &self.profile)
            .field("web_socket", &self.web_socket.is_some())
            .field("connect_delay", &self.connect_delay)
            .field("awaiting_pong", &self.awaiting_pong)
            .field("skip_toggle_live_delivery", &self.skip_toggle_live_delivery)
            .field("skip_unpack_messages", &self.skip_unpack_messages)
            .finish()
    }
}

/// Apply ±15% random jitter to a base backoff delay (in seconds). When the
/// mediator recovers, clients that all disconnected together would otherwise
/// reconnect in lock-step and stampede it; jitter spreads the reconnections
/// out. Non-cryptographic randomness is fine here.
fn jittered_backoff(base_secs: u8) -> Duration {
    let factor = rand::rng().random_range(0.85..1.15);
    Duration::from_secs_f64(base_secs as f64 * factor)
}

/// Next backoff step: 0→1→2→4→8→16→32→60s (capped).
fn escalate_delay(current: u8) -> u8 {
    match current {
        0 => 1,
        d if d < 60 => (d * 2).min(60),
        _ => 60,
    }
}

/// Never reconnect sooner than a refusing server's `Retry-After` asked, within
/// the backoff's 60s cap. A shorter wait is a reconnect the limiter is certain
/// to refuse again, and each one spends another token of the client's quota.
fn honour_retry_after(current: u8, retry_after_secs: u64) -> u8 {
    let retry_after = u8::try_from(retry_after_secs.min(60)).unwrap_or(60);
    current.max(retry_after)
}

/// Next `connect_delay` after the live socket went away.
///
/// `connected_for` is how long the socket that just died had been up (`None` if
/// there was no live socket — i.e. the connect attempt itself failed). Only a
/// connection that lasted [`STABLE_CONNECTION`] earns a reset; see
/// [`WebSocketTransport::on_disconnected`] for why anything else must escalate.
fn delay_after_disconnect(current: u8, connected_for: Option<Duration>) -> u8 {
    match connected_for {
        Some(lifetime) if lifetime >= STABLE_CONNECTION => 0,
        _ => escalate_delay(current),
    }
}

/// How long after connecting to proactively refresh the access token and
/// reconnect: 80% of the token's remaining lifetime, leaving the final ~20%
/// as budget to refresh + reconnect before the mediator force-closes the
/// socket at expiry.
fn refresh_after_secs(ttl_secs: u64) -> u64 {
    // `*4` first for accuracy on short TTLs; token lifetimes can't overflow u64.
    (ttl_secs * 4) / 5
}

/// Should this inbound frame be delivered **packed** rather than DIDComm-
/// unpacked?
///
/// Two reasons to skip the unpacker: the consumer asked for packed frames
/// (`skip_unpack`), or the frame is TSP and the unpacker would only mangle it.
///
/// A free function purely so the decision is testable in *both* feature
/// configurations — see [`tests::a_tsp_frame_is_delivered_packed_in_every_build`].
/// The TSP half must never be gated on the `tsp` feature: gating it is precisely
/// the defect this replaced, where an unrecognised TSP frame reached
/// `atm.unpack` and surfaced as `Cannot parse message as JSON`.
fn deliver_packed(skip_unpack: bool, message: &str) -> bool {
    skip_unpack || crate::tsp_wire::looks_like_tsp(message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_after_is_a_floor_on_the_reconnect_delay() {
        // Backoff already longer than the server asked: keep it.
        assert_eq!(honour_retry_after(16, 4), 16);
        // Backoff shorter: wait as long as the server asked.
        assert_eq!(honour_retry_after(1, 4), 4);
        // Capped with the backoff, so a hostile value cannot park the socket.
        assert_eq!(honour_retry_after(1, u64::MAX), 60);
    }

    /// The regression guard for the gating defect. This test compiles and runs
    /// in **every** feature configuration, so re-introducing a
    /// `#[cfg(feature = "tsp")]` around the TSP classification fails the default
    /// build rather than silently restoring the silent-drop behaviour.
    #[test]
    fn a_tsp_frame_is_delivered_packed_in_every_build() {
        use base64::prelude::*;
        let tsp = BASE64_URL_SAFE_NO_PAD.encode([crate::tsp_wire::TSP_MAGIC_BYTE, 0x41, 0x42]);

        assert!(
            deliver_packed(false, &tsp),
            "a TSP frame must bypass the DIDComm unpacker even when the consumer did not ask \
             for packed frames, and even in a build without the `tsp` feature — otherwise it \
             dies in serde_json as `invalid number at line 1 column 2`"
        );
    }

    /// The other direction: DIDComm still goes to the unpacker unless the
    /// consumer opted out. A classifier that over-claimed would divert real
    /// DIDComm traffic into the packed path — a worse failure than the one fixed.
    #[test]
    fn didcomm_still_goes_to_the_unpacker() {
        let didcomm =
            r#"{"protected":"eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLWVuY3J5cHRlZCtqc29uIn0"}"#;
        assert!(!deliver_packed(false, didcomm));
        // ...unless the consumer explicitly wants packed frames.
        assert!(deliver_packed(true, didcomm));
    }

    #[test]
    fn a_long_lived_connection_earns_an_immediate_retry() {
        // A socket that proved itself and then dropped should come straight
        // back, whatever the delay had climbed to beforehand.
        for current in [0u8, 1, 8, 60] {
            assert_eq!(
                delay_after_disconnect(current, Some(STABLE_CONNECTION)),
                0,
                "a stable connection must reset the backoff"
            );
        }
        assert_eq!(
            delay_after_disconnect(4, Some(STABLE_CONNECTION + Duration::from_secs(3600))),
            0
        );
    }

    #[test]
    fn a_short_lived_connection_escalates_instead_of_resetting() {
        // The duel case: connect succeeds, then the peer is evicted moments
        // later. Every attempt "succeeds", so if success alone reset the delay
        // this pair would reconnect at ~1Hz forever. Walk the full ladder to
        // the cap to prove it decays instead.
        let brief = Some(Duration::from_millis(200));
        let mut delay = 0u8;
        for expected in [1u8, 2, 4, 8, 16, 32, 60] {
            delay = delay_after_disconnect(delay, brief);
            assert_eq!(delay, expected, "backoff must escalate on a short session");
        }
        // Capped, not wrapping (u8 would overflow at 128).
        for _ in 0..10 {
            delay = delay_after_disconnect(delay, brief);
            assert_eq!(delay, 60);
        }
    }

    #[test]
    fn a_failed_connect_attempt_escalates() {
        // No socket ever came up, so there is nothing to have been stable.
        assert_eq!(delay_after_disconnect(0, None), 1);
        assert_eq!(delay_after_disconnect(16, None), 32);
        assert_eq!(delay_after_disconnect(60, None), 60);
    }

    #[test]
    fn stability_threshold_outlasts_the_watchdog_interval() {
        // "Stable" must mean at least one completed ping/pong round-trip,
        // otherwise a connection we never proved could reset the backoff.
        assert!(
            STABLE_CONNECTION > Duration::from_secs(20),
            "STABLE_CONNECTION must exceed the 20s watchdog interval"
        );
        // Just under the threshold still escalates — no off-by-one grace.
        assert_eq!(
            delay_after_disconnect(2, Some(STABLE_CONNECTION - Duration::from_millis(1))),
            4
        );
    }

    #[test]
    fn refresh_fires_before_expiry_with_budget_to_spare() {
        // Always strictly before expiry (so we beat the mediator's forced
        // close) and never zero for a non-trivial TTL (so we don't hot-loop).
        for ttl in [10u64, 60, 300, 900, 86_400] {
            let after = refresh_after_secs(ttl);
            assert!(
                after < ttl,
                "ttl {ttl}: refresh at {after} not before expiry"
            );
            assert!(after > 0, "ttl {ttl}: refresh delay must be positive");
            // ~80% of the lifetime.
            assert_eq!(after, (ttl * 4) / 5);
        }
        // Degenerate inputs don't panic.
        assert_eq!(refresh_after_secs(0), 0);
        assert_eq!(refresh_after_secs(1), 0);
    }

    #[test]
    fn jittered_backoff_stays_within_15_percent() {
        // Sample repeatedly: every jittered delay must land within ±15% of
        // the base and never be zero/negative.
        for base in [1u8, 2, 4, 8, 16, 32, 60] {
            for _ in 0..1000 {
                let d = jittered_backoff(base).as_secs_f64();
                assert!(
                    d >= base as f64 * 0.85 && d < base as f64 * 1.15,
                    "jittered {base}s -> {d}s out of ±15% band"
                );
                assert!(d > 0.0);
            }
        }
    }

    /// The missed-pong rule. Before this, `awaiting_pong` was never set, so the
    /// `Dead` arm was unreachable and a half-open socket (peer gone, no FIN) sat
    /// `Connected` indefinitely.
    #[test]
    fn watchdog_pings_then_declares_a_silent_socket_dead() {
        assert_eq!(watchdog_step(false, false), WatchdogStep::Ping);
        assert_eq!(watchdog_step(true, false), WatchdogStep::Dead);
    }

    /// With reads paused on full caches a pong cannot have been read, so its
    /// absence proves nothing — closing then would drop a healthy socket.
    #[test]
    fn watchdog_waits_while_reads_are_paused() {
        assert_eq!(watchdog_step(true, true), WatchdogStep::Wait);
        assert_eq!(watchdog_step(false, true), WatchdogStep::Ping);
    }

    /// Any frame from the peer counts as the answer to an outstanding ping.
    #[tokio::test]
    async fn any_inbound_frame_clears_an_outstanding_ping() {
        let atm = plaintext_atm().await;
        let mut ws = test_transport(&atm);
        ws.awaiting_pong = true;
        ws.handle_inbound_message(&atm, Ok(Message::Ping(Bytes::new())))
            .await;
        assert!(!ws.awaiting_pong);
    }

    /// A minimal, disconnected [`WebSocketTransport`] for unit-testing inbound
    /// message handling without a real socket. Mirrors the field set built by
    /// [`WebSocketTransport::start`].
    fn test_transport(atm: &ATM) -> WebSocketTransport {
        use crate::profiles::{ATMProfile, ATMProfileInner};
        let profile = Arc::new(ATMProfile {
            inner: Arc::new(ATMProfileInner {
                did: "did:peer:fake".to_string(),
                alias: "test".to_string(),
                mediator: Arc::new(None),
            }),
        });
        let (conn_state_tx, _rx) = watch::channel(ConnState::Connecting);
        let (health_tx, _rx) = watch::channel(ReceiveHealth::default());
        WebSocketTransport::new(
            profile,
            atm.inner.clone(),
            None,
            false,
            false,
            conn_state_tx,
            health_tx,
        )
    }

    /// A live-delivery frame that fails to unpack (here a plaintext the secure
    /// default policy rejects) is dropped by the WebSocket handler *and*
    /// reported on the unprocessable-message channel, so a consumer can observe /
    /// quarantine it instead of losing it to a log line.
    #[tokio::test]
    async fn live_delivery_reports_unprocessable_on_the_channel() {
        use crate::config::ATMConfig;
        use affinidi_messaging_didcomm::message::Message as DcMessage;
        use affinidi_tdk_common::{TDKSharedState, config::TDKConfig};
        use serde_json::json;

        let config = ATMConfig::builder()
            .with_unprocessable_message_channel(16)
            .build()
            .unwrap();
        let tdk = Arc::new(
            TDKSharedState::new(TDKConfig::headless().unwrap())
                .await
                .unwrap(),
        );
        let atm = ATM::new(config, tdk).await.unwrap();
        let mut rx = atm
            .get_unprocessable_message_channel()
            .expect("unprocessable channel");

        let mut ws = test_transport(&atm);

        // A plaintext DIDComm message: unauthenticated, so the secure default
        // policy rejects it on unpack and the live handler drops it.
        let plaintext = DcMessage::build(
            "evil".to_string(),
            "example/v1".to_string(),
            json!({"x": 1}),
        )
        .from("did:example:sender".to_string())
        .to("did:example:recipient".to_string())
        .finalize();
        let raw = serde_json::to_string(&plaintext).unwrap();
        // The mediator derives a message's id as `sha256(packed message)` and
        // live-delivers those exact bytes (see the mediator store's
        // `store_message` / `store_and_stream`), so hashing the received frame
        // reproduces the mediator message id — the same identifier the pickup
        // drain reports and deletes by.
        let hash = sha256::digest(&raw);

        ws.process_inbound_didcomm_message(&atm, raw.clone()).await;

        let p = rx
            .try_recv()
            .expect("a live unprocessable frame must be reported");
        assert_eq!(p.raw, raw, "the raw frame is retained for quarantine");
        assert_eq!(
            p.attachment_id.as_deref(),
            Some(hash.as_str()),
            "reported with the mediator message id (sha256 of the delivered frame)"
        );
        assert!(!p.reason.is_empty(), "a rejection reason is included");
        assert!(rx.try_recv().is_err(), "exactly one unprocessable event");
    }

    /// An ATM that accepts plaintext, so a test frame unpacks without keys.
    async fn plaintext_atm() -> ATM {
        use crate::config::{ATMConfig, MessageWrappingType, UnpackPolicy};
        use affinidi_tdk_common::{TDKSharedState, config::TDKConfig};

        let config = ATMConfig::builder()
            .with_unpack_policy(UnpackPolicy {
                expected: vec![MessageWrappingType::Plaintext],
                ..UnpackPolicy::default()
            })
            .build()
            .unwrap();
        let tdk = Arc::new(
            TDKSharedState::new(TDKConfig::headless().unwrap())
                .await
                .unwrap(),
        );
        ATM::new(config, tdk).await.unwrap()
    }

    fn plaintext_frame(id: &str, thid: Option<&str>) -> String {
        use affinidi_messaging_didcomm::message::Message as DcMessage;
        let mut msg = DcMessage::build(
            id.to_string(),
            "example/v1".to_string(),
            serde_json::json!({ "n": id }),
        )
        .from("did:example:sender".to_string())
        .to("did:example:recipient".to_string());
        if let Some(thid) = thid {
            msg = msg.thid(thid.to_string());
        }
        serde_json::to_string(&msg.finalize()).unwrap()
    }

    /// Park a `Next` waiter the way `live_stream_next` does, and return its
    /// receiver so the test decides whether it is still listening.
    fn park_next(ws: &mut WebSocketTransport, id: u32) -> oneshot::Receiver<WebSocketResponses> {
        let (tx, rx) = oneshot::channel();
        ws.next_requests.insert(id, tx);
        ws.next_requests_list.push_back(id);
        rx
    }

    /// A `live_stream_next` whose poll window has just elapsed has dropped its
    /// receiver, but its `CancelNext` has not reached the task yet. A message
    /// that arrives in that gap used to be handed to the dead waiter and lost
    /// (`let _ = sender.send(..)`). About one message in twenty was lost to a
    /// caller polling in 500 ms windows. It must be cached instead.
    #[tokio::test]
    async fn a_message_for_a_gone_next_waiter_is_cached_not_lost() {
        let atm = plaintext_atm().await;
        let mut ws = test_transport(&atm);
        drop(park_next(&mut ws, 1)); // the poll timed out

        ws.process_inbound_didcomm_message(&atm, plaintext_frame("m1", None))
            .await;

        let (cached, _) = ws
            .inbound_cache
            .next()
            .expect("the message must be cached, not lost with the gone waiter");
        assert_eq!(cached.id, "m1");
        assert!(ws.next_requests.is_empty() && ws.next_requests_list.is_empty());
    }

    /// A gone waiter hands the message on to the next live one, oldest first.
    #[tokio::test]
    async fn a_message_skips_a_gone_next_waiter_for_a_live_one() {
        let atm = plaintext_atm().await;
        let mut ws = test_transport(&atm);
        drop(park_next(&mut ws, 1)); // timed out
        let live = park_next(&mut ws, 2); // still listening

        ws.process_inbound_didcomm_message(&atm, plaintext_frame("m2", None))
            .await;

        // Bounded: before the fix the gone waiter swallowed the message and
        // this waiter was never answered.
        let answered = tokio::time::timeout(Duration::from_secs(2), live)
            .await
            .expect("the live waiter must be answered, not starved by the gone one");
        match answered.expect("the live waiter must be answered") {
            WebSocketResponses::MessageReceived(msg, _) => assert_eq!(msg.id, "m2"),
            _ => panic!("expected the unpacked message"),
        }
        assert!(
            ws.inbound_cache.next().is_none(),
            "delivered once, not also cached"
        );
    }

    /// A `live_stream_get` that gave up a moment early must not take the reply
    /// with it: the reply is cached for a retry or a `Next`.
    #[tokio::test]
    async fn a_reply_for_a_gone_get_waiter_is_cached_not_lost() {
        let atm = plaintext_atm().await;
        let mut ws = test_transport(&atm);
        let (tx, rx) = oneshot::channel();
        assert!(ws.inbound_cache.get_or_add_wanted("thread-1", tx).is_none());
        drop(rx); // the get timed out

        ws.process_inbound_didcomm_message(&atm, plaintext_frame("reply-1", Some("thread-1")))
            .await;

        let (cached, _) = ws
            .inbound_cache
            .next()
            .expect("the reply must be cached, not lost with the gone waiter");
        assert_eq!(cached.id, "reply-1");
    }

    /// A frame that can never unpack — here a plaintext the secure default
    /// policy rejects — is deleted from the mediator, keyed by the sha256 of
    /// the frame, and the deletion is queued without blocking the task.
    /// Before, it was only logged (and, with a channel configured, reported),
    /// so it stayed in the inbox counting against its sender's per-peer quota.
    #[tokio::test]
    async fn a_permanently_unprocessable_frame_is_deleted() {
        use crate::config::ATMConfig;
        use affinidi_tdk_common::{TDKSharedState, config::TDKConfig};

        let config = ATMConfig::builder()
            .with_unprocessable_message_channel(16)
            .build()
            .unwrap();
        let tdk = Arc::new(
            TDKSharedState::new(TDKConfig::headless().unwrap())
                .await
                .unwrap(),
        );
        let atm = ATM::new(config, tdk).await.unwrap();
        let mut rx = atm.get_unprocessable_message_channel().unwrap();
        let mut ws = test_transport(&atm);

        let raw = plaintext_frame("poison", None);
        tokio::time::timeout(
            Duration::from_secs(2),
            ws.process_inbound_didcomm_message(&atm, raw.clone()),
        )
        .await
        .expect("handling an unprocessable frame must not block the transport task");

        assert_eq!(ws.health.unprocessable_deleted, 1, "queued for deletion");
        assert_eq!(ws.unpack_sightings.len(), 0, "nothing left to retry");
        let reported = rx.try_recv().expect("still reported on the channel");
        assert_eq!(reported.attachment_id, Some(sha256::digest(&raw)));
    }

    /// Opting out keeps the old behaviour.
    #[tokio::test]
    async fn deletion_can_be_turned_off() {
        use crate::config::ATMConfig;
        use affinidi_tdk_common::{TDKSharedState, config::TDKConfig};

        let config = ATMConfig::builder()
            .with_delete_unprocessable(false)
            .build()
            .unwrap();
        let tdk = Arc::new(
            TDKSharedState::new(TDKConfig::headless().unwrap())
                .await
                .unwrap(),
        );
        let atm = ATM::new(config, tdk).await.unwrap();
        let mut ws = test_transport(&atm);
        ws.process_inbound_didcomm_message(&atm, plaintext_frame("kept", None))
            .await;
        assert_eq!(ws.health.unprocessable_deleted, 0);
    }

    /// A transient failure (a resolver hiccup) is not poison: the frame is left
    /// for redelivery, and deleted only on its third failed offer.
    #[tokio::test]
    async fn a_transiently_unprocessable_frame_is_deleted_only_on_its_third_offer() {
        let atm = plaintext_atm().await;
        let mut ws = test_transport(&atm);
        let err = ATMError::DIDError("could not resolve did:web:flaky".into());
        let raw = plaintext_frame("flaky", None);
        let id = sha256::digest(&raw);

        ws.handle_unprocessable(&atm, &id, &raw, &err);
        ws.handle_unprocessable(&atm, &id, &raw, &err);
        assert_eq!(ws.health.unprocessable_deleted, 0, "kept for redelivery");
        assert_eq!(ws.health.unprocessable_retained, 1);

        ws.handle_unprocessable(&atm, &id, &raw, &err);
        assert_eq!(ws.health.unprocessable_deleted, 1, "third offer deletes");
        assert_eq!(ws.health.unprocessable_retained, 0);
    }

    /// The mediator's answer to our own receive-leg probe is ours: it must not
    /// reach the application, which never asked for it.
    #[tokio::test]
    async fn a_probe_answer_is_consumed_not_delivered() {
        let atm = plaintext_atm().await;
        let mut ws = test_transport(&atm);
        ws.probe_ids.push_back("probe-1".to_string());
        let waiter = park_next(&mut ws, 1);

        let status = {
            use affinidi_messaging_didcomm::message::Message as DcMessage;
            serde_json::to_string(
                &DcMessage::build(
                    "status-1".to_string(),
                    STATUS_TYPE.to_string(),
                    serde_json::json!({"message_count": 0}),
                )
                .thid("probe-1".to_string())
                .from("did:example:mediator".to_string())
                .to("did:example:recipient".to_string())
                .finalize(),
            )
            .unwrap()
        };
        ws.process_inbound_didcomm_message(&atm, status).await;

        assert!(ws.inbound_cache.next().is_none(), "not cached");
        assert_eq!(
            ws.next_requests_list.len(),
            1,
            "the waiter is still waiting"
        );
        drop(waiter);

        // A status answering somebody else's request still goes through.
        ws.process_inbound_didcomm_message(&atm, plaintext_frame("other", Some("not-a-probe")))
            .await;
        assert!(ws.inbound_cache.next().is_some() || ws.next_requests_list.is_empty());
    }

    /// Any inbound data frame answers an outstanding probe; a pong does not —
    /// it proves the socket, not that the mediator is delivering to it.
    #[tokio::test]
    async fn a_data_frame_answers_the_probe_and_a_pong_does_not() {
        let atm = plaintext_atm().await;
        let mut ws = test_transport(&atm);
        ws.probe = Some(("p".into(), tokio::time::Instant::now()));

        ws.handle_inbound_message(&atm, Ok(Message::Pong(Bytes::new())))
            .await;
        assert!(ws.probe.is_some(), "a pong is not evidence of delivery");

        ws.handle_inbound_message(&atm, Ok(Message::text(plaintext_frame("d", None))))
            .await;
        assert!(ws.probe.is_none(), "a data frame answers the probe");
        assert!(ws.health.last_data_frame_at.is_some());
    }

    /// Frames held with no consumer taking them are reported as a stall, and
    /// the report clears once they are taken.
    #[tokio::test]
    async fn held_frames_nobody_takes_are_reported_as_a_stall() {
        let atm = plaintext_atm().await;
        let mut ws = test_transport(&atm);
        ws.process_inbound_didcomm_message(&atm, plaintext_frame("held", None))
            .await;
        ws.track_held_frames();
        assert_eq!(ws.health.held_frames, 1);

        // Pretend it has been held past the threshold.
        ws.held_since = Some(tokio::time::Instant::now() - CONSUMER_STALL_AFTER);
        ws.check_receive_leg(&atm).await;
        assert!(ws.health.consumer_stalled(), "a stall is reported");

        let _ = ws.inbound_cache.next();
        ws.track_held_frames();
        ws.check_receive_leg(&atm).await;
        assert!(!ws.health.consumer_stalled(), "and clears once drained");
    }
}
