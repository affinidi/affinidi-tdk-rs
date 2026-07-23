/*!
 A task that listens for streaming notifications from the storage
 backend and sends them to clients over a websocket.

 It maintains a HashMap of channels keyed by DID hash. If a duplicate
 WebSocket is opened for the same DID the older session is forcibly
 closed so only the most recent one receives messages.

 When a duplicate replaces an existing session, the surviving socket is
 sent a redelivery of the recipient's undelivered inbox (see
 [`spawn_inbox_redelivery`]). A live-stream notification published in the
 instant the old socket is torn down would otherwise be stranded: the
 message is durably stored in the inbox (the store both live-pushes *and*
 persists every non-ephemeral message) but the surviving socket is never
 told to re-cover it, so a client that relies on live delivery hangs until
 timeout. Redelivery closes that gap — at-least-once, consistent with the
 message-pickup delete-to-ack contract. See issue #374.

 The notification stream comes from `MediatorStore::streaming_subscribe`,
 so the task runs unchanged whether the backend is Redis pub/sub,
 Fjall's in-process broadcast, or the test MemoryStore.
*/
use crate::common::metrics::names::{
    WEBSOCKET_CHURN_REFUSED_TOTAL, WEBSOCKET_DUPLICATE_CHURN_TOTAL,
    WEBSOCKET_DUPLICATE_REPLACEMENTS_TOTAL, WEBSOCKET_REDELIVERED_MESSAGES_TOTAL,
    WS_LIVE_DELIVERY_DROPPED,
};
use crate::common::ws_budget::{SendPermit, WsSendBudget};
use crate::tasks::supervisor::TaskSupervisor;
use affinidi_messaging_mediator_common::{
    errors::MediatorError,
    store::{MediatorStore, StreamingClientState, types::PubSubRecord},
    types::messages::FetchOptions,
};
use ahash::AHashMap as HashMap;
use dashmap::DashSet;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    select,
    sync::{Mutex, broadcast, mpsc},
    time::sleep,
};
use tracing::{Instrument, Level, debug, error, info, span, warn};

/// A duplicate replacement arriving within this window of the previous
/// registration for the same DID is counted as socket *churn* (the
/// flip-flop signal in issue #374).
const CHURN_WINDOW: Duration = Duration::from_secs(5);

/// Consecutive in-window replacements for one DID before the duel damper in
/// `_handle_registration` starts holding the slot for the incumbent. Two is a
/// hand-off (A replaced by B, B replaced by A); three or more is a duel.
const CHURN_REFUSE_STREAK: u32 = 3;

/// Page size for the inbox-redelivery drain.
const REDELIVERY_PAGE: usize = 50;

/// Safety bound on how many messages a single redelivery will re-push,
/// so a pathologically large inbox can't pin the drain task. If hit, the
/// remainder is left for the client to pick up via normal message-pickup.
const REDELIVERY_MAX: usize = 1000;

/// Slots in a single connection's send queue.
///
/// This is the per-connection *depth* cap; the aggregate *byte* cap is the
/// shared [`WsSendBudget`]. Depth still matters: without it one client could
/// reserve the entire global pool for itself. Together they bound a connection
/// at `WS_CHANNEL_SLOTS × message_size` and all connections at the pool size.
pub const WS_CHANNEL_SLOTS: usize = 8;

/// One registered streaming client for a DID.
struct ClientEntry {
    /// Channel to the per-connection websocket handler.
    tx: mpsc::Sender<QueuedCommand>,
    /// Session id of the owning websocket (used for churn/diagnostic logs).
    session_id: String,
    /// Whether live delivery is currently active for this client.
    active: bool,
    /// When this client registered — used to detect rapid replacement churn.
    registered_at: Instant,
    /// Consecutive in-churn-window replacements this DID's slot has seen.
    /// Carried across replacements and reset by any registration that arrives
    /// outside the window. Drives the duel damper in `_handle_registration`.
    churn_streak: u32,
}

/// Used when updating the streaming state.
/// Register: Creates the hash map entry for the DID hash and TX Channel
/// Start: Start streaming messages to clients.
/// Stop: Stop streaming messages to clients.
/// Deregister: Remove the hash map entry for the DID hash.
pub enum StreamingUpdateState {
    Register {
        channel: mpsc::Sender<QueuedCommand>,
        session_id: String,
        did: String,
    },
    /// Enable live delivery for the socket owned by `session_id`.
    ///
    /// Session-scoped for the same reason [`Deregister`](Self::Deregister) is:
    /// `clients` is keyed by DID hash, so an update that doesn't name its
    /// session acts on whichever connection currently holds the slot — which
    /// may not be the one that sent it.
    Start { session_id: String },
    /// Disable live delivery for the socket owned by `session_id`.
    Stop { session_id: String },
    /// Remove the map entry for this DID — but only if it is still *this*
    /// session's entry. `clients` is keyed by DID hash, not by connection, so a
    /// deregistration must name the session it belongs to: a socket that has
    /// already been replaced (one DID, one slot) would otherwise evict its
    /// successor on the way out. See the session-id check in the handler.
    Deregister { session_id: String },
}

/// Used to send commands from the streaming task to the websocket handler
pub enum WebSocketCommands {
    Message(String), // Send a message to the client
    Close,           // Close the websocket connection
}

/// A command sitting in a connection's send queue, together with the byte
/// reservation it holds against the global [`WsSendBudget`].
///
/// The permit is owned by the queue item on purpose: it is released exactly when
/// the item is dropped, which is when the connection's writer has taken it off
/// the queue. There is no separate "release" call to forget.
pub struct QueuedCommand {
    pub cmd: WebSocketCommands,
    /// `None` for control commands (`Close`), which carry no payload and must
    /// never be refused for want of buffer bytes.
    _permit: Option<SendPermit>,
}

impl QueuedCommand {
    /// A control command. Always admissible — it holds no bytes.
    fn control(cmd: WebSocketCommands) -> Self {
        Self { cmd, _permit: None }
    }
}

/// Queue a payload to one client without blocking.
///
/// Returns `false` if the message was dropped — either the global byte pool is
/// exhausted or this connection's queue is full. Both mean the client is not
/// keeping up; the message is already durable in its inbox, so it will arrive on
/// the next poll or on reconnect redelivery.
///
/// Non-blocking is the whole point: this is called from the single streaming
/// loop that serves every DID, so awaiting one slow client here would stall live
/// delivery for all of them.
fn try_queue_message(
    tx: &mpsc::Sender<QueuedCommand>,
    budget: &WsSendBudget,
    did_hash: &str,
    message: String,
) -> bool {
    let Some(permit) = budget.try_reserve(message.len()) else {
        warn!(
            "WebSocket send buffer exhausted ({} bytes total); dropping live notification for {}. \
             Client will pick the message up from its inbox.",
            budget.total_bytes(),
            did_hash
        );
        metrics::counter!(WS_LIVE_DELIVERY_DROPPED).increment(1);
        return false;
    };

    let queued = QueuedCommand {
        cmd: WebSocketCommands::Message(message),
        _permit: Some(permit),
    };

    if tx.try_send(queued).is_err() {
        // Channel full (slow consumer) or closed (socket gone). Either way the
        // push is dropped; a closed channel is reaped by the caller.
        debug!("Send queue unavailable for {did_hash}; dropping live notification");
        metrics::counter!(WS_LIVE_DELIVERY_DROPPED).increment(1);
        return false;
    }
    true
}

/// Used to update the streaming state.
/// did_hash: The DID hash to update the state for.
/// state: The state to update to.
pub struct StreamingUpdate {
    pub did_hash: String,
    pub state: StreamingUpdateState,
}

#[derive(Clone)]
pub struct StreamingTask {
    pub uuid: String,
    pub channel: mpsc::Sender<StreamingUpdate>,
    /// Global byte pool shared by every connection's send queue.
    pub send_budget: WsSendBudget,
}

impl StreamingTask {
    /// Create the streaming task's command channel and register the task with
    /// the [`TaskSupervisor`], so a panic or startup error restarts it with
    /// backoff (and surfaces as a `degraded` component in `/readyz`) instead of
    /// dying silently with a dropped `JoinHandle`.
    ///
    /// The returned [`StreamingTask`] holds the `tx` side of the command
    /// channel (cloned into `SharedData` and every WebSocket handler). The `rx`
    /// side is wrapped in an `Arc<Mutex<_>>` so it survives restarts: the
    /// supervisor builds a fresh future each restart, but it re-locks the
    /// *same* receiver, so queued commands and the live `tx` clones stay valid.
    /// `tokio`'s `Mutex` doesn't poison, so a panicking run releases the guard
    /// cleanly for the next restart.
    ///
    /// Not load-bearing: if streaming is down, clients fall back to
    /// message-pickup polling, so it degrades `/readyz` rather than failing it.
    pub fn spawn_supervised(
        supervisor: &TaskSupervisor,
        database: Arc<dyn MediatorStore>,
        mediator_uuid: &str,
        send_budget: WsSendBudget,
    ) -> Self {
        // Control-plane channel (register/start/stop/deregister). Carries no
        // message bodies — a handful of small structs — so a slot count is the
        // right bound here and 10 is plenty.
        let (tx, rx) = mpsc::channel(10);
        let task = StreamingTask {
            channel: tx,
            uuid: mediator_uuid.to_string(),
            send_budget,
        };
        let rx = Arc::new(Mutex::new(rx));

        let supervised = task.clone();
        supervisor.spawn("websocket_streaming", false, move || {
            let task = supervised.clone();
            let database = database.clone();
            let rx = rx.clone();
            async move {
                let mut rx = rx.lock().await;
                task.ws_streaming_task(database, &mut rx).await
            }
        });

        task
    }

    /// Streams messages to subscribed clients over websocket.
    /// Is spawned as a task
    async fn ws_streaming_task(
        self,
        database: Arc<dyn MediatorStore>,
        channel: &mut mpsc::Receiver<StreamingUpdate>,
    ) -> Result<(), MediatorError> {
        let _span = span!(Level::INFO, "ws_streaming_task", uuid = &self.uuid);

        async move {
            info!("WebSocket streaming task starting");

            // Clean up any existing sessions left over from previous runs
            database.streaming_clean_start(&self.uuid).await?;

            // Create a hashmap to store the clients keyed by did_hash.
            let mut clients: HashMap<String, ClientEntry> = HashMap::new();

            // DIDs with an inbox-redelivery drain currently in flight. Used to
            // damp duplicate-socket flip-flop: a duel that replaces the socket
            // every couple of seconds must not re-dump the whole inbox on each
            // replacement. A replay already running for a DID covers the current
            // inbox state, so concurrent replacements skip spawning another.
            let replay_in_progress: Arc<DashSet<String>> = Arc::new(DashSet::new());

            // Subscribe to delivery notifications via the trait. Backends
            // are responsible for the wire-level transport (Redis pub/sub,
            // in-process broadcast, etc.) — the task just consumes
            // already-decoded `PubSubRecord`s.
            let mut rx = database.streaming_subscribe(&self.uuid).await?;

            loop {
                select! {
                    value = rx.recv() => {
                        match value {
                            Ok(payload) => {
                                self.dispatch_payload(database.as_ref(), &mut clients, payload).await;
                            }
                            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                                // Subscriber fell behind; backend's broadcast capacity
                                // was exceeded. Live messages were dropped, but the
                                // queueing path still picked them up — clients just
                                // won't get a real-time push for those entries.
                                warn!(
                                    "Streaming subscriber lagged, dropped {} live notifications",
                                    skipped
                                );
                            }
                            Err(broadcast::error::RecvError::Closed) => {
                                error!("Streaming subscription closed, attempting to resubscribe");
                                rx = loop {
                                    sleep(Duration::from_secs(1)).await;
                                    match database.streaming_subscribe(&self.uuid).await {
                                        Ok(rx) => break rx,
                                        Err(err) => {
                                            error!("Error resubscribing to streaming channel: {err}");
                                            continue;
                                        }
                                    }
                                };
                            }
                        }
                    }
                    value = channel.recv() => { // mpsc command channel
                        if let Some(value) = &value {
                            match &value.state {
                                StreamingUpdateState::Register { .. } => {
                                    self._handle_registration(&database, &mut clients, &replay_in_progress, value).await;
                                },
                                StreamingUpdateState::Start { session_id } => {
                                    self._handle_activation(&database, &mut clients, &value.did_hash, session_id, true).await;
                                },
                                StreamingUpdateState::Stop { session_id } => {
                                    self._handle_activation(&database, &mut clients, &value.did_hash, session_id, false).await;
                                },
                                StreamingUpdateState::Deregister { session_id } => {
                                    // Only the session that currently owns the slot may
                                    // vacate it. One DID has one entry, so a socket that
                                    // was already replaced still runs its own teardown —
                                    // and an unconditional remove here would take the
                                    // *successor's* channel out with it. Dropping that
                                    // `tx` closes the live socket's command channel, so
                                    // its handler exits with "streaming task unavailable"
                                    // and the client sees the connection closed for no
                                    // reason it can act on. Common whenever one DID hands
                                    // off between transports (a DIDComm session closing
                                    // as a raw-TSP socket opens).
                                    match clients.get(value.did_hash.as_str()) {
                                        Some(entry) if entry.session_id != *session_id => {
                                            debug!(
                                                did_hash = %value.did_hash,
                                                leaving_session = %session_id,
                                                current_session = %entry.session_id,
                                                "Ignoring deregistration from a replaced session; the slot belongs to a newer connection",
                                            );
                                        }
                                        Some(_) => {
                                            clients.remove(value.did_hash.as_str());
                                            info!("Deregistered streaming for DID: ({}) registered_clients({})", value.did_hash, clients.len());
                                            if let Err(err) = database.streaming_set_state(&value.did_hash, &self.uuid, StreamingClientState::Deregistered).await {
                                                error!("Error stopping streaming for client ({}): {}",value.did_hash, err);
                                            }
                                        }
                                        None => {
                                            debug!(
                                                did_hash = %value.did_hash,
                                                leaving_session = %session_id,
                                                "Deregistration for a DID with no registered client",
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        .instrument(_span)
        .await
    }

    /// Forward one streaming notification to the WebSocket sender for
    /// its target DID, dropping clients whose channels have closed.
    ///
    /// Never awaits a client's send queue: this runs in the single loop that
    /// serves every DID, so blocking on one slow socket would stall live
    /// delivery for all of them. A client that cannot keep up has its push
    /// dropped (see [`try_queue_message`]).
    async fn dispatch_payload(
        &self,
        database: &dyn MediatorStore,
        clients: &mut HashMap<String, ClientEntry>,
        payload: PubSubRecord,
    ) {
        let PubSubRecord {
            did_hash,
            message,
            force_delivery,
        } = payload;
        match clients.get(&did_hash) {
            Some(entry) => {
                if force_delivery || entry.active {
                    // A closed channel means the socket is gone and the entry is
                    // stale; a *full* one means a slow client, which is not a
                    // reason to tear the connection down. Distinguish them, or a
                    // brief burst would evict a perfectly healthy client.
                    if entry.tx.is_closed() {
                        warn!("Dead WebSocket channel for ({did_hash}), cleaning up");
                        clients.remove(&did_hash);
                        if let Err(e) = database
                            .streaming_set_state(
                                &did_hash,
                                &self.uuid,
                                StreamingClientState::Deregistered,
                            )
                            .await
                        {
                            error!("Error deregistering dead client ({did_hash}): {e}");
                        }
                    } else if try_queue_message(
                        &entry.tx,
                        &self.send_budget,
                        &did_hash,
                        // Moved, not cloned: the body already exists in the
                        // broadcast ring slot, and `payload` is owned here.
                        message,
                    ) {
                        debug!("Sent message to client ({did_hash})");
                    }
                } else {
                    debug!("pub/sub msg received for did_hash({did_hash}) but it is not active");
                    if let Err(err) = database
                        .streaming_set_state(
                            &did_hash,
                            &self.uuid,
                            StreamingClientState::Registered,
                        )
                        .await
                    {
                        error!("Error stopping streaming for client ({did_hash}): {err}");
                    }
                }
            }
            None => {
                warn!(
                    "pub/sub msg received for did_hash({did_hash}) but it doesn't exist in clients HashMap"
                );
            }
        }
    }

    /// Turn live delivery on or off for **the session that owns the DID's slot**.
    ///
    /// `clients` is keyed by DID hash, not by connection, so an update that
    /// doesn't name its session acts on whoever holds the slot now. That is a
    /// real hazard for a DID whose sessions overlap: a `live-delivery-change`
    /// from a connection that has since been replaced would otherwise flip
    /// delivery for its *successor* — and a stale `Stop` is the bad one,
    /// because it clears both `active` and the stored `Live` state, so the
    /// healthy socket stays connected and simply stops receiving pushes. That
    /// is the same silent stop-delivering failure as the `Deregister` bug, and
    /// just as hard to see from either end.
    ///
    /// An update whose session no longer owns the slot — or that arrives when
    /// there is no slot at all — is dropped. A slot-less `Start` is worth
    /// dropping in its own right: marking a DID `Live` with no channel to
    /// deliver on only produces "not in clients HashMap" warnings when messages
    /// arrive. Ordering makes this safe for legitimate traffic: `Register` and
    /// `Start` travel the same FIFO channel, so a live session's own `Start`
    /// always finds its entry.
    async fn _handle_activation(
        &self,
        database: &Arc<dyn MediatorStore>,
        clients: &mut HashMap<String, ClientEntry>,
        did_hash: &str,
        session_id: &str,
        active: bool,
    ) {
        match clients.get_mut(did_hash) {
            Some(entry) if entry.session_id == session_id => {
                entry.active = active;
            }
            Some(entry) => {
                debug!(
                    did_hash = %did_hash,
                    requesting_session = %session_id,
                    current_session = %entry.session_id,
                    active,
                    "Ignoring a live-delivery change from a session that no longer owns this DID's slot",
                );
                return;
            }
            None => {
                debug!(
                    did_hash = %did_hash,
                    requesting_session = %session_id,
                    active,
                    "Ignoring a live-delivery change for a DID with no registered client",
                );
                return;
            }
        }

        let (state, verb) = if active {
            (StreamingClientState::Live, "Starting")
        } else {
            (StreamingClientState::Registered, "Stopping")
        };
        info!("{verb} streaming for DID: ({did_hash})");
        if let Err(err) = database
            .streaming_set_state(did_hash, &self.uuid, state)
            .await
        {
            error!("Error changing streaming state for client ({did_hash}): {err}");
        }
    }

    /// Helper function to handle the registration of a new client.
    /// Handles if this is a duplicate channel for a DID
    async fn _handle_registration(
        &self,
        database: &Arc<dyn MediatorStore>,
        clients: &mut HashMap<String, ClientEntry>,
        replay_in_progress: &Arc<DashSet<String>>,
        value: &StreamingUpdate,
    ) {
        let StreamingUpdateState::Register {
            channel: client_tx,
            session_id: new_session_id,
            did,
        } = &value.state
        else {
            // Only `Register` updates reach this helper.
            return;
        };
        let new_session_id = new_session_id.as_str();
        let did = did.as_str();

        // Defensive guard: an empty `did` means the upstream session
        // arrived without an authenticated DID populated. Registering
        // it would index this client under
        // `did_hash = sha256("") = e3b0c44...` and silently misroute
        // every subsequent message. Refuse and log loudly so the
        // upstream auth bug surfaces immediately.
        if did.is_empty() || value.did_hash.is_empty() {
            error!(
                session = new_session_id,
                did_hash = %value.did_hash,
                "Refusing to register streaming client with empty DID — \
                 the upstream session is missing its authenticated DID. \
                 Closing the channel."
            );
            let _ = client_tx
                .send(QueuedCommand::control(WebSocketCommands::Close))
                .await;
            return;
        }

        // Is this replacing an existing session for the same DID?
        let mut churn_streak = 0;
        let replacing = if let Some(old) = clients.get_mut(&value.did_hash) {
            let since_last = old.registered_at.elapsed();
            let churn = since_last < CHURN_WINDOW;
            let since_last_ms = since_last.as_millis() as u64;
            churn_streak = if churn { old.churn_streak + 1 } else { 0 };

            // Duel damper. Newest-wins is the right rule for an isolated
            // duplicate — a client that reconnected after a half-open socket
            // must be able to take its slot back. It is the wrong rule for a
            // *sustained* duel: with two or more live sessions for one DID,
            // every takeover evicts a peer that immediately reconnects and
            // takes the slot straight back, and the pair (or the pack) saturate
            // the server with connect/close churn indefinitely.
            //
            // Past a short streak, hold the slot for the incumbent instead —
            // but only while the incumbent's channel is demonstrably alive, so
            // a stale entry can never lock a DID out. This is self-limiting:
            // refusals don't touch the incumbent's `registered_at`, so once it
            // ages past `CHURN_WINDOW` the next contender is accepted normally.
            // Worst case is one takeover per window rather than one per
            // round-trip.
            if churn && churn_streak >= CHURN_REFUSE_STREAK && !old.tx.is_closed() {
                old.churn_streak = churn_streak;
                metrics::counter!(WEBSOCKET_CHURN_REFUSED_TOTAL).increment(1);
                // Warn once as the duel starts, then stay quiet — the refusal
                // path is hot by definition and the metric is the live signal.
                if churn_streak == CHURN_REFUSE_STREAK {
                    warn!(
                        did = did,
                        incumbent_session = old.session_id,
                        refused_session = new_session_id,
                        since_last_ms,
                        churn_streak,
                        "Sustained duplicate-WebSocket duel for this DID: holding the \
                         incumbent session and refusing new connections for up to {}s. \
                         Something is running more than one live session for this DID.",
                        CHURN_WINDOW.as_secs(),
                    );
                } else {
                    debug!(
                        did = did,
                        incumbent_session = old.session_id,
                        refused_session = new_session_id,
                        churn_streak,
                        "Refusing duplicate WebSocket registration (duel damper)",
                    );
                }
                let _ = client_tx
                    .send(QueuedCommand::control(WebSocketCommands::Close))
                    .await;
                return;
            }

            let msg = "Duplicate WebSocket connection: closing old session in favour of new one";
            // A churning DID replaces its own socket every few seconds
            // (e.g. two client sessions for the same DID dueling over the
            // one-socket-per-DID slot). Logging every flip at WARN buries
            // the log — a two-hour duel emits thousands of identical lines.
            // Emit churn at DEBUG and let the dedicated
            // `WEBSOCKET_DUPLICATE_CHURN_TOTAL` counter be the operator
            // signal (rate-alert on it). A genuine, spaced-out duplicate
            // (non-churn) is still noteworthy, so keep it at WARN.
            if churn {
                debug!(
                    did = did,
                    old_session = old.session_id,
                    new_session = new_session_id,
                    since_last_ms,
                    churn,
                    "{msg}",
                );
            } else {
                warn!(
                    did = did,
                    old_session = old.session_id,
                    new_session = new_session_id,
                    since_last_ms,
                    churn,
                    "{msg}",
                );
            }
            metrics::counter!(WEBSOCKET_DUPLICATE_REPLACEMENTS_TOTAL).increment(1);
            if churn {
                // Rapid replacement for the same DID — surface the flip-flop
                // via a metric. The newest socket still wins (the one-socket
                // invariant is unchanged); only the redelivery is damped below.
                metrics::counter!(WEBSOCKET_DUPLICATE_CHURN_TOTAL).increment(1);
            }
            // Channel already exists, close the old one.
            let _ = old
                .tx
                .send(QueuedCommand::control(WebSocketCommands::Close))
                .await;
            true
        } else {
            false
        };

        // Count after this registration lands. A replacement swaps a map entry
        // rather than adding one, so `len() + 1` over-reported by one on every
        // duplicate — which reads, misleadingly, like a client leak during a
        // duel. `clients` is keyed by DID hash, so this is the number of DIDs
        // with a live socket, not the number of sockets.
        let registered_clients = if replacing {
            clients.len()
        } else {
            clients.len() + 1
        };
        info!(
            did = did,
            session = new_session_id,
            "Registered streaming for DID: ({}) registered_clients({})",
            value.did_hash,
            registered_clients
        );
        clients.insert(
            value.did_hash.clone(),
            ClientEntry {
                tx: client_tx.clone(),
                session_id: new_session_id.to_string(),
                active: false,
                registered_at: Instant::now(),
                churn_streak,
            },
        );

        if let Err(err) = database
            .streaming_set_state(
                &value.did_hash,
                &self.uuid,
                StreamingClientState::Registered,
            )
            .await
        {
            error!(
                "Error starting streaming to client ({}) streaming: {}",
                value.did_hash, err
            );
        }

        // On a replacement, re-cover any inbox message that was in flight to
        // the now-closed socket by redelivering the recipient's undelivered
        // inbox to the new socket (issue #374). Skip if a redelivery for this
        // DID is already running, so a flip-flop duel can't amplify into a
        // repeated whole-inbox dump.
        if replacing {
            // `DashSet::insert` returns `true` only when the hash was newly
            // added, so a concurrent redelivery for the same DID still sees
            // `false` and skips the duplicate drain — same guard semantics as
            // the previous `HashSet`, without the lock-poison hazard.
            let spawn = replay_in_progress.insert(value.did_hash.clone());
            if spawn {
                spawn_inbox_redelivery(
                    Arc::clone(database),
                    client_tx.clone(),
                    self.send_budget.clone(),
                    value.did_hash.clone(),
                    new_session_id.to_string(),
                    Arc::clone(replay_in_progress),
                );
            } else {
                debug!(
                    did_hash = %value.did_hash,
                    "Inbox redelivery already in progress for DID; skipping duplicate drain"
                );
            }
        }
    }
}

/// Drain the recipient's undelivered inbox to a freshly-registered socket
/// after it displaced a duplicate, re-pushing each stored (but not yet
/// deleted) message as a live-stream frame. Runs as a detached task so the
/// streaming `select!` loop — which services every DID — never blocks on a
/// multi-page database drain.
///
/// Messages are fetched with `DoNotDelete`: redelivery is a notification
/// re-cover, not an ack. The client deletes what it has processed via the
/// normal message-pickup path, so this is at-least-once and idempotent by
/// message id.
fn spawn_inbox_redelivery(
    database: Arc<dyn MediatorStore>,
    client_tx: mpsc::Sender<QueuedCommand>,
    budget: WsSendBudget,
    did_hash: String,
    session_id: String,
    replay_in_progress: Arc<DashSet<String>>,
) {
    tokio::spawn(async move {
        let mut start_id: Option<String> = None;
        let mut total: usize = 0;

        'drain: loop {
            let options = FetchOptions {
                limit: REDELIVERY_PAGE,
                start_id: start_id.clone(),
                ..Default::default() // delete_policy defaults to DoNotDelete
            };
            let page = match database
                .fetch_messages(&session_id, &did_hash, &options)
                .await
            {
                Ok(page) => page,
                Err(err) => {
                    warn!(
                        did_hash = %did_hash,
                        "Inbox redelivery fetch failed, aborting drain: {err}"
                    );
                    break 'drain;
                }
            };
            if page.success.is_empty() {
                break 'drain;
            }
            let page_len = page.success.len();

            for element in page.success {
                // Advance the cursor regardless of body presence so a missing
                // body can't pin the drain on the same page forever.
                if let Some(receive_id) = &element.receive_id {
                    start_id = Some(receive_id.clone());
                }
                let Some(msg) = element.msg else { continue };

                // Fetched with `DoNotDelete`, so anything not queued here stays
                // in the inbox. Stopping the drain early is therefore lossless —
                // the client picks the remainder up via normal message-pickup,
                // exactly as it does when REDELIVERY_MAX is hit.
                if !try_queue_message(&client_tx, &budget, &did_hash, msg) {
                    debug!(
                        did_hash = %did_hash,
                        "Send queue or byte budget unavailable mid-redelivery; \
                         stopping drain, remainder left for message-pickup"
                    );
                    break 'drain;
                }
                metrics::counter!(WEBSOCKET_REDELIVERED_MESSAGES_TOTAL).increment(1);
                total += 1;

                if total >= REDELIVERY_MAX {
                    warn!(
                        did_hash = %did_hash,
                        max = REDELIVERY_MAX,
                        "Inbox redelivery hit its safety cap; remaining messages \
                         left for normal message-pickup"
                    );
                    break 'drain;
                }
            }

            // A short page means the stream is exhausted.
            if page_len < REDELIVERY_PAGE {
                break 'drain;
            }
        }

        if total > 0 {
            debug!(did_hash = %did_hash, total, "Inbox redelivery complete");
        }
        replay_in_progress.remove(&did_hash);
    });
}

// MemoryStore (the in-process backend used here) is only compiled under the
// `memory-backend` feature, so gate these tests on it.
#[cfg(all(test, feature = "memory-backend"))]
mod tests {
    use super::*;
    use crate::store::memory_store::MemoryStore;
    use sha256::digest;
    use std::time::Duration as StdDuration;
    use tokio::time::timeout;

    fn streaming_task() -> StreamingTask {
        // The command channel is unused by `_handle_registration` directly; a
        // throwaway sender keeps the struct well-formed.
        let (tx, _rx) = mpsc::channel(1);
        StreamingTask {
            uuid: "test-mediator".to_string(),
            channel: tx,
            // Generous budget: these tests exercise registration/redelivery, not
            // buffer exhaustion (which `ws_budget` covers directly).
            send_budget: WsSendBudget::new(16 * 1024 * 1024),
        }
    }

    /// Build a client map holding one entry, owned by `session_id`.
    fn clients_with(
        did_hash: &str,
        session_id: &str,
        active: bool,
    ) -> HashMap<String, ClientEntry> {
        let (tx, _rx) = mpsc::channel(5);
        let mut clients = HashMap::new();
        clients.insert(
            did_hash.to_string(),
            ClientEntry {
                tx,
                session_id: session_id.to_string(),
                active,
                registered_at: Instant::now(),
                churn_streak: 0,
            },
        );
        clients
    }

    /// A `Stop` from a session that has already been replaced must not switch
    /// live delivery off for the connection that replaced it.
    ///
    /// This is the bad direction of the bug: `clients` is keyed by DID hash, so
    /// an unscoped `Stop` clears both `active` and the stored `Live` state for
    /// whoever holds the slot. The healthy socket stays connected and simply
    /// stops receiving pushes — the same silent stop-delivering failure as the
    /// `Deregister` bug, invisible from both ends.
    #[tokio::test]
    async fn a_stale_sessions_stop_does_not_deactivate_the_current_socket() {
        let database: Arc<dyn MediatorStore> = Arc::new(MemoryStore::new());
        let did_hash = digest("did:example:alice");
        let task = streaming_task();

        // Session B currently owns the slot and is live.
        let mut clients = clients_with(&did_hash, "B", true);
        database
            .streaming_set_state(&did_hash, &task.uuid, StreamingClientState::Live)
            .await
            .expect("mark live");

        // Session A — long since replaced — disables live delivery on its way out.
        task._handle_activation(&database, &mut clients, &did_hash, "A", false)
            .await;

        assert!(
            clients.get(&did_hash).expect("entry still present").active,
            "a replaced session must not deactivate its successor"
        );
        assert!(
            database
                .streaming_is_client_live(&did_hash, false)
                .await
                .is_some(),
            "the stored Live state belongs to the owning session and must survive"
        );
    }

    /// The mirror: a stale `Start` must not switch delivery on for a socket
    /// that deliberately turned it off.
    #[tokio::test]
    async fn a_stale_sessions_start_does_not_activate_the_current_socket() {
        let database: Arc<dyn MediatorStore> = Arc::new(MemoryStore::new());
        let did_hash = digest("did:example:bob");
        let task = streaming_task();

        let mut clients = clients_with(&did_hash, "B", false);

        task._handle_activation(&database, &mut clients, &did_hash, "A", true)
            .await;

        assert!(
            !clients.get(&did_hash).expect("entry still present").active,
            "a replaced session must not activate its successor"
        );
        assert!(
            database
                .streaming_is_client_live(&did_hash, false)
                .await
                .is_none(),
            "no Live state may be written on behalf of a session that does not own the slot"
        );
    }

    /// The owning session still works — without this, "ignore everything" would
    /// satisfy the two tests above.
    #[tokio::test]
    async fn the_owning_sessions_activation_is_applied() {
        let database: Arc<dyn MediatorStore> = Arc::new(MemoryStore::new());
        let did_hash = digest("did:example:carol");
        let task = streaming_task();

        let mut clients = clients_with(&did_hash, "B", false);

        task._handle_activation(&database, &mut clients, &did_hash, "B", true)
            .await;
        assert!(
            clients.get(&did_hash).expect("entry").active,
            "the owning session's start must apply"
        );
        assert!(
            database
                .streaming_is_client_live(&did_hash, false)
                .await
                .is_some(),
            "and must be reflected in the stored streaming state"
        );

        task._handle_activation(&database, &mut clients, &did_hash, "B", false)
            .await;
        assert!(
            !clients.get(&did_hash).expect("entry").active,
            "and its stop must apply too"
        );
        assert!(
            database
                .streaming_is_client_live(&did_hash, false)
                .await
                .is_none(),
            "stopping must clear the stored Live state"
        );
    }

    /// An activation for a DID with no registered client is dropped. Marking a
    /// DID `Live` with no channel to deliver on only produces "not in clients
    /// HashMap" warnings when messages arrive for it.
    #[tokio::test]
    async fn an_activation_without_a_registered_client_is_ignored() {
        let database: Arc<dyn MediatorStore> = Arc::new(MemoryStore::new());
        let did_hash = digest("did:example:dave");
        let task = streaming_task();

        let mut clients: HashMap<String, ClientEntry> = HashMap::new();
        task._handle_activation(&database, &mut clients, &did_hash, "A", true)
            .await;

        assert!(
            database
                .streaming_is_client_live(&did_hash, false)
                .await
                .is_none(),
            "a DID with no socket must not be marked live"
        );
    }

    /// Issue #374: a duplicate connect for a DID with an in-flight (stored but
    /// not yet delivered) message must close the old socket *and* redeliver the
    /// stored message to the surviving socket.
    #[tokio::test]
    async fn duplicate_replacement_redelivers_inbox_to_new_socket() {
        let database: Arc<dyn MediatorStore> = Arc::new(MemoryStore::new());
        let did = "did:example:alice";
        let did_hash = digest(did);
        let stored = "packed-in-flight-message";

        // A message is sitting in the inbox (the store persists every
        // non-ephemeral message, even when live-streamed).
        database
            .store_message("sess-store", stored, &did_hash, None, 0, 1000)
            .await
            .expect("store message");

        let task = streaming_task();
        let replay_in_progress: Arc<DashSet<String>> = Arc::new(DashSet::new());
        let mut clients: HashMap<String, ClientEntry> = HashMap::new();

        // Client A is the existing live session.
        let (a_tx, mut a_rx) = mpsc::channel(5);
        clients.insert(
            did_hash.clone(),
            ClientEntry {
                tx: a_tx,
                session_id: "A".to_string(),
                active: true,
                registered_at: Instant::now(),
                churn_streak: 0,
            },
        );

        // Client B connects for the same DID (the duplicate).
        let (b_tx, mut b_rx) = mpsc::channel(5);
        let update = StreamingUpdate {
            did_hash: did_hash.clone(),
            state: StreamingUpdateState::Register {
                channel: b_tx.clone(),
                session_id: "B".to_string(),
                did: did.to_string(),
            },
        };

        task._handle_registration(&database, &mut clients, &replay_in_progress, &update)
            .await;

        // The old socket is told to close.
        match timeout(StdDuration::from_secs(1), a_rx.recv())
            .await
            .expect("A receives a command")
        {
            Some(QueuedCommand {
                cmd: WebSocketCommands::Close,
                ..
            }) => {}
            other => panic!("expected Close on old socket, got {:?}", other.is_some()),
        }

        // The surviving socket receives the stranded message via redelivery.
        match timeout(StdDuration::from_secs(2), b_rx.recv())
            .await
            .expect("B receives the redelivered message")
        {
            Some(QueuedCommand {
                cmd: WebSocketCommands::Message(msg),
                ..
            }) => assert_eq!(msg, stored),
            _ => panic!("expected redelivered Message on the surviving socket"),
        }

        // And the new client is now the registered entry.
        assert_eq!(
            clients.get(&did_hash).map(|e| e.session_id.as_str()),
            Some("B")
        );
    }

    /// A fresh (non-duplicate) registration must NOT trigger an inbox
    /// redelivery — only replacements re-cover in-flight messages.
    #[tokio::test]
    async fn fresh_registration_does_not_redeliver() {
        let database: Arc<dyn MediatorStore> = Arc::new(MemoryStore::new());
        let did = "did:example:bob";
        let did_hash = digest(did);

        database
            .store_message("sess-store", "some-message", &did_hash, None, 0, 1000)
            .await
            .expect("store message");

        let task = streaming_task();
        let replay_in_progress: Arc<DashSet<String>> = Arc::new(DashSet::new());
        let mut clients: HashMap<String, ClientEntry> = HashMap::new();

        let (b_tx, mut b_rx) = mpsc::channel(5);
        let update = StreamingUpdate {
            did_hash: did_hash.clone(),
            state: StreamingUpdateState::Register {
                channel: b_tx.clone(),
                session_id: "B".to_string(),
                did: did.to_string(),
            },
        };

        task._handle_registration(&database, &mut clients, &replay_in_progress, &update)
            .await;

        // No replacement ⇒ no redelivery push within the window.
        assert!(
            timeout(StdDuration::from_millis(300), b_rx.recv())
                .await
                .is_err(),
            "fresh registration must not redeliver the inbox"
        );
    }

    /// Newest-wins is correct for an isolated duplicate, but under a sustained
    /// duel it makes both sides reconnect forever. Past `CHURN_REFUSE_STREAK`
    /// in-window replacements the incumbent keeps the slot and the contender is
    /// closed instead.
    #[tokio::test]
    async fn sustained_duel_holds_the_slot_for_the_incumbent() {
        let database: Arc<dyn MediatorStore> = Arc::new(MemoryStore::new());
        let did = "did:example:duellist";
        let did_hash = digest(did);

        let task = streaming_task();
        let replay_in_progress: Arc<DashSet<String>> = Arc::new(DashSet::new());
        let mut clients: HashMap<String, ClientEntry> = HashMap::new();

        // Keep every receiver alive: a live incumbent channel is a precondition
        // of the damper (see the dead-incumbent test below).
        let mut keepalive = Vec::new();

        let register = |session: &str, tx: mpsc::Sender<QueuedCommand>| StreamingUpdate {
            did_hash: did_hash.clone(),
            state: StreamingUpdateState::Register {
                channel: tx,
                session_id: session.to_string(),
                did: did.to_string(),
            },
        };

        // First connection takes the slot uncontested.
        let (tx, rx) = mpsc::channel(5);
        keepalive.push(rx);
        task._handle_registration(
            &database,
            &mut clients,
            &replay_in_progress,
            &register("s0", tx),
        )
        .await;

        // Contenders arrive back-to-back, well inside CHURN_WINDOW. The first
        // few take the slot (a genuine reconnect must still be able to).
        for i in 1..CHURN_REFUSE_STREAK {
            let session = format!("s{i}");
            let (tx, rx) = mpsc::channel(5);
            keepalive.push(rx);
            task._handle_registration(
                &database,
                &mut clients,
                &replay_in_progress,
                &register(&session, tx),
            )
            .await;
            assert_eq!(
                clients.get(&did_hash).map(|e| e.session_id.as_str()),
                Some(session.as_str()),
                "replacement {i} is below the streak threshold and must be accepted"
            );
        }

        // This one crosses the threshold: it must be refused, not honoured.
        let incumbent = clients
            .get(&did_hash)
            .map(|e| e.session_id.clone())
            .expect("an incumbent is registered");
        let (late_tx, mut late_rx) = mpsc::channel(5);
        task._handle_registration(
            &database,
            &mut clients,
            &replay_in_progress,
            &register("refused", late_tx),
        )
        .await;

        assert_eq!(
            clients.get(&did_hash).map(|e| e.session_id.as_str()),
            Some(incumbent.as_str()),
            "the incumbent must keep the slot once the duel is detected"
        );
        match timeout(StdDuration::from_secs(1), late_rx.recv())
            .await
            .expect("the refused contender is answered")
        {
            Some(QueuedCommand {
                cmd: WebSocketCommands::Close,
                ..
            }) => {}
            other => panic!(
                "expected Close on the refused socket, got {:?}",
                other.is_some()
            ),
        }
    }

    /// The damper must never be able to strand a DID. If the incumbent's channel
    /// is gone, the slot is handed over however long the streak is.
    #[tokio::test]
    async fn duel_damper_yields_to_a_dead_incumbent() {
        let database: Arc<dyn MediatorStore> = Arc::new(MemoryStore::new());
        let did = "did:example:ghost";
        let did_hash = digest(did);

        let task = streaming_task();
        let replay_in_progress: Arc<DashSet<String>> = Arc::new(DashSet::new());
        let mut clients: HashMap<String, ClientEntry> = HashMap::new();

        // Incumbent deep in a churn streak, but its receiver is dropped — the
        // socket behind it is gone.
        let (dead_tx, dead_rx) = mpsc::channel(5);
        drop(dead_rx);
        clients.insert(
            did_hash.clone(),
            ClientEntry {
                tx: dead_tx,
                session_id: "ghost".to_string(),
                active: true,
                registered_at: Instant::now(),
                churn_streak: CHURN_REFUSE_STREAK * 10,
            },
        );

        let (tx, _rx) = mpsc::channel(5);
        let update = StreamingUpdate {
            did_hash: did_hash.clone(),
            state: StreamingUpdateState::Register {
                channel: tx,
                session_id: "live".to_string(),
                did: did.to_string(),
            },
        };
        task._handle_registration(&database, &mut clients, &replay_in_progress, &update)
            .await;

        assert_eq!(
            clients.get(&did_hash).map(|e| e.session_id.as_str()),
            Some("live"),
            "a dead incumbent must never hold the slot against a live client"
        );
    }
}
