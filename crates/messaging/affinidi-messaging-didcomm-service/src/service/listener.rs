use std::sync::Arc;
use std::time::Duration;

use affinidi_messaging_core::ConnState;
use affinidi_messaging_sdk::config::ATMConfigBuilder;
#[cfg(feature = "tsp")]
use affinidi_messaging_sdk::protocols::message_pickup::InboundFrame;
use affinidi_messaging_sdk::{ATM, profiles::ATMProfile};
use affinidi_secrets_resolver::SecretsResolver;
use affinidi_tdk_common::TDKSharedState;
#[cfg(feature = "tsp")]
use tokio::sync::oneshot;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, broadcast, watch};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::config::ListenerConfig;
use crate::error::{DIDCommServiceError, StartupError};
use crate::handler::{DIDCommHandler, HandlerContext, TspHandler};
use crate::response::DIDCommResponse;
use crate::service::ListenerEvent;
use crate::service::inflight::Claim;
use crate::service::inflight::InFlight;
use crate::service::mediator::OfflineSync;
use crate::service::poison::{Disposition, HandlerGuard, report_dead_letter};
use crate::transport;
#[cfg(feature = "tsp")]
use crate::utils::new_message_id;
use crate::utils::{get_parent_thread_id, get_thread_id};

/// Convert SDK compat UnpackMetadata to didcomm crate UnpackMetadata
pub(crate) fn convert_meta(
    sdk_meta: affinidi_messaging_sdk::messages::compat::UnpackMetadata,
) -> affinidi_messaging_didcomm::UnpackMetadata {
    affinidi_messaging_didcomm::UnpackMetadata {
        encrypted: sdk_meta.encrypted,
        authenticated: sdk_meta.authenticated,
        non_repudiation: sdk_meta.non_repudiation,
        anonymous_sender: sdk_meta.anonymous_sender,
        re_wrapped_in_forward: sdk_meta.re_wrapped_in_forward,
        encrypted_from_kid: sdk_meta.encrypted_from_kid,
        encrypted_to_kids: sdk_meta.encrypted_to_kids,
        sign_from: sdk_meta.sign_from,
    }
}

const ATM_OPERATION_TIMEOUT_SECS: u64 = 10;

/// Shared handle providing access to a listener's ATM connection and profile.
///
/// Published via a `watch` channel after the listener connects, allowing
/// outbound messaging through the same mediator websocket.
#[derive(Clone)]
pub(crate) struct ConnectionHandle {
    pub atm: ATM,
    pub profile: Arc<ATMProfile>,
}

pub(crate) struct Listener {
    pub config: ListenerConfig,
    pub handler: Arc<dyn DIDCommHandler>,
    /// Optional TSP handler. When set and `config.protocols.tsp` is on, inbound
    /// TSP frames off the shared socket are routed here. `None` → TSP frames are
    /// dropped with a warning.
    ///
    /// Only read by `process_next_frame`, which is `#[cfg(feature = "tsp")]`.
    /// In a default (non-`tsp`) build the field is still set by `new()` but
    /// never read, so silence the dead-code lint there — otherwise the
    /// default-feature publish-verify build fails under `-D warnings`.
    #[cfg_attr(not(feature = "tsp"), allow(dead_code))]
    pub tsp_handler: Option<Arc<dyn TspHandler>>,
    pub shutdown: CancellationToken,
    atm: Option<ATM>,
    profile: Option<Arc<ATMProfile>>,
    /// Watch channel sender — updated after each successful connect().
    pub(crate) connection_tx: watch::Sender<Option<ConnectionHandle>>,
    /// Broadcast sender for lifecycle events.
    pub(crate) events_tx: broadcast::Sender<ListenerEvent>,
    /// Keeps each peer's inbound TSP frames in arrival order through unpack.
    /// Only touched by `process_next_frame`, on the listener loop.
    #[cfg(feature = "tsp")]
    tsp_order: std::sync::Mutex<SenderOrder>,
    /// Queue ids being handled, shared by the live stream and the offline
    /// drain so a message is dispatched by one of them only (R1.7).
    in_flight: Arc<InFlight>,
    /// Bounds concurrent handler invocations (`max_concurrent_handlers`).
    handler_permits: Arc<Semaphore>,
    /// Runs handlers under `handler_timeout` and dead-letters a message whose
    /// handler keeps failing (`max_handler_failures`); shared with the offline
    /// drain.
    guard: Arc<HandlerGuard>,
}

impl Listener {
    pub fn new(
        config: ListenerConfig,
        handler: Arc<dyn DIDCommHandler>,
        tsp_handler: Option<Arc<dyn TspHandler>>,
        shutdown: CancellationToken,
        connection_tx: watch::Sender<Option<ConnectionHandle>>,
        events_tx: broadcast::Sender<ListenerEvent>,
    ) -> Self {
        let handler_permits = Arc::new(Semaphore::new(config.max_concurrent_handlers.max(1)));
        let guard = Arc::new(HandlerGuard::new(
            config.handler_timeout,
            config.max_handler_failures,
        ));
        Self {
            config,
            handler,
            tsp_handler,
            shutdown,
            atm: None,
            profile: None,
            connection_tx,
            events_tx,
            #[cfg(feature = "tsp")]
            tsp_order: std::sync::Mutex::new(SenderOrder::default()),
            in_flight: Arc::new(InFlight::default()),
            handler_permits,
            guard,
        }
    }

    pub(crate) fn atm(&self) -> Result<&ATM, DIDCommServiceError> {
        self.atm
            .as_ref()
            .ok_or_else(|| DIDCommServiceError::Internal("Listener not connected".into()))
    }

    pub(crate) fn profile(&self) -> Result<&Arc<ATMProfile>, DIDCommServiceError> {
        self.profile
            .as_ref()
            .ok_or_else(|| DIDCommServiceError::Internal("Listener not connected".into()))
    }

    pub async fn connect(&mut self) -> Result<(), DIDCommServiceError> {
        // Clean up any existing connection before reconnecting to prevent
        // orphaned websocket tasks that independently retry and cause
        // duplicate-channel floods when the mediator comes back online.
        // The post-success-then-disconnect case is handled by stop_websocket
        // on `self.profile`. The partial-init case (profile_add failed before
        // returning a handle) is handled below by stop_websocket on the
        // locally-built `atm_profile`, since `from_tdk_profile` returns an
        // Arc and `profile_add(&atm_profile, true)` shares the same Mediator
        // (and therefore the same `ws_channel_tx` slot).
        if let Some(ref profile) = self.profile {
            let _ = profile.stop_websocket().await;
        }
        self.profile = None;
        self.atm = None;
        // Clear the connection handle so outbound callers get NotConnected
        let _ = self.connection_tx.send(None);

        // Clone rather than `take()` the caller-seeded config: `connect()` runs
        // on every restart-loop iteration (see `restart::run_with_restart`), and
        // `Option::take` left the field `None` after the first attempt, so every
        // subsequent retry fell back to a cold `TDKConfig::headless()` — losing
        // the caller's pre-seeded DID resolver and its warm cache (F4). Both
        // `TDKConfig` and its `DIDCacheClient` are Arc-cheap clones that share the
        // same underlying resolver state, so cloning keeps the warm resolver
        // across every reconnect.
        let tdk_config = match self.config.tdk_config.clone() {
            Some(cfg) => cfg,
            None => affinidi_tdk_common::config::TDKConfig::headless()?,
        };
        let shared_state = Arc::new(TDKSharedState::new(tdk_config).await?);

        shared_state
            .secrets_resolver()
            .insert_vec(self.config.profile.secrets())
            .await;

        // Relationship gating is left at its default (on). A service built on
        // this framework is an endpoint in the sense of spec Rev 3 §7.2.2, and
        // the framework now records inbound control messages — see
        // `dispatch_tsp_frame` — so it can hold the relationships the gate
        // checks for.
        //
        // A `relationship_store` on the listener config makes those relationships
        // durable across a restart; without one the ATM's ephemeral default is
        // used, and a bounce drops every peer's traffic until each re-handshakes.
        let atm_builder = ATMConfigBuilder::default();
        #[cfg(feature = "tsp")]
        let atm_builder = match self.config.relationship_store.clone() {
            Some(store) => atm_builder.with_relationship_store(store),
            None => atm_builder,
        };
        let atm_config = atm_builder.build().map_err(StartupError::Config)?;

        let atm = ATM::new(atm_config, shared_state)
            .await
            .map_err(StartupError::Init)?;

        let atm_profile = ATMProfile::from_tdk_profile(&atm, &self.config.profile).await?;

        let profile_arc = match tokio::time::timeout(
            Duration::from_secs(ATM_OPERATION_TIMEOUT_SECS),
            atm.profile_add(&atm_profile, true),
        )
        .await
        {
            Ok(Ok(p)) => p,
            Ok(Err(e)) => {
                // Belt-and-braces against older SDK versions / future
                // regressions: ensure a half-started websocket transport is
                // torn down. With the SDK fix in profile_enable_websocket
                // this is a no-op, but it prevents the duplicate-channel
                // storm described in the bug report if that fix is missing.
                let _ = atm_profile.stop_websocket().await;
                return Err(e.into());
            }
            Err(e) => {
                warn!(profile = %self.config.profile.alias, error = %e, "Timeout adding profile");
                let _ = atm_profile.stop_websocket().await;
                return Err(DIDCommServiceError::Timeout(e));
            }
        };

        let conn_handle = ConnectionHandle {
            atm: atm.clone(),
            profile: profile_arc.clone(),
        };

        self.atm = Some(atm);
        self.profile = Some(profile_arc);

        // Publish the connection handle so outbound messaging can use it
        let _ = self.connection_tx.send(Some(conn_handle));

        let _ = self.events_tx.send(ListenerEvent::Connected {
            listener_id: self.config.id.clone(),
        });

        Ok(())
    }

    pub async fn listen(&self) -> Result<(), DIDCommServiceError> {
        if let Some(ref acl_mode) = self.config.acl_mode {
            self.set_acl_mode(acl_mode).await?;
        }

        let atm = self.atm()?;
        let profile = self.profile()?;
        let handle = ConnectionHandle {
            atm: atm.clone(),
            profile: profile.clone(),
        };

        // R6.2: follow the transport's own connection state for as long as this
        // connection lives. The SDK reconnects the websocket privately; without
        // this, `Connected` and the published handle were boot-time latches and
        // a dropped socket went unreported. `connect()` published the handle,
        // so start from "connected" and apply whatever the transport says now.
        let mut conn_rx = profile.connection_state().await;
        let mut connected = true;
        if let Some(rx) = conn_rx.as_mut() {
            let state = *rx.borrow_and_update();
            apply_conn_state(
                state,
                &mut connected,
                &handle,
                &self.connection_tx,
                &self.events_tx,
                &self.config.id,
            );
        }

        // Stops the offline drain when this connection ends, whether by
        // shutdown or because the transport went away.
        let listen_token = self.shutdown.child_token();
        let mut tasks = JoinSet::new();

        let sync = OfflineSync {
            listener_id: self.config.id.clone(),
            atm: atm.clone(),
            profile: profile.clone(),
            handler: self.handler.clone(),
            tsp_handler: self.tsp_handler.clone(),
            in_flight: self.in_flight.clone(),
            permits: self.handler_permits.clone(),
            auto_delete: self.config.auto_delete,
            protocols: self.config.protocols,
            guard: self.guard.clone(),
        };
        let sync_token = listen_token.clone();
        tasks.spawn(async move { sync.run(&sync_token).await });

        let result = loop {
            // Reap completed tasks and log panics
            while let Some(result) = tasks.try_join_next() {
                if let Err(e) = result
                    && e.is_panic()
                {
                    error!(profile = %profile.inner.alias, error = %e, "Handler task panicked");
                }
            }

            tokio::select! {
                _ = self.shutdown.cancelled() => {
                    info!(profile = %profile.inner.alias, "Listener received shutdown signal");
                    break Ok(());
                }
                change = next_conn_change(&mut conn_rx) => match change {
                    Some(state) => apply_conn_state(
                        state,
                        &mut connected,
                        &handle,
                        &self.connection_tx,
                        &self.events_tx,
                        &self.config.id,
                    ),
                    None => {
                        // The transport task is gone and will not reconnect by
                        // itself: end this connection so the restart policy
                        // builds a new one.
                        let _ = self.connection_tx.send(None);
                        break Err(DIDCommServiceError::Internal(
                            "the mediator websocket transport stopped".into(),
                        ));
                    }
                },
                // While the socket is down there is nothing to pull; wait for
                // the reconnect instead of spinning on receive errors.
                result = self.process_next_message(&mut tasks), if connected => {
                    if let Err(e) = result {
                        warn!(profile = %profile.inner.alias, error = %e, "Error processing message");
                    }
                }
            }
        };

        listen_token.cancel();
        self.drain_tasks(&mut tasks).await;
        result
    }

    /// Wait for in-flight handlers (and the offline drain) to finish, for at
    /// most `shutdown_drain_timeout`, then abort what is left. An aborted
    /// handler's message was not acked, so the mediator redelivers it.
    async fn drain_tasks(&self, tasks: &mut JoinSet<()>) {
        let alias = &self.config.profile.alias;
        let timeout = self.config.shutdown_drain_timeout;
        info!(profile = %alias, count = tasks.len(), "Waiting for in-flight tasks to complete");
        let drained = tokio::time::timeout(timeout, async {
            while let Some(result) = tasks.join_next().await {
                if let Err(e) = result
                    && e.is_panic()
                {
                    error!(profile = %alias, error = %e, "Handler task panicked during shutdown");
                }
            }
        })
        .await;
        if drained.is_err() {
            warn!(
                profile = %alias,
                remaining = tasks.len(),
                timeout_secs = timeout.as_secs(),
                "Handlers still running after the drain timeout; aborting them (their messages \
                 were not acked and will be redelivered)"
            );
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
        }
    }

    async fn process_next_message(
        &self,
        tasks: &mut JoinSet<()>,
    ) -> Result<(), DIDCommServiceError> {
        // When TSP is enabled, pull frames of *either* protocol off the one
        // socket and route by transport (a node speaks both over a single
        // per-DID websocket — opening a second would be evicted as a duplicate).
        #[cfg(feature = "tsp")]
        if self.config.protocols.tsp() {
            return self.process_next_frame(tasks).await;
        }

        let wait_duration = Duration::from_secs(self.config.message_wait_duration_secs);
        let atm = self.atm()?;
        let profile = self.profile()?;

        // Bound concurrent handlers: with every permit taken, stop pulling
        // until one is free. The mediator keeps the rest queued.
        let permit = self.acquire_permit().await?;

        // R1.6/R1.7: pull the message WITHOUT acking it to the mediator
        // (`auto_delete = false`). The mediator keeps its copy until we ack —
        // and we ack only after the handler has processed the message, in
        // `dispatch_message`. Acking on receipt (the old default) meant a
        // teardown between receipt and the spawned handler task losing the
        // message forever.
        let next = atm
            .message_pickup()
            .live_stream_next(profile, Some(wait_duration), false)
            .await
            .map_err(DIDCommServiceError::ATM)?;

        if let Some((message, meta)) = next {
            // One owner per message (R1.7): the offline drain may already be
            // handling this one, since it is still queued at the mediator.
            let Some(claim) = self.in_flight.claim(&meta.sha256_hash) else {
                debug!(profile = %profile.inner.alias, "Message already being handled; skipped");
                return Ok(());
            };
            // Acked after handoff, by `spawn_then_ack`, honouring the
            // operator's `auto_delete = false` opt-out.
            let meta = convert_meta(*meta);
            let listener_id = self.config.id.clone();
            let handler = self.handler.clone();
            let conn = self.ack_conn(atm, profile);
            let (atm, profile) = (atm.clone(), profile.clone());
            Self::spawn_then_ack(tasks, permit, claim, conn, async move {
                Self::dispatch_message(&listener_id, &atm, &profile, &handler, message, meta, None)
                    .await;
                true
            });
        }

        Ok(())
    }

    /// Multiplexed receive: pull the next inbound frame (DIDComm *or* TSP) off
    /// the shared websocket and dispatch by transport.
    ///
    /// Like the DIDComm-only path, the frame is pulled WITHOUT acking it
    /// (`auto_delete = false`) and acked only after its handler has returned
    /// (R1.6), so a teardown between receipt and handling leaves it queued at
    /// the mediator for redelivery instead of losing it (#1150).
    #[cfg(feature = "tsp")]
    async fn process_next_frame(&self, tasks: &mut JoinSet<()>) -> Result<(), DIDCommServiceError> {
        let wait_duration = Duration::from_secs(self.config.message_wait_duration_secs);
        let atm = self.atm()?;
        let profile = self.profile()?;
        let permit = self.acquire_permit().await?;

        let next = atm
            .message_pickup()
            .live_stream_next_frame(profile, Some(wait_duration), false)
            .await
            .map_err(DIDCommServiceError::ATM)?;

        if let Some(frame) = next {
            self.route_frame(frame, permit, tasks).await?;
        }
        Ok(())
    }

    /// Claim and dispatch one frame taken off the live stream.
    ///
    /// Every frame — TSP included — is claimed in the in-flight record shared
    /// with the offline drain, keyed by the mediator's id for it
    /// ([`InboundFrame::ack_id`], which equals the delivery attachment id the
    /// drain keys by), so a queued message is dispatched by one path only
    /// (R1.7). A frame no handler here will ever take is acked at once, as the
    /// offline drain does; a handled frame is acked after its handler, and only
    /// with `auto_delete`.
    #[cfg(feature = "tsp")]
    async fn route_frame(
        &self,
        frame: InboundFrame,
        permit: OwnedSemaphorePermit,
        tasks: &mut JoinSet<()>,
    ) -> Result<(), DIDCommServiceError> {
        let atm = self.atm()?;
        let profile = self.profile()?;
        let ack_on = self.ack_conn(atm, profile);

        let Some(claim) = self.in_flight.claim(&frame.ack_id()) else {
            debug!(profile = %profile.inner.alias, "Message already being handled; skipped");
            return Ok(());
        };

        match frame {
            InboundFrame::DidComm(..) if !self.config.protocols.didcomm() => {
                debug!(
                    profile = %profile.inner.alias,
                    "DIDComm frame on a listener with DIDComm disabled; dropped (acked)"
                );
                Self::drop_frame(atm, profile, claim).await;
            }
            InboundFrame::DidComm(message, meta) => {
                let meta = convert_meta(*meta);
                let listener_id = self.config.id.clone();
                let atm = atm.clone();
                let profile = profile.clone();
                let handler = self.handler.clone();
                Self::spawn_then_ack(tasks, permit, claim, ack_on.clone(), async move {
                    Self::dispatch_message(
                        &listener_id,
                        &atm,
                        &profile,
                        &handler,
                        *message,
                        meta,
                        None,
                    )
                    .await;
                    true
                });
            }
            InboundFrame::Tsp(packed) => {
                let Some(tsp_handler) = self.tsp_handler.clone() else {
                    warn!(
                        profile = %profile.inner.alias,
                        "received TSP frame but no TspHandler configured — dropping (acked)"
                    );
                    Self::drop_frame(atm, profile, claim).await;
                    return Ok(());
                };
                // `decode` is base64url plus a check of the TSP magic bytes: a
                // pure function of the bytes the mediator holds, with no I/O,
                // so a failure is permanent — a retry would read the same
                // bytes and fail the same way. The frame is acked so it stops
                // being redelivered, and reported on the unprocessable-message
                // channel with its raw body, so the loss is observable and the
                // frame recoverable rather than only a log line.
                let qb2 = match atm.tsp().decode(&packed) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        warn!(
                            profile = %profile.inner.alias,
                            error = %e,
                            "Failed to decode TSP frame; dropping (acked) and reporting it as \
                             unprocessable"
                        );
                        atm.report_unprocessable(
                            Some(claim.id().to_string()),
                            (*packed).clone(),
                            format!("TSP frame could not be decoded: {e}"),
                        );
                        Self::drop_frame(atm, profile, claim).await;
                        return Ok(());
                    }
                };
                // Each frame is handled on its own task, but one peer's
                // frames must be unpacked in the order they arrived: an
                // invite admits the payload sent right behind it only once
                // it is recorded, and a payload unpacked first is discarded
                // by the relationship gate. So a frame waits for the
                // previous frame *from the same sender* to be unpacked
                // (and, for a control message, recorded) — not for its
                // handler to run. Frames from different peers never wait on
                // each other.
                //
                // The key is the envelope's cleartext sender, read before
                // any key is used, so it can be forged. Ordering only ever
                // makes a frame wait; it never admits one. A frame that lies
                // about its sender queues behind that VID's unpack, which is
                // cheap, and is refused at unpack anyway. What forged
                // senders could cost is memory and head-of-line delay, so
                // `SenderOrder` bounds both: past its limits a frame is
                // handled unordered, as it was before ordering existed.
                let slot = affinidi_tsp::MetaEnvelope::parse(&qb2)
                    .ok()
                    .and_then(|meta| {
                        self.tsp_order
                            .lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .enqueue(&meta.sender)
                    });
                let listener_id = self.config.id.clone();
                let atm = atm.clone();
                let profile = profile.clone();
                Self::spawn_then_ack(tasks, permit, claim, ack_on.clone(), async move {
                    let (prev, done) = match slot {
                        Some((prev, done)) => (prev, Some(done)),
                        None => (None, None),
                    };
                    if let Some(prev) = prev
                        && tokio::time::timeout(TSP_ORDER_WAIT, prev).await.is_err()
                    {
                        warn!(
                            profile = %profile.inner.alias,
                            wait_secs = TSP_ORDER_WAIT.as_secs(),
                            "The previous TSP frame from this sender is still being unpacked; \
                             handling this one without waiting further, so it may be \
                             unpacked out of order"
                        );
                    }
                    Self::dispatch_tsp_bytes(&listener_id, &atm, &profile, &tsp_handler, &qb2, done)
                        .await
                });
            }
            // `InboundFrame` is `#[non_exhaustive]`; tolerate a future frame
            // kind this build doesn't yet route.
            _ => {
                warn!(
                    profile = %profile.inner.alias,
                    "received unrecognised inbound frame kind — dropping (acked)"
                );
                Self::drop_frame(atm, profile, claim).await;
            }
        }

        Ok(())
    }

    /// What `spawn_then_ack` needs to settle a frame on this connection.
    fn ack_conn(&self, atm: &ATM, profile: &Arc<ATMProfile>) -> AckConn {
        AckConn {
            atm: atm.clone(),
            profile: profile.clone(),
            auto_delete: self.config.auto_delete,
            guard: self.guard.clone(),
        }
    }

    /// Run `work` — one frame's handler — on its own task holding `permit`,
    /// under the handler timeout with its panic caught, then settle the
    /// claimed message (R1.6):
    ///
    /// - handled (`work` returned `true`): acked, when `auto_delete` is on;
    /// - a failure that may clear (`work` returned `false`): left queued for a
    ///   later sync;
    /// - the handler panicked or timed out: left queued, until it has done so
    ///   `max_handler_failures` times; then dead-lettered — acked (whatever
    ///   `auto_delete` says: nothing will ever take it) and reported.
    ///
    /// The claim is released either way, recording the ack so a copy the
    /// offline drain fetched before it landed is skipped. A task aborted before
    /// then (teardown past the drain timeout) drops its claim unacked, and
    /// aborts the handler: the message is still queued at the mediator and is
    /// redelivered.
    fn spawn_then_ack<F>(
        tasks: &mut JoinSet<()>,
        permit: OwnedSemaphorePermit,
        claim: Claim,
        conn: AckConn,
        work: F,
    ) where
        F: std::future::Future<Output = bool> + Send + 'static,
    {
        tasks.spawn(async move {
            let _permit = permit;
            let disposition = conn.guard.run(claim.id(), work).await;
            let acked = match disposition {
                Disposition::Ack if conn.auto_delete => {
                    Self::ack(&conn.atm, &conn.profile, claim.id()).await
                }
                Disposition::Ack | Disposition::Leave => false,
                Disposition::DeadLetter { attempts, why } => {
                    report_dead_letter(
                        &conn.atm,
                        &conn.profile.inner.alias,
                        claim.id(),
                        attempts,
                        why,
                    );
                    Self::ack(&conn.atm, &conn.profile, claim.id()).await
                }
            };
            claim.finish(acked);
        });
    }

    /// Ack a frame no handler here will take, so the mediator stops
    /// redelivering it, and release its claim.
    #[cfg(feature = "tsp")]
    async fn drop_frame(atm: &ATM, profile: &Arc<ATMProfile>, claim: Claim) {
        let acked = Self::ack(atm, profile, claim.id()).await;
        claim.finish(acked);
    }

    /// Ack (delete) `id` at the mediator. Returns whether the delete was
    /// queued; a failure is logged and the message is redelivered.
    async fn ack(atm: &ATM, profile: &Arc<ATMProfile>, id: &str) -> bool {
        match atm.delete_message_background(profile, id).await {
            Ok(()) => true,
            Err(e) => {
                warn!(profile = %profile.inner.alias, error = %e, "Failed to ack (delete) message");
                false
            }
        }
    }

    /// Unpack a TSP frame (yielding cleartext payload + authenticated sender VID)
    /// and hand it to the configured [`TspHandler`].
    ///
    /// `message_id` is the frame's mediator id. A frame that does not decode
    /// can never decode (see `route_frame`), so it is acked — and reported
    /// on the unprocessable-message channel under that id with its raw body,
    /// as on the live path, rather than only logged.
    #[cfg(feature = "tsp")]
    pub(crate) async fn dispatch_tsp(
        listener_id: &str,
        atm: &ATM,
        profile: &Arc<ATMProfile>,
        handler: &Arc<dyn TspHandler>,
        message_id: &str,
        packed: String,
    ) -> bool {
        // The pickup socket surfaces the frame as the **qb64** stored string
        // (`base64url(qb2)`, i.e. `-E…` text) — NOT raw qb2. Use `unpack`, which
        // decodes the base64url first; `unpack_bytes(packed.as_bytes())` would
        // feed the ASCII `'-','E',…` bytes straight into the CESR parser and
        // fail with "missing -E envelope wrapper". (The raw-TSP `connect_websocket`
        // path yields already-decoded qb2 and correctly uses `unpack_bytes`; this
        // DIDComm-multiplexed path does not.)
        // A control message and an application message are indistinguishable
        // until opened — the kind lives in the encrypted payload, not the
        // envelope — so unpack once and branch on what comes back.
        let qb2 = match atm.tsp().decode(&packed) {
            Ok(bytes) => bytes,
            Err(e) => {
                warn!(
                    profile = %profile.inner.alias,
                    error = %e,
                    "Failed to decode TSP frame; dropping (acked) and reporting it as unprocessable"
                );
                atm.report_unprocessable(
                    Some(message_id.to_string()),
                    packed,
                    format!("TSP frame could not be decoded: {e}"),
                );
                return true;
            }
        };
        Self::dispatch_tsp_bytes(listener_id, atm, profile, handler, &qb2, None).await
    }

    /// [`dispatch_tsp`](Self::dispatch_tsp) on an already-decoded frame.
    ///
    /// Returns whether the frame may be acked (deleted at the mediator): `true`
    /// once it was handled or refused for good, `false` when unpacking failed
    /// for a reason that may clear
    /// ([`ATMError::is_transient_unpack_failure`](affinidi_messaging_sdk::errors::ATMError::is_transient_unpack_failure)),
    /// so it stays queued for a later sync.
    ///
    /// `order` is this frame's place in its sender's queue (see
    /// [`SenderOrder`]). It is released — dropped — as soon as the frame is
    /// unpacked and, for a control message, recorded: that is the point after
    /// which the sender's next frame sees this one's effect on the relationship
    /// gate. The handler then runs without holding up the next frame.
    #[cfg(feature = "tsp")]
    async fn dispatch_tsp_bytes(
        listener_id: &str,
        atm: &ATM,
        profile: &Arc<ATMProfile>,
        handler: &Arc<dyn TspHandler>,
        qb2: &[u8],
        order: Option<OrderSlot>,
    ) -> bool {
        let inbound = match atm.tsp().unpack_message(profile, qb2).await {
            Ok(v) => v,
            // A failure that may clear — the sender's DID did not resolve, or
            // its key state is not confirmed after a silence (Rev 3 §7.4.2)
            // because a refresh failed. The frame may well be valid, so it is
            // not acked: it stays queued at the mediator and the next offline
            // sync offers it again.
            Err(e) if e.is_transient_unpack_failure() => {
                warn!(
                    profile = %profile.inner.alias,
                    error = %e,
                    "Could not unpack an inbound TSP frame yet; left queued for a later retry"
                );
                return false;
            }
            Err(e) => {
                // Includes an application message the relationship gate
                // discarded (§7.2.2) — the one case where a peer's data is lost.
                warn!(
                    profile = %profile.inner.alias,
                    error = %e,
                    "Dropped an inbound TSP frame: it could not be unpacked"
                );
                return true;
            }
        };

        let (payload, sender_vid) = match inbound {
            affinidi_messaging_sdk::protocols::tsp::InboundTsp::Application { payload, sender } => {
                (payload, sender)
            }
            // §9.4: "The receiver SHOULD silently discard padding messages."
            // Logged at debug and dropped — it is normal traffic whose whole
            // purpose is to carry nothing, so anything louder would turn the
            // countermeasure into noise in the operator's log.
            affinidi_messaging_sdk::protocols::tsp::InboundTsp::Padding { sender } => {
                debug!(
                    profile = %profile.inner.alias,
                    from = %sender,
                    "Discarded a TSP padding message"
                );
                return true;
            }
            // Carried like an application message but labelled as control for
            // the layer above. This service has no upper layer of its own to
            // hand it to, so it is dropped rather than passed off as user data
            // — which is what would happen if the label were ignored.
            affinidi_messaging_sdk::protocols::tsp::InboundTsp::UpperLayerControl {
                sender,
                ..
            } => {
                debug!(
                    profile = %profile.inner.alias,
                    from = %sender,
                    "Ignored an upper-layer TSP control message (XCTL); this service has no \
                     upper layer to route it to"
                );
                return true;
            }
            affinidi_messaging_sdk::protocols::tsp::InboundTsp::Control {
                control,
                sender,
                thread_digest,
            } => {
                // Record it, and stop. Recording an invite is what admits the
                // application messages that follow it (§7.2.2 with §3.6), so a
                // service that did not would gate itself into silence.
                //
                // It is recorded but not answered. Whether to accept a
                // relationship an invite proposes is the application's
                // decision, not the framework's — so the invite is surfaced to
                // the handler, which may call `accept_relationship` with the
                // digest carried here.
                let recorded = atm
                    .tsp()
                    .record_incoming_control(profile, &sender, &control)
                    .await;
                // Recorded (or refused): the sender's next frame may go ahead.
                drop(order);
                match recorded {
                    Ok(incoming) => {
                        debug!(
                            profile = %profile.inner.alias,
                            sender = %sender,
                            state = ?incoming.state,
                            reply_expected = incoming.reply_expected,
                            "Recorded inbound TSP control message"
                        );
                        handler
                            .handle_control(
                                HandlerContext {
                                    listener_id: listener_id.to_string(),
                                    atm: atm.clone(),
                                    profile: profile.clone(),
                                    sender_did: Some(sender.clone()),
                                    // A TSP control message carries no DIDComm
                                    // ids; its thread digest is the stable one.
                                    message_id: control_message_id(&thread_digest),
                                    thread_id: control_message_id(&thread_digest),
                                    parent_thread_id: None,
                                },
                                *control,
                                sender,
                                thread_digest,
                            )
                            .await;
                    }
                    Err(e) => {
                        // Discarded by a protocol rule — a cancellation for a
                        // relationship we do not hold, the losing side of an
                        // invite race, or a copy of an invite already acted
                        // on. Not an error to answer.
                        debug!(
                            profile = %profile.inner.alias,
                            sender = %sender,
                            error = %e,
                            "Inbound TSP control message not recorded (a cancellation for a relationship \
                             we do not hold, the losing side of an invite race, or a copy of an \
                             invite already acted on)"
                        );
                    }
                }
                return true;
            }
            // `InboundTsp` is `#[non_exhaustive]`: a kind added later must not
            // fall through to the application-message path, which is what an
            // exhaustive match would have forced on the next person to add one.
            // Dropped and named, so it shows up as unhandled rather than as
            // user data.
            other => {
                warn!(
                    profile = %profile.inner.alias,
                    kind = ?std::mem::discriminant(&other),
                    "Dropped a TSP message of a kind this service does not handle"
                );
                return true;
            }
        };

        // Unpacked and admitted: the sender's next frame may go ahead while the
        // handler runs.
        drop(order);

        let ctx = HandlerContext {
            listener_id: listener_id.to_string(),
            atm: atm.clone(),
            profile: profile.clone(),
            sender_did: Some(sender_vid.clone()),
            // A TSP frame carries no DIDComm thread/message id; synthesize one so
            // handlers and logs have a stable id.
            message_id: new_message_id(),
            thread_id: String::new(),
            parent_thread_id: None,
        };

        let profile_alias = profile.inner.alias.clone();
        match handler.handle(ctx, payload, sender_vid.clone()).await {
            Ok(Some(response)) => {
                if let Err(e) = Self::send_tsp_reply(atm, profile, &sender_vid, &response).await {
                    warn!(profile = %profile_alias, error = %e, "Failed to send TSP reply");
                }
            }
            Ok(None) => {}
            Err(e) => {
                warn!(profile = %profile_alias, error = %e, "Unhandled TSP handler error");
            }
        }
        true
    }

    /// Seal a [`TspHandler`] reply to the authenticated sender and route it back
    /// over the same shared mediator websocket — the TSP analogue of
    /// [`send_response`](Self::send_response).
    ///
    /// Routing rule: when the listener's profile has a mediator (the common
    /// case — the sender is reachable through the same mediator we're connected
    /// to), route metadata-privately as `[mediator_did, sender_vid]` via
    /// `send_routed`. If the profile has no mediator configured, fall back to a
    /// TSP Direct `send`. Cross-mediator senders (a sender reachable only via a
    /// *different* mediator) are not resolved here — a handler that needs that
    /// can return `Ok(None)` and drive [`AffinidiMessageService::send_tsp_routed`]
    /// itself with an explicit route.
    #[cfg(feature = "tsp")]
    async fn send_tsp_reply(
        atm: &ATM,
        profile: &Arc<ATMProfile>,
        sender_vid: &str,
        response: &crate::handler::TspResponse,
    ) -> Result<(), DIDCommServiceError> {
        match profile.dids() {
            Ok((_, mediator_did)) => {
                let route = [mediator_did.to_string(), sender_vid.to_string()];
                atm.tsp()
                    .send_routed(profile, &route, &response.payload)
                    .await?;
            }
            Err(_) => {
                atm.tsp()
                    .send(profile, sender_vid, &response.payload)
                    .await?;
            }
        }
        Ok(())
    }

    async fn acquire_permit(&self) -> Result<OwnedSemaphorePermit, DIDCommServiceError> {
        self.handler_permits
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| DIDCommServiceError::Internal("handler semaphore closed".into()))
    }

    /// Hand `message` to the handler, send its reply, then ack `ack_id` if
    /// given. Returns whether the ack was made.
    pub(crate) async fn dispatch_message(
        listener_id: &str,
        atm: &ATM,
        profile: &Arc<ATMProfile>,
        handler: &Arc<dyn DIDCommHandler>,
        message: affinidi_messaging_didcomm::Message,
        meta: affinidi_messaging_didcomm::UnpackMetadata,
        // Mediator queue-id to ack (delete) AFTER handoff. `None` when the
        // caller acks elsewhere (the TSP-multiplexed path) or `auto_delete` is
        // off.
        ack_id: Option<String>,
    ) -> bool {
        let sender_did = crate::handler::authenticated_sender_did(&meta);
        let thread_id = get_thread_id(&message);
        let parent_thread_id = get_parent_thread_id(&message, false);

        let ctx = HandlerContext {
            listener_id: listener_id.to_string(),
            atm: atm.clone(),
            profile: profile.clone(),
            sender_did,
            message_id: message.id.clone(),
            thread_id,
            parent_thread_id,
        };

        let profile_alias = ctx.profile.inner.alias.clone();
        let inbound_type = message.typ.clone();
        match handler.handle(ctx.clone(), message, meta).await {
            Ok(Some(response)) if !reply_allowed(&inbound_type, &response) => {
                debug!(
                    profile = %profile_alias,
                    message_type = %inbound_type,
                    "Problem report not answered with a problem report"
                );
            }
            Ok(Some(response)) => {
                if let Err(e) = Self::send_response(&ctx, response).await {
                    warn!(profile = %profile_alias, error = %e, "Failed to send response");
                }
            }
            Ok(None) => {}
            Err(e) => {
                warn!(profile = %profile_alias, error = %e, "Unhandled handler error");
            }
        }

        // R1.6: ack (delete from the mediator) only NOW — after the handler has
        // had the message. If the process is torn down before this line the
        // message stays queued at the mediator and is redelivered on the next
        // pickup, rather than being lost. A failed ack is non-fatal: the message
        // is redelivered and de-duplicated by the receiver instead.
        match ack_id {
            Some(sha256_hash) => Self::ack(atm, profile, &sha256_hash).await,
            None => false,
        }
    }

    pub(crate) async fn send_response(
        ctx: &HandlerContext,
        response: DIDCommResponse,
    ) -> Result<(), DIDCommServiceError> {
        let message = response.into_message(ctx)?;
        transport::send_response(ctx, message).await
    }
}

/// The connection a handled frame is settled on, and how.
#[derive(Clone)]
pub(crate) struct AckConn {
    atm: ATM,
    profile: Arc<ATMProfile>,
    auto_delete: bool,
    guard: Arc<HandlerGuard>,
}

/// The next connection-state transition, or `None` once the transport has gone
/// (its sender dropped). Never resolves when there is no websocket transport.
pub(crate) async fn next_conn_change(
    rx: &mut Option<watch::Receiver<ConnState>>,
) -> Option<ConnState> {
    match rx {
        None => std::future::pending().await,
        Some(rx) => match rx.changed().await {
            Ok(()) => Some(*rx.borrow_and_update()),
            Err(_) => None,
        },
    }
}

/// Mirror a transport connection-state transition onto the listener's
/// connection handle and event stream (R6.2): on a drop, withdraw the handle
/// (so `send_message` returns `NotConnected` and `wait_connected` waits) and
/// emit `Disconnected`; on a reconnect, republish it and emit `Connected`.
/// Repeats of the current state are ignored.
pub(crate) fn apply_conn_state(
    state: ConnState,
    connected: &mut bool,
    handle: &ConnectionHandle,
    connection_tx: &watch::Sender<Option<ConnectionHandle>>,
    events_tx: &broadcast::Sender<ListenerEvent>,
    listener_id: &str,
) {
    let up = matches!(state, ConnState::Connected);
    if up == *connected {
        return;
    }
    *connected = up;
    if up {
        info!(listener = %listener_id, "Mediator websocket reconnected");
        let _ = connection_tx.send(Some(handle.clone()));
        let _ = events_tx.send(ListenerEvent::Connected {
            listener_id: listener_id.to_string(),
        });
    } else {
        warn!(listener = %listener_id, state = ?state, "Mediator websocket dropped; reconnecting");
        let _ = connection_tx.send(None);
        let _ = events_tx.send(ListenerEvent::Disconnected {
            listener_id: listener_id.to_string(),
            error: Some("mediator websocket dropped; reconnecting".into()),
        });
    }
}

/// A problem report is never answered with another one, so two services that
/// each report the other's reports cannot keep a pair of them going.
fn reply_allowed(inbound_type: &str, response: &DIDCommResponse) -> bool {
    !(transport::is_problem_report_type(inbound_type)
        && transport::is_problem_report_type(&response.type_))
}

/// How long a TSP frame waits for the previous frame from the same sender to
/// be unpacked before it goes ahead anyway. That step is one unpack and one
/// relationship-store write, so reaching this means the store is stuck; waiting
/// forever would stall that peer for good.
///
/// Going ahead is safe: ordering never admits a frame, it only delays it. A
/// payload that overtakes its invite this way meets the relationship gate
/// unrecorded and is refused and logged — the loss this ordering exists to
/// avoid, confined to a store that has stopped answering for 30 seconds.
#[cfg(feature = "tsp")]
const TSP_ORDER_WAIT: Duration = Duration::from_secs(30);

/// Per-sender ordering for inbound TSP frames.
///
/// Holds, for each sender VID, the completion signal of the latest frame taken
/// from it. A new frame is handed that signal to wait on and a fresh one to
/// release, so one sender's frames form a chain while different senders' frames
/// run side by side. A signal is released when its sender half is dropped,
/// which also happens if the task holding it panics or is cancelled, so a
/// failed frame never wedges the chain.
///
/// The sender VID is read from the cleartext envelope before anything is
/// verified, so the map is sized against forged senders: a VID longer than
/// [`MAX_SENDER_LEN`](Self::MAX_SENDER_LEN), a sender with
/// [`MAX_DEPTH`](Self::MAX_DEPTH) frames already queued, or a new sender once
/// [`MAX_SENDERS`](Self::MAX_SENDERS) have frames in flight, gets no place and
/// is handled unordered. Capping one sender's depth also caps how long a flood
/// under a victim's VID can hold the victim's own frames back.
///
/// Entries with no frame in flight are pruned once the map has doubled since
/// the last prune, so it stays bounded by the senders with frames in flight at
/// amortised O(1) per frame.
#[cfg(feature = "tsp")]
#[derive(Default)]
pub(crate) struct SenderOrder {
    tails: std::collections::HashMap<String, SenderTail>,
    prune_at: usize,
}

/// A sender's latest frame, and a count of its frames in flight: every
/// [`OrderSlot`] holds a clone of `in_flight`.
#[cfg(feature = "tsp")]
struct SenderTail {
    done: oneshot::Receiver<()>,
    in_flight: Arc<()>,
}

/// A frame's place in its sender's queue. Dropping it lets the sender's next
/// frame go ahead.
#[cfg(feature = "tsp")]
pub(crate) struct OrderSlot {
    _done: oneshot::Sender<()>,
    _in_flight: Arc<()>,
}

#[cfg(feature = "tsp")]
impl SenderOrder {
    const MIN_PRUNE_AT: usize = 64;
    /// Senders with frames in flight that get ordering; the rest go unordered.
    const MAX_SENDERS: usize = 4096;
    /// Frames one sender may have queued before the next goes unordered.
    const MAX_DEPTH: usize = 64;
    /// Longest sender VID that is tracked.
    const MAX_SENDER_LEN: usize = 2048;

    /// Take the next place in `sender`'s queue: the signal to wait on (none if
    /// nothing from `sender` is in flight) and the slot to drop when done.
    /// `None` when a limit is reached and the frame should go unordered.
    pub(crate) fn enqueue(
        &mut self,
        sender: &str,
    ) -> Option<(Option<oneshot::Receiver<()>>, OrderSlot)> {
        if sender.len() > Self::MAX_SENDER_LEN {
            return None;
        }
        if !self.tails.contains_key(sender) {
            if self.tails.len() >= self.prune_at.max(Self::MIN_PRUNE_AT)
                || self.tails.len() >= Self::MAX_SENDERS
            {
                self.tails
                    .retain(|_, t| Arc::strong_count(&t.in_flight) > 1);
                self.prune_at = self.tails.len() * 2;
            }
            if self.tails.len() >= Self::MAX_SENDERS {
                return None;
            }
        }
        let (done_tx, done_rx) = oneshot::channel();
        let (prev, in_flight) = match self.tails.get_mut(sender) {
            Some(tail) => {
                if Arc::strong_count(&tail.in_flight) > Self::MAX_DEPTH {
                    return None;
                }
                (
                    Some(std::mem::replace(&mut tail.done, done_rx)),
                    tail.in_flight.clone(),
                )
            }
            None => {
                let in_flight = Arc::new(());
                self.tails.insert(
                    sender.to_string(),
                    SenderTail {
                        done: done_rx,
                        in_flight: in_flight.clone(),
                    },
                );
                (None, in_flight)
            }
        };
        Some((
            prev,
            OrderSlot {
                _done: done_tx,
                _in_flight: in_flight,
            },
        ))
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.tails.len()
    }
}

/// A stable id for a TSP control message, derived from its thread digest.
///
/// A control message carries no DIDComm message or thread id, so handlers and
/// logs get one built from the digest that identifies the exchange.
#[cfg(feature = "tsp")]
fn control_message_id(digest: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    digest
        .iter()
        .fold(String::from("tsp-control-"), |mut acc, b| {
            let _ = write!(acc, "{b:02x}");
            acc
        })
}

#[cfg(all(test, feature = "tsp"))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn one_senders_frames_chain_and_another_senders_do_not_wait() {
        let mut order = SenderOrder::default();
        let (first, a1) = order.enqueue("did:a").unwrap();
        assert!(first.is_none(), "nothing from did:a in flight yet");
        let (after_a1, a2) = order.enqueue("did:a").unwrap();
        let (other, _b1) = order.enqueue("did:b").unwrap();
        assert!(other.is_none(), "did:b does not wait on did:a");

        let mut after_a1 = after_a1.expect("did:a's second frame waits on its first");
        assert!(
            after_a1.try_recv().is_err(),
            "still waiting while the first is in flight"
        );
        drop(a1);
        assert!(
            matches!(
                after_a1.try_recv(),
                Err(oneshot::error::TryRecvError::Closed)
            ),
            "released once the first is done"
        );
        drop(a2);
    }

    #[tokio::test]
    async fn finished_senders_are_pruned() {
        let mut order = SenderOrder::default();
        for i in 0..10_000 {
            let (_prev, done) = order.enqueue(&format!("did:{i}")).unwrap();
            drop(done);
        }
        assert!(
            order.len() <= 2 * SenderOrder::MIN_PRUNE_AT,
            "len {}",
            order.len()
        );
    }

    #[tokio::test]
    async fn forged_senders_cannot_grow_the_map_past_its_cap() {
        let mut order = SenderOrder::default();
        let mut held = Vec::new();
        for i in 0..SenderOrder::MAX_SENDERS {
            held.push(order.enqueue(&format!("did:{i}")).unwrap());
        }
        assert!(order.enqueue("did:one-too-many").is_none());
        assert_eq!(order.len(), SenderOrder::MAX_SENDERS);
        assert!(
            order.enqueue("did:0").is_some(),
            "a sender already tracked keeps its ordering"
        );
        held.clear();
        assert!(
            order.enqueue("did:after-drain").is_some(),
            "room again once frames finish"
        );
    }

    #[tokio::test]
    async fn one_sender_cannot_queue_past_the_depth_cap() {
        let mut order = SenderOrder::default();
        let held: Vec<_> = (0..SenderOrder::MAX_DEPTH)
            .map(|_| order.enqueue("did:victim").unwrap())
            .collect();
        assert!(order.enqueue("did:victim").is_none());
        drop(held);
        assert!(order.enqueue("did:victim").is_some());
    }

    #[tokio::test]
    async fn an_oversized_sender_is_not_tracked() {
        let mut order = SenderOrder::default();
        let long = "x".repeat(SenderOrder::MAX_SENDER_LEN + 1);
        assert!(order.enqueue(&long).is_none());
        assert_eq!(order.len(), 0);
    }
}

#[cfg(test)]
mod reply_tests {
    use super::*;
    use crate::problem_report::{ProblemReport, ServiceProblemReport};
    use crate::transport::PROBLEM_REPORT_TYPE;

    #[test]
    fn a_problem_report_is_not_answered_with_a_problem_report() {
        let report = DIDCommResponse::problem_report(ProblemReport::internal_error("x"));
        assert!(!reply_allowed(PROBLEM_REPORT_TYPE, &report));
    }

    #[test]
    fn other_replies_are_sent() {
        let report = DIDCommResponse::problem_report(ProblemReport::internal_error("x"));
        let ack = DIDCommResponse::new("https://example.com/ack", serde_json::json!({}));
        assert!(reply_allowed("https://example.com/request", &report));
        assert!(reply_allowed(PROBLEM_REPORT_TYPE, &ack));
    }
}

#[cfg(test)]
mod connection_and_dispatch_tests {
    use super::*;
    use affinidi_messaging_didcomm::{Message, UnpackMetadata};
    use async_trait::async_trait;
    use serde_json::json;

    async fn handle() -> ConnectionHandle {
        let ctx = crate::handler::test_context().await;
        ConnectionHandle {
            atm: ctx.atm,
            profile: ctx.profile,
        }
    }

    /// #1029 (R6.2): a websocket drop and the SDK's private reconnect are
    /// mirrored onto the connection handle and the event stream, every time.
    #[tokio::test]
    async fn a_drop_and_reconnect_are_reported_every_time() {
        let handle = handle().await;
        let (conn_tx, conn_rx) = watch::channel(Some(handle.clone()));
        let (events_tx, mut events) = broadcast::channel(16);
        let (state_tx, state_rx) = watch::channel(ConnState::Connected);
        let mut state_rx = Some(state_rx);
        let mut connected = true;

        for _round in 0..2 {
            state_tx.send(ConnState::Disconnected).unwrap();
            let s = next_conn_change(&mut state_rx).await.unwrap();
            apply_conn_state(s, &mut connected, &handle, &conn_tx, &events_tx, "l1");
            assert!(conn_rx.borrow().is_none(), "sends must see NotConnected");
            assert_eq!(
                events.try_recv().unwrap(),
                ListenerEvent::Disconnected {
                    listener_id: "l1".into(),
                    error: Some("mediator websocket dropped; reconnecting".into()),
                }
            );

            // Still reconnecting: no repeat event.
            state_tx.send(ConnState::Connecting).unwrap();
            let s = next_conn_change(&mut state_rx).await.unwrap();
            apply_conn_state(s, &mut connected, &handle, &conn_tx, &events_tx, "l1");
            assert!(events.try_recv().is_err());

            state_tx.send(ConnState::Connected).unwrap();
            let s = next_conn_change(&mut state_rx).await.unwrap();
            apply_conn_state(s, &mut connected, &handle, &conn_tx, &events_tx, "l1");
            assert!(conn_rx.borrow().is_some(), "handle republished");
            assert_eq!(
                events.try_recv().unwrap(),
                ListenerEvent::Connected {
                    listener_id: "l1".into()
                }
            );
        }

        // The transport going away ends the watch.
        drop(state_tx);
        assert!(next_conn_change(&mut state_rx).await.is_none());
    }

    struct Capture(tokio::sync::Mutex<Option<HandlerContext>>);

    #[async_trait]
    impl DIDCommHandler for Arc<Capture> {
        async fn handle(
            &self,
            ctx: HandlerContext,
            _message: Message,
            _meta: UnpackMetadata,
        ) -> Result<Option<DIDCommResponse>, DIDCommServiceError> {
            *self.0.lock().await = Some(ctx);
            Ok(None)
        }
    }

    /// #1028 regression: a request without a `thid` that reaches the handler
    /// through the offline drain (`ack_id: None`, the drain acks the batch) is
    /// seen with the sender's id, and the reply threads to it, not to the
    /// mediator's queue id.
    #[tokio::test]
    async fn an_offline_request_without_thid_is_answered_on_its_own_id() {
        let ctx = crate::handler::test_context().await;
        let capture = Arc::new(Capture(tokio::sync::Mutex::new(None)));
        let handler: Arc<dyn DIDCommHandler> = Arc::new(capture.clone());
        let request = Message::build(
            "req-1".to_string(),
            "https://didcomm.org/trust-ping/2.0/ping".to_string(),
            json!({}),
        )
        .from("did:example:peer".to_string())
        .finalize();
        let meta = UnpackMetadata {
            authenticated: true,
            encrypted: true,
            encrypted_from_kid: Some("did:example:peer#key-1".into()),
            ..Default::default()
        };

        let acked =
            Listener::dispatch_message("l1", &ctx.atm, &ctx.profile, &handler, request, meta, None)
                .await;
        assert!(!acked, "the offline drain acks the batch itself");

        let seen = capture.0.lock().await.take().expect("handler ran");
        assert_eq!(seen.message_id, "req-1");
        assert_eq!(seen.thread_id, "req-1");
        assert_eq!(seen.sender_did.as_deref(), Some("did:example:peer"));
        let reply = DIDCommResponse::new(
            "https://didcomm.org/trust-ping/2.0/ping-response",
            json!({}),
        )
        .into_message(&seen)
        .unwrap();
        assert_eq!(reply.thid.as_deref(), Some("req-1"));
    }
}

/// #1150: the TSP-multiplexed live path acks after the handler, and its TSP
/// frames share the in-flight record with the offline drain (R1.6/R1.7).
#[cfg(all(test, feature = "tsp"))]
mod multiplexed_path_tests {
    use super::*;
    use crate::config::Protocols;
    use crate::handler::TspResponse;
    use affinidi_messaging_didcomm::{Message, UnpackMetadata};
    use affinidi_messaging_sdk::messages::compat::UnpackMetadata as SdkMeta;
    use affinidi_messaging_sdk::protocols::message_pickup::DeliveryOutcome;
    use affinidi_tdk_common::profiles::TDKProfile;
    use async_trait::async_trait;
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::Notify;

    /// A DIDComm handler that blocks until released.
    #[derive(Default)]
    struct Gate {
        entered: Notify,
        release: Notify,
        finished: AtomicUsize,
    }

    #[async_trait]
    impl DIDCommHandler for Arc<Gate> {
        async fn handle(
            &self,
            _ctx: HandlerContext,
            _message: Message,
            _meta: UnpackMetadata,
        ) -> Result<Option<DIDCommResponse>, DIDCommServiceError> {
            self.entered.notify_one();
            self.release.notified().await;
            self.finished.fetch_add(1, Ordering::SeqCst);
            Ok(None)
        }
    }

    struct NoopTsp;

    #[async_trait]
    impl TspHandler for NoopTsp {
        async fn handle(
            &self,
            _ctx: HandlerContext,
            _payload: Vec<u8>,
            _sender_vid: String,
        ) -> Result<Option<TspResponse>, DIDCommServiceError> {
            Ok(None)
        }
    }

    /// A connected multiplexing listener (DIDComm + TSP, `auto_delete` on).
    async fn listener(gate: Arc<Gate>, drain_timeout: Duration) -> Listener {
        let ctx = crate::handler::test_context().await;
        let mut config = ListenerConfig::new(
            "l1",
            TDKProfile::new("svc", "did:example:service", None, vec![]),
        );
        config.protocols = Protocols::BOTH;
        config.shutdown_drain_timeout = drain_timeout;
        let (connection_tx, _) = watch::channel(None);
        let (events_tx, _) = broadcast::channel(16);
        let mut l = Listener::new(
            config,
            Arc::new(gate),
            Some(Arc::new(NoopTsp)),
            CancellationToken::new(),
            connection_tx,
            events_tx,
        );
        l.atm = Some(ctx.atm);
        l.profile = Some(ctx.profile);
        l
    }

    /// A listener like [`listener`], with `configure` applied to its config
    /// and an ATM that has an unprocessable-message channel, returned
    /// subscribed.
    async fn reporting_listener(
        configure: impl FnOnce(&mut ListenerConfig),
    ) -> (
        Listener,
        broadcast::Receiver<
            affinidi_messaging_sdk::protocols::message_pickup::UnprocessableMessage,
        >,
    ) {
        use affinidi_messaging_sdk::config::ATMConfig;
        use affinidi_tdk_common::config::TDKConfig;
        let tdk = TDKSharedState::new(TDKConfig::headless().expect("headless TDK config"))
            .await
            .expect("TDK shared state");
        let atm = ATM::new(
            ATMConfig::builder()
                .with_unprocessable_message_channel(16)
                .build()
                .expect("ATM config"),
            Arc::new(tdk),
        )
        .await
        .expect("ATM");
        let profile = ATMProfile::new(&atm, None, "did:example:service".into(), None)
            .await
            .expect("profile");
        let reports = atm
            .get_unprocessable_message_channel()
            .expect("channel configured");
        let mut config = ListenerConfig::new(
            "l1",
            TDKProfile::new("svc", "did:example:service", None, vec![]),
        );
        config.protocols = Protocols::BOTH;
        configure(&mut config);
        let (connection_tx, _) = watch::channel(None);
        let (events_tx, _) = broadcast::channel(16);
        let mut l = Listener::new(
            config,
            Arc::new(Arc::new(Gate::default())),
            Some(Arc::new(NoopTsp)),
            CancellationToken::new(),
            connection_tx,
            events_tx,
        );
        l.atm = Some(atm);
        l.profile = Some(Arc::new(profile));
        (l, reports)
    }

    /// #542: a frame whose handler panics is left queued (not acked) and
    /// redelivered, until it has failed `max_handler_failures` times; then it
    /// is dead-lettered — acked, so it stops coming back, and reported.
    #[tokio::test]
    async fn a_panicking_handlers_frame_is_retried_then_dead_lettered() {
        let (l, mut reports) = reporting_listener(|c| c.max_handler_failures = 3).await;
        let id = "h-poison";
        let conn = || l.ack_conn(l.atm.as_ref().unwrap(), l.profile.as_ref().unwrap());
        let mut tasks = JoinSet::new();
        for attempt in 1..=3 {
            let claim = l
                .in_flight
                .claim(id)
                .expect("redelivered copy is claimable");
            let permit = l.acquire_permit().await.unwrap();
            Listener::spawn_then_ack(&mut tasks, permit, claim, conn(), async {
                panic!("handler bug")
            });
            join(&mut tasks).await;
            assert!(
                !l.in_flight.is_active(id),
                "attempt {attempt}: claim released"
            );
            if attempt < 3 {
                assert!(!l.in_flight.is_recent(id), "attempt {attempt}: left queued");
                assert!(reports.try_recv().is_err(), "not reported yet");
            }
        }
        assert!(l.in_flight.is_recent(id), "dead-lettered: acked");
        let report = reports.try_recv().expect("reported as unprocessable");
        assert_eq!(report.attachment_id.as_deref(), Some(id));
        assert!(
            report.reason.contains("3 handler failures"),
            "{}",
            report.reason
        );
    }

    /// #542: a handler that hangs is aborted at the handler timeout; its frame
    /// is left queued for redelivery rather than holding a permit forever.
    #[tokio::test]
    async fn a_hanging_handler_times_out_and_its_frame_stays_queued() {
        let (l, _reports) =
            reporting_listener(|c| c.handler_timeout = Duration::from_millis(50)).await;
        let id = "h-hang";
        let claim = l.in_flight.claim(id).unwrap();
        let permit = l.acquire_permit().await.unwrap();
        let mut tasks = JoinSet::new();
        let conn = l.ack_conn(l.atm.as_ref().unwrap(), l.profile.as_ref().unwrap());
        Listener::spawn_then_ack(
            &mut tasks,
            permit,
            claim,
            conn,
            std::future::pending::<bool>(),
        );
        tokio::time::timeout(Duration::from_secs(5), join(&mut tasks))
            .await
            .expect("the hung handler is timed out");
        assert!(!l.in_flight.is_active(id), "claim released");
        assert!(!l.in_flight.is_recent(id), "not acked: redelivered later");
    }

    /// #542 on the offline drain: a handler that hangs is timed out and its
    /// message left queued; once it has failed `max_handler_failures` times it
    /// is dead-lettered (acked with the batch, reported).
    #[tokio::test]
    async fn the_offline_drain_dead_letters_a_hanging_handlers_message() {
        let (l, mut reports) = reporting_listener(|c| {
            c.handler_timeout = Duration::from_millis(50);
            c.max_handler_failures = 2;
        })
        .await;
        let sync = offline_sync(&l);
        for attempt in 1..=2 {
            let (set, handled, dropped) = sync
                .route_frames(vec![(
                    DeliveryOutcome::Frame(didcomm_frame("h-off")),
                    "h-off".to_string(),
                )])
                .await
                .unwrap();
            assert!(handled.is_empty() && dropped.is_empty());
            let (handled, dead) = sync.join_all(set).await;
            assert!(handled.is_empty(), "attempt {attempt}: not handled");
            if attempt == 1 {
                assert!(dead.is_empty(), "left queued after one failure");
                assert!(!l.in_flight.is_active("h-off"), "claim released");
            } else {
                let ids: Vec<&str> = dead.iter().map(|c| c.id()).collect();
                assert_eq!(ids, ["h-off"], "dead-lettered, to be acked with the batch");
                let report = reports.try_recv().expect("reported");
                assert_eq!(report.attachment_id.as_deref(), Some("h-off"));
            }
        }
    }

    /// #541: a TSP frame that does not decode can never decode (it is a pure
    /// function of the bytes the mediator holds), so it is acked — and
    /// reported on the unprocessable-message channel with its raw body, not
    /// only logged.
    #[tokio::test]
    async fn an_undecodable_tsp_frame_is_acked_and_reported() {
        let (l, mut reports) = reporting_listener(|_| {}).await;
        let packed = "not base64url at all!".to_string();
        let frame = InboundFrame::Tsp(Box::new(packed.clone()));
        let id = frame.ack_id();
        let mut tasks = JoinSet::new();
        let permit = l.acquire_permit().await.unwrap();
        l.route_frame(frame, permit, &mut tasks).await.unwrap();
        join(&mut tasks).await;
        assert!(l.in_flight.is_recent(&id), "acked");
        let report = reports.try_recv().expect("reported");
        assert_eq!(report.attachment_id.as_deref(), Some(id.as_str()));
        assert_eq!(report.raw, packed);
        assert!(report.reason.contains("could not be decoded"));
    }

    /// #541 on the offline drain: an undecodable TSP frame is acked with the
    /// batch and reported on the unprocessable-message channel, as on the live
    /// path, rather than only logged.
    #[tokio::test]
    async fn the_offline_drain_reports_an_undecodable_tsp_frame() {
        let (l, mut reports) = reporting_listener(|_| {}).await;
        let sync = offline_sync(&l);
        let packed = "not base64url at all!".to_string();
        let (set, handled, dropped) = sync
            .route_frames(vec![(
                DeliveryOutcome::Frame(InboundFrame::Tsp(Box::new(packed.clone()))),
                "t-off".to_string(),
            )])
            .await
            .unwrap();
        assert!(dropped.is_empty());
        let (joined, dead) = sync.join_all(set).await;
        let acked: Vec<&str> = handled.iter().chain(&joined).map(|c| c.id()).collect();
        assert_eq!(acked, ["t-off"], "acked: it can never decode");
        assert!(dead.is_empty());
        let report = reports.try_recv().expect("reported");
        assert_eq!(report.attachment_id.as_deref(), Some("t-off"));
        assert_eq!(report.raw, packed);
        assert!(report.reason.contains("could not be decoded"));
    }

    fn offline_sync(l: &Listener) -> OfflineSync {
        OfflineSync {
            listener_id: l.config.id.clone(),
            atm: l.atm.clone().unwrap(),
            profile: l.profile.clone().unwrap(),
            handler: l.handler.clone(),
            tsp_handler: l.tsp_handler.clone(),
            in_flight: l.in_flight.clone(),
            permits: l.handler_permits.clone(),
            auto_delete: l.config.auto_delete,
            protocols: l.config.protocols,
            guard: l.guard.clone(),
        }
    }

    /// A stored-form TSP frame (`base64url(qb2)`, leading magic byte) that
    /// classifies and decodes as TSP but does not unpack.
    fn tsp_frame(l: &Listener, n: u8) -> String {
        l.atm.as_ref().unwrap().tsp().encode(&[
            affinidi_messaging_sdk::tsp_wire::TSP_MAGIC_BYTE,
            0x41,
            0x42,
            n,
        ])
    }

    fn didcomm_frame(hash: &str) -> InboundFrame {
        let msg = Message::build("m1".to_string(), "example/v1".to_string(), json!({})).finalize();
        let mut meta = SdkMeta::default();
        meta.sha256_hash = hash.to_string();
        InboundFrame::DidComm(Box::new(msg), Box::new(meta))
    }

    async fn join(tasks: &mut JoinSet<()>) {
        while let Some(r) = tasks.join_next().await {
            r.expect("task did not panic");
        }
    }

    /// The mediator id of a live TSP frame is what the offline drain keys the
    /// same message by (its delivery attachment id, sha256 of the body).
    #[tokio::test]
    async fn a_live_tsp_frame_is_keyed_by_its_mediator_id() {
        let l = listener(Arc::new(Gate::default()), Duration::from_secs(5)).await;
        let packed = tsp_frame(&l, 1);
        let frame = InboundFrame::Tsp(Box::new(packed.clone()));
        assert_eq!(frame.ack_id(), sha256::digest(packed.as_str()));
    }

    /// A DIDComm frame on the multiplexed path is not acked until its handler
    /// returns (it used to be acked on receipt).
    #[tokio::test]
    async fn a_multiplexed_didcomm_frame_is_acked_only_after_its_handler() {
        let gate = Arc::new(Gate::default());
        let l = listener(gate.clone(), Duration::from_secs(5)).await;
        let mut tasks = JoinSet::new();

        let permit = l.acquire_permit().await.unwrap();
        l.route_frame(didcomm_frame("h-dc"), permit, &mut tasks)
            .await
            .unwrap();
        gate.entered.notified().await;

        assert!(l.in_flight.is_active("h-dc"), "held while the handler runs");
        assert!(!l.in_flight.is_recent("h-dc"), "not acked yet");

        gate.release.notify_one();
        join(&mut tasks).await;
        assert_eq!(gate.finished.load(Ordering::SeqCst), 1);
        assert!(!l.in_flight.is_active("h-dc"));
        assert!(l.in_flight.is_recent("h-dc"), "acked after the handler");
    }

    /// A TSP frame's ack waits for its handler too: the work spawned for it
    /// runs to completion before the ack is made and recorded.
    #[tokio::test]
    async fn a_tsp_frame_is_acked_only_after_its_handler() {
        let l = listener(Arc::new(Gate::default()), Duration::from_secs(5)).await;
        let frame = InboundFrame::Tsp(Box::new(tsp_frame(&l, 2)));
        let id = frame.ack_id();
        let claim = l.in_flight.claim(&id).unwrap();
        let release = Arc::new(Notify::new());
        let ack_on = l.ack_conn(l.atm.as_ref().unwrap(), l.profile.as_ref().unwrap());

        let mut tasks = JoinSet::new();
        let permit = l.acquire_permit().await.unwrap();
        let r = release.clone();
        Listener::spawn_then_ack(&mut tasks, permit, claim, ack_on, async move {
            r.notified().await;
            true
        });
        tokio::task::yield_now().await;

        assert!(l.in_flight.is_active(&id));
        assert!(!l.in_flight.is_recent(&id), "not acked while handling");

        release.notify_one();
        join(&mut tasks).await;
        assert!(!l.in_flight.is_active(&id));
        assert!(l.in_flight.is_recent(&id), "acked once handled");
    }

    /// A TSP frame whose unpack failed for a reason that may clear (the
    /// sender's key state could not be refreshed) is not acked on the live
    /// path: its claim is released unacked, so the offline drain's copy is
    /// dispatched later, and that attempt — now unpacking — is acked.
    #[tokio::test]
    async fn a_transiently_failing_tsp_frame_is_not_acked_and_is_retried() {
        let l = listener(Arc::new(Gate::default()), Duration::from_secs(5)).await;
        let frame = InboundFrame::Tsp(Box::new(tsp_frame(&l, 6)));
        let id = frame.ack_id();
        let ack_on = || l.ack_conn(l.atm.as_ref().unwrap(), l.profile.as_ref().unwrap());

        // Live attempt: the work reports a transient failure.
        let mut tasks = JoinSet::new();
        let claim = l.in_flight.claim(&id).unwrap();
        let permit = l.acquire_permit().await.unwrap();
        Listener::spawn_then_ack(&mut tasks, permit, claim, ack_on(), async { false });
        join(&mut tasks).await;
        assert!(!l.in_flight.is_recent(&id), "not acked: it stays queued");
        assert!(!l.in_flight.is_active(&id), "claim released");

        // A later attempt (the offline drain's copy) succeeds and is acked.
        let claim = l
            .in_flight
            .claim(&id)
            .expect("the retried copy can be claimed");
        let permit = l.acquire_permit().await.unwrap();
        Listener::spawn_then_ack(&mut tasks, permit, claim, ack_on(), async { true });
        join(&mut tasks).await;
        assert!(l.in_flight.is_recent(&id), "acked once handled");
    }

    /// A TSP frame the live stream dispatched is skipped by the offline drain,
    /// both while it is being handled and after it was acked (it used to be
    /// outside the record, so the drain could dispatch it again).
    #[tokio::test]
    async fn a_live_tsp_frame_is_skipped_by_the_offline_drain() {
        let l = listener(Arc::new(Gate::default()), Duration::from_secs(5)).await;
        let sync = offline_sync(&l);
        let packed = tsp_frame(&l, 3);
        // The drain keys by the delivery attachment id: sha256 of the body.
        let id = sha256::digest(packed.as_str());

        // While the live path holds it.
        let held = l
            .in_flight
            .claim(&InboundFrame::Tsp(Box::new(packed.clone())).ack_id())
            .expect("live claim");
        let (set, handled, dropped) = sync
            .route_frames(vec![(
                DeliveryOutcome::Frame(InboundFrame::Tsp(Box::new(packed.clone()))),
                id.clone(),
            )])
            .await
            .unwrap();
        assert!(set.is_empty() && handled.is_empty() && dropped.is_empty());
        drop(held);

        // Through the live router: claimed, handled (it does not unpack, so the
        // handler is never reached), acked and recorded.
        let mut tasks = JoinSet::new();
        let permit = l.acquire_permit().await.unwrap();
        l.route_frame(
            InboundFrame::Tsp(Box::new(packed.clone())),
            permit,
            &mut tasks,
        )
        .await
        .unwrap();
        join(&mut tasks).await;
        assert!(l.in_flight.is_recent(&id), "acked by the live path");

        let (set, handled, dropped) = sync
            .route_frames(vec![(
                DeliveryOutcome::Frame(InboundFrame::Tsp(Box::new(packed))),
                id,
            )])
            .await
            .unwrap();
        assert!(
            set.is_empty() && handled.is_empty() && dropped.is_empty(),
            "a copy fetched before the live ack landed is not dispatched again"
        );
    }

    /// The offline drain acks a permanent reject but not a transient failure
    /// (e.g. a signer DID that did not resolve this time): that one is neither
    /// dispatched nor acked, stays queued, and is handled when a later sync
    /// fetches it again and it now unpacks.
    #[tokio::test]
    async fn the_offline_drain_retries_a_transient_failure_and_acks_a_reject() {
        let l = listener(Arc::new(Gate::default()), Duration::from_secs(5)).await;
        let sync = offline_sync(&l);

        let (set, handled, dropped) = sync
            .route_frames(vec![
                (DeliveryOutcome::Retry, "transient".to_string()),
                (DeliveryOutcome::Reject, "permanent".to_string()),
            ])
            .await
            .unwrap();
        assert!(set.is_empty() && handled.is_empty());
        let dropped_ids: Vec<&str> = dropped.iter().map(|c| c.id()).collect();
        assert_eq!(
            dropped_ids,
            ["permanent"],
            "only the permanent reject is acked"
        );
        drop(dropped);
        assert!(
            !l.in_flight.is_active("transient") && !l.in_flight.is_recent("transient"),
            "a transient failure is neither claimed nor recorded as acked"
        );

        // Next tick: the same message comes back and now unpacks.
        let packed = tsp_frame(&l, 5);
        let (set, handled, dropped) = sync
            .route_frames(vec![(
                DeliveryOutcome::Frame(InboundFrame::Tsp(Box::new(packed))),
                "transient".to_string(),
            )])
            .await
            .unwrap();
        assert!(set.is_empty() && dropped.is_empty());
        let handled_ids: Vec<&str> = handled.iter().map(|c| c.id()).collect();
        assert_eq!(handled_ids, ["transient"], "redelivered and handled");
    }

    /// A frame pulled just as the socket drops is not lost: nothing acked it on
    /// receipt, and when the connection is torn down before its handler
    /// finishes, its claim is released unacked, so the redelivered copy can be
    /// dispatched.
    #[tokio::test]
    async fn a_frame_pulled_as_the_socket_drops_is_redelivered() {
        let gate = Arc::new(Gate::default());
        let l = listener(gate.clone(), Duration::from_millis(50)).await;
        let handle = ConnectionHandle {
            atm: l.atm.clone().unwrap(),
            profile: l.profile.clone().unwrap(),
        };
        let (conn_tx, conn_rx) = watch::channel(Some(handle.clone()));
        let (events_tx, _events) = broadcast::channel(16);
        let (state_tx, state_rx) = watch::channel(ConnState::Connected);
        let mut state_rx = Some(state_rx);
        let mut connected = true;

        // Pulled (a DIDComm frame and a TSP frame), handlers still running.
        let mut tasks = JoinSet::new();
        let permit = l.acquire_permit().await.unwrap();
        l.route_frame(didcomm_frame("h-drop"), permit, &mut tasks)
            .await
            .unwrap();
        gate.entered.notified().await;
        let tsp = InboundFrame::Tsp(Box::new(tsp_frame(&l, 4)));
        let tsp_id = tsp.ack_id();
        let claim = l.in_flight.claim(&tsp_id).unwrap();
        let permit = l.acquire_permit().await.unwrap();
        let ack_on = l.ack_conn(&handle.atm, &handle.profile);
        Listener::spawn_then_ack(
            &mut tasks,
            permit,
            claim,
            ack_on,
            std::future::pending::<bool>(),
        );

        // The socket drops.
        state_tx.send(ConnState::Disconnected).unwrap();
        let s = next_conn_change(&mut state_rx).await.unwrap();
        apply_conn_state(s, &mut connected, &handle, &conn_tx, &events_tx, "l1");
        assert!(!connected && conn_rx.borrow().is_none());

        // The connection is torn down before the handlers finish.
        l.drain_tasks(&mut tasks).await;
        assert_eq!(gate.finished.load(Ordering::SeqCst), 0);

        for id in ["h-drop", tsp_id.as_str()] {
            assert!(!l.in_flight.is_recent(id), "{id}: never acked");
            assert!(
                l.in_flight.claim(id).is_some(),
                "{id}: released unacked, so its redelivered copy is dispatched"
            );
        }
    }
}
