use std::sync::Arc;
use std::time::Duration;

use affinidi_messaging_sdk::config::ATMConfigBuilder;
use affinidi_messaging_sdk::{ATM, profiles::ATMProfile};
use affinidi_secrets_resolver::SecretsResolver;
use affinidi_tdk_common::TDKSharedState;
use tokio::sync::{broadcast, watch};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::config::ListenerConfig;
use crate::error::{DIDCommServiceError, StartupError};
use crate::handler::{DIDCommHandler, HandlerContext, TspHandler};
use crate::response::DIDCommResponse;
use crate::service::ListenerEvent;
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
        Self {
            config,
            handler,
            tsp_handler,
            shutdown,
            atm: None,
            profile: None,
            connection_tx,
            events_tx,
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

        let tdk_config = match self.config.tdk_config.take() {
            Some(cfg) => cfg,
            None => affinidi_tdk_common::config::TDKConfig::headless()?,
        };
        let shared_state = Arc::new(TDKSharedState::new(tdk_config).await?);

        shared_state
            .secrets_resolver()
            .insert_vec(self.config.profile.secrets())
            .await;

        let atm_config = ATMConfigBuilder::default()
            .build()
            .map_err(StartupError::Config)?;

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

        let mut tasks = JoinSet::new();

        // Spawn offline sync as a tracked task
        let listener_id = self.config.id.clone();
        let shutdown_clone = self.shutdown.clone();
        let atm_clone = atm.clone();
        let profile_clone = profile.clone();
        let handler_clone = self.handler.clone();
        let tsp_handler_clone = self.tsp_handler.clone();
        tasks.spawn(async move {
            Listener::run_periodic_offline_sync(
                &listener_id,
                &atm_clone,
                &profile_clone,
                &handler_clone,
                tsp_handler_clone.as_ref(),
                &shutdown_clone,
            )
            .await;
        });

        loop {
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
                    break;
                }
                result = self.process_next_message(&mut tasks) => {
                    if let Err(e) = result {
                        warn!(profile = %profile.inner.alias, error = %e, "Error processing message");
                    }
                }
            }
        }

        // Drain in-flight tasks on shutdown
        info!(profile = %profile.inner.alias, count = tasks.len(), "Waiting for in-flight tasks to complete");
        while let Some(result) = tasks.join_next().await {
            if let Err(e) = result
                && e.is_panic()
            {
                error!(profile = %profile.inner.alias, error = %e, "Handler task panicked during shutdown");
            }
        }

        Ok(())
    }

    async fn process_next_message(
        &self,
        tasks: &mut JoinSet<()>,
    ) -> Result<(), DIDCommServiceError> {
        // When TSP is enabled, pull frames of *either* protocol off the one
        // socket and route by transport (a node speaks both over a single
        // per-DID websocket — opening a second would be evicted as a duplicate).
        #[cfg(feature = "tsp")]
        if self.config.protocols.tsp {
            return self.process_next_frame(tasks).await;
        }

        let wait_duration = Duration::from_secs(self.config.message_wait_duration_secs);
        let auto_delete = self.config.auto_delete;
        let atm = self.atm()?;
        let profile = self.profile()?;

        let next = atm
            .message_pickup()
            .live_stream_next(profile, Some(wait_duration), auto_delete)
            .await
            .map_err(DIDCommServiceError::ATM)?;

        if let Some((message, meta)) = next {
            let meta = convert_meta(*meta);
            let listener_id = self.config.id.clone();
            let atm = atm.clone();
            let profile = profile.clone();
            let handler = self.handler.clone();
            tasks.spawn(async move {
                Self::dispatch_message(&listener_id, &atm, &profile, &handler, message, meta).await;
            });
        }

        Ok(())
    }

    /// Multiplexed receive: pull the next inbound frame (DIDComm *or* TSP) off
    /// the shared websocket and dispatch by transport.
    #[cfg(feature = "tsp")]
    async fn process_next_frame(&self, tasks: &mut JoinSet<()>) -> Result<(), DIDCommServiceError> {
        use affinidi_messaging_sdk::protocols::message_pickup::InboundFrame;

        let wait_duration = Duration::from_secs(self.config.message_wait_duration_secs);
        let auto_delete = self.config.auto_delete;
        let atm = self.atm()?;
        let profile = self.profile()?;

        let next = atm
            .message_pickup()
            .live_stream_next_frame(profile, Some(wait_duration), auto_delete)
            .await
            .map_err(DIDCommServiceError::ATM)?;

        match next {
            Some(InboundFrame::DidComm(message, meta)) => {
                let meta = convert_meta(*meta);
                let listener_id = self.config.id.clone();
                let atm = atm.clone();
                let profile = profile.clone();
                let handler = self.handler.clone();
                tasks.spawn(async move {
                    Self::dispatch_message(&listener_id, &atm, &profile, &handler, *message, meta)
                        .await;
                });
            }
            Some(InboundFrame::Tsp(packed)) => {
                if let Some(tsp_handler) = self.tsp_handler.clone() {
                    let listener_id = self.config.id.clone();
                    let atm = atm.clone();
                    let profile = profile.clone();
                    tasks.spawn(async move {
                        Self::dispatch_tsp(&listener_id, &atm, &profile, &tsp_handler, *packed)
                            .await;
                    });
                } else {
                    warn!(
                        profile = %profile.inner.alias,
                        "received TSP frame but no TspHandler configured — dropping"
                    );
                }
            }
            // `InboundFrame` is `#[non_exhaustive]`; tolerate a future frame
            // kind this build doesn't yet route.
            Some(_) => {
                warn!(
                    profile = %profile.inner.alias,
                    "received unrecognised inbound frame kind — dropping"
                );
            }
            None => {}
        }

        Ok(())
    }

    /// Unpack a TSP frame (yielding cleartext payload + authenticated sender VID)
    /// and hand it to the configured [`TspHandler`].
    #[cfg(feature = "tsp")]
    pub(crate) async fn dispatch_tsp(
        listener_id: &str,
        atm: &ATM,
        profile: &Arc<ATMProfile>,
        handler: &Arc<dyn TspHandler>,
        packed: String,
    ) {
        // The pickup socket surfaces the frame as the **qb64** stored string
        // (`base64url(qb2)`, i.e. `-E…` text) — NOT raw qb2. Use `unpack`, which
        // decodes the base64url first; `unpack_bytes(packed.as_bytes())` would
        // feed the ASCII `'-','E',…` bytes straight into the CESR parser and
        // fail with "missing -E envelope wrapper". (The raw-TSP `connect_websocket`
        // path yields already-decoded qb2 and correctly uses `unpack_bytes`; this
        // DIDComm-multiplexed path does not.)
        let (payload, sender_vid) = match atm.tsp().unpack(profile, &packed).await {
            Ok(v) => v,
            Err(e) => {
                warn!(profile = %profile.inner.alias, error = %e, "Failed to unpack TSP frame");
                return;
            }
        };

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

    pub(crate) async fn dispatch_message(
        listener_id: &str,
        atm: &ATM,
        profile: &Arc<ATMProfile>,
        handler: &Arc<dyn DIDCommHandler>,
        message: affinidi_messaging_didcomm::Message,
        meta: affinidi_messaging_didcomm::UnpackMetadata,
    ) {
        let sender_did = message.from.clone();
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
        match handler.handle(ctx.clone(), message, meta).await {
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
    }

    pub(crate) async fn send_response(
        ctx: &HandlerContext,
        response: DIDCommResponse,
    ) -> Result<(), DIDCommServiceError> {
        let message = response.into_message(ctx)?;
        transport::send_response(ctx, message).await
    }
}
