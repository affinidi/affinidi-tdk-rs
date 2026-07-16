/*!
 * Profiles modules contains the implementation of the Profile struct and its methods.
 *
 * For Profile network connections:
 * 1. REST based API is stateless
 * 2. WebSockets are managed via the WS_Handler task
*/

use crate::{
    ATM,
    errors::ATMError,
    transports::websockets::{
        WebSocketResponses,
        websocket::{WebSocketCommands, WebSocketTransport},
    },
};
use affinidi_did_common::{
    Document,
    service::{Endpoint, Service},
};
use affinidi_messaging_core::ConnState;
use affinidi_tdk_common::profiles::TDKProfile;
use ahash::AHashMap as HashMap;
use serde_json::Value;
use std::{
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    time::Duration,
};
use tokio::{
    select,
    sync::{RwLock, broadcast, mpsc, oneshot, watch},
};
use tracing::debug;

/// Wrapper for ATMProfileInner that lowers the cost of cloning the Profile
#[derive(Clone, Debug)]
pub struct ATMProfile {
    pub inner: Arc<ATMProfileInner>,
}

/// Working struct of a ATM Profile
/// This is used within ATM and contains everything to manage a Profile
#[derive(Debug)]
pub struct ATMProfileInner {
    pub did: String,
    pub alias: String,
    pub mediator: Arc<Option<Mediator>>,
}

impl ATMProfile {
    /// Creates a new ATM Profile
    /// If no alias is provided, the DID is used as the alias
    /// If no mediator is provided, the mediator field will default the Default Mediator if provided
    /// If no mediator and no default mediator is provided, the mediator field will be None (which is unlikely to be useful)
    pub async fn new(
        atm: &ATM,
        alias: Option<String>,
        did: String,
        mediator: Option<String>,
    ) -> Result<Self, ATMError> {
        let alias = if let Some(alias) = alias {
            alias.clone()
        } else {
            did.clone()
        };

        let mediator = if let Some(mediator) = mediator {
            Mediator::new(atm, mediator).await.ok()
        } else {
            None
        };

        debug!("Mediator: {:?}", mediator);

        let profile = ATMProfile {
            inner: Arc::new(ATMProfileInner {
                did,
                alias,
                mediator: Arc::new(mediator),
            }),
        };

        Ok(profile)
    }

    /// Convert TDK Profile to an ATM Profile
    pub async fn from_tdk_profile(atm: &ATM, tdk_profile: &TDKProfile) -> Result<Self, ATMError> {
        ATMProfile::new(
            atm,
            Some(tdk_profile.alias.clone()),
            tdk_profile.did.clone(),
            tdk_profile.mediator.clone(),
        )
        .await
    }

    /// Converts an ATM Profile into a TDK Profile (without secrets).
    pub fn to_tdk_profile(&self) -> TDKProfile {
        TDKProfile::new(
            &self.inner.alias,
            &self.inner.did,
            self.inner
                .mediator
                .as_ref()
                .as_ref()
                .map(|m| m.did.as_str()),
            Vec::new(),
        )
    }

    /// Returns the DID for the Profile and Associated Mediator
    /// Will return an error if no Mediator
    /// Returns Ok(profile_did, mediator_did)
    pub fn dids(&self) -> Result<(&str, &str), ATMError> {
        let Some(mediator) = &*self.inner.mediator else {
            return Err(ATMError::ConfigError(
                "No Mediator is configured for this Profile".to_string(),
            ));
        };

        Ok((&self.inner.did, &mediator.did))
    }

    /// Return the REST endpoint for this profile if it exists
    pub fn get_mediator_rest_endpoint(&self) -> Option<String> {
        match &*self.inner.mediator {
            Some(mediator) => mediator.rest_endpoint.clone(),
            _ => None,
        }
    }

    /// Sets up a direct channel to a provided MPSC Receiver
    /// This will bypass the WS_Handler and send messages directly to the provided Receiver
    pub async fn enable_direct_channel(
        &self,
        channel_tx: broadcast::Sender<WebSocketResponses>,
    ) -> Result<(), ATMError> {
        match &*self.inner.mediator {
            Some(mediator) => {
                if let Some(channel) = &*mediator.ws_channel_tx.read().await {
                    channel
                        .send(WebSocketCommands::EnableInboundChannel(channel_tx))
                        .await
                        .map_err(|err| {
                            ATMError::TransportError(format!(
                                "Could not send websocket EnableInboundChannel command: {err:?}"
                            ))
                        })?;
                }

                Ok(())
            }
            _ => Err(ATMError::TransportError(
                "There is no mediator configured for this profile".to_string(),
            )),
        }
    }

    /// Disables the direct channel to the provided MPSC Receiver
    pub async fn disable_direct_channel(&self) -> Result<(), ATMError> {
        match &*self.inner.mediator {
            Some(mediator) => {
                if let Some(channel) = &*mediator.ws_channel_tx.read().await {
                    channel
                        .send(WebSocketCommands::DisableInboundChannel)
                        .await
                        .map_err(|err| {
                            ATMError::TransportError(format!(
                                "Could not send websocket DisableInboundChannel command: {err:?}"
                            ))
                        })?;
                }

                Ok(())
            }
            _ => Err(ATMError::TransportError(
                "There is no mediator configured for this profile".to_string(),
            )),
        }
    }

    /// Stops the WebSocket connection for this profile
    /// This will stop the WebSocket connection and any related tasks
    pub async fn stop_websocket(&self) -> Result<(), ATMError> {
        if let Some(mediator) = &*self.inner.mediator
            && let Some(channel) = &*mediator.ws_channel_tx.read().await
        {
            channel.send(WebSocketCommands::Stop).await.map_err(|err| {
                ATMError::TransportError(format!("Could not send websocket Stop command: {err:?}"))
            })?;
        }

        Ok(())
    }

    /// A re-falsifiable view of this profile's DIDComm websocket connection
    /// state.
    ///
    /// Returns a [`watch::Receiver<ConnState>`] that transitions to
    /// [`ConnState::Connected`] on every successful (re)connect and
    /// [`ConnState::Disconnected`] on every drop, for the life of the
    /// transport task — it is a live signal, not a boot-time latch. Returns
    /// `None` if no websocket transport is running for this profile (REST-only,
    /// or before `profile_enable_websocket`). Callers observe drops/reconnects
    /// with [`watch::Receiver::changed`].
    pub async fn connection_state(&self) -> Option<watch::Receiver<ConnState>> {
        let mediator = self.inner.mediator.as_ref().as_ref()?;
        mediator.ws_conn_state_rx.read().await.clone()
    }
}

#[derive(Debug)]
pub struct Mediator {
    pub did: String,
    pub rest_endpoint: Option<String>,
    pub(crate) websocket_endpoint: Option<String>,

    /// MPSC Channel to send commands to the WebSocket connection
    pub(crate) ws_channel_tx: RwLock<Option<mpsc::Sender<WebSocketCommands>>>,

    /// Re-falsifiable connection-state signal for the WebSocket transport,
    /// published by the transport task on every drop/reconnect. `None` when no
    /// websocket transport is running for this mediator. Cloned out by
    /// [`ATMProfile::connection_state`].
    pub(crate) ws_conn_state_rx: RwLock<Option<watch::Receiver<ConnState>>>,

    /// Unique ID that is used for anything requiring a unique transaction identifier
    pub(crate) tx_uuid: AtomicU32,
}

impl Mediator {
    pub(crate) async fn new(atm: &ATM, did: String) -> Result<Self, ATMError> {
        let mediator_doc = match atm.inner.tdk_common.did_resolver().resolve(&did).await {
            Ok(response) => response.doc,
            Err(err) => {
                return Err(ATMError::DIDError(format!(
                    "Couldn't resolve DID ({did}). Reason: {err}"
                )));
            }
        };

        let mediator = Mediator {
            did,
            rest_endpoint: Mediator::find_rest_endpoint(&mediator_doc),
            websocket_endpoint: Mediator::find_ws_endpoint(&mediator_doc),
            ws_channel_tx: RwLock::new(None),
            ws_conn_state_rx: RwLock::new(None),
            tx_uuid: AtomicU32::new(0),
        };

        Ok(mediator)
    }

    /// Helper function to find the endpoint for the Mediator
    /// protocol allows you to specify the URI scheme (http, ws, etc)
    fn _find_endpoint(service: &Service, protocol: &str) -> Option<String> {
        fn check(value: &Value, protocol: &str) -> Option<String> {
            if let Some(accept) = value.get("accept") {
                let accept: Vec<String> = match serde_json::from_value(accept.to_owned()) {
                    Ok(accept) => accept,
                    Err(_) => return None,
                };

                if accept.contains(&"didcomm/v2".to_string())
                    && let Some(uri) = value.get("uri")
                    && let Some(uri) = uri.as_str()
                    && uri.starts_with(protocol)
                {
                    Some(uri.to_string())
                } else {
                    None
                }
            } else {
                None
            }
        }

        if service.type_.contains(&"DIDCommMessaging".to_string()) {
            match &service.service_endpoint {
                Endpoint::Map(map) => {
                    if map.is_array() {
                        map.as_array().and_then(|arr| {
                            for item in arr {
                                if let Some(uri) = check(item, protocol) {
                                    return Some(uri);
                                }
                            }
                            None
                        })
                    } else {
                        check(map, protocol)
                    }
                }
                _ => {
                    // Ignore URI
                    None
                }
            }
        } else {
            None
        }
    }

    /// Finds the REST endpoint for the Mediator if it exists
    fn find_rest_endpoint(doc: &Document) -> Option<String> {
        for service in doc.service.iter() {
            if let Some(endpoint) = Mediator::_find_endpoint(service, "http") {
                return Some(endpoint);
            }
        }

        None
    }

    /// Finds the WebSocket endpoint for the Mediator if it exists
    fn find_ws_endpoint(doc: &Document) -> Option<String> {
        for service in doc.service.iter() {
            if let Some(endpoint) = Mediator::_find_endpoint(service, "ws") {
                return Some(endpoint);
            }
        }

        None
    }

    /// Retruns the next transaction UUID
    pub(crate) fn get_tx_uuid(&self) -> u32 {
        self.tx_uuid.fetch_add(1, Ordering::Relaxed)
    }

    /// Tear down a half-started websocket transport for this Mediator.
    ///
    /// Called from the error paths of `profile_enable_websocket` and
    /// `profile_start_live_streaming`, which spawn a `WebSocketTransport`
    /// task and store its command sender in `ws_channel_tx`. Without this
    /// cleanup, the spawned task stays alive forever via an Arc cycle:
    /// the task holds `Arc<ATMProfile>` → `Mediator` → `ws_channel_tx` →
    /// `Sender`, so the channel never reaches zero senders and the run
    /// loop never returns. Take the sender out of the slot and send
    /// `Stop` so the task exits cleanly and drops its arcs on the way out.
    pub(crate) async fn cleanup_failed_websocket(&self) {
        let sender = self.ws_channel_tx.write().await.take();
        // Drop the stale connection-state receiver alongside the command sender;
        // a fresh one is installed on the next `WebSocketTransport::start`.
        let _ = self.ws_conn_state_rx.write().await.take();
        if let Some(sender) = sender {
            let _ = sender.send(WebSocketCommands::Stop).await;
        }
    }
}

/// Key is the alias of the profile
/// If no alias is provided, the DID is used as the key
#[derive(Default)]
pub struct Profiles(pub HashMap<String, Arc<ATMProfile>>);

impl Profiles {
    /// Inserts a new profile into the ATM SDK profiles HashMap
    /// Returns the thread-safe wrapped profile
    pub fn insert(&mut self, profile: ATMProfile) -> Arc<ATMProfile> {
        let _key = profile.inner.alias.clone();
        let _profile = Arc::new(profile);
        self.0.insert(_key, _profile.clone());

        _profile
    }

    pub fn get(&self, key: &str) -> Option<Arc<ATMProfile>> {
        self.0.get(key).cloned()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Searches through the profiles to find a profile with the given DID
    pub fn find_by_did(&self, did: &str) -> Option<Arc<ATMProfile>> {
        for profile in self.0.values() {
            if profile.inner.did == did {
                return Some(profile.clone());
            }
        }

        None
    }
}

impl ATM {
    /// Adds a profile to the ATM instance
    /// Returns None if the profile is new
    /// Returns thread-safe wrapped profile
    ///   NOTE: It will have replaced the old profile with the new one
    /// Inputs:
    ///   profile: Profile - DID and Mediator information
    ///   live_stream: bool - If true, then start websocket connection and live_streaming
    ///
    /// NOTE:
    pub async fn profile_add(
        &self,
        profile: &ATMProfile,
        live_stream: bool,
    ) -> Result<Arc<ATMProfile>, ATMError> {
        let _profile = self.inner.profiles.write().await.insert(profile.clone());
        debug!("Profile({}): Added to profiles", _profile.inner.alias);

        if live_stream && let Err(err) = self.profile_enable_websocket(&_profile).await {
            // Roll back the insertion so a retry doesn't see a stale entry
            // and so the map doesn't grow unbounded across reconnect attempts.
            let alias = _profile.inner.alias.clone();
            self.inner.profiles.write().await.0.remove(&alias);
            debug!("Profile({alias}): removed from profiles after websocket startup failure");
            return Err(err);
        }
        Ok(_profile)
    }

    /// Removes a profile from the ATM instance
    /// Will shutdown any websockets and related tasks if they exist
    /// profile: &str - The alias of the profile to remove
    ///
    /// Returns true if the profile was removed
    pub async fn profile_remove(&self, profile: &str) -> Result<bool, ATMError> {
        match self.inner.profiles.write().await.0.remove(profile) {
            Some(profile) => {
                let _ = profile.stop_websocket().await;

                debug!("Profile({}): Removed from profiles", &profile.inner.alias);
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    /// Will create a websocket connection for the profile if one doesn't already exist
    /// Will return Ok() if a connection already exists, or if it successfully started a new connection
    /// Automatically starts live_streaming
    pub async fn profile_enable_websocket(
        &self,
        profile: &Arc<ATMProfile>,
    ) -> Result<(), ATMError> {
        let Some(mediator) = &*profile.inner.mediator else {
            return Err(ATMError::ConfigError(
                "No Mediator is configured for this Profile".to_string(),
            ));
        };

        if mediator.ws_channel_tx.read().await.is_some() {
            // Already connected
            debug!(
                "Profile ({}): is already connected to the WebSocket",
                profile.inner.alias
            );
            return Ok(());
        }

        debug!("Profile({}): enabling...", profile.inner.alias);

        let (_, ws_channel, conn_state_rx) = WebSocketTransport::start(
            profile.clone(),
            self.inner.clone(),
            self.inner.config.inbound_message_channel.clone(),
        )
        .await;
        mediator.ws_channel_tx.write().await.replace(ws_channel);
        mediator
            .ws_conn_state_rx
            .write()
            .await
            .replace(conn_state_rx);

        // Every error path past WebSocketTransport::start MUST clear the
        // sender slot and tell the spawned task to stop. Otherwise the task
        // stays alive forever via an Arc cycle (see Mediator::cleanup_failed_websocket).
        match Self::wait_for_websocket_ready(mediator, &profile.inner.alias).await {
            Ok(()) => Ok(()),
            Err(err) => {
                mediator.cleanup_failed_websocket().await;
                Err(err)
            }
        }
    }

    /// Will create a websocket connection for the profile if one doesn't already exist
    /// Will return Ok() if a connection already exists, or if it successfully started a new connection
    /// Automatically starts live_streaming
    /// skip_toggle_live_delivery: if true, will not call toggle_live_delivery during connection setup
    /// skip_unpack_messages: if true, messages received via websocket will not be unpacked
    pub async fn profile_start_live_streaming(
        &self,
        profile: &Arc<ATMProfile>,
        skip_toggle_live_delivery: bool,
        skip_unpack_messages: bool,
    ) -> Result<(), ATMError> {
        let Some(mediator) = &*profile.inner.mediator else {
            return Err(ATMError::ConfigError(
                "No Mediator is configured for this Profile".to_string(),
            ));
        };

        if mediator.ws_channel_tx.read().await.is_some() {
            // Already connected
            debug!(
                "Profile ({}): is already connected to the WebSocket",
                profile.inner.alias
            );
            return Ok(());
        }

        debug!("Profile({}): enabling...", profile.inner.alias);

        let (_, ws_channel, conn_state_rx) = WebSocketTransport::start_with_options(
            profile.clone(),
            self.inner.clone(),
            self.inner.config.inbound_message_channel.clone(),
            skip_toggle_live_delivery,
            skip_unpack_messages,
        )
        .await;
        mediator.ws_channel_tx.write().await.replace(ws_channel);
        mediator
            .ws_conn_state_rx
            .write()
            .await
            .replace(conn_state_rx);

        // Every error path past WebSocketTransport::start_with_options MUST
        // clear the sender slot and tell the spawned task to stop. Otherwise
        // the task stays alive forever via an Arc cycle (see
        // Mediator::cleanup_failed_websocket).
        match Self::wait_for_websocket_ready(mediator, &profile.inner.alias).await {
            Ok(()) => Ok(()),
            Err(err) => {
                mediator.cleanup_failed_websocket().await;
                Err(err)
            }
        }
    }

    /// Send `NotifyConnection` to the spawned websocket task and wait up to
    /// 10s for the response. Caller is responsible for tearing down the
    /// transport via `Mediator::cleanup_failed_websocket` if this returns Err.
    async fn wait_for_websocket_ready(mediator: &Mediator, alias: &str) -> Result<(), ATMError> {
        let (tx, rx) = oneshot::channel();

        {
            let guard = mediator.ws_channel_tx.read().await;
            let Some(channel_tx) = &*guard else {
                return Err(ATMError::TransportError(
                    "No WebSocket channel is configured for this Profile".to_string(),
                ));
            };
            channel_tx
                .send(WebSocketCommands::NotifyConnection(tx))
                .await
                .map_err(|err| {
                    ATMError::TransportError(format!(
                        "Could not send websocket NotifyConnection? command: {err:?}"
                    ))
                })?;
        }

        let sleep = tokio::time::sleep(Duration::from_secs(10));
        tokio::pin!(sleep);

        select! {
            _ = sleep => Err(ATMError::TransportError(
                "WebSocket isActive? command timed out".to_string(),
            )),
            val = rx => match val {
                Ok(true) => {
                    debug!("Profile({}): WebSocket is active", alias);
                    Ok(())
                }
                Ok(false) => {
                    debug!("Profile({}): WebSocket is not active", alias);
                    Err(ATMError::TransportError(
                        "WebSocket is not active".to_string(),
                    ))
                }
                Err(err) => Err(ATMError::TransportError(format!(
                    "Could not receive websocket NotifyConnection? response: {err:?}"
                ))),
            }
        }
    }

    /// Returns all active profiles within ATM
    pub fn get_profiles(&self) -> Arc<RwLock<Profiles>> {
        self.inner.profiles.clone()
    }

    /// Returns a specific profile for a given DID
    pub async fn find_profile(&self, did: &str) -> Option<Arc<ATMProfile>> {
        self.inner.profiles.read().await.find_by_did(did)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ATM;
    use crate::config::ATMConfig;
    use affinidi_tdk_common::TDKSharedState;
    use affinidi_tdk_common::config::TDKConfig;
    use tokio::time::timeout;

    /// Build an `ATMProfile` with a manually-constructed `Mediator` whose
    /// endpoints point at a closed port. Bypasses `Mediator::new` (which
    /// would resolve the DID) so we can test transport-level behaviour
    /// without a real mediator.
    fn fake_profile() -> Arc<ATMProfile> {
        let mediator = Mediator {
            did: "did:peer:fake-mediator".to_string(),
            rest_endpoint: Some("http://127.0.0.1:1/".to_string()),
            websocket_endpoint: Some("ws://127.0.0.1:1/".to_string()),
            ws_channel_tx: RwLock::new(None),
            ws_conn_state_rx: RwLock::new(None),
            tx_uuid: AtomicU32::new(0),
        };
        Arc::new(ATMProfile {
            inner: Arc::new(ATMProfileInner {
                did: "did:peer:fake-profile".to_string(),
                alias: "test-orphan".to_string(),
                mediator: Arc::new(Some(mediator)),
            }),
        })
    }

    fn mediator_of(profile: &Arc<ATMProfile>) -> &Mediator {
        profile
            .inner
            .mediator
            .as_ref()
            .as_ref()
            .expect("test profile has a mediator")
    }

    /// Regression test for the websocket orphan/Arc-cycle bug.
    ///
    /// Before the fix, when `profile_enable_websocket` failed after spawning
    /// `WebSocketTransport`, the spawned task stayed alive forever: it held
    /// `Arc<ATMProfile>` → `Mediator` → `ws_channel_tx` → `Sender`, so the
    /// channel never reached zero senders and the run loop never returned.
    ///
    /// `Mediator::cleanup_failed_websocket` breaks the cycle by taking the
    /// sender out of the slot and sending `Stop`, which causes the task's
    /// run loop to break and drop its `Arc<ATMProfile>` clone.
    #[tokio::test]
    async fn cleanup_failed_websocket_terminates_orphan_task() {
        let tdk_cfg = TDKConfig::headless().expect("headless tdk config");
        let tdk = Arc::new(
            TDKSharedState::new(tdk_cfg)
                .await
                .expect("tdk shared state"),
        );
        let atm_cfg = ATMConfig::builder().build().expect("atm config");
        let atm = ATM::new(atm_cfg, tdk).await.expect("atm");

        let profile = fake_profile();
        let mediator = mediator_of(&profile);

        // Start the transport directly — same call sequence
        // `profile_enable_websocket` performs internally.
        let (handle, ws_channel, _conn_state_rx) =
            crate::transports::websockets::websocket::WebSocketTransport::start(
                profile.clone(),
                atm.inner.clone(),
                None,
            )
            .await;
        mediator.ws_channel_tx.write().await.replace(ws_channel);

        assert!(!handle.is_finished(), "task should be alive after start");
        assert!(
            mediator.ws_channel_tx.read().await.is_some(),
            "sender slot should be populated after start",
        );

        // Trigger the cleanup that the fix invokes on every error path.
        mediator.cleanup_failed_websocket().await;

        assert!(
            mediator.ws_channel_tx.read().await.is_none(),
            "sender slot must be cleared after cleanup",
        );

        // The task must terminate. Without the fix it lives forever via the
        // Arc cycle. Bound generously to allow for an in-flight authenticate
        // (default timeout 10s) before the run loop processes Stop.
        timeout(Duration::from_secs(15), handle)
            .await
            .expect("websocket task did not terminate within 15s")
            .expect("websocket task panicked");

        atm.graceful_shutdown().await;
    }

    /// The connection-state signal is `None` until a transport runs, then is
    /// exposed via `ATMProfile::connection_state()` starting at `Connecting`.
    #[tokio::test]
    async fn connection_state_is_exposed_and_starts_connecting() {
        let tdk_cfg = TDKConfig::headless().expect("headless tdk config");
        let tdk = Arc::new(
            TDKSharedState::new(tdk_cfg)
                .await
                .expect("tdk shared state"),
        );
        let atm_cfg = ATMConfig::builder().build().expect("atm config");
        let atm = ATM::new(atm_cfg, tdk).await.expect("atm");

        let profile = fake_profile();

        // No websocket transport yet → no signal.
        assert!(
            profile.connection_state().await.is_none(),
            "no signal before a transport is started",
        );

        let mediator = mediator_of(&profile);
        let (handle, ws_channel, conn_state_rx) =
            crate::transports::websockets::websocket::WebSocketTransport::start(
                profile.clone(),
                atm.inner.clone(),
                None,
            )
            .await;
        mediator.ws_channel_tx.write().await.replace(ws_channel);
        mediator
            .ws_conn_state_rx
            .write()
            .await
            .replace(conn_state_rx);

        // Exposed once running, and initial state is `Connecting`. The fake
        // mediator endpoint is a closed port, so it never reaches `Connected`
        // and the initial state is stable for the assertion.
        let rx = profile
            .connection_state()
            .await
            .expect("connection_state present once the transport is running");
        assert_eq!(*rx.borrow(), ConnState::Connecting);

        // Tear down the spawned task.
        mediator.cleanup_failed_websocket().await;
        let _ = timeout(Duration::from_secs(15), handle).await;
        atm.graceful_shutdown().await;
    }

    /// `cleanup_failed_websocket` is a no-op when there is no transport
    /// running (slot already empty). Guards against double-cleanup paths.
    #[tokio::test]
    async fn cleanup_failed_websocket_is_idempotent_when_slot_empty() {
        let profile = fake_profile();
        let mediator = mediator_of(&profile);

        assert!(mediator.ws_channel_tx.read().await.is_none());
        mediator.cleanup_failed_websocket().await;
        assert!(mediator.ws_channel_tx.read().await.is_none());
    }

    /// Truthful send (R1.1): a `send_message` over the websocket transport while
    /// the socket is down returns `Err`, not a false `Ok(EmptyResponse)`. The
    /// fake mediator endpoint is a closed port, so the transport never connects
    /// and the frame is never transmitted.
    #[tokio::test]
    async fn send_message_errors_when_websocket_disconnected() {
        let tdk_cfg = TDKConfig::headless().expect("headless tdk config");
        let tdk = Arc::new(
            TDKSharedState::new(tdk_cfg)
                .await
                .expect("tdk shared state"),
        );
        let atm_cfg = ATMConfig::builder().build().expect("atm config");
        let atm = ATM::new(atm_cfg, tdk).await.expect("atm");

        let profile = fake_profile();
        let mediator = mediator_of(&profile);

        // Start the transport; the socket stays `None` (closed port).
        let (handle, ws_channel, conn_state_rx) =
            crate::transports::websockets::websocket::WebSocketTransport::start(
                profile.clone(),
                atm.inner.clone(),
                None,
            )
            .await;
        mediator.ws_channel_tx.write().await.replace(ws_channel);
        mediator
            .ws_conn_state_rx
            .write()
            .await
            .replace(conn_state_rx);

        // A fire-and-forget send while disconnected must FAIL, not silently
        // succeed. Before the fix this returned `Ok(EmptyResponse)`.
        let result = atm
            .send_message(&profile, "{}", "msg-1", false, false)
            .await;
        assert!(
            result.is_err(),
            "send while disconnected must return Err, got {result:?}",
        );

        mediator.cleanup_failed_websocket().await;
        let _ = timeout(Duration::from_secs(15), handle).await;
        atm.graceful_shutdown().await;
    }
}
