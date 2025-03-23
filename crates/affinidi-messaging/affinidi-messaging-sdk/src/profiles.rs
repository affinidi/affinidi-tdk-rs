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
    messages::AuthorizationResponse,
    protocols::message_pickup::MessagePickup,
    transports::websockets::{
        ws_connection::WsConnectionCommands,
        ws_handler::{WsHandlerCommands, WsHandlerMode},
    },
};
use affinidi_messaging_didcomm::{Message, UnpackMetadata};
use affinidi_tdk_common::profiles::TDKProfile;
use ahash::AHashMap as HashMap;
use ssi::dids::{
    Document,
    document::{Service, service::Endpoint},
};
use std::{
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};
use tokio::sync::{
    Mutex, RwLock,
    mpsc::{Receiver, Sender},
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
    pub(crate) authorization: Mutex<Option<AuthorizationResponse>>,
    pub(crate) authenticated: AtomicBool,
    /// Channel to send commands to the WS_Handler task
    pub(crate) channel_tx: Mutex<Sender<WsHandlerCommands>>,
    /// Channel to receive commands from the WS_Handler task
    pub(crate) channel_rx: Mutex<Receiver<WsHandlerCommands>>,
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

        let (tx, rx) = tokio::sync::mpsc::channel(32);

        let profile = ATMProfile {
            inner: Arc::new(ATMProfileInner {
                did,
                alias,
                mediator: Arc::new(mediator),
                authorization: Mutex::new(None),
                authenticated: AtomicBool::new(false),
                channel_tx: Mutex::new(tx),
                channel_rx: Mutex::new(rx),
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

    /// Converts an ATM  Profile into a TDK Profile
    pub fn to_tdk_profile(&self) -> TDKProfile {
        TDKProfile {
            alias: self.inner.alias.clone(),
            did: self.inner.did.clone(),
            mediator: self.inner.mediator.as_ref().as_ref().map(|m| m.did.clone()),
            secrets: Vec::new(),
        }
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
        channel_tx: Sender<Box<(Message, UnpackMetadata)>>,
    ) -> Result<(), ATMError> {
        match &*self.inner.mediator {
            Some(mediator) => {
                if let Some(channel) = &*mediator.ws_channel_tx.lock().await {
                    channel
                        .send(WsConnectionCommands::EnableDirectChannel(channel_tx))
                        .await
                        .map_err(|err| {
                            ATMError::TransportError(format!(
                                "Could not send websocket message: {:?}",
                                err
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
                if let Some(channel) = &*mediator.ws_channel_tx.lock().await {
                    channel
                        .send(WsConnectionCommands::DisableDirectChannel)
                        .await
                        .map_err(|err| {
                            ATMError::TransportError(format!(
                                "Could not send websocket message: {:?}",
                                err
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
}

#[derive(Debug)]
pub struct Mediator {
    pub did: String,
    pub rest_endpoint: Option<String>,
    pub(crate) websocket_endpoint: Option<String>,
    pub(crate) ws_connected: AtomicBool, // Whether the websocket is connected
    pub(crate) ws_channel_tx: Mutex<Option<Sender<WsConnectionCommands>>>,
}

impl Mediator {
    pub(crate) async fn new(atm: &ATM, did: String) -> Result<Self, ATMError> {
        let mediator_doc = match atm.inner.tdk_common.did_resolver.resolve(&did).await {
            Ok(response) => response.doc,
            Err(err) => {
                return Err(ATMError::DIDError(format!(
                    "Couldn't resolve DID ({}). Reason: {}",
                    did, err
                )));
            }
        };

        let mediator = Mediator {
            did,
            rest_endpoint: Mediator::find_rest_endpoint(&mediator_doc),
            websocket_endpoint: Mediator::find_ws_endpoint(&mediator_doc),
            ws_connected: AtomicBool::new(false),
            ws_channel_tx: Mutex::new(None),
        };

        Ok(mediator)
    }

    /// Helper function to find the endpoint for the Mediator
    /// protocol allows you to specify the URI scheme (http, ws, etc)
    fn _find_endpoint(service: &Service, protocol: &str) -> Option<String> {
        if service.type_.contains(&"DIDCommMessaging".to_string()) {
            if let Some(endpoint) = &service.service_endpoint {
                for endpoint in endpoint.into_iter() {
                    match endpoint {
                        Endpoint::Map(map) => {
                            if let Some(accept) = map.get("accept") {
                                let accept: Vec<String> =
                                    match serde_json::from_value(accept.to_owned()) {
                                        Ok(accept) => accept,
                                        Err(_) => continue,
                                    };

                                if accept.contains(&"didcomm/v2".to_string()) {
                                    if let Some(uri) = map.get("uri") {
                                        if let Some(uri) = uri.as_str() {
                                            if uri.starts_with(protocol) {
                                                return Some(uri.to_string());
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        _ => {
                            // Ignore URI}
                        }
                    }
                }
            }
        }

        None
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

        if live_stream {
            // Grab a copy of the wrapped Profile
            self.profile_enable_websocket(&_profile).await?;
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
                // Send a signal to the WsHandler to Remove this Profile
                let _ = self
                    .inner
                    .ws_handler_send_stream
                    .send(WsHandlerCommands::Deactivate(profile.clone()))
                    .await;

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
        let mediator = {
            let Some(mediator) = &*profile.inner.mediator else {
                return Err(ATMError::ConfigError(
                    "No Mediator is configured for this Profile".to_string(),
                ));
            };
            mediator
        };

        if mediator
            .ws_connected
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            // Already connected
            debug!(
                "Profile ({}): is already connected to the WebSocket",
                profile.inner.alias
            );
            return Ok(());
        }

        debug!("Profile({}): enabling...", profile.inner.alias);

        // Send this profile info to the WS_Handler
        let status_msg_id = match self
            .inner
            .ws_handler_send_stream
            .send(WsHandlerCommands::Activate(profile.clone()))
            .await
        {
            Ok(_) => {
                debug!(
                    "Profile({}): Successfully sent Activate command to WS_Handler",
                    profile.inner.alias
                );

                // Wait for the Activated message from the WS_handler
                let mut rx_guard = profile.inner.channel_rx.lock().await;
                match rx_guard.recv().await {
                    Some(WsHandlerCommands::Activated(status_msg_id)) => {
                        debug!("Profile({}): Activated", profile.inner.alias);
                        status_msg_id
                    }
                    _ => {
                        return Err(ATMError::TransportError(format!(
                            "Profile({}): Couldn't activate the profile",
                            profile.inner.alias
                        )));
                    }
                }
            }
            Err(err) => {
                return Err(ATMError::TransportError(format!(
                    "Profile({}): Couldn't send Activate command to WS_Handler. Reason: {}",
                    profile.inner.alias, err
                )));
            }
        };

        // If we are running in cached mode, then we should wait for the live-pickup status message and clear it
        if let WsHandlerMode::Cached = self.inner.config.ws_handler_mode {
            let _ = MessagePickup::default()
                .live_stream_get(
                    self,
                    profile,
                    true,
                    &status_msg_id,
                    Duration::from_secs(10),
                    false,
                )
                .await;
        }

        Ok(())
    }

    pub fn get_profiles(&self) -> Arc<RwLock<Profiles>> {
        self.inner.profiles.clone()
    }
}
