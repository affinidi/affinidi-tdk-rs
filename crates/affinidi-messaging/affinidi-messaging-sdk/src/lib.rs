//! # Affinidi Trusted Messaging SDK
//!
//! The Affinidi Trusted Messaging (ATM) SDK provides a high-level interface for
//! [DIDComm v2](https://identity.foundation/didcomm-messaging/spec/) messaging
//! through a mediator service. It handles message encryption, signing, routing,
//! and transport so you can focus on building your application.
//!
//! ## Key Concepts
//!
//! - **[`ATM`]** - The main entry point. Holds configuration, profiles, and manages
//!   background tasks (e.g. message deletion).
//! - **[`profiles::ATMProfile`]** - Represents a DID identity with an associated
//!   mediator. Each profile can independently send and receive messages.
//! - **Mediator** - A service that stores and forwards DIDComm messages on behalf
//!   of your profile. Discovered automatically from the mediator's DID Document.
//! - **[`protocols::Protocols`]** - Pre-built DIDComm protocol implementations
//!   (Trust Ping, Message Pickup 3.0, Routing 2.0, etc.).
//! - **Transports** - The SDK supports both REST (HTTPS) and WebSocket (WSS)
//!   transports. REST is used for authentication and bulk operations; WebSocket
//!   enables low-latency sending and live message streaming.
//!
//! ## Getting Started
//!
//! ### 1. Initialize the TDK shared state
//!
//! The SDK builds on top of `affinidi-tdk-common` which manages DID resolution
//! and secrets. You need a [`TDKSharedState`] instance first:
//!
//! ```rust,ignore
//! use affinidi_tdk::common::{TDKSharedState, environments::TDKEnvironments};
//! use std::sync::Arc;
//!
//! // Load environment configuration (DIDs, secrets, mediator endpoints)
//! let mut environment = TDKEnvironments::fetch_from_file(
//!     Some("environments.json"),
//!     "default",
//! )?;
//!
//! let tdk = Arc::new(TDKSharedState::default().await);
//! ```
//!
//! ### 2. Build an ATM configuration and create the SDK instance
//!
//! Use [`config::ATMConfig::builder()`] to configure the SDK, then pass it to
//! [`ATM::new()`]:
//!
//! ```rust,ignore
//! use affinidi_messaging_sdk::{ATM, config::ATMConfig};
//!
//! let config = ATMConfig::builder()
//!     // Add custom SSL/TLS certificates if the mediator uses self-signed certs
//!     .with_ssl_certificates(&mut environment.ssl_certificates)
//!     // Optional: tune the per-profile message fetch cache
//!     .with_fetch_cache_limit_count(100)
//!     .with_fetch_cache_limit_bytes(10 * 1024 * 1024)
//!     .build()?;
//!
//! let atm = ATM::new(config, tdk).await?;
//! ```
//!
//! ### 3. Register a profile
//!
//! A profile ties a DID to a mediator. Add it to both the TDK (for secrets/DID
//! resolution) and the ATM SDK:
//!
//! ```rust,ignore
//! use affinidi_messaging_sdk::profiles::ATMProfile;
//!
//! // Get a profile from your environment configuration
//! let alice_tdk = environment.profiles.get("Alice").unwrap();
//! tdk.add_profile(alice_tdk).await;
//!
//! // Convert and register with ATM (live_stream=false means no WebSocket yet)
//! let alice = atm
//!     .profile_add(
//!         &ATMProfile::from_tdk_profile(&atm, alice_tdk).await?,
//!         false,
//!     )
//!     .await?;
//! ```
//!
//! ### 4. Send a message (REST)
//!
//! The simplest way to verify connectivity is a DIDComm Trust Ping:
//!
//! ```rust,ignore
//! use affinidi_messaging_sdk::protocols::Protocols;
//!
//! let protocols = Protocols::new();
//!
//! // Send a signed trust-ping, requesting a pong response
//! let ping = protocols
//!     .trust_ping
//!     .send_ping(
//!         &atm,
//!         &alice,       // sender profile
//!         &target_did,  // recipient DID
//!         true,         // signed
//!         true,         // request pong response
//!         false,        // don't block waiting for response
//!     )
//!     .await?;
//! ```
//!
//! ### 5. Retrieve and unpack messages
//!
//! After sending a message that produces a response, fetch and decrypt it:
//!
//! ```rust,ignore
//! use affinidi_messaging_sdk::messages::GetMessagesRequest;
//!
//! let response = atm
//!     .get_messages(
//!         &alice,
//!         &GetMessagesRequest {
//!             message_ids: vec![msg_id],
//!             delete: true, // delete after retrieval
//!         },
//!     )
//!     .await?;
//!
//! for msg in response.success {
//!     let (message, metadata) = atm.unpack(&msg.msg.unwrap()).await?;
//!     println!("Received: {:?}", message);
//! }
//! ```
//!
//! ### 6. Upgrade to WebSocket for live streaming
//!
//! For lower latency and push-based message delivery, enable the WebSocket
//! transport on a profile:
//!
//! ```rust,ignore
//! use std::time::Duration;
//!
//! // Open a WebSocket connection to the mediator
//! atm.profile_enable_websocket(&alice).await?;
//!
//! // Send a ping (now routed over WebSocket automatically)
//! let ping = protocols
//!     .trust_ping
//!     .send_ping(&atm, &alice, &target_did, true, true, false)
//!     .await?;
//!
//! // Wait for the pong via the live stream
//! let pong = protocols
//!     .message_pickup
//!     .live_stream_get(
//!         &atm,
//!         &alice,
//!         &ping.message_id,
//!         Duration::from_secs(10),
//!         true, // auto-unpack
//!     )
//!     .await?;
//! ```
//!
//! ### 7. Graceful shutdown
//!
//! Always shut down cleanly to close WebSocket connections and stop background
//! tasks:
//!
//! ```rust,ignore
//! atm.graceful_shutdown().await;
//! ```
//!
//! ## Module Overview
//!
//! | Module | Description |
//! |--------|-------------|
//! | [`config`] | SDK configuration via the builder pattern ([`config::ATMConfig`]) |
//! | [`profiles`] | DID profile and mediator management ([`profiles::ATMProfile`]) |
//! | [`messages`] | Pack, unpack, send, list, get, fetch, and delete DIDComm messages |
//! | [`protocols`] | Higher-level DIDComm protocol implementations (Trust Ping, Message Pickup, Routing) |
//! | [`transports`] | REST and WebSocket transport layer |
//! | [`errors`] | Error types ([`errors::ATMError`]) |
//! | [`delete_handler`] | Background message deletion task |
//! | [`public`] | Public utility functions (e.g. well-known DID resolution) |
//!
//! ## Debug Logging
//!
//! Enable SDK debug logs via the `RUST_LOG` environment variable:
//!
//! ```bash
//! export RUST_LOG=none,affinidi_messaging_sdk=debug
//! ```

use affinidi_tdk_common::TDKSharedState;
use config::ATMConfig;
use delete_handler::DeletionHandlerCommands;
use errors::ATMError;
use profiles::Profiles;
use std::sync::Arc;
use tokio::sync::{
    Mutex, RwLock, broadcast,
    mpsc::{self, Receiver, Sender},
};
use tracing::debug;
use transports::websockets::WebSocketResponses;

//pub mod authentication;
pub mod config;
pub mod delete_handler;
pub mod errors;
pub mod messages;
pub mod profiles;
pub mod protocols;
pub mod public;
pub mod transports;

#[derive(Clone)]
pub struct ATM {
    pub(crate) inner: Arc<SharedState>,
}

/// Private SharedState struct for the ATM to be used across tasks
pub(crate) struct SharedState {
    pub(crate) config: ATMConfig,
    pub(crate) tdk_common: Arc<TDKSharedState>,
    pub(crate) profiles: Arc<RwLock<Profiles>>,
    pub(crate) deletion_handler_send_stream: Sender<delete_handler::DeletionHandlerCommands>, // Sends MPSC messages to the Deletion Handler
    pub(crate) deletion_handler_recv_stream:
        Mutex<Receiver<delete_handler::DeletionHandlerCommands>>, // Receives MPSC messages from the Deletion Handler
}

/// Affinidi Trusted Messaging SDK
/// This is the top level struct for the SDK
///
/// Example:
/// ```ignore
/// use affinidi_messaging_sdk::ATM;
/// use affinidi_messaging_sdk::config::ATMConfigBuilder;
///
/// let config = ATMConfigBuilder::default().build()?;
/// let atm = ATM::new(config, tdk_shared_state).await?;
/// ```
impl ATM {
    /// Creates a new instance of the SDK with a given configuration
    /// You need to add at least the DID Method for the SDK DID to work
    pub async fn new(config: ATMConfig, tdk_common: Arc<TDKSharedState>) -> Result<ATM, ATMError> {
        // Create a new channel with a capacity of at most 32. This communicates from SDK to the deletion handler
        let (sdk_deletion_tx, deletion_sdk_rx) = mpsc::channel::<DeletionHandlerCommands>(32);

        // Create a new channel with a capacity of at most 32. This communicates from deletion handler to the SDK
        let (deletion_sdk_tx, sdk_deletion_rx) = mpsc::channel::<DeletionHandlerCommands>(32);

        let shared_state = SharedState {
            config: config.clone(),
            tdk_common,
            profiles: Arc::new(RwLock::new(Profiles::default())),
            deletion_handler_send_stream: sdk_deletion_tx,
            deletion_handler_recv_stream: Mutex::new(sdk_deletion_rx),
        };

        let atm = ATM {
            inner: Arc::new(shared_state),
        };

        // Start the deletion handler
        atm.start_deletion_handler(deletion_sdk_rx, deletion_sdk_tx)
            .await?;

        debug!("ATM SDK initialized");

        Ok(atm)
    }

    pub async fn graceful_shutdown(&self) {
        debug!("Shutting down ATM SDK");

        // turn off incoming messages on websockets

        // Send a shutdown message to the Deletion Handler
        let _ = self.abort_deletion_handler().await;
        {
            let mut guard = self.inner.deletion_handler_recv_stream.lock().await;
            let _ = guard.recv().await;
            // Only ever send back a closing command
            // safe to exit now
            debug!("Deletion Handler stopped");
        }

        {
            let profiles = &*self.inner.profiles.read().await;
            for (_, profile) in profiles.0.iter() {
                // Send a Stop command to each profile
                let _ = profile.stop_websocket().await;
            }
        }
    }

    /// If you have set the ATM SDK to be in DirectChannel mode, you can get the inbound channel here
    /// This allows you to directly stream messages from the WebSocket Handler to your own client code
    pub fn get_inbound_channel(&self) -> Option<broadcast::Receiver<WebSocketResponses>> {
        self.inner
            .config
            .inbound_message_channel
            .as_ref()
            .map(|sender| sender.subscribe())
    }

    /// Get the TDK Shared State
    pub fn get_tdk(&self) -> &TDKSharedState {
        &self.inner.tdk_common
    }
}
