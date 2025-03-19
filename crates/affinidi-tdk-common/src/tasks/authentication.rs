/*!
 * Authentication credentials cache and wrapper for DID Authentication
 *
 * Enables a TDK Profile to authenticate using their DID and Secrets to other services that accept DID Auth
 *
 * The Authentication service runs as a separate task and is shared across all TDK Profiles
 *
 */

use std::{hash::Hasher, sync::Arc};

use affinidi_did_authentication::AuthorizationTokens;
use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_secrets_resolver::task::SecretTaskCommand;
use ahash::AHasher;
use moka::future::Cache;
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
};
use tracing::{debug, warn};

/// Top-level Authentication Cache struct
pub struct AuthenticationCache {
    cache: Cache<u64, AuthorizationTokens>,
    channel_rx: mpsc::Receiver<AuthenticationCommand>,
    did_resolver: DIDCacheClient,
    secrets_task: mpsc::Sender<SecretTaskCommand>,
}

/// MPSC Authentication Commands
pub enum AuthenticationCommand {
    /// Terminate the Authentication Service
    Terminate,

    /// Check if a DID is authenticated against a service
    /// Will NOT authenticate if not already authenticated
    Authenticated {
        /// DID of the Profile
        profile_did: Arc<String>,

        /// Service Endpoint DID
        service_endpoint_did: Arc<String>,

        /// Channel to send the result
        tx: oneshot::Sender<Option<AuthorizationTokens>>,
    },

    /// Authenticate a DID against a service
    Authenticate {
        /// DID of the Profile
        profile_did: Arc<String>,

        /// Service Endpoint DID
        service_endpoint_did: Arc<String>,

        /// Channel to send the result
        tx: oneshot::Sender<Option<AuthorizationTokens>>,
    },

    /// Invalidate (remove) an authentication entry
    Invalidate {
        /// DID of the Profile
        profile_did: Arc<String>,

        /// Service Endpoint DID
        service_endpoint_did: Arc<String>,
    },
}

impl AuthenticationCache {
    /// Create a new AuthenticationCache
    /// # Arguments
    /// * `max_capacity` - Maximum number of entries to store in the cache (# of DIDs * # of services)
    /// * `did_resolver` - DID Resolver Cache Client
    pub fn new(
        max_capacity: u64,
        did_resolver: &DIDCacheClient,
        secrets_task_channel: mpsc::Sender<SecretTaskCommand>,
    ) -> (Self, mpsc::Sender<AuthenticationCommand>) {
        let (tx, rx) = mpsc::channel(10);

        (
            AuthenticationCache {
                cache: Cache::new(max_capacity),
                channel_rx: rx,
                did_resolver: did_resolver.clone(),
                secrets_task: secrets_task_channel,
            },
            tx,
        )
    }

    /// Start the Authentication Service
    pub async fn start(self) -> JoinHandle<()> {
        tokio::spawn(async move {
            self.run().await;
        })
    }

    /// Main loop of the authentication service
    async fn run(mut self) {
        fn hash(profile_did: &str, service_endpoint_did: &str) -> u64 {
            let mut hasher_1 = AHasher::default();
            hasher_1.write([profile_did, service_endpoint_did].concat().as_bytes());
            hasher_1.finish()
        }

        loop {
            tokio::select! {
                msg = self.channel_rx.recv() => {
                    match msg {
                        Some(AuthenticationCommand::Terminate) => {
                            debug!("Terminating Authentication Service");
                            break;
                        }
                        Some(AuthenticationCommand::Authenticated { profile_did, service_endpoint_did, tx }) => {
                            let hash = hash(&profile_did, &service_endpoint_did);

                            debug!("Checking if {} is authenticated against {}", profile_did, service_endpoint_did);
                            let is_authenticated = self.cache.get(&hash).await.is_some();
                            debug!("{} is authenticated against {}: {}", profile_did, service_endpoint_did, is_authenticated);
                        }
                        Some(AuthenticationCommand::Authenticate { profile_did, service_endpoint_did, tx }) => {
                            let hash = hash(&profile_did, &service_endpoint_did);


                            debug!("Authenticating {} against {}", profile_did, service_endpoint_did);
                        }
                        Some(AuthenticationCommand::Invalidate { profile_did, service_endpoint_did }) => {
                            let hash = hash(&profile_did, &service_endpoint_did);

                            debug!("Invalidating profile_did({}) for service_did({}) hash({})", profile_did, service_endpoint_did, hash);
                            self.cache.invalidate(&hash).await;
                        }
                        None => {
                            warn!("Authentication Service channel closed unexpectedly");
                            break;
                        }
                    }
                }
            }
        } // End of loop
        debug!("Exiting Authentication Service");
    }
}
