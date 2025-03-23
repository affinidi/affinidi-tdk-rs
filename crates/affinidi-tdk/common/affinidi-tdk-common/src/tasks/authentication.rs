/*!
 * Authentication credentials cache and wrapper for DID Authentication
 *
 * Enables a TDK Profile to authenticate using their DID and Secrets to other services that accept DID Auth
 *
 * The Authentication Task runs as a separate task and is shared across all TDK Profiles
 *
 */

use affinidi_did_authentication::{AuthorizationTokens, DIDAuthentication, errors::DIDAuthError};
use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_secrets_resolver::ThreadedSecretsResolver;
use ahash::AHasher;
use moka::future::Cache;
use reqwest::Client;
use std::{hash::Hasher, sync::Arc, time::Duration};
use tokio::{
    sync::{
        Mutex,
        mpsc::{self, error::TrySendError},
        oneshot,
    },
    task::JoinHandle,
};
use tracing::{debug, warn};

/// Top-level Authentication Cache struct
#[derive(Clone)]
pub struct AuthenticationCache {
    inner: Arc<Mutex<AuthenticationCacheInner>>,
    tx: mpsc::Sender<AuthenticationCommand>,
}

/// Private inner struct for AuthenticationCache
pub struct AuthenticationCacheInner {
    cache: Cache<u64, AuthorizationTokens>,
    channel_rx: mpsc::Receiver<AuthenticationCommand>,
    did_resolver: DIDCacheClient,
    secrets_resolver: ThreadedSecretsResolver,
    client: Client,
}

/// MPSC Authentication Commands
pub enum AuthenticationCommand {
    /// Terminate the Authentication Task
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

        /// How many times to retry the authentication
        retry_limit: u8,

        /// timeout for authentication task
        timeout: Duration,

        /// Channel to send the result
        tx: oneshot::Sender<Result<AuthorizationTokens, DIDAuthError>>,
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
    /// * `secrets_resolver` - SecretsResolver
    /// * `client` - Reqwest Client
    pub fn new(
        max_capacity: u64,
        did_resolver: &DIDCacheClient,
        secrets_resolver: ThreadedSecretsResolver,
        client: &Client,
    ) -> (Self, mpsc::Sender<AuthenticationCommand>) {
        let (tx, rx) = mpsc::channel(32);

        (
            AuthenticationCache {
                inner: Arc::new(Mutex::new(AuthenticationCacheInner {
                    cache: Cache::new(max_capacity),
                    channel_rx: rx,
                    did_resolver: did_resolver.clone(),
                    secrets_resolver,
                    client: client.clone(),
                })),
                tx: tx.clone(),
            },
            tx,
        )
    }

    /// Start the Authentication Task
    pub async fn start(self) -> JoinHandle<()> {
        tokio::spawn(async move {
            self.run().await;
        })
    }

    /// Main loop of the authentication Task
    async fn run(self) {
        let mut inner = self.inner.lock().await;

        loop {
            tokio::select! {
                msg = inner.channel_rx.recv() => {
                    if inner.handle_channel(msg).await {
                        break;
                    }
                }
            }
        } // End of loop
        debug!("Exiting Authentication Task");
    }

    /// Terminates the Authentication Task
    pub async fn terminate(&self) {
        let _ = self.tx.send(AuthenticationCommand::Terminate).await;
    }

    /// Check if already authenticated, will not re-authenticate if not
    /// Use authenticate which will do a complete authentication flow if not already authenticated
    pub async fn authenticated(
        &self,
        profile_did: String,
        service_endpoint_did: String,
    ) -> Option<AuthorizationTokens> {
        let (tx, rx) = oneshot::channel();
        match self.tx.try_send(AuthenticationCommand::Authenticated {
            profile_did: Arc::new(profile_did),
            service_endpoint_did: Arc::new(service_endpoint_did),
            tx,
        }) {
            Ok(_) => {}
            Err(TrySendError::Closed(_)) => {
                warn!("Authenticated Task channel closed unexpectedly");
                return None;
            }
            Err(TrySendError::Full(_)) => {
                warn!("Authenticated Task channel full");
                return None;
            }
        }

        let timeout = tokio::time::sleep(Duration::from_secs(2));
        tokio::pin!(timeout);

        tokio::select! {
            _ = &mut timeout => {
                warn!("Timeout reached");
                None
            }
            value = rx => {
                match value {
                    Ok(tokens) => tokens,
                    Err(_) => {
                        warn!("Authenticated Task channel closed unexpectedly");
                        None
                    }
                }
            }
        }
    }

    /// Authenticate a profile DID against a service endpoint DID
    /// If already authenticated, will return existing tokens
    /// Will auto-refresh tokens as needed.
    ///
    /// # Arguments
    /// * `profile_did` - DID of the Profile
    /// * `service_endpoint_did` - DID of the Service Endpoint
    /// * `retry_limit` - How many times to retry the authentication
    /// * `timeout` - Optional timeout for the authentication (default 10 seconds)
    pub async fn authenticate(
        &self,
        profile_did: String,
        service_endpoint_did: String,
        retry_limit: u8,
        timeout: Option<Duration>,
    ) -> Result<AuthorizationTokens, DIDAuthError> {
        let (tx, rx) = oneshot::channel();
        match self.tx.try_send(AuthenticationCommand::Authenticate {
            profile_did: Arc::new(profile_did),
            service_endpoint_did: Arc::new(service_endpoint_did),
            retry_limit,
            timeout: timeout.unwrap_or(Duration::from_secs(10)),
            tx,
        }) {
            Ok(_) => {}
            Err(TrySendError::Closed(_)) => {
                warn!("Authenticated Task channel closed unexpectedly");
                return Err(DIDAuthError::AuthenticationAbort(
                    "Authentication Task channel closed unexpectedly".to_string(),
                ));
            }
            Err(TrySendError::Full(_)) => {
                warn!("Authenticated Task channel full");
                return Err(DIDAuthError::AuthenticationAbort(
                    "Authentication Task channel full".to_string(),
                ));
            }
        }

        let timeout = tokio::time::sleep(timeout.unwrap_or(Duration::from_secs(10)));
        tokio::pin!(timeout);

        tokio::select! {
            value = rx => {
                match value {
                    Ok(tokens) => tokens,
                    Err(_) => Err(DIDAuthError::AuthenticationAbort(
                        "Authentication Task channel closed unexpectedly".to_string(),
                    )),
                }
            }
            _ = &mut timeout => {
                warn!("Timeout reached");
                Err(DIDAuthError::AuthenticationAbort("Timeout reached".to_string()))
            }
        }
    }
}

impl AuthenticationCacheInner {
    async fn handle_channel(&self, cmd: Option<AuthenticationCommand>) -> bool {
        let mut exit_flag = false;
        match cmd {
            Some(AuthenticationCommand::Terminate) => {
                debug!("Terminating Authentication Task");
                exit_flag = true;
            }
            Some(AuthenticationCommand::Authenticated {
                profile_did,
                service_endpoint_did,
                tx,
            }) => {
                let hash = hash(&profile_did, &service_endpoint_did);

                debug!(
                    "Checking if {} is authenticated against {}",
                    profile_did, service_endpoint_did
                );
                let is_authenticated = self.cache.get(&hash).await;
                debug!(
                    "{} is authenticated against {}: {}",
                    profile_did,
                    service_endpoint_did,
                    is_authenticated.is_some()
                );
                let _ = tx.send(is_authenticated);
            }
            Some(AuthenticationCommand::Authenticate {
                profile_did,
                service_endpoint_did,
                tx,
                retry_limit,
                timeout,
            }) => {
                let hash = hash(&profile_did, &service_endpoint_did);

                debug!(
                    "Authenticating {} against {}",
                    profile_did, service_endpoint_did
                );

                if let Some(tokens) = self.cache.get(&hash).await {
                    debug!(
                        "{} is already authenticated against {}",
                        profile_did, service_endpoint_did
                    );
                    let _ = tx.send(Ok(tokens));
                } else {
                    let did_resolver = self.did_resolver.clone();
                    let secrets_resolver = self.secrets_resolver.clone();
                    let client = self.client.clone();
                    let profile_copy = profile_did.clone();
                    let service_copy = service_endpoint_did.clone();

                    let handle = tokio::spawn(async move {
                        let mut auth = DIDAuthentication::new();
                        match auth
                            .authenticate(
                                &profile_copy,
                                &service_copy,
                                &did_resolver,
                                &secrets_resolver,
                                &client,
                                retry_limit as i32,
                            )
                            .await
                        {
                            Ok(_) => Ok(auth.tokens),
                            Err(e) => Err(e),
                        }
                    });

                    let timeout = tokio::time::sleep(timeout);
                    tokio::pin!(timeout);

                    tokio::select! {
                        value = handle => {
                            match value {
                                Ok(result) => {
                                    match result {
                                        Ok(tokens) => {
                                            if let Some(tokens) = &tokens {
                                                self.cache.insert(hash, tokens.clone()).await;
                                                let _ = tx.send(Ok(tokens.clone()));
                                            } else {
                                                let _ = tx.send(Err(DIDAuthError::AuthenticationAbort(
                                                    "Internal Error: Authenticated ok, but no tokens!"
                                                        .to_string(),
                                                )));
                                            }
                                        }
                                        Err(e) => {
                                            warn!(
                                                "Failed to authenticate {} against {}: {}",
                                                profile_did, service_endpoint_did, e
                                            );
                                            let _ = tx.send(Err(e));
                                    }
                                }
                            }
                                Err(e) => {
                                    warn!(
                                        "Failed to authenticate {} against {}: {}",
                                        profile_did, service_endpoint_did, e
                                    );
                                    let _ = tx.send(Err(DIDAuthError::AuthenticationAbort(format!("JoinHandle Error on spawned Authentication task: {}", e))));
                                }
                            }
                        }
                        _ = &mut timeout => {
                            warn!("Timeout reached");
                            let _ = tx.send(Err(DIDAuthError::AuthenticationAbort("Timeout reached".to_string())));
                        }
                    }
                }
            }
            Some(AuthenticationCommand::Invalidate {
                profile_did,
                service_endpoint_did,
            }) => {
                let hash = hash(&profile_did, &service_endpoint_did);

                debug!(
                    "Invalidating profile_did({}) for service_did({}) hash({})",
                    profile_did, service_endpoint_did, hash
                );
                self.cache.invalidate(&hash).await;
            }
            None => {
                warn!("Authentication Task channel closed unexpectedly");
                exit_flag = true;
            }
        }

        exit_flag
    }
}

fn hash(profile_did: &str, service_endpoint_did: &str) -> u64 {
    let mut hasher_1 = AHasher::default();
    hasher_1.write([profile_did, service_endpoint_did].concat().as_bytes());
    hasher_1.finish()
}
