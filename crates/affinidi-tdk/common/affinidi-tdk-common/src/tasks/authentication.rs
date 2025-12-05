/*!
 * Authentication credentials cache and wrapper for DID Authentication
 *
 * Enables a TDK Profile to authenticate using their DID and Secrets to other services that accept DID Auth
 *
 * The Authentication Task runs as a separate task and is shared across all TDK Profiles
 *
 */

use affinidi_did_authentication::{
    AuthenticationType, AuthorizationTokens, DIDAuthentication, RefreshCheck, errors::DIDAuthError,
    refresh_check,
};
use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_secrets_resolver::ThreadedSecretsResolver;
use ahash::{AHasher, RandomState};
use moka::{
    Expiry,
    future::{Cache, CacheBuilder},
};
use reqwest::Client;
use std::{
    hash::Hasher,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
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
    pub inner: Arc<Mutex<AuthenticationCacheInner>>,
    tx: mpsc::Sender<AuthenticationCommand>,
}

/// Private inner struct for AuthenticationCache
pub struct AuthenticationCacheInner {
    cache: Cache<u64, AuthenticationRecord, RandomState>,
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

/// Authentication Record stored in the cache
#[derive(Clone)]
struct AuthenticationRecord {
    tokens: AuthorizationTokens,
    type_: AuthenticationType,
}

// Sets up expiry for the AuthenticationRecord to expire when the refresh token expires
impl Expiry<u64, AuthenticationRecord> for AuthenticationRecord {
    fn expire_after_create(
        &self,
        _key: &u64,
        value: &AuthenticationRecord,
        _current_time: Instant,
    ) -> Option<Duration> {
        // Set the expiry of this entry to the expiry of the refresh token
        // It is the delta Duration between now and the refresh expiry
        let refresh_expiry = Duration::from_secs(value.tokens.refresh_expires_at);
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        Some(refresh_expiry - now)
    }
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

        // Dummy expiry that is used to set the expiry of the AuthenticationRecord
        let expiry = AuthenticationRecord {
            tokens: AuthorizationTokens::default(),
            type_: AuthenticationType::Unknown,
        };
        let cache = CacheBuilder::new(max_capacity)
            .expire_after(expiry)
            .build_with_hasher(ahash::RandomState::default());

        (
            AuthenticationCache {
                inner: Arc::new(Mutex::new(AuthenticationCacheInner {
                    cache,
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
    pub async fn start(&self) -> JoinHandle<()> {
        let self_clone = self.clone();
        tokio::spawn(async move {
            self_clone.run(None).await;
        })
    }

    /// Start the Authentication Task with initial tokens
    pub async fn start_with_tokens(&self, tokens: AuthorizationTokens) -> JoinHandle<()> {
        let self_clone = self.clone();
        tokio::spawn(async move {
            self_clone.run(Some(tokens)).await;
        })
    }

    /// Main loop of the authentication Task
    async fn run(self, initial_tokens: Option<AuthorizationTokens>) {
        let mut inner = self.inner.lock().await;

        loop {
            tokio::select! {
                msg = inner.channel_rx.recv() => {
                    if inner.handle_channel(msg, initial_tokens.clone()).await {
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
    async fn handle_channel(&self, cmd: Option<AuthenticationCommand>, tokens: Option<AuthorizationTokens>) -> bool {
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
                if let Some(record) = is_authenticated {
                    let _ = tx.send(Some(record.tokens));
                } else {
                    let _ = tx.send(None);
                }
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

                let mut auth = if let Some(record) = self.cache.get(&hash).await {
                    debug!(
                        "{} is already authenticated against {}",
                        profile_did, service_endpoint_did
                    );

                    match refresh_check(&record.tokens) {
                        RefreshCheck::Ok => {
                            debug!("Tokens are valid");
                            let _ = tx.send(Ok(record.tokens));
                            return false;
                        }
                        RefreshCheck::Refresh => {
                            debug!("Refresh needed");
                            DIDAuthentication {
                                type_: record.type_,
                                tokens: Some(record.tokens.clone()),
                                authenticated: true,
                            }
                        }
                        RefreshCheck::Expired => {
                            debug!("Tokens expired");
                            DIDAuthentication::new()
                        }
                    }
                } else {
                    DIDAuthentication::new()
                };

                match tokens {
                    Some(t) => {
                        auth.tokens = Some(t);
                        auth.authenticated = true;
                        auth.type_ = AuthenticationType::AffinidiMessaging;
                    }
                    None => {}
                }

                let did_resolver = self.did_resolver.clone();
                let secrets_resolver = self.secrets_resolver.clone();
                let client = self.client.clone();
                let profile_copy = profile_did.clone();
                let service_copy = service_endpoint_did.clone();

                let handle = tokio::spawn(async move {
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
                        Ok(_) => Ok(auth),
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
                                    Ok(auth) => {
                                        if let Some(tokens) = &auth.tokens {
                                            self.cache.insert(hash, AuthenticationRecord {  tokens: tokens.clone(), type_: auth.type_ }).await;
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
                                let _ = tx.send(Err(DIDAuthError::AuthenticationAbort(format!("JoinHandle Error on spawned Authentication task: {e}"))));
                            }
                        }
                    }
                    _ = &mut timeout => {
                        warn!("Timeout reached");
                        let _ = tx.send(Err(DIDAuthError::AuthenticationAbort("Timeout reached".to_string())));
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

#[cfg(test)]
mod tests {
    use crate::tasks::authentication::AuthenticationRecord;
    use affinidi_did_authentication::{AuthenticationType, AuthorizationTokens};
    use moka::future::CacheBuilder;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    /// Test the cache expires correctly
    #[tokio::test]
    async fn check_cache_expiry_good() {
        let expiry = AuthenticationRecord {
            tokens: AuthorizationTokens::default(),
            type_: AuthenticationType::Unknown,
        };
        let cache = CacheBuilder::new(1)
            .expire_after(expiry)
            .build_with_hasher(ahash::RandomState::default());

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        cache
            .insert(
                1,
                AuthenticationRecord {
                    tokens: AuthorizationTokens {
                        access_token: "access".to_string(),
                        access_expires_at: now.as_secs() + 1,
                        refresh_token: "refresh".to_string(),
                        refresh_expires_at: now.as_secs() + 1,
                    },
                    type_: AuthenticationType::Unknown,
                },
            )
            .await;

        // Cache should contain the key
        assert!(cache.contains_key(&1));

        tokio::time::sleep(Duration::from_secs(2)).await;
        cache.run_pending_tasks().await;

        assert!(!cache.contains_key(&1));
        assert!(cache.get(&1).await.is_none());
    }
}
