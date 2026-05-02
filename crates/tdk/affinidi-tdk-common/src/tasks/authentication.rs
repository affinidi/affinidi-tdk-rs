/*!
 * Authentication credentials cache and wrapper for DID Authentication.
 *
 * Enables a TDK Profile to authenticate using its DID and secrets to other
 * services that accept DID Auth. The cache is shared across all profiles in
 * the host process and runs as a single background task driven by an MPSC
 * command channel.
 *
 * Cached entries expire when their refresh token expires; expired-token
 * authentication kicks off a fresh DID Auth handshake.
 */

use affinidi_did_authentication::{
    AuthenticationType, AuthorizationTokens, CustomAuthHandlers, DIDAuthentication, RefreshCheck,
    errors::DIDAuthError, refresh_check,
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
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    sync::{
        mpsc::{self, error::TrySendError},
        oneshot,
    },
    task::JoinHandle,
};
use tracing::{debug, warn};

/// MPSC channel buffer size for [`AuthenticationCommand`]. Sized for short
/// burst tolerance — sustained backpressure shows up as `TrySendError::Full`
/// warnings and should be addressed at the call site.
const COMMAND_CHANNEL_CAPACITY: usize = 32;

/// Default retries for [`AuthenticationCache::authenticate_default`].
pub const DEFAULT_AUTH_RETRIES: u8 = 3;

/// Default timeout applied when no explicit timeout is supplied to
/// [`AuthenticationCache::authenticate`].
pub const DEFAULT_AUTH_TIMEOUT: Duration = Duration::from_secs(10);

/// Timeout for the lightweight [`AuthenticationCache::authenticated`] check.
pub const AUTHENTICATED_QUERY_TIMEOUT: Duration = Duration::from_secs(2);

/// Top-level Authentication Cache handle.
///
/// Cheap to clone — internally an [`Arc<mpsc::Sender>`] plus a slot for the
/// background-task `JoinHandle`.
#[derive(Clone)]
pub struct AuthenticationCache {
    tx: mpsc::Sender<AuthenticationCommand>,
    /// Holds the spawned task's `JoinHandle` until [`terminate`](Self::terminate)
    /// awaits it. `Mutex<Option<...>>` rather than `RwLock` because contention
    /// is essentially zero (start once, terminate once).
    handle: Arc<Mutex<Option<JoinHandle<()>>>>,
    /// Inner state — moved into the spawned task at [`start`](Self::start)
    /// time. After `start`, this field is `None`.
    state: Arc<Mutex<Option<AuthenticationCacheInner>>>,
}

/// Inner state owned by the background task.
struct AuthenticationCacheInner {
    cache: Cache<u64, AuthenticationRecord, RandomState>,
    channel_rx: mpsc::Receiver<AuthenticationCommand>,
    did_resolver: DIDCacheClient,
    secrets_resolver: ThreadedSecretsResolver,
    client: Client,
    custom_handlers: Option<CustomAuthHandlers>,
}

/// MPSC commands consumed by the background authentication task.
///
/// Internal — `pub(crate)` because public methods on
/// [`AuthenticationCache`] (`authenticate`, `authenticated`, `invalidate`,
/// `terminate`) are the supported way to drive the cache.
pub(crate) enum AuthenticationCommand {
    /// Terminate the Authentication Task
    Terminate,

    /// Check if a DID is authenticated against a service.
    /// Will NOT authenticate if not already authenticated.
    Authenticated {
        profile_did: Arc<String>,
        service_endpoint_did: Arc<String>,
        tx: oneshot::Sender<Option<AuthorizationTokens>>,
    },

    /// Authenticate a DID against a service.
    Authenticate {
        profile_did: Arc<String>,
        service_endpoint_did: Arc<String>,
        retry_limit: u8,
        timeout: Duration,
        tx: oneshot::Sender<Result<AuthorizationTokens, DIDAuthError>>,
    },

    /// Invalidate (remove) an authentication entry.
    Invalidate {
        profile_did: Arc<String>,
        service_endpoint_did: Arc<String>,
    },
}

/// Authentication Record stored in the cache
#[derive(Clone)]
struct AuthenticationRecord {
    tokens: AuthorizationTokens,
    type_: AuthenticationType,
}

/// Sets up expiry for the AuthenticationRecord to expire when the refresh
/// token expires. Saturating-subtracts so a token whose refresh has already
/// passed is evicted immediately rather than panicking.
impl Expiry<u64, AuthenticationRecord> for AuthenticationRecord {
    fn expire_after_create(
        &self,
        _key: &u64,
        value: &AuthenticationRecord,
        _current_time: Instant,
    ) -> Option<Duration> {
        let refresh_at = Duration::from_secs(value.tokens.refresh_expires_at);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO);
        Some(refresh_at.saturating_sub(now))
    }
}

impl AuthenticationCache {
    /// Build a new [`AuthenticationCache`].
    ///
    /// # Arguments
    /// * `max_capacity` — maximum number of entries (≈ DIDs × services).
    /// * `did_resolver` — DID Resolver Cache Client.
    /// * `secrets_resolver` — `SecretsResolver`.
    /// * `client` — `reqwest::Client`.
    /// * `custom_handlers` — optional custom authentication handlers.
    pub fn new(
        max_capacity: u64,
        did_resolver: &DIDCacheClient,
        secrets_resolver: ThreadedSecretsResolver,
        client: &Client,
        custom_handlers: Option<CustomAuthHandlers>,
    ) -> Self {
        let (tx, rx) = mpsc::channel(COMMAND_CHANNEL_CAPACITY);

        let expiry_template = AuthenticationRecord {
            tokens: AuthorizationTokens::default(),
            type_: AuthenticationType::Unknown,
        };
        let cache = CacheBuilder::new(max_capacity)
            .expire_after(expiry_template)
            .build_with_hasher(ahash::RandomState::default());

        let inner = AuthenticationCacheInner {
            cache,
            channel_rx: rx,
            did_resolver: did_resolver.clone(),
            secrets_resolver,
            client: client.clone(),
            custom_handlers,
        };

        AuthenticationCache {
            tx,
            handle: Arc::new(Mutex::new(None)),
            state: Arc::new(Mutex::new(Some(inner))),
        }
    }

    /// Spawn the background task. Idempotent — if the task is already running
    /// the call is a no-op. Synchronous because no async work happens here;
    /// the spawned task runs concurrently.
    pub fn start(&self) {
        let inner = match self.state.lock() {
            Ok(mut guard) => guard.take(),
            Err(_) => return,
        };
        let Some(inner) = inner else { return };
        let handle = tokio::spawn(run(inner));
        if let Ok(mut slot) = self.handle.lock() {
            *slot = Some(handle);
        }
    }

    /// Send a Terminate command and wait for the background task to exit.
    pub async fn terminate(&self) {
        let _ = self.tx.send(AuthenticationCommand::Terminate).await;
        let handle = self.handle.lock().ok().and_then(|mut slot| slot.take());
        if let Some(h) = handle {
            let _ = h.await;
        }
    }

    /// Check whether `(profile_did, service_endpoint_did)` is currently
    /// authenticated. Does not initiate a fresh handshake.
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
                warn!("Authentication task channel closed unexpectedly");
                return None;
            }
            Err(TrySendError::Full(_)) => {
                warn!(
                    "Authentication task channel full (capacity {})",
                    COMMAND_CHANNEL_CAPACITY
                );
                return None;
            }
        }

        let timeout = tokio::time::sleep(AUTHENTICATED_QUERY_TIMEOUT);
        tokio::pin!(timeout);

        tokio::select! {
            _ = &mut timeout => {
                warn!("Timeout reached during authenticated() check");
                None
            }
            value = rx => match value {
                Ok(tokens) => tokens,
                Err(_) => {
                    warn!("Authentication task closed the response channel");
                    None
                }
            },
        }
    }

    /// Authenticate `profile_did` against `service_endpoint_did`. If a valid
    /// cached record exists and is not due for refresh, returns it directly.
    /// Otherwise runs a fresh DID Auth handshake (or a refresh if the access
    /// token has expired but the refresh token is still valid).
    ///
    /// # Arguments
    /// * `profile_did` — DID of the Profile.
    /// * `service_endpoint_did` — DID of the Service Endpoint.
    /// * `retry_limit` — How many times to retry the authentication.
    /// * `timeout` — Optional override; defaults to [`DEFAULT_AUTH_TIMEOUT`].
    pub async fn authenticate(
        &self,
        profile_did: String,
        service_endpoint_did: String,
        retry_limit: u8,
        timeout: Option<Duration>,
    ) -> Result<AuthorizationTokens, DIDAuthError> {
        let timeout = timeout.unwrap_or(DEFAULT_AUTH_TIMEOUT);
        let (tx, rx) = oneshot::channel();
        match self.tx.try_send(AuthenticationCommand::Authenticate {
            profile_did: Arc::new(profile_did),
            service_endpoint_did: Arc::new(service_endpoint_did),
            retry_limit,
            timeout,
            tx,
        }) {
            Ok(_) => {}
            Err(TrySendError::Closed(_)) => {
                warn!("Authentication task channel closed unexpectedly");
                return Err(DIDAuthError::AuthenticationAbort(
                    "Authentication Task channel closed unexpectedly".to_string(),
                ));
            }
            Err(TrySendError::Full(_)) => {
                warn!(
                    "Authentication task channel full (capacity {})",
                    COMMAND_CHANNEL_CAPACITY
                );
                return Err(DIDAuthError::AuthenticationAbort(
                    "Authentication Task channel full".to_string(),
                ));
            }
        }

        let sleep = tokio::time::sleep(timeout);
        tokio::pin!(sleep);

        tokio::select! {
            value = rx => match value {
                Ok(tokens) => tokens,
                Err(_) => Err(DIDAuthError::AuthenticationAbort(
                    "Authentication Task channel closed unexpectedly".to_string(),
                )),
            },
            _ = &mut sleep => {
                warn!("Timeout reached during authenticate()");
                Err(DIDAuthError::AuthenticationAbort("Timeout reached".to_string()))
            }
        }
    }

    /// Convenience helper using [`DEFAULT_AUTH_RETRIES`] and the default
    /// timeout. Equivalent to `authenticate(p, s, DEFAULT_AUTH_RETRIES, None)`.
    pub async fn authenticate_default(
        &self,
        profile_did: String,
        service_endpoint_did: String,
    ) -> Result<AuthorizationTokens, DIDAuthError> {
        self.authenticate(
            profile_did,
            service_endpoint_did,
            DEFAULT_AUTH_RETRIES,
            None,
        )
        .await
    }

    /// Send an Invalidate command for the given pair, dropping any cached
    /// tokens. Best-effort — failures to enqueue are logged.
    pub async fn invalidate(&self, profile_did: String, service_endpoint_did: String) {
        if let Err(e) = self
            .tx
            .send(AuthenticationCommand::Invalidate {
                profile_did: Arc::new(profile_did),
                service_endpoint_did: Arc::new(service_endpoint_did),
            })
            .await
        {
            warn!(error = %e, "Failed to send Invalidate command");
        }
    }
}

/// Background task entry point. Owns `inner` for its lifetime — when this
/// future completes, the task exits.
async fn run(mut inner: AuthenticationCacheInner) {
    loop {
        tokio::select! {
            msg = inner.channel_rx.recv() => {
                if inner.handle_channel(msg).await {
                    break;
                }
            }
        }
    }
    debug!("Exiting Authentication Task");
}

impl AuthenticationCacheInner {
    /// Returns `true` when the task should exit.
    async fn handle_channel(&self, cmd: Option<AuthenticationCommand>) -> bool {
        match cmd {
            Some(AuthenticationCommand::Terminate) => {
                debug!("Terminating Authentication Task");
                true
            }
            Some(AuthenticationCommand::Authenticated {
                profile_did,
                service_endpoint_did,
                tx,
            }) => {
                let key = hash(&profile_did, &service_endpoint_did);
                let result = self.cache.get(&key).await.map(|r| r.tokens);
                debug!(
                    profile = %profile_did,
                    service = %service_endpoint_did,
                    cached = result.is_some(),
                    "checked authentication state"
                );
                let _ = tx.send(result);
                false
            }
            Some(AuthenticationCommand::Authenticate {
                profile_did,
                service_endpoint_did,
                tx,
                retry_limit,
                timeout,
            }) => {
                self.handle_authenticate(
                    profile_did,
                    service_endpoint_did,
                    retry_limit,
                    timeout,
                    tx,
                )
                .await;
                false
            }
            Some(AuthenticationCommand::Invalidate {
                profile_did,
                service_endpoint_did,
            }) => {
                let key = hash(&profile_did, &service_endpoint_did);
                debug!(
                    profile = %profile_did,
                    service = %service_endpoint_did,
                    %key,
                    "invalidating authentication record"
                );
                self.cache.invalidate(&key).await;
                false
            }
            None => {
                warn!("Authentication Task channel closed unexpectedly");
                true
            }
        }
    }

    async fn handle_authenticate(
        &self,
        profile_did: Arc<String>,
        service_endpoint_did: Arc<String>,
        retry_limit: u8,
        timeout: Duration,
        tx: oneshot::Sender<Result<AuthorizationTokens, DIDAuthError>>,
    ) {
        let key = hash(&profile_did, &service_endpoint_did);
        debug!(
            profile = %profile_did,
            service = %service_endpoint_did,
            "authenticating"
        );

        let mut auth = if let Some(record) = self.cache.get(&key).await {
            match refresh_check(&record.tokens) {
                RefreshCheck::Ok => {
                    debug!("Cached tokens valid; returning");
                    let _ = tx.send(Ok(record.tokens));
                    return;
                }
                RefreshCheck::Refresh => {
                    debug!("Refresh needed");
                    DIDAuthentication {
                        type_: record.type_,
                        tokens: Some(record.tokens.clone()),
                        authenticated: true,
                        custom_handlers: self.custom_handlers.clone(),
                    }
                }
                RefreshCheck::Expired => {
                    debug!("Tokens expired; running fresh authentication");
                    DIDAuthentication::new().with_custom_handlers(self.custom_handlers.clone())
                }
            }
        } else {
            DIDAuthentication::new().with_custom_handlers(self.custom_handlers.clone())
        };

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

        let sleep = tokio::time::sleep(timeout);
        tokio::pin!(sleep);

        tokio::select! {
            value = handle => {
                match value {
                    Ok(Ok(auth)) => {
                        if let Some(tokens) = &auth.tokens {
                            self.cache
                                .insert(
                                    key,
                                    AuthenticationRecord { tokens: tokens.clone(), type_: auth.type_ },
                                )
                                .await;
                            let _ = tx.send(Ok(tokens.clone()));
                        } else {
                            let _ = tx.send(Err(DIDAuthError::AuthenticationAbort(
                                "Internal Error: Authenticated ok, but no tokens".to_string(),
                            )));
                        }
                    }
                    Ok(Err(e)) => {
                        warn!(profile = %profile_did, service = %service_endpoint_did, error = %e, "authentication failed");
                        let _ = tx.send(Err(e));
                    }
                    Err(e) => {
                        warn!(profile = %profile_did, service = %service_endpoint_did, error = %e, "join error on authentication task");
                        let _ = tx.send(Err(DIDAuthError::AuthenticationAbort(format!(
                            "JoinHandle error on spawned authentication task: {e}"
                        ))));
                    }
                }
            }
            _ = &mut sleep => {
                warn!("Timeout reached during authentication");
                let _ = tx.send(Err(DIDAuthError::AuthenticationAbort("Timeout reached".to_string())));
            }
        }
    }
}

/// Hash key for the auth cache. Writes both DIDs through the hasher with a
/// length-prefix between them, avoiding the "ab|c" vs "a|bc" collision class
/// without allocating an intermediate string.
fn hash(profile_did: &str, service_endpoint_did: &str) -> u64 {
    let mut hasher = AHasher::default();
    hasher.write(profile_did.as_bytes());
    // length-prefix delimiter to disambiguate concatenations
    hasher.write_u64(profile_did.len() as u64);
    hasher.write(service_endpoint_did.as_bytes());
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_did_authentication::{AuthenticationType, AuthorizationTokens};
    use moka::future::CacheBuilder;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    /// Cache evicts entries once the refresh-token expiry is reached. Uses
    /// real time because `moka` reads `std::time::Instant`; ~2 seconds.
    #[tokio::test]
    async fn cache_expires_at_refresh_token_lifetime() {
        let template = AuthenticationRecord {
            tokens: AuthorizationTokens::default(),
            type_: AuthenticationType::Unknown,
        };
        let cache = CacheBuilder::new(1)
            .expire_after(template)
            .build_with_hasher(ahash::RandomState::default());

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        cache
            .insert(
                1,
                AuthenticationRecord {
                    tokens: AuthorizationTokens {
                        access_token: "access".into(),
                        access_expires_at: now.as_secs() + 1,
                        refresh_token: "refresh".into(),
                        refresh_expires_at: now.as_secs() + 1,
                    },
                    type_: AuthenticationType::Unknown,
                },
            )
            .await;
        assert!(cache.contains_key(&1));

        tokio::time::sleep(Duration::from_secs(2)).await;
        cache.run_pending_tasks().await;

        assert!(!cache.contains_key(&1));
        assert!(cache.get(&1).await.is_none());
    }

    /// `expire_after_create` returns ZERO instead of panicking when the
    /// refresh token is already expired (regression test for #SECURITY-2).
    #[test]
    fn expire_after_create_handles_already_expired() {
        let template = AuthenticationRecord {
            tokens: AuthorizationTokens::default(),
            type_: AuthenticationType::Unknown,
        };
        let already_expired = AuthenticationRecord {
            tokens: AuthorizationTokens {
                access_token: "a".into(),
                access_expires_at: 1, // 1970
                refresh_token: "r".into(),
                refresh_expires_at: 1,
            },
            type_: AuthenticationType::Unknown,
        };
        let ttl = template.expire_after_create(&0u64, &already_expired, Instant::now());
        assert_eq!(ttl, Some(Duration::ZERO));
    }

    /// Hash is deterministic and order-sensitive.
    #[test]
    fn hash_is_order_sensitive() {
        let h1 = hash("did:a", "did:b");
        let h2 = hash("did:b", "did:a");
        let h3 = hash("did:a", "did:b");
        assert_eq!(h1, h3);
        assert_ne!(h1, h2);
    }

    /// Length-prefix prevents collisions of pathological concatenations.
    #[test]
    fn hash_avoids_concat_collision() {
        // "ab"+"c" vs "a"+"bc" must not collide.
        let h_ab_c = hash("ab", "c");
        let h_a_bc = hash("a", "bc");
        assert_ne!(h_ab_c, h_a_bc);
    }
}
