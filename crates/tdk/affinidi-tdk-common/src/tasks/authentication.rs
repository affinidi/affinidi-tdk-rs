/*!
 * Authentication credentials cache and wrapper for DID Authentication.
 *
 * Enables a TDK Profile to authenticate using its DID and secrets to other
 * services that accept DID Auth. The cache is shared across all profiles in
 * the host process and is driven by a background task reading an MPSC
 * command channel.
 *
 * The task answers cheap commands (is this pair authenticated? forget this
 * pair) itself, and runs each authentication in a task of its own, so one
 * slow service does not hold up the others. Concurrent requests for the same
 * pair share one authentication.
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
    collections::HashMap,
    hash::Hasher,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    sync::{mpsc, oneshot},
    task::{JoinHandle, JoinSet},
};
use tracing::{debug, warn};

/// MPSC channel buffer size for [`AuthenticationCommand`]. The task reads the
/// channel without waiting on any authentication, so it drains quickly; a
/// caller that finds it full waits for room within its own timeout.
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
    channel_rx: mpsc::Receiver<AuthenticationCommand>,
    authenticator: Arc<Authenticator>,
}

/// What an authentication needs, shared by the task and every authentication
/// it runs.
struct Authenticator {
    cache: Cache<u64, AuthenticationRecord, RandomState>,
    did_resolver: DIDCacheClient,
    secrets_resolver: ThreadedSecretsResolver,
    client: Client,
    custom_handlers: Option<CustomAuthHandlers>,
    allow_insecure_http_endpoints: bool,
}

type AuthResponder = oneshot::Sender<Result<AuthorizationTokens, DIDAuthError>>;

/// Authentications in progress, by (pair, forced refresh), with every caller
/// waiting on each.
type Inflight = Arc<Mutex<HashMap<(u64, bool), Vec<AuthResponder>>>>;

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
        /// Force a token refresh even when the cached access token is still
        /// within its validity window (used for proactive refresh ahead of
        /// expiry). Falls back to a full handshake only if the refresh token
        /// has itself expired.
        force_refresh: bool,
        tx: AuthResponder,
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

fn task_unavailable() -> DIDAuthError {
    DIDAuthError::TaskUnavailable(
        "the authentication task is not running (terminated, or never started)".to_string(),
    )
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
    ///
    /// The `#auth` endpoint of a target DID must pass
    /// [`check_service_endpoint`](crate::check_service_endpoint) with
    /// `allow_insecure_http = false`; use
    /// [`with_endpoint_policy`](Self::with_endpoint_policy) to choose.
    pub fn new(
        max_capacity: u64,
        did_resolver: &DIDCacheClient,
        secrets_resolver: ThreadedSecretsResolver,
        client: &Client,
        custom_handlers: Option<CustomAuthHandlers>,
    ) -> Self {
        Self::with_endpoint_policy(
            max_capacity,
            did_resolver,
            secrets_resolver,
            client,
            custom_handlers,
            false,
        )
    }

    /// [`new`](Self::new), choosing whether a target DID's `#auth` endpoint
    /// may be `http://` on a non-loopback host (see
    /// [`check_service_endpoint`](crate::check_service_endpoint)).
    pub fn with_endpoint_policy(
        max_capacity: u64,
        did_resolver: &DIDCacheClient,
        secrets_resolver: ThreadedSecretsResolver,
        client: &Client,
        custom_handlers: Option<CustomAuthHandlers>,
        allow_insecure_http_endpoints: bool,
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
            channel_rx: rx,
            authenticator: Arc::new(Authenticator {
                cache,
                did_resolver: did_resolver.clone(),
                secrets_resolver,
                client: client.clone(),
                custom_handlers,
                allow_insecure_http_endpoints,
            }),
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
    /// Authentications still in progress are cancelled; their callers get
    /// [`DIDAuthError::TaskUnavailable`].
    pub async fn terminate(&self) {
        let _ = self.tx.send(AuthenticationCommand::Terminate).await;
        let handle = self.handle.lock().ok().and_then(|mut slot| slot.take());
        if let Some(h) = handle {
            let _ = h.await;
        }
    }

    /// Check whether `(profile_did, service_endpoint_did)` is currently
    /// authenticated. Does not initiate a fresh handshake.
    ///
    /// `None` when the pair is not authenticated, and also when the task does
    /// not answer within [`AUTHENTICATED_QUERY_TIMEOUT`] (logged).
    pub async fn authenticated(
        &self,
        profile_did: String,
        service_endpoint_did: String,
    ) -> Option<AuthorizationTokens> {
        let (tx, rx) = oneshot::channel();
        let command = AuthenticationCommand::Authenticated {
            profile_did: Arc::new(profile_did),
            service_endpoint_did: Arc::new(service_endpoint_did),
            tx,
        };
        let exchange = async {
            self.tx.send(command).await.ok()?;
            rx.await.ok()
        };
        match tokio::time::timeout(AUTHENTICATED_QUERY_TIMEOUT, exchange).await {
            Ok(Some(tokens)) => tokens,
            Ok(None) => {
                warn!("Authentication task is not running; authenticated() answers None");
                None
            }
            Err(_) => {
                warn!("Timeout reached during authenticated() check");
                None
            }
        }
    }

    /// Authenticate `profile_did` against `service_endpoint_did`. If a valid
    /// cached record exists and is not due for refresh, returns it directly.
    /// Otherwise runs a fresh DID Auth handshake (or a refresh if the access
    /// token has expired but the refresh token is still valid).
    ///
    /// Concurrent calls for the same pair share one handshake; calls for
    /// different pairs run concurrently. The handshake is bounded by the
    /// `timeout` of the call that started it, and cancelled when it runs out.
    ///
    /// # Arguments
    /// * `profile_did` — DID of the Profile.
    /// * `service_endpoint_did` — DID of the Service Endpoint.
    /// * `retry_limit` — How many times to retry the authentication.
    /// * `timeout` — Optional override; defaults to [`DEFAULT_AUTH_TIMEOUT`].
    ///
    /// # Errors
    /// [`DIDAuthError::Timeout`] when no result arrives within `timeout`
    /// (from handing the request to the task to its answer);
    /// [`DIDAuthError::TaskUnavailable`] when the task is not running; or the
    /// authentication's own error.
    pub async fn authenticate(
        &self,
        profile_did: String,
        service_endpoint_did: String,
        retry_limit: u8,
        timeout: Option<Duration>,
    ) -> Result<AuthorizationTokens, DIDAuthError> {
        self.request_authentication(
            profile_did,
            service_endpoint_did,
            retry_limit,
            timeout.unwrap_or(DEFAULT_AUTH_TIMEOUT),
            false,
        )
        .await
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

    /// Force a token refresh for the given pair, regardless of whether the
    /// cached access token is still within its validity window.
    ///
    /// This drives the refresh-token flow (a fresh access token is minted from
    /// the still-valid refresh token, with the mediator re-checking that the
    /// DID is still allowed to connect); it falls back to a full handshake only
    /// if the refresh token has itself expired or there is no cached record.
    ///
    /// Used for *proactive* refresh ahead of expiry (e.g. a long-lived
    /// WebSocket that must reconnect with a fresh token before the server
    /// closes the socket at token expiry). After this returns, a subsequent
    /// [`authenticate`](Self::authenticate) returns the freshly cached token.
    pub async fn refresh(
        &self,
        profile_did: String,
        service_endpoint_did: String,
    ) -> Result<AuthorizationTokens, DIDAuthError> {
        self.request_authentication(
            profile_did,
            service_endpoint_did,
            DEFAULT_AUTH_RETRIES,
            DEFAULT_AUTH_TIMEOUT,
            true,
        )
        .await
    }

    /// Hand an authentication to the task and wait for its result, all within
    /// `timeout`.
    async fn request_authentication(
        &self,
        profile_did: String,
        service_endpoint_did: String,
        retry_limit: u8,
        timeout: Duration,
        force_refresh: bool,
    ) -> Result<AuthorizationTokens, DIDAuthError> {
        let (tx, rx) = oneshot::channel();
        let command = AuthenticationCommand::Authenticate {
            profile_did: Arc::new(profile_did.clone()),
            service_endpoint_did: Arc::new(service_endpoint_did.clone()),
            retry_limit,
            timeout,
            force_refresh,
            tx,
        };
        let exchange = async {
            self.tx
                .send(command)
                .await
                .map_err(|_| task_unavailable())?;
            rx.await.map_err(|_| task_unavailable())?
        };
        match tokio::time::timeout(timeout, exchange).await {
            Ok(result) => result,
            Err(_) => {
                warn!(
                    profile = %profile_did,
                    service = %service_endpoint_did,
                    "Timeout reached during authentication"
                );
                Err(DIDAuthError::Timeout(format!(
                    "{profile_did} to {service_endpoint_did}: no result within {timeout:?}"
                )))
            }
        }
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
/// future completes, the task exits, cancelling the authentications still in
/// progress.
async fn run(mut inner: AuthenticationCacheInner) {
    let inflight: Inflight = Arc::default();
    let mut authentications = JoinSet::new();
    loop {
        tokio::select! {
            command = inner.channel_rx.recv() => {
                if inner.handle_command(command, &inflight, &mut authentications).await {
                    break;
                }
            }
            Some(finished) = authentications.join_next(), if !authentications.is_empty() => {
                if let Err(e) = finished {
                    warn!(error = %e, "authentication task failed");
                }
            }
        }
    }
    authentications.shutdown().await;
    debug!("Exiting Authentication Task");
}

impl AuthenticationCacheInner {
    /// Returns `true` when the task should exit.
    async fn handle_command(
        &self,
        command: Option<AuthenticationCommand>,
        inflight: &Inflight,
        authentications: &mut JoinSet<()>,
    ) -> bool {
        match command {
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
                let result = self.authenticator.cache.get(&key).await.map(|r| r.tokens);
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
                force_refresh,
            }) => {
                let key = hash(&profile_did, &service_endpoint_did);
                let flight = (key, force_refresh);
                {
                    let Ok(mut waiting) = inflight.lock() else {
                        let _ = tx.send(Err(task_unavailable()));
                        return false;
                    };
                    if let Some(waiters) = waiting.get_mut(&flight) {
                        debug!(
                            profile = %profile_did,
                            service = %service_endpoint_did,
                            "joining the authentication in progress"
                        );
                        waiters.push(tx);
                        return false;
                    }
                    waiting.insert(flight, vec![tx]);
                }

                let authenticator = self.authenticator.clone();
                let inflight = inflight.clone();
                authentications.spawn(async move {
                    // Dropping the authentication on timeout cancels it: it
                    // does not go on retrying in the background.
                    let result = match tokio::time::timeout(
                        timeout,
                        authenticator.authenticate(
                            key,
                            &profile_did,
                            &service_endpoint_did,
                            retry_limit,
                            force_refresh,
                        ),
                    )
                    .await
                    {
                        Ok(result) => result,
                        Err(_) => {
                            warn!(
                                profile = %profile_did,
                                service = %service_endpoint_did,
                                "authentication did not finish within {timeout:?}; cancelled"
                            );
                            Err(DIDAuthError::Timeout(format!(
                                "{profile_did} to {service_endpoint_did}: authentication did \
                                 not finish within {timeout:?}"
                            )))
                        }
                    };
                    let waiters = inflight
                        .lock()
                        .ok()
                        .and_then(|mut waiting| waiting.remove(&flight))
                        .unwrap_or_default();
                    for waiter in waiters {
                        let _ = waiter.send(result.clone());
                    }
                });
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
                self.authenticator.cache.invalidate(&key).await;
                false
            }
            None => {
                warn!("Authentication Task channel closed unexpectedly");
                true
            }
        }
    }
}

impl Authenticator {
    /// Authenticate the pair: the cached tokens when still good, else a
    /// refresh or a full handshake, whose tokens are cached.
    async fn authenticate(
        &self,
        key: u64,
        profile_did: &str,
        service_endpoint_did: &str,
        retry_limit: u8,
        force_refresh: bool,
    ) -> Result<AuthorizationTokens, DIDAuthError> {
        debug!(
            profile = %profile_did,
            service = %service_endpoint_did,
            force_refresh,
            "authenticating"
        );

        let mut auth = if let Some(record) = self.cache.get(&key).await {
            // `force_refresh` skips the "still valid → return cached" path and
            // forces a refresh, but still degrades to a full handshake if the
            // refresh token has itself expired.
            let check = if force_refresh {
                match refresh_check(&record.tokens) {
                    RefreshCheck::Expired => RefreshCheck::Expired,
                    _ => RefreshCheck::Refresh,
                }
            } else {
                refresh_check(&record.tokens)
            };
            match check {
                RefreshCheck::Ok => {
                    debug!("Cached tokens valid; returning");
                    return Ok(record.tokens);
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

        check_auth_endpoint(
            service_endpoint_did,
            &self.did_resolver,
            self.allow_insecure_http_endpoints,
        )
        .await?;

        // A forced refresh has to say so. `authenticate` re-derives the
        // decision from the token's expiry and refreshes only inside the last
        // five seconds of its life — which is never true of a *proactive*
        // refresh, whose whole point is to run while the token is still good.
        // Asking through `authenticate` therefore returned the same token, and
        // the caller acted on a refresh that had not happened; a transport
        // that rebuilds its connection to carry the new token then rebuilt it
        // onto the old one, over and over, until the token actually expired.
        //
        // A failure here is not fatal: fall through to the full handshake
        // below, which is what an expired refresh token needs anyway.
        let refreshed = force_refresh
            && auth
                .refresh_tokens(
                    profile_did,
                    service_endpoint_did,
                    &self.did_resolver,
                    &self.secrets_resolver,
                    &self.client,
                )
                .await
                .is_ok();
        if !refreshed
            && let Err(e) = auth
                .authenticate(
                    profile_did,
                    service_endpoint_did,
                    &self.did_resolver,
                    &self.secrets_resolver,
                    &self.client,
                    retry_limit as i32,
                )
                .await
        {
            warn!(profile = %profile_did, service = %service_endpoint_did, error = %e, "authentication failed");
            return Err(e);
        }

        let Some(tokens) = auth.tokens else {
            return Err(DIDAuthError::AuthenticationAbort(
                "Internal Error: Authenticated ok, but no tokens".to_string(),
            ));
        };
        self.cache
            .insert(
                key,
                AuthenticationRecord {
                    tokens: tokens.clone(),
                    type_: auth.type_,
                },
            )
            .await;
        Ok(tokens)
    }
}

/// Refuse to authenticate against a target DID whose `#auth` service endpoint
/// fails [`check_service_endpoint`](crate::check_service_endpoint): the
/// challenge response and refresh token would be sent there.
///
/// A target that is not a DID, or a DID without an `#auth` service, is left to
/// the authentication flow (a custom handler may not use `#auth` at all).
async fn check_auth_endpoint(
    service_endpoint_did: &str,
    did_resolver: &DIDCacheClient,
    allow_insecure_http: bool,
) -> Result<(), DIDAuthError> {
    if !service_endpoint_did.starts_with("did:") {
        return Ok(());
    }
    let resolved = did_resolver.resolve(service_endpoint_did).await?;
    let Some(endpoint) = DIDAuthentication::find_service_endpoint(&resolved.doc) else {
        return Ok(());
    };
    crate::check_service_endpoint(&endpoint, allow_insecure_http).map_err(|e| {
        DIDAuthError::AuthenticationAbort(format!(
            "{service_endpoint_did}: refusing to authenticate: {e}"
        ))
    })
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

    /// The task side of the cache, driven by a custom authentication handler
    /// so no service is needed: a target ending in `slow` takes `SLOW`, one
    /// ending in `hang` never finishes, anything else answers at once.
    mod concurrency {
        use super::super::*;
        use affinidi_did_authentication::{CustomAuthHandler, CustomAuthHandlers};
        use affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder;
        use std::{
            future::Future,
            pin::Pin,
            sync::atomic::{AtomicUsize, Ordering},
        };

        const SLOW: Duration = Duration::from_secs(3);

        #[derive(Default)]
        struct Handler {
            calls: AtomicUsize,
            cancelled: Arc<AtomicUsize>,
        }

        /// Counts a handshake dropped before it finished.
        struct CancelGuard(Arc<AtomicUsize>);

        impl Drop for CancelGuard {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        fn tokens() -> AuthorizationTokens {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            AuthorizationTokens {
                access_token: "access".into(),
                access_expires_at: now + 3600,
                refresh_token: "refresh".into(),
                refresh_expires_at: now + 7200,
            }
        }

        impl CustomAuthHandler for Handler {
            fn authenticate<'a>(
                &'a self,
                _profile_did: &'a str,
                endpoint_did: &'a str,
                _did_resolver: &'a DIDCacheClient,
                _client: &'a Client,
            ) -> Pin<Box<dyn Future<Output = Result<AuthorizationTokens, DIDAuthError>> + Send + 'a>>
            {
                self.calls.fetch_add(1, Ordering::SeqCst);
                let cancelled = self.cancelled.clone();
                Box::pin(async move {
                    if endpoint_did.ends_with("hang") {
                        let guard = CancelGuard(cancelled);
                        std::future::pending::<()>().await;
                        std::mem::forget(guard);
                    } else if endpoint_did.ends_with("slow") {
                        tokio::time::sleep(SLOW).await;
                    }
                    Ok(tokens())
                })
            }
        }

        async fn cache(handler: Arc<Handler>) -> AuthenticationCache {
            let resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
                .await
                .unwrap();
            let (secrets, _task) = ThreadedSecretsResolver::new(None).await;
            let cache = AuthenticationCache::new(
                100,
                &resolver,
                secrets,
                &Client::new(),
                Some(CustomAuthHandlers::new().with_auth_handler(handler)),
            );
            cache.start();
            cache
        }

        /// One slow service no longer holds up authentication to the others,
        /// nor the `authenticated()` probe.
        #[tokio::test]
        async fn a_slow_authentication_does_not_hold_up_the_others() {
            let handler = Arc::new(Handler::default());
            let cache = cache(handler.clone()).await;

            let slow = {
                let cache = cache.clone();
                tokio::spawn(async move {
                    cache
                        .authenticate(
                            "did:example:alice".into(),
                            "https://slow".into(),
                            1,
                            Some(Duration::from_secs(10)),
                        )
                        .await
                })
            };
            tokio::time::sleep(Duration::from_millis(100)).await;

            let started = std::time::Instant::now();
            cache
                .authenticate_default("did:example:alice".into(), "https://fast".into())
                .await
                .expect("the fast service authenticates");
            assert!(
                cache
                    .authenticated("did:example:alice".into(), "https://fast".into())
                    .await
                    .is_some()
            );
            assert!(started.elapsed() < SLOW / 2, "{:?}", started.elapsed());

            slow.await
                .unwrap()
                .expect("the slow service authenticates too");
        }

        /// Concurrent requests for one pair share one handshake.
        #[tokio::test]
        async fn concurrent_requests_for_one_pair_share_one_handshake() {
            let handler = Arc::new(Handler::default());
            let cache = cache(handler.clone()).await;

            let mut requests = Vec::new();
            for _ in 0..10 {
                let cache = cache.clone();
                requests.push(tokio::spawn(async move {
                    cache
                        .authenticate(
                            "did:example:alice".into(),
                            "https://slow".into(),
                            1,
                            Some(Duration::from_secs(10)),
                        )
                        .await
                }));
            }
            for request in requests {
                request.await.unwrap().expect("authenticated");
            }
            assert_eq!(handler.calls.load(Ordering::SeqCst), 1);

            // And the result is cached.
            cache
                .authenticate_default("did:example:alice".into(), "https://slow".into())
                .await
                .unwrap();
            assert_eq!(handler.calls.load(Ordering::SeqCst), 1);
        }

        /// A handshake that outlives its timeout is cancelled, not left to
        /// run on, and the caller is told it timed out.
        #[tokio::test]
        async fn a_timed_out_authentication_is_cancelled() {
            let handler = Arc::new(Handler::default());
            let cancelled = handler.cancelled.clone();
            let cache = cache(handler.clone()).await;

            let err = cache
                .authenticate(
                    "did:example:alice".into(),
                    "https://hang".into(),
                    1,
                    Some(Duration::from_millis(200)),
                )
                .await
                .expect_err("never finishes");
            assert!(matches!(err, DIDAuthError::Timeout(_)), "{err:?}");
            assert!(err.is_retryable());

            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while cancelled.load(Ordering::SeqCst) == 0 {
                assert!(
                    std::time::Instant::now() < deadline,
                    "the handshake was not cancelled"
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }

        /// After `terminate`, a request is told the task is gone.
        #[tokio::test]
        async fn a_terminated_cache_reports_the_task_unavailable() {
            let cache = cache(Arc::new(Handler::default())).await;
            cache.terminate().await;
            let err = cache
                .authenticate_default("did:example:alice".into(), "https://fast".into())
                .await
                .expect_err("terminated");
            assert!(matches!(err, DIDAuthError::TaskUnavailable(_)), "{err:?}");
        }
    }
}
