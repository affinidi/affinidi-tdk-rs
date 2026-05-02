/*!
# affinidi-tdk-common

Shared building blocks for Affinidi Trust Development Kit (TDK) crates.

The crate is organised around four core concepts:

- **[`TDKConfig`]** ([`config`]) — typed configuration with a builder. Owns the
  optional DID resolver, secrets resolver, environment-file path, and custom
  authentication handlers used by the rest of the stack.
- **[`TDKSharedState`]** — the runtime container that other Affinidi crates take
  by reference. It bundles the DID resolver, secrets resolver, HTTPS client, and
  the [`AuthenticationCache`](tasks::authentication::AuthenticationCache).
  Subsystems are exposed via accessors (e.g. [`TDKSharedState::client`]) rather
  than public fields, so the internal layout can evolve without breaking
  consumers.
- **[`TDKProfile`]** + **[`TDKEnvironment`]** ([`profiles`], [`environments`]) —
  serialisable identity profiles and the on-disk format for grouping profiles
  by environment (local / dev / prod).
- **[`KeyringStore`](secrets::KeyringStore)** ([`secrets`]) — handle into the
  OS native credential store (macOS Keychain, Windows Credential Manager,
  freedesktop Secret Service) for persisting profile secrets.

Errors are funneled through [`TDKError`]; consumers convert it to their own
error types via `From<TDKError>` impls.
*/

use std::sync::OnceLock;

use affinidi_did_authentication::{AuthorizationTokens, errors::DIDAuthError};
use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use affinidi_secrets_resolver::{SecretsResolver, ThreadedSecretsResolver};
use config::TDKConfig;
use environments::{TDKEnvironment, TDKEnvironments};
use errors::TDKError;
use profiles::TDKProfile;
use reqwest::Client;
use rustls::ClientConfig;
use rustls_platform_verifier::ConfigVerifierExt;
use tracing::warn;

pub mod config;
pub mod environments;
pub mod errors;
pub mod profiles;
pub mod secrets;
pub mod tasks;

pub use affinidi_secrets_resolver as secrets_resolver;
use tasks::authentication::AuthenticationCache;

/// Runtime state shared across Affinidi TDK crates.
///
/// Construct with [`TDKSharedState::new`]. Subsystems are exposed via accessor
/// methods rather than public fields so internals can evolve without a
/// breaking change. Cloning is cheap — every subsystem is internally
/// reference-counted.
#[derive(Clone)]
pub struct TDKSharedState {
    pub(crate) config: TDKConfig,
    pub(crate) did_resolver: DIDCacheClient,
    pub(crate) secrets_resolver: ThreadedSecretsResolver,
    pub(crate) client: Client,
    pub(crate) environment: TDKEnvironment,
    pub(crate) authentication: AuthenticationCache,
}

/// Build a reusable HTTP/HTTPS [`Client`] backed by `rustls` with the platform
/// trust verifier.
///
/// Installs `rustls`'s `aws-lc-rs` crypto provider as the process default
/// exactly once via [`OnceLock`] — repeated calls are a no-op.
///
/// # Errors
///
/// Returns [`TDKError::Config`] if the platform TLS verifier or the
/// [`reqwest::Client`] cannot be constructed.
pub fn create_http_client() -> Result<Client, TDKError> {
    static CRYPTO_INIT: OnceLock<()> = OnceLock::new();
    CRYPTO_INIT.get_or_init(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });

    let tls_config = ClientConfig::with_platform_verifier()
        .map_err(|e| TDKError::Config(format!("rustls platform verifier init failed: {e}")))?;
    reqwest::ClientBuilder::new()
        .use_rustls_tls()
        .use_preconfigured_tls(tls_config)
        .user_agent(format!(
            "Affinidi Trust Development Kit {}",
            env!("CARGO_PKG_VERSION")
        ))
        .build()
        .map_err(|e| TDKError::Config(format!("HTTP client build failed: {e}")))
}

impl TDKSharedState {
    /// Build a new [`TDKSharedState`] from the supplied configuration.
    ///
    /// The DID resolver is selected in priority order:
    /// 1. `config.did_resolver` — a pre-built resolver instance
    /// 2. `config.did_resolver_config` — a custom resolver configuration
    /// 3. Default local-mode resolver
    ///
    /// The secrets resolver is similarly taken from config if present, else a
    /// fresh empty in-memory resolver is created.
    ///
    /// The [`AuthenticationCache`] task is spawned and runs until
    /// [`TDKSharedState::shutdown`] is called.
    ///
    /// # Errors
    ///
    /// Returns [`TDKError::Config`] if the DID resolver or HTTP client fails
    /// to initialise.
    pub async fn new(config: TDKConfig) -> Result<Self, TDKError> {
        let did_resolver = if let Some(resolver) = config.did_resolver.clone() {
            resolver
        } else {
            let resolver_config = config
                .did_resolver_config
                .clone()
                .unwrap_or_else(|| DIDCacheConfigBuilder::default().build());
            DIDCacheClient::new(resolver_config)
                .await
                .map_err(|e| TDKError::Config(format!("DID resolver init failed: {e}")))?
        };

        let secrets_resolver = if let Some(sr) = config.secrets_resolver.clone() {
            sr
        } else {
            let (sr, _) = ThreadedSecretsResolver::new(None).await;
            sr
        };

        let client = create_http_client()?;
        let environment = if config.load_environment {
            match TDKEnvironments::fetch_from_file(
                Some(&config.environment_path),
                &config.environment_name,
            ) {
                Ok(env) => env,
                Err(e) => {
                    warn!(
                        path = %config.environment_path,
                        name = %config.environment_name,
                        error = %e,
                        "environment-file load failed; falling back to default"
                    );
                    TDKEnvironment::default()
                }
            }
        } else {
            TDKEnvironment::default()
        };
        let authentication = AuthenticationCache::new(
            config.authentication_cache_limit as u64,
            &did_resolver,
            secrets_resolver.clone(),
            &client,
            config.custom_auth_handlers.clone(),
        );
        authentication.start();

        Ok(TDKSharedState {
            config,
            did_resolver,
            secrets_resolver,
            client,
            environment,
            authentication,
        })
    }

    /// Add a [`TDKProfile`]'s secrets to the shared `SecretsResolver`.
    pub async fn add_profile(&self, profile: &TDKProfile) {
        self.secrets_resolver.insert_vec(&profile.secrets).await;
    }

    /// Authenticate the given `profile` against `target_did` using the
    /// shared [`AuthenticationCache`] with default retry / timeout
    /// settings (see
    /// [`tasks::authentication::DEFAULT_AUTH_RETRIES`] /
    /// [`tasks::authentication::DEFAULT_AUTH_TIMEOUT`]).
    ///
    /// Returns cached tokens if a valid record exists; otherwise runs a
    /// fresh DID Auth handshake (or refresh, depending on token state).
    pub async fn authenticate_profile(
        &self,
        profile: &TDKProfile,
        target_did: &str,
    ) -> Result<AuthorizationTokens, DIDAuthError> {
        self.authentication
            .authenticate_default(profile.did.clone(), target_did.to_string())
            .await
    }

    /// Configuration this state was built from.
    pub fn config(&self) -> &TDKConfig {
        &self.config
    }

    /// DID resolver cache client.
    pub fn did_resolver(&self) -> &DIDCacheClient {
        &self.did_resolver
    }

    /// Threaded `SecretsResolver` (clone-cheap, internally `Arc`).
    pub fn secrets_resolver(&self) -> &ThreadedSecretsResolver {
        &self.secrets_resolver
    }

    /// Shared HTTP/HTTPS client. Cloning is cheap.
    pub fn client(&self) -> &Client {
        &self.client
    }

    /// Active environment (profiles, default mediator, etc).
    pub fn environment(&self) -> &TDKEnvironment {
        &self.environment
    }

    /// In-process authentication cache + worker handle.
    pub fn authentication(&self) -> &AuthenticationCache {
        &self.authentication
    }

    /// Stop the background [`AuthenticationCache`] task and wait for it to
    /// exit. Call before process shutdown for graceful drain.
    pub async fn shutdown(&self) {
        self.authentication.terminate().await;
    }
}
