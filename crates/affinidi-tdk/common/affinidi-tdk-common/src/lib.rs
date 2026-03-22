/*!
 * Common modules used across Affinidi TDK and services
 */

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use errors::TDKError;
use affinidi_secrets_resolver::{SecretsResolver, ThreadedSecretsResolver};
use config::TDKConfig;
use environments::TDKEnvironment;
use profiles::TDKProfile;
use reqwest::Client;
use rustls::ClientConfig;
use rustls_platform_verifier::ConfigVerifierExt;

pub mod config;
pub mod environments;
pub mod errors;
pub mod profiles;
pub mod secrets;
pub mod tasks;

//pub use affinidi_did_authentication as did_authentication;
pub use affinidi_secrets_resolver as secrets_resolver;
use tasks::authentication::AuthenticationCache;

/// Common SharedState struct for Affinidi TDK Crates to use internally
/// Can be used on it's own as bootstrap into individual crates without using TDK directly
/// This shared state should only contain what is absolutely necessary for the crate to function
#[derive(Clone)]
pub struct TDKSharedState {
    pub config: TDKConfig,
    pub did_resolver: DIDCacheClient,
    pub secrets_resolver: ThreadedSecretsResolver,
    pub client: Client,
    pub environment: TDKEnvironment,
    pub authentication: AuthenticationCache,
}

/// Creates a reusable HTTP/HTTPS Client that can be used
pub fn create_http_client() -> Client {
    // Set a process wide default crypto provider.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let tls_config = ClientConfig::with_platform_verifier();
    reqwest::ClientBuilder::new()
        .use_rustls_tls()
        .use_preconfigured_tls(tls_config.unwrap())
        .user_agent(format!(
            "Affinidi Trust Development Kit {}",
            env!("CARGO_PKG_VERSION")
        ))
        .build()
        .unwrap()
}

impl TDKSharedState {
    /// Creates a new `TDKSharedState` from the provided configuration.
    ///
    /// The DID resolver is selected in priority order:
    /// 1. `config.did_resolver` — a pre-built resolver instance
    /// 2. `config.did_resolver_config` — a custom resolver configuration
    /// 3. Default local-mode resolver
    ///
    /// # Errors
    ///
    /// Returns [`TDKError::Config`] if the DID resolver fails to initialize.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use affinidi_tdk_common::{TDKSharedState, config::TDKConfig};
    /// use affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder;
    ///
    /// // Use a network-mode resolver (e.g., for Nitro Enclave deployments)
    /// let resolver_config = DIDCacheConfigBuilder::default()
    ///     .with_network_mode("ws://127.0.0.1:4445/did/v1/ws")
    ///     .build();
    ///
    /// let config = TDKConfig::builder()
    ///     .with_did_resolver_config(resolver_config)
    ///     .build()?;
    ///
    /// let tdk = TDKSharedState::new(config).await?;
    /// ```
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

        let client = create_http_client();
        let environment = TDKEnvironment::default();
        let (authentication, _) = AuthenticationCache::new(
            config.authentication_cache_limit as u64,
            &did_resolver,
            secrets_resolver.clone(),
            &client,
            config.custom_auth_handlers.clone(),
        );
        authentication.start().await;

        Ok(TDKSharedState {
            config,
            did_resolver,
            secrets_resolver,
            client,
            environment,
            authentication,
        })
    }

    /// Default basic setup for TDKSharedState
    /// For production code you should be using the TDKConfig Builder to create a custom setup
    pub async fn default() -> Self {
        let config = TDKConfig::builder().build().unwrap();
        Self::new(config).await.unwrap()
    }

    /// Adds a TDK Profile to the shared state
    /// Which is really just adding the secrets to the secrets resolver
    /// For the moment...
    pub async fn add_profile(&self, profile: &TDKProfile) {
        self.secrets_resolver.insert_vec(&profile.secrets).await;
    }
}
