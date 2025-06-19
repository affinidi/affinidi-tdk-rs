/*!
 * Common modules used across Affinidi TDK and services
 */

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
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
    /// default basic setup for TDKSharedState
    /// For production code you should be using the TDKConfig Builder to create a custom setup
    pub async fn default() -> Self {
        let config = TDKConfig::builder().build().unwrap();
        let did_resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .unwrap();
        let (secrets_resolver, _) = ThreadedSecretsResolver::new(None).await;
        let client = create_http_client();
        let environment = TDKEnvironment::default();
        let (authentication, _) =
            AuthenticationCache::new(1_000, &did_resolver, secrets_resolver.clone(), &client);
        authentication.start().await;

        TDKSharedState {
            config,
            did_resolver,
            secrets_resolver,
            client,
            environment,
            authentication: authentication.clone(),
        }
    }

    /// Adds a TDK Profile to the shared state
    /// Which is really just adding the secrets to the secrets resolver
    /// For the moment...
    pub async fn add_profile(&self, profile: &TDKProfile) {
        self.secrets_resolver.insert_vec(&profile.secrets).await;
    }
}
