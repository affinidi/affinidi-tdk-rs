/*!
 * Common modules used across Affinidi TDK and services
 */

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_secrets_resolver::SecretsResolver;
use config::TDKConfig;
use environments::TDKEnvironment;
use reqwest::Client;

pub mod config;
pub mod environments;
pub mod errors;

pub use affinidi_secrets_resolver;
use rustls::ClientConfig;
use rustls_platform_verifier::ConfigVerifierExt;

/// Private SharedState struct for the TDK to use internally
pub struct TDKSharedState {
    pub config: TDKConfig,
    pub did_resolver: DIDCacheClient,
    pub secrets_resolver: SecretsResolver,
    pub client: Client,
    pub environment: TDKEnvironment,
}

/// Creates a reusable HTTP/HTTPS Client that can be used
pub fn create_http_client() -> Client {
    let tls_config = ClientConfig::with_platform_verifier();
    reqwest::ClientBuilder::new()
        .use_rustls_tls()
        .use_preconfigured_tls(tls_config.clone())
        .user_agent(format!(
            "Affinidi Trust Development Kit {}",
            env!("CARGO_PKG_VERSION")
        ))
        .build()
        .unwrap()
}
