/*!
 * Affinidi Trust Development Kit
 *
 * Instantiate a TDK client with the `new` function
 */

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
#[cfg(feature = "messaging")]
use affinidi_messaging_sdk::ATM;
use affinidi_secrets_resolver::{SecretsResolver, ThreadedSecretsResolver};
use affinidi_tdk_common::{environments::TDKEnvironments, errors::Result};
use common::{config::TDKConfig, environments::TDKEnvironment};
use reqwest::Client;
use rustls::ClientConfig;
use rustls_platform_verifier::ConfigVerifierExt;
use std::sync::Arc;

pub mod dids;

// Re-export required crates for convenience to applications
#[cfg(feature = "meeting-place")]
pub use affinidi_meeting_place as meeting_place;
pub use affinidi_messaging_didcomm as didcomm;
#[cfg(feature = "messaging")]
pub use affinidi_messaging_sdk as messaging;
pub use affinidi_secrets_resolver as secrets_resolver;
pub use affinidi_tdk_common as common;

/// TDK instance that can be used to interact with Affinidi services
#[derive(Clone)]
pub struct TDK {
    pub(crate) inner: Arc<SharedState>,
}

/// Private SharedState struct for the TDK to use internally
pub(crate) struct SharedState {
    pub(crate) config: TDKConfig,
    pub(crate) did_resolver: DIDCacheClient,
    pub(crate) secrets_resolver: ThreadedSecretsResolver,
    pub(crate) client: Client,
    #[cfg(feature = "messaging")]
    pub(crate) atm: Option<ATM>,
    pub(crate) environment: TDKEnvironment,
}

/// Affinidi Trusted Development Kit (TDK)
///
/// Use this to instantiate everything required to easily interact with Affinidi services
/// If you are self hosting the services, you can use your own service URL's where required
///
/// Example:
/// ```ignore
/// use affinidi_tdk::TDK;
/// use affinidi_tdk::config::Config;
///
/// let config = Config::builder().build();
/// let mut tdk = TDK::new(config).await?;
///
///
/// ```
impl TDK {
    pub async fn new(config: TDKConfig) -> Result<Self> {
        let tls_config = ClientConfig::with_platform_verifier();
        let client = reqwest::ClientBuilder::new()
            .use_rustls_tls()
            .use_preconfigured_tls(tls_config.clone())
            .user_agent(format!(
                "Affinidi Trust Development Kit {}",
                env!("CARGO_PKG_VERSION")
            ))
            .build()
            .unwrap();

        // Instantiate the DID resolver for TDK
        let did_resolver = if let Some(did_resolver) = &config.did_resolver {
            did_resolver.to_owned()
        } else if let Some(did_resolver_config) = &config.did_resolver_config {
            DIDCacheClient::new(did_resolver_config.to_owned()).await?
        } else {
            DIDCacheClient::new(DIDCacheConfigBuilder::default().build()).await?
        };

        // Instantiate the SecretsManager for TDK
        let secrets_resolver = if let Some(secrets_resolver) = &config.secrets_resolver {
            secrets_resolver.to_owned()
        } else {
            ThreadedSecretsResolver::new(None).await.0
        };

        /*
        #[cfg(feature = "messaging")]
        // Instantiate Affinidi Messaging
        let atm = if config.use_atm {
            if let Some(atm) = &config.atm {
                Some(atm.to_owned())
            } else if let Some(atm_config) = &config.atm_config {
                Some(ATM::new(atm_config.to_owned()).await?)
            } else {
                // Use the same DID Resolver for ATM
                Some(
                    ATM::new(
                        ATMConfigBuilder::default()
                            .with_external_did_resolver(&did_resolver)
                            .build()?,
                    )
                    .await?,
                )
            }
        } else {
            None
        };
        */

        // Load Environment
        // Adds secrets to the secrets resolver
        // Removes secrets from the environment itself
        let environment = if config.load_environment {
            let mut environment = TDKEnvironments::fetch_from_file(
                Some(&config.environment_path),
                &config.environment_name,
            )?;
            for (_, profile) in environment.profiles.iter_mut() {
                secrets_resolver
                    .insert_vec(profile.secrets.as_slice())
                    .await;

                // Remove secrets from profile after adding them to the secrets resolver
                profile.secrets.clear();
            }
            environment
        } else {
            TDKEnvironment::default()
        };

        let shared_state = SharedState {
            config,
            did_resolver,
            secrets_resolver,
            client,
            #[cfg(feature = "messaging")]
            atm: None,
            environment,
        };

        Ok(TDK {
            inner: Arc::new(shared_state),
        })
    }
}
