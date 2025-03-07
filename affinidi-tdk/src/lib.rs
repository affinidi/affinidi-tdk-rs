/*!
 * Affinidi Trust Development Kit
 *
 * Instantiate a TDK client with the `new` function
 */

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
#[cfg(feature = "messaging")]
use affinidi_messaging_sdk::{ATM, config::ATMConfigBuilder};
use affinidi_secrets_resolver::SecretsResolver;
use affinidi_tdk_common::{
    errors::Result,
    profiles::{TDKEnvironments, TDKProfile},
};
use config::TDKConfig;
use reqwest::Client;
use rustls::ClientConfig;
use rustls_platform_verifier::ConfigVerifierExt;
use std::{collections::HashMap, sync::Arc};

pub mod config;
pub mod did_authentication;
pub mod dids;
pub mod profile;

// Re-export required crates for convenience to applications
pub extern crate affinidi_secrets_resolver as secrets_resolver;
pub extern crate affinidi_tdk_common as common;

/// TDK instance that can be used to interact with Affinidi services
#[derive(Clone)]
pub struct TDK {
    pub(crate) inner: Arc<SharedState>,
}

/// Private SharedState struct for the TDK to use internally
pub(crate) struct SharedState {
    pub(crate) config: TDKConfig,
    pub(crate) did_resolver: DIDCacheClient,
    pub(crate) secrets_resolver: SecretsResolver,
    pub(crate) client: Client,
    #[cfg(feature = "messaging")]
    pub(crate) atm: Option<ATM>,
    pub(crate) profiles: HashMap<String, TDKProfile>,
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
            SecretsResolver::new(vec![])
        };

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

        // Load Environment
        let profiles = if config.load_environment {
            let profiles = TDKEnvironments::load_from_file(
                &config.environment_path,
                &config.environment_name,
            )?;
            let mut map = HashMap::new();
            for mut profile in profiles {
                secrets_resolver.insert_vec(profile.secrets.as_slice());

                // Remove secrets from profile after adding them to the secrets resolver
                profile.secrets.clear();
                map.insert(profile.alias.clone(), profile);
            }
            map
        } else {
            HashMap::new()
        };

        let shared_state = SharedState {
            config,
            did_resolver,
            secrets_resolver,
            client,
            #[cfg(feature = "messaging")]
            atm,
            profiles,
        };

        Ok(TDK {
            inner: Arc::new(shared_state),
        })
    }
}
