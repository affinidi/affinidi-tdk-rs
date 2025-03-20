/*!
 * Affinidi Trust Development Kit
 *
 * Instantiate a TDK client with the `new` function
 */

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
#[cfg(feature = "messaging")]
use affinidi_messaging_sdk::ATM;
use affinidi_messaging_sdk::config::ATMConfigBuilder;
use affinidi_secrets_resolver::{SecretsResolver, ThreadedSecretsResolver};
use affinidi_tdk_common::{
    TDKSharedState, create_http_client, environments::TDKEnvironments, errors::Result,
    tasks::authentication::AuthenticationCache,
};
use common::{config::TDKConfig, environments::TDKEnvironment};
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
    pub(crate) inner: Arc<TDKSharedState>,
    #[cfg(feature = "messaging")]
    pub atm: Option<ATM>,
    #[cfg(feature = "meeting-place")]
    pub meeting_place: Option<meeting_place::MeetingPlace>,
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
    pub async fn new(
        config: TDKConfig,
        #[cfg(feature = "messaging")] atm: Option<ATM>,
    ) -> Result<Self> {
        let client = create_http_client();

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

        // Instantiate the authentication cache
        let (authentication, _) = AuthenticationCache::new(
            config.authentication_cache_limit as u64,
            &did_resolver,
            secrets_resolver.clone(),
            &client,
        );

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

        // Create the shared state, then we can use this inside other Affinidi Crates
        let shared_state = TDKSharedState {
            config,
            did_resolver,
            secrets_resolver,
            client,
            environment,
            authentication,
        };

        #[cfg(feature = "messaging")]
        // Instantiate Affinidi Messaging
        let atm = if shared_state.config.use_atm {
            if let Some(atm) = atm {
                Some(atm.to_owned())
            } else {
                // Use the same DID Resolver for ATM
                Some(ATM::new(ATMConfigBuilder::default().build()?, shared_state.clone()).await?)
            }
        } else {
            None
        };

        Ok(TDK {
            inner: Arc::new(shared_state),
            #[cfg(feature = "messaging")]
            atm,
            #[cfg(feature = "meeting-place")]
            meeting_place: None,
        })
    }

    /// Get the shared state of the TDK
    pub fn get_shared_state(&self) -> Arc<TDKSharedState> {
        self.inner.clone()
    }
}
