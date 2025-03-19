/*!
 * TDK Configuration options
 */

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfig};
use affinidi_secrets_resolver::ThreadedSecretsResolver;

use crate::errors::TDKError;

const DEFAULT_ENVIRONMENT_PATH: &str = "environment.json";

pub struct TDKConfig {
    pub did_resolver: Option<DIDCacheClient>,
    pub did_resolver_config: Option<DIDCacheConfig>,
    pub secrets_resolver: Option<ThreadedSecretsResolver>,
    pub environment_path: String,
    pub load_environment: bool,
    pub environment_name: String,
}

impl TDKConfig {
    /// Returns a builder for `Config`
    /// Example:
    /// ```
    /// use affinidi_tdk::config::TDKConfig;
    ///
    /// let config = TDKConfig::builder().build();
    /// ```
    pub fn builder() -> TDKConfigBuilder {
        TDKConfigBuilder::default()
    }
}

/// Builder for `TDKConfig`.
/// Example:
/// ```
/// use affinidi_tdk::config::TDKConfig;
///
/// // Create a new `TDKConfig` with defaults
/// let config = TDKConfig::builder().build();
/// ```
pub struct TDKConfigBuilder {
    /// Affinidi DID Resolver cache client
    did_resolver: Option<DIDCacheClient>,

    /// Affinidi DID Resolver cache configuration
    /// Allows for a custom configuration when instantiating the DID Resolver internally
    /// Does nothing if `did_resolver` is provided
    did_resolver_config: Option<DIDCacheConfig>,

    /// Affinidi Secrets Resolver
    /// Allows for a custom secrets resolver to be provided
    secrets_resolver: Option<ThreadedSecretsResolver>,

    /// Path to load a profile environment from
    environment_path: Option<String>,

    /// Load the environment profile on startup
    /// Defaults to `true`
    load_environment: bool,

    /// Default environment name to load
    /// Default: default
    environment_name: Option<String>,
}

impl Default for TDKConfigBuilder {
    fn default() -> Self {
        TDKConfigBuilder {
            did_resolver: None,
            did_resolver_config: None,
            secrets_resolver: None,
            environment_path: None,
            load_environment: true,
            environment_name: None,
        }
    }
}

impl TDKConfigBuilder {
    /// Default starting constructor for `TDKConfigBuilder`
    pub fn new() -> TDKConfigBuilder {
        TDKConfigBuilder::default()
    }

    /// Build the `TDKConfig` from the builder
    pub fn build(self) -> Result<TDKConfig, TDKError> {
        Ok(TDKConfig {
            did_resolver: self.did_resolver,
            did_resolver_config: self.did_resolver_config,
            secrets_resolver: self.secrets_resolver,
            environment_path: self
                .environment_path
                .unwrap_or(DEFAULT_ENVIRONMENT_PATH.into()),
            load_environment: self.load_environment,
            environment_name: self.environment_name.unwrap_or("default".into()),
        })
    }

    /// If you want to provide a DID resolver already setup outside of the TDK
    /// Example:
    /// ```
    /// use affinidi_tdk::config::TDKConfig;
    /// use affinidi_did_resolver_cache_sdk::DIDCacheClient;
    ///
    /// let did_resolver = DIDCacheClient::new()
    /// let tdk_config = TDKConfig::builder().with_did_resolver(did_resolver).build();
    ///
    /// let tdk = TDK::new(tdk_config);
    /// ```
    pub fn with_did_resolver(mut self, did_resolver: DIDCacheClient) -> Self {
        self.did_resolver = Some(did_resolver);
        self
    }

    /// If you have a SecretsResolver already setup outside of the TDK
    /// Example:
    /// ```
    /// use affinidi_tdk::config::TDKConfig;
    /// use affinidi_secrets_resolver::ThreadedSecretsResolver;
    ///
    /// let secrets_resolver = ThreadedSecretsResolver::new(None);
    /// let tdk_config = TDKConfig::builder().with_secrets_resolver(secrets_resolver).build();
    ///
    /// let tdk = TDK::new(tdk_config);
    /// ```
    pub fn with_secrets_resolver(mut self, secrets_resolver: ThreadedSecretsResolver) -> Self {
        self.secrets_resolver = Some(secrets_resolver);
        self
    }

    /// Specify a path to the environment profile file containing profiles
    /// Example:
    /// ```
    /// use affinidi_tdk::config::TDKConfig;
    ///
    /// let tdk_config = TDKConfig::builder().with_environment_path("environment.json".into()).build();
    ///
    /// let tdk = TDK::new(tdk_config);
    /// ```
    pub fn with_environment_path(mut self, environment_path: String) -> Self {
        self.environment_path = Some(environment_path);
        self
    }

    /// Should TDK load an environment on startup?
    /// Example:
    /// ```
    /// use affinidi_tdk::config::TDKConfig;
    ///
    /// let tdk_config = TDKConfig::builder().with_load_environment(false).build();
    ///
    /// let tdk = TDK::new(tdk_config);
    /// ```
    pub fn with_load_environment(mut self, load_environment: bool) -> Self {
        self.load_environment = load_environment;
        self
    }

    /// Change the environment to load on startup
    /// Defaults: "default"
    /// Example:
    /// ```
    /// use affinidi_tdk::config::TDKConfig;
    ///
    /// let tdk_config = TDKConfig::builder().with_environment_name("local".into()).build();
    ///
    /// let tdk = TDK::new(tdk_config);
    /// ```
    pub fn with_environment_name(mut self, environment_name: String) -> Self {
        self.environment_name = Some(environment_name);
        self
    }
}
