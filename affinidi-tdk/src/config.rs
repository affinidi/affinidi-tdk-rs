/*!
 * TDK Configuration options
 */

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfig};
#[cfg(feature = "messaging")]
use affinidi_messaging_sdk::{ATM, config::ATMConfig};
use affinidi_secrets_resolver::SecretsResolver;
use affinidi_tdk_common::errors::TDKError;

const DEFAULT_ENVIRONMENT_PATH: &str = "environment.json";

pub struct TDKConfig {
    #[cfg(feature = "messaging")]
    pub(crate) atm_config: Option<ATMConfig>,
    #[cfg(feature = "messaging")]
    pub(crate) atm: Option<ATM>,
    #[cfg(feature = "messaging")]
    pub(crate) use_atm: bool,
    pub(crate) did_resolver: Option<DIDCacheClient>,
    pub(crate) did_resolver_config: Option<DIDCacheConfig>,
    pub(crate) secrets_resolver: Option<SecretsResolver>,
    pub(crate) environment_path: String,
    pub(crate) load_environment: bool,
    pub(crate) environment_name: String,
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
    #[cfg(feature = "messaging")]
    /// Affinidi Messaging SDK configuration
    atm_config: Option<ATMConfig>,

    #[cfg(feature = "messaging")]
    /// Externally instantiated Affinidi Messaging SDK instance
    atm: Option<ATM>,

    #[cfg(feature = "messaging")]
    /// Whether to start the Affinidi Messaging SDK
    /// Default to `true`
    use_atm: bool,

    /// Affinidi DID Resolver cache client
    did_resolver: Option<DIDCacheClient>,

    /// Affinidi DID Resolver cache configuration
    /// Allows for a custom configuration when instantiating the DID Resolver internally
    /// Does nothing if `did_resolver` is provided
    did_resolver_config: Option<DIDCacheConfig>,

    /// Affinidi Secrets Resolver
    /// Allows for a custom secrets resolver to be provided
    secrets_resolver: Option<SecretsResolver>,

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
            #[cfg(feature = "messaging")]
            atm_config: None,
            #[cfg(feature = "messaging")]
            atm: None,
            #[cfg(feature = "messaging")]
            use_atm: true,
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
            #[cfg(feature = "messaging")]
            atm_config: self.atm_config,
            #[cfg(feature = "messaging")]
            atm: self.atm,
            #[cfg(feature = "messaging")]
            use_atm: self.use_atm,
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

    #[cfg(feature = "messaging")]
    /// If you want to customise the Affinidi Messaging SDK configuration
    /// Example:
    /// ```
    /// use affinidi_tdk::config::TDKConfig;
    /// use affinidi_messaging_sdk::config::ATMConfig;
    ///
    /// let atm_config = ATMConfig::builder().with_fetch_cache_limit_bytes(1_000_000).build();
    /// let tdk_config = TDKConfig::builder().with_atm_config(atm_config).build();
    ///
    /// let tdk = TDK::new(tdk_config);
    /// ```
    pub fn with_atm_config(mut self, atm_config: ATMConfig) -> Self {
        self.atm_config = Some(atm_config);
        self
    }

    #[cfg(feature = "messaging")]
    /// Use an already configured and running ATM instance?
    /// Example:
    /// ```
    /// use affinidi_tdk::config::TDKConfig;
    /// use affinidi_messaging_sdk::ATM;
    /// use affinidi_messaging_sdk::config::ATMConfig;
    ///
    /// let atm = ATM::new(ATMConfig::builder().build());
    /// let tdk_config = TDKConfig::builder().with_atm(atm).build();
    ///
    /// let tdk = TDK::new(tdk_config);
    /// ```
    pub fn with_atm(mut self, atm: ATM) -> Self {
        self.atm = Some(atm);
        self
    }

    #[cfg(feature = "messaging")]
    /// Whether Affinidi Messaging should be enabled for TDK?
    /// Example:
    /// ```
    /// use affinidi_tdk::config::TDKConfig;
    ///
    /// let tdk_config = TDKConfig::builder().with_use_atm(false).build();
    ///
    /// let tdk = TDK::new(tdk_config);
    /// ```
    pub fn with_use_atm(mut self, use_atm: bool) -> Self {
        self.use_atm = use_atm;
        self
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
    /// use affinidi_secrets_resolver::SecretsResolver;
    ///
    /// let secrets_resolver = SecretsResolver::new(vec![]);
    /// let tdk_config = TDKConfig::builder().with_secrets_resolver(secrets_resolver).build();
    ///
    /// let tdk = TDK::new(tdk_config);
    /// ```
    pub fn with_secrets_resolver(mut self, secrets_resolver: SecretsResolver) -> Self {
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
