/*!
 * TDK Configuration options
 */

use affinidi_did_authentication::AuthorizationTokens;
use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfig};
use affinidi_secrets_resolver::ThreadedSecretsResolver;

use crate::errors::TDKError;

const DEFAULT_ENVIRONMENT_PATH: &str = "environments.json";

#[derive(Clone)]
pub struct TDKConfig {
    pub did_resolver: Option<DIDCacheClient>,
    pub did_resolver_config: Option<DIDCacheConfig>,
    pub secrets_resolver: Option<ThreadedSecretsResolver>,
    pub environment_path: String,
    pub load_environment: bool,
    pub environment_name: String,
    pub authentication_cache_limit: usize,
    pub use_atm: bool,
    pub auth_tokens: Option<AuthorizationTokens>,
}

impl TDKConfig {
    /// Returns a builder for `Config`
    /// Example:
    /// ```
    /// use affinidi_tdk_common::config::TDKConfig;
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
/// use affinidi_tdk_common::config::TDKConfig;
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

    /// Limit for the authentication cache
    /// Default: 1000
    authentication_cache_limit: usize,

    #[cfg(feature = "messaging")]
    /// Use Affinidi Trusted Messaging
    /// Default: true
    /// NOTE: You can specify an externally configured ATM instance when instantiating TDK which will override this
    use_atm: bool,

    /// Authentication tokens to be used by ATM
    auth_tokens: Option<AuthorizationTokens>,
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
            authentication_cache_limit: 1_000,
            #[cfg(feature = "messaging")]
            use_atm: true,
            auth_tokens: None,
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
            authentication_cache_limit: self.authentication_cache_limit,
            #[cfg(feature = "messaging")]
            use_atm: self.use_atm,
            auth_tokens: self.auth_tokens,
        })
    }

    /// If you want to provide a DID resolver already setup outside of the TDK
    /// Example:
    /// ```
    /// // use affinidi_tdk::TDK;
    /// use affinidi_tdk_common::config::TDKConfig;
    /// use affinidi_did_resolver_cache_sdk::DIDCacheClient;
    ///
    /// // let did_resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build()).await?;
    /// // let tdk_config = TDKConfig::builder().with_did_resolver(did_resolver).build();
    ///
    /// // let tdk = TDK::new(tdk_config);
    /// ```
    pub fn with_did_resolver(mut self, did_resolver: DIDCacheClient) -> Self {
        self.did_resolver = Some(did_resolver);
        self
    }

    /// If you have a SecretsResolver already setup outside of the TDK
    /// Example:
    /// ```
    /// // use affinidi_tdk::TDK;
    /// use affinidi_tdk_common::config::TDKConfig;
    /// use affinidi_secrets_resolver::ThreadedSecretsResolver;
    ///
    /// // let secrets_resolver = ThreadedSecretsResolver::new(None).await?;
    /// // let tdk_config = TDKConfig::builder().with_secrets_resolver(secrets_resolver).build();
    ///
    /// // let tdk = TDK::new(tdk_config);
    /// ```
    pub fn with_secrets_resolver(mut self, secrets_resolver: ThreadedSecretsResolver) -> Self {
        self.secrets_resolver = Some(secrets_resolver);
        self
    }

    /// Specify a path to the environment profile file containing profiles
    /// Example:
    /// ```
    /// // use affinidi_tdk::TDK;
    /// use affinidi_tdk_common::config::TDKConfig;
    ///
    /// let tdk_config = TDKConfig::builder().with_environment_path("environment.json".into()).build();
    ///
    /// // let tdk = TDK::new(tdk_config);
    /// ```
    pub fn with_environment_path(mut self, environment_path: String) -> Self {
        self.environment_path = Some(environment_path);
        self
    }

    /// Should TDK load an environment on startup?
    /// Example:
    /// ```
    /// // use affinidi_tdk::TDK;
    /// use affinidi_tdk_common::config::TDKConfig;
    ///
    /// let tdk_config = TDKConfig::builder().with_load_environment(false).build();
    ///
    /// // let tdk = TDK::new(tdk_config);
    /// ```
    pub fn with_load_environment(mut self, load_environment: bool) -> Self {
        self.load_environment = load_environment;
        self
    }

    /// Change the environment to load on startup
    /// Defaults: "default"
    /// Example:
    /// ```
    /// // use affinidi_tdk::TDK;
    /// use affinidi_tdk_common::config::TDKConfig;
    ///
    /// let tdk_config = TDKConfig::builder().with_environment_name("local".into()).build();
    ///
    /// // let tdk = TDK::new(tdk_config);
    /// ```
    pub fn with_environment_name(mut self, environment_name: String) -> Self {
        self.environment_name = Some(environment_name);
        self
    }

    /// How many Authentication sets should we cache?
    /// Defaults: 1_000
    /// Example:
    /// ```
    /// // use affinidi_tdk::TDK;
    /// use affinidi_tdk_common::config::TDKConfig;
    ///
    /// let tdk_config = TDKConfig::builder().with_authentication_cache_limit(10_000).build();
    ///
    /// // let tdk = TDK::new(tdk_config);
    /// ```
    pub fn with_authentication_cache_limit(mut self, authentication_cache_limit: usize) -> Self {
        self.authentication_cache_limit = authentication_cache_limit;
        self
    }

    #[cfg(feature = "messaging")]
    /// Should TDK create an ATM instance internally?
    /// Defaults: true
    /// Example:
    /// ```
    /// // use affinidi_tdk::TDK;
    /// use affinidi_tdk_common::config::TDKConfig;
    ///
    /// let tdk_config = TDKConfig::builder().with_use_atm(false).build();
    ///
    /// // let tdk = TDK::new(tdk_config);
    /// ```
    pub fn with_use_atm(mut self, use_atm: bool) -> Self {
        self.use_atm = use_atm;
        self
    }

    /// Set authentication tokens
    /// Example:
    /// ```
    /// // use affinidi_tdk::TDK;
    /// use affinidi_tdk_common::config::TDKConfig;
    /// use affinidi_did_authentication::AuthorizationTokens;
    ///
    /// let tokens = AuthorizationTokens {
    ///     access_token: "access".to_string(),
    ///     access_expires_at: 1234567890,
    ///     refresh_token: "refresh".to_string(),
    ///     refresh_expires_at: 1234567890,
    /// };
    /// let tdk_config = TDKConfig::builder().with_auth_tokens(tokens).build();
    ///
    /// // let tdk = TDK::new(tdk_config);
    /// ```
    pub fn with_auth_tokens(mut self, auth_tokens: AuthorizationTokens) -> Self {
        self.auth_tokens = Some(auth_tokens);
        self
    }
}
