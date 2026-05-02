/*!
 * TDK Configuration options
 */

use affinidi_did_authentication::CustomAuthHandlers;
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
    pub custom_auth_handlers: Option<CustomAuthHandlers>,
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

    /// Use Affinidi Trusted Messaging
    /// Default: true
    /// NOTE: You can specify an externally configured ATM instance when instantiating TDK which will override this
    use_atm: bool,

    /// Custom authentication handlers used when this TDK instance acts as the
    /// authenticating party. Lets the host application override the default
    /// DID Auth challenge / refresh flow — for example, to inject Nitro Enclave
    /// attestations or to swap in a non-DID identity provider. See
    /// [`affinidi_did_authentication::CustomAuthHandlers`] for the trait shape.
    custom_auth_handlers: Option<CustomAuthHandlers>,
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
            use_atm: true,
            custom_auth_handlers: None,
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
            use_atm: self.use_atm,
            custom_auth_handlers: self.custom_auth_handlers,
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

    /// Provide a custom DID resolver configuration.
    /// This is used when the TDK creates the DID resolver internally.
    /// Has no effect if `with_did_resolver()` is also called (pre-built resolver takes priority).
    ///
    /// Use this to configure network mode for deployments where the resolver
    /// runs as a sidecar (e.g., Nitro Enclaves).
    ///
    /// Example:
    /// ```ignore
    /// use affinidi_tdk_common::config::TDKConfig;
    /// use affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder;
    ///
    /// let resolver_config = DIDCacheConfigBuilder::default()
    ///     .with_network_mode("ws://127.0.0.1:4445/did/v1/ws")
    ///     .build();
    ///
    /// let tdk_config = TDKConfig::builder()
    ///     .with_did_resolver_config(resolver_config)
    ///     .build()?;
    /// ```
    pub fn with_did_resolver_config(mut self, config: DIDCacheConfig) -> Self {
        self.did_resolver_config = Some(config);
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

    /// Set custom authentication handlers
    /// Example:
    /// ```
    /// // use affinidi_tdk::TDK;
    /// use affinidi_tdk_common::config::TDKConfig;
    /// use affinidi_did_authentication::CustomAuthHandlers;
    ///
    /// // let handlers = CustomAuthHandlers::new()
    /// //     .with_auth_handler(Arc::new(MyCustomAuthHandler))
    /// //     .with_refresh_handler(Arc::new(MyCustomRefreshHandler));
    /// // let tdk_config = TDKConfig::builder().with_custom_auth_handlers(handlers).build();
    ///
    /// // let tdk = TDK::new(tdk_config);
    /// ```
    pub fn with_custom_auth_handlers(mut self, handlers: CustomAuthHandlers) -> Self {
        self.custom_auth_handlers = Some(handlers);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_defaults_are_sensible() {
        let cfg = TDKConfig::builder().build().unwrap();
        assert_eq!(cfg.environment_path, DEFAULT_ENVIRONMENT_PATH);
        assert_eq!(cfg.environment_name, "default");
        assert_eq!(cfg.authentication_cache_limit, 1_000);
        assert!(cfg.use_atm);
        assert!(cfg.load_environment);
    }

    #[test]
    fn builder_overrides_apply() {
        let cfg = TDKConfig::builder()
            .with_environment_path("custom.json".to_string())
            .with_environment_name("prod".to_string())
            .with_authentication_cache_limit(50)
            .with_load_environment(false)
            .build()
            .unwrap();
        assert_eq!(cfg.environment_path, "custom.json");
        assert_eq!(cfg.environment_name, "prod");
        assert_eq!(cfg.authentication_cache_limit, 50);
        assert!(!cfg.load_environment);
    }
}
