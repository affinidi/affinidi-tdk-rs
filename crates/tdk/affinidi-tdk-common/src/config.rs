/*!
 * TDK Configuration options.
 *
 * Build a [`TDKConfig`] via [`TDKConfig::builder`] and one or more `with_*`
 * methods. Fields are encapsulated; read them through accessor methods on
 * [`TDKConfig`] (e.g. [`TDKConfig::environment_path`]).
 */

use affinidi_did_authentication::CustomAuthHandlers;
use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfig};
use affinidi_secrets_resolver::ThreadedSecretsResolver;

use crate::errors::TDKError;

const DEFAULT_ENVIRONMENT_PATH: &str = "environments.json";

/// Configuration for [`crate::TDKSharedState`].
///
/// Construct via [`TDKConfig::builder`]. Fields are `pub(crate)`; consumers
/// read them through accessor methods.
#[derive(Clone)]
pub struct TDKConfig {
    pub(crate) did_resolver: Option<DIDCacheClient>,
    pub(crate) did_resolver_config: Option<DIDCacheConfig>,
    pub(crate) secrets_resolver: Option<ThreadedSecretsResolver>,
    pub(crate) environment_path: String,
    pub(crate) load_environment: bool,
    pub(crate) environment_name: String,
    pub(crate) authentication_cache_limit: usize,
    pub(crate) use_atm: bool,
    pub(crate) custom_auth_handlers: Option<CustomAuthHandlers>,
}

impl TDKConfig {
    /// Returns a fresh [`TDKConfigBuilder`] with default values.
    pub fn builder() -> TDKConfigBuilder {
        TDKConfigBuilder::default()
    }

    /// Pre-built DID resolver, if one was supplied to the builder.
    pub fn did_resolver(&self) -> Option<&DIDCacheClient> {
        self.did_resolver.as_ref()
    }

    /// Custom DID-resolver configuration. Used when the TDK constructs the
    /// resolver internally (i.e. `did_resolver()` is `None`).
    pub fn did_resolver_config(&self) -> Option<&DIDCacheConfig> {
        self.did_resolver_config.as_ref()
    }

    /// Pre-built `SecretsResolver`, if one was supplied to the builder.
    pub fn secrets_resolver(&self) -> Option<&ThreadedSecretsResolver> {
        self.secrets_resolver.as_ref()
    }

    /// Path to the on-disk environment file.
    pub fn environment_path(&self) -> &str {
        &self.environment_path
    }

    /// Whether [`crate::TDKSharedState::new`] should load
    /// [`crate::environments::TDKEnvironments`] from disk on construction.
    pub fn load_environment(&self) -> bool {
        self.load_environment
    }

    /// Name of the environment to load on startup.
    pub fn environment_name(&self) -> &str {
        &self.environment_name
    }

    /// Maximum number of entries the in-process authentication cache will
    /// retain.
    pub fn authentication_cache_limit(&self) -> usize {
        self.authentication_cache_limit
    }

    /// Whether the host TDK should auto-instantiate Affinidi Trusted Messaging.
    /// Read by `affinidi-tdk` (which owns the `dep:affinidi-messaging-sdk`
    /// linkage); ignored by this crate.
    pub fn use_atm(&self) -> bool {
        self.use_atm
    }

    /// Custom authentication handlers, if any.
    pub fn custom_auth_handlers(&self) -> Option<&CustomAuthHandlers> {
        self.custom_auth_handlers.as_ref()
    }
}

/// Manual `Debug` impl. The upstream `DIDCacheClient`,
/// `ThreadedSecretsResolver`, and `CustomAuthHandlers` types do not implement
/// `Debug`; we render them as `<…>` placeholders so logs still surface the
/// scalar config knobs.
impl std::fmt::Debug for TDKConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TDKConfig")
            .field(
                "did_resolver",
                &self.did_resolver.as_ref().map(|_| "<DIDCacheClient>"),
            )
            .field("did_resolver_config", &self.did_resolver_config)
            .field(
                "secrets_resolver",
                &self.secrets_resolver.as_ref().map(|_| "<SecretsResolver>"),
            )
            .field("environment_path", &self.environment_path)
            .field("load_environment", &self.load_environment)
            .field("environment_name", &self.environment_name)
            .field(
                "authentication_cache_limit",
                &self.authentication_cache_limit,
            )
            .field("use_atm", &self.use_atm)
            .field(
                "custom_auth_handlers",
                &self
                    .custom_auth_handlers
                    .as_ref()
                    .map(|_| "<CustomAuthHandlers>"),
            )
            .finish()
    }
}

/// Builder for [`TDKConfig`]. Construct via [`TDKConfig::builder`].
pub struct TDKConfigBuilder {
    did_resolver: Option<DIDCacheClient>,
    did_resolver_config: Option<DIDCacheConfig>,
    secrets_resolver: Option<ThreadedSecretsResolver>,
    environment_path: Option<String>,
    load_environment: bool,
    environment_name: Option<String>,
    authentication_cache_limit: usize,
    use_atm: bool,
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
    /// Build the [`TDKConfig`] from the builder.
    pub fn build(self) -> Result<TDKConfig, TDKError> {
        Ok(TDKConfig {
            did_resolver: self.did_resolver,
            did_resolver_config: self.did_resolver_config,
            secrets_resolver: self.secrets_resolver,
            environment_path: self
                .environment_path
                .unwrap_or_else(|| DEFAULT_ENVIRONMENT_PATH.to_string()),
            load_environment: self.load_environment,
            environment_name: self
                .environment_name
                .unwrap_or_else(|| "default".to_string()),
            authentication_cache_limit: self.authentication_cache_limit,
            use_atm: self.use_atm,
            custom_auth_handlers: self.custom_auth_handlers,
        })
    }

    /// Supply a pre-built DID resolver. Takes priority over
    /// [`with_did_resolver_config`](Self::with_did_resolver_config).
    pub fn with_did_resolver(mut self, did_resolver: DIDCacheClient) -> Self {
        self.did_resolver = Some(did_resolver);
        self
    }

    /// Supply a custom DID-resolver configuration. Used when the TDK
    /// constructs the resolver internally; ignored if
    /// [`with_did_resolver`](Self::with_did_resolver) is also set.
    ///
    /// Useful for sidecar deployments (e.g. Nitro Enclaves) where the
    /// resolver lives at a known network endpoint.
    pub fn with_did_resolver_config(mut self, config: DIDCacheConfig) -> Self {
        self.did_resolver_config = Some(config);
        self
    }

    /// Supply a pre-built `SecretsResolver`. If absent, a fresh empty
    /// in-memory resolver is created at `TDKSharedState::new`.
    pub fn with_secrets_resolver(mut self, secrets_resolver: ThreadedSecretsResolver) -> Self {
        self.secrets_resolver = Some(secrets_resolver);
        self
    }

    /// Set the path to the environment file (defaults to `environments.json`).
    pub fn with_environment_path(mut self, environment_path: String) -> Self {
        self.environment_path = Some(environment_path);
        self
    }

    /// Whether to load the environment file at `TDKSharedState::new` time.
    /// Defaults to `true`.
    pub fn with_load_environment(mut self, load_environment: bool) -> Self {
        self.load_environment = load_environment;
        self
    }

    /// Name of the environment to load on startup. Defaults to `"default"`.
    pub fn with_environment_name(mut self, environment_name: String) -> Self {
        self.environment_name = Some(environment_name);
        self
    }

    /// Maximum number of entries in the authentication cache. Defaults to
    /// 1000.
    pub fn with_authentication_cache_limit(mut self, authentication_cache_limit: usize) -> Self {
        self.authentication_cache_limit = authentication_cache_limit;
        self
    }

    /// Whether `affinidi-tdk` should auto-instantiate ATM (Affinidi Trusted
    /// Messaging). Defaults to `true`. Read by the umbrella crate; ignored
    /// here.
    pub fn with_use_atm(mut self, use_atm: bool) -> Self {
        self.use_atm = use_atm;
        self
    }

    /// Override the default DID Auth challenge / refresh flow.
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
        assert_eq!(cfg.environment_path(), DEFAULT_ENVIRONMENT_PATH);
        assert_eq!(cfg.environment_name(), "default");
        assert_eq!(cfg.authentication_cache_limit(), 1_000);
        assert!(cfg.use_atm());
        assert!(cfg.load_environment());
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
        assert_eq!(cfg.environment_path(), "custom.json");
        assert_eq!(cfg.environment_name(), "prod");
        assert_eq!(cfg.authentication_cache_limit(), 50);
        assert!(!cfg.load_environment());
    }
}
