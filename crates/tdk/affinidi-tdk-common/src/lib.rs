#![forbid(unsafe_code)]
/*!
# affinidi-tdk-common

Shared building blocks for Affinidi Trust Development Kit (TDK) crates.

The crate is organised around four core concepts:

- **[`TDKConfig`]** ([`config`]) — typed configuration with a builder. Owns the
  optional DID resolver, secrets resolver, environment-file path, and custom
  authentication handlers used by the rest of the stack.
- **[`TDKSharedState`]** — the runtime container that other Affinidi crates take
  by reference. It bundles the DID resolver, secrets resolver, HTTPS client, and
  the [`AuthenticationCache`](tasks::authentication::AuthenticationCache).
  Subsystems are exposed via accessors (e.g. [`TDKSharedState::client`]) rather
  than public fields, so the internal layout can evolve without breaking
  consumers.
- **[`TDKProfile`]** + **[`TDKEnvironment`]** ([`profiles`], [`environments`]) —
  serialisable identity profiles and the on-disk format for grouping profiles
  by environment (local / dev / prod).
- **[`KeyringStore`](secrets::KeyringStore)** ([`secrets`]) — handle into the
  OS native credential store (macOS Keychain, Windows Credential Manager,
  freedesktop Secret Service) for persisting profile secrets.

Errors are funneled through [`TDKError`]; consumers convert it to their own
error types via `From<TDKError>` impls.
*/

use std::sync::{Arc, OnceLock};

use affinidi_did_authentication::{AuthorizationTokens, errors::DIDAuthError};
use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use affinidi_secrets_resolver::{SecretsResolver, ThreadedSecretsResolver};
use config::TDKConfig;
use environments::{TDKEnvironment, TDKEnvironments};
use errors::TDKError;
use profiles::TDKProfile;
use reqwest::Client;
use rustls::{ClientConfig, pki_types::CertificateDer};
use rustls_platform_verifier::{ConfigVerifierExt, Verifier};
use tracing::warn;

pub mod config;
pub mod environments;
pub mod errors;
pub mod profiles;
pub mod secrets;
pub mod tasks;

pub use affinidi_secrets_resolver as secrets_resolver;
use tasks::authentication::AuthenticationCache;

/// Runtime state shared across Affinidi TDK crates.
///
/// Construct with [`TDKSharedState::new`]. Subsystems are exposed via accessor
/// methods rather than public fields so internals can evolve without a
/// breaking change. Cloning is cheap — every subsystem is internally
/// reference-counted.
#[derive(Clone)]
pub struct TDKSharedState {
    pub(crate) config: TDKConfig,
    pub(crate) did_resolver: DIDCacheClient,
    pub(crate) secrets_resolver: ThreadedSecretsResolver,
    pub(crate) client: Client,
    pub(crate) environment: TDKEnvironment,
    pub(crate) authentication: AuthenticationCache,
}

/// Build a reusable HTTP/HTTPS [`Client`] backed by `rustls` with the platform
/// trust verifier, optionally extended with `extra_roots`.
///
/// Pass an empty slice for the default behaviour (platform trust store only).
/// Non-empty `extra_roots` are added on top of the platform store via
/// [`Verifier::new_with_extra_roots`] — useful for environments with
/// internal/private CAs (see
/// [`TDKEnvironment::ssl_certificate_paths`](environments::TDKEnvironment::ssl_certificate_paths)).
///
/// Installs `rustls`'s `aws-lc-rs` crypto provider as the process default
/// exactly once via [`OnceLock`] — repeated calls are a no-op.
///
/// # Errors
///
/// Returns [`TDKError::Config`] if the platform TLS verifier or the
/// [`reqwest::Client`] cannot be constructed.
pub fn create_http_client(extra_roots: &[CertificateDer<'static>]) -> Result<Client, TDKError> {
    static CRYPTO_INIT: OnceLock<()> = OnceLock::new();
    CRYPTO_INIT.get_or_init(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });

    let tls_config = if extra_roots.is_empty() {
        ClientConfig::with_platform_verifier()
            .map_err(|e| TDKError::Config(format!("rustls platform verifier init failed: {e}")))?
    } else {
        let crypto_provider = rustls::crypto::CryptoProvider::get_default()
            .cloned()
            .unwrap_or_else(|| Arc::new(rustls::crypto::aws_lc_rs::default_provider()));
        let verifier =
            Verifier::new_with_extra_roots(extra_roots.iter().cloned(), crypto_provider.clone())
                .map_err(|e| {
                    TDKError::Config(format!(
                        "rustls platform verifier (with extra roots) init failed: {e}"
                    ))
                })?;
        ClientConfig::builder_with_provider(crypto_provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| TDKError::Config(format!("rustls protocol-version setup failed: {e}")))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth()
    };
    reqwest::ClientBuilder::new()
        .use_rustls_tls()
        .use_preconfigured_tls(tls_config)
        .user_agent(format!(
            "Affinidi Trust Development Kit {}",
            env!("CARGO_PKG_VERSION")
        ))
        .build()
        .map_err(|e| TDKError::Config(format!("HTTP client build failed: {e}")))
}

impl TDKSharedState {
    /// Build a new [`TDKSharedState`] from the supplied configuration.
    ///
    /// The DID resolver is selected in priority order:
    /// 1. `config.did_resolver` — a pre-built resolver instance
    /// 2. `config.did_resolver_config` — a custom resolver configuration
    /// 3. Default local-mode resolver
    ///
    /// The secrets resolver is similarly taken from config if present, else a
    /// fresh empty in-memory resolver is created.
    ///
    /// The [`AuthenticationCache`] task is spawned and runs until
    /// [`TDKSharedState::shutdown`] is called.
    ///
    /// # Errors
    ///
    /// Returns [`TDKError::Config`] if the DID resolver or HTTP client fails
    /// to initialise.
    pub async fn new(config: TDKConfig) -> Result<Self, TDKError> {
        let did_resolver = if let Some(resolver) = config.did_resolver.clone() {
            resolver
        } else {
            let resolver_config = config
                .did_resolver_config
                .clone()
                .unwrap_or_else(|| DIDCacheConfigBuilder::default().build());
            DIDCacheClient::new(resolver_config)
                .await
                .map_err(|e| TDKError::Config(format!("DID resolver init failed: {e}")))?
        };

        let secrets_resolver = if let Some(sr) = config.secrets_resolver.clone() {
            sr
        } else {
            let (sr, _) = ThreadedSecretsResolver::new(None).await;
            sr
        };

        // Resolve the environment in priority order:
        // 1. pre-built env supplied via TDKConfigBuilder::with_environment,
        // 2. file-load via environment_path + environment_name (when
        //    load_environment is true),
        // 3. default empty environment.
        // Its `ssl_certificates` feed the HTTPS client we build next.
        let environment = if let Some(env) = config.prebuilt_environment.clone() {
            env
        } else if config.load_environment {
            match TDKEnvironments::fetch_from_file(
                Some(&config.environment_path),
                &config.environment_name,
            ) {
                Ok(env) => env,
                Err(e) => {
                    warn!(
                        path = %config.environment_path,
                        name = %config.environment_name,
                        error = %e,
                        "environment-file load failed; falling back to default"
                    );
                    TDKEnvironment::default()
                }
            }
        } else {
            TDKEnvironment::default()
        };

        // Parse environment-supplied PEM files; these become extra trust
        // roots on top of the platform verifier.
        let extra_roots = environment.load_ssl_certificates()?;
        let client = create_http_client(&extra_roots)?;

        let authentication = AuthenticationCache::new(
            config.authentication_cache_limit as u64,
            &did_resolver,
            secrets_resolver.clone(),
            &client,
            config.custom_auth_handlers.clone(),
        );
        authentication.start();

        Ok(TDKSharedState {
            config,
            did_resolver,
            secrets_resolver,
            client,
            environment,
            authentication,
        })
    }

    /// Add a [`TDKProfile`]'s secrets to the shared `SecretsResolver`.
    ///
    /// Note: this borrows the profile's secrets — the original `Vec` lives
    /// on with the profile until it is dropped or [`TDKProfile::take_secrets`]
    /// is called. For tighter plaintext lifetime, prefer
    /// [`add_profile_drained`](Self::add_profile_drained), which moves the
    /// secrets into the resolver in one call.
    pub async fn add_profile(&self, profile: &TDKProfile) {
        self.secrets_resolver.insert_vec(profile.secrets()).await;
    }

    /// Drain a profile's secrets into the shared `SecretsResolver`.
    ///
    /// Security-preferred variant of [`add_profile`](Self::add_profile): the
    /// plaintext is moved out of the profile (which retains an empty
    /// allocation), the resolver holds the only live copies, and
    /// `Zeroize`-on-drop fires promptly when those copies are dropped.
    ///
    /// Use this when the profile is no longer needed as a secret carrier
    /// after registration. Use [`add_profile`](Self::add_profile) when the
    /// caller still needs the profile to retain its secrets (e.g. for
    /// later re-registration into a different resolver).
    pub async fn add_profile_drained(&self, profile: &mut TDKProfile) {
        let secrets = profile.take_secrets();
        self.secrets_resolver.insert_vec(&secrets).await;
    }

    /// Resolve the effective mediator DID for a profile, using the active
    /// environment as the fallback. Delegates to
    /// [`TDKEnvironment::resolve_mediator`].
    pub fn resolve_mediator<'a>(&'a self, profile: &'a TDKProfile) -> Option<&'a str> {
        self.environment.resolve_mediator(profile)
    }

    /// Load the environment's [`admin_did`](environments::TDKEnvironment::admin_did)
    /// secrets into the shared `SecretsResolver`, returning the admin
    /// `TDKProfile` (with secrets drained) for further use.
    ///
    /// Admin secrets are sensitive and **not** loaded automatically by
    /// [`new`](Self::new). Call this only when you need the admin identity
    /// active in the resolver.
    ///
    /// The returned profile carries `alias` / `did` / `mediator` only — its
    /// `secrets` `Vec` is drained before return, so the only live plaintext
    /// copy is the one held by the resolver. The original entry on
    /// [`TDKEnvironment::admin_did`] is unmodified (the environment owns the
    /// canonical copy on disk).
    ///
    /// Returns `Ok(None)` if no admin DID is configured.
    pub async fn activate_admin_profile(&self) -> Result<Option<TDKProfile>, TDKError> {
        let Some(admin) = self.environment.admin_did() else {
            return Ok(None);
        };
        let mut admin = admin.clone();
        let secrets = admin.take_secrets();
        self.secrets_resolver.insert_vec(&secrets).await;
        Ok(Some(admin))
    }

    /// Authenticate the given `profile` against `target_did` using the
    /// shared [`AuthenticationCache`] with default retry / timeout
    /// settings (see
    /// [`tasks::authentication::DEFAULT_AUTH_RETRIES`] /
    /// [`tasks::authentication::DEFAULT_AUTH_TIMEOUT`]).
    ///
    /// Returns cached tokens if a valid record exists; otherwise runs a
    /// fresh DID Auth handshake (or refresh, depending on token state).
    pub async fn authenticate_profile(
        &self,
        profile: &TDKProfile,
        target_did: &str,
    ) -> Result<AuthorizationTokens, DIDAuthError> {
        self.authentication
            .authenticate_default(profile.did.clone(), target_did.to_string())
            .await
    }

    /// Configuration this state was built from.
    pub fn config(&self) -> &TDKConfig {
        &self.config
    }

    /// DID resolver cache client.
    pub fn did_resolver(&self) -> &DIDCacheClient {
        &self.did_resolver
    }

    /// Threaded `SecretsResolver` (clone-cheap, internally `Arc`).
    pub fn secrets_resolver(&self) -> &ThreadedSecretsResolver {
        &self.secrets_resolver
    }

    /// Shared HTTP/HTTPS client. Cloning is cheap.
    pub fn client(&self) -> &Client {
        &self.client
    }

    /// Active environment (profiles, default mediator, etc).
    pub fn environment(&self) -> &TDKEnvironment {
        &self.environment
    }

    /// In-process authentication cache + worker handle.
    pub fn authentication(&self) -> &AuthenticationCache {
        &self.authentication
    }

    /// Stop the background [`AuthenticationCache`] task and wait for it to
    /// exit. Call before process shutdown for graceful drain.
    pub async fn shutdown(&self) {
        self.authentication.terminate().await;
    }
}
