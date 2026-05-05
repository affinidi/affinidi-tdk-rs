//! Embedded mediator fixture for integration tests.
//!
//! Spins up a fully functional Affinidi messaging mediator on
//! `127.0.0.1:0` (ephemeral port), with a freshly-generated `did:peer`
//! identity, a random JWT signing key, and the caller's choice of
//! storage backend. Returns a [`TestMediatorHandle`] exposing the
//! bound URL, the mediator DID, the populated secrets resolver, and
//! a shutdown control.
//!
//! # Quick start
//!
//! ```ignore
//! use affinidi_messaging_test_mediator::TestMediator;
//!
//! #[tokio::test]
//! async fn end_to_end_round_trip() {
//!     let mediator = TestMediator::builder()
//!         .redis_url("redis://localhost:6379")
//!         .spawn()
//!         .await
//!         .expect("test mediator spawn");
//!
//!     let endpoint = mediator.endpoint();
//!     let did = mediator.did();
//!     // ... use SDK against `endpoint` and `did` ...
//!
//!     mediator.shutdown();
//!     mediator.join().await.unwrap();
//! }
//! ```
//!
//! # Storage backends
//!
//! The fixture defaults to `MemoryStore` — fastest, no I/O, automatic
//! cleanup. Pass a custom store via [`TestMediatorBuilder::store`] for
//! tests that need different semantics:
//!
//! - **Fjall** (on-disk LSM) — compile with the `fjall-backend` feature
//!   and call [`TestMediatorBuilder::fjall_backend`]. The fixture
//!   manages a temp directory whose lifetime is tied to the handle, so
//!   no partition files leak.
//! - **Redis** — supply an `Arc<RedisStore>` via `store(...)`. Useful
//!   for tests that exercise multi-mediator coordination, but requires
//!   a reachable Redis instance.
//!
//! [`MediatorStore`]: affinidi_messaging_mediator_common::store::MediatorStore
//!
//! # DID resolution
//!
//! The mediator's DID is `did:peer:2.*` — fully self-describing. Test
//! clients using `affinidi-did-resolver-cache-sdk` resolve it locally
//! via the built-in `PeerResolver`; no DNS or network round trip is
//! required. The fixture's secrets resolver is pre-populated with the
//! mediator's signing and key-agreement secrets so the SDK can encrypt
//! to the mediator without any setup beyond cloning the resolver:
//!
//! ```ignore
//! let resolver = mediator.secrets_resolver();
//! // hand `resolver` to your SDK setup ...
//! ```

#![deny(rust_2018_idioms)]
#![warn(missing_docs)]

pub mod environment;
pub use environment::{TestEnvironment, TestEnvironmentError, TestUser};

use std::{
    net::{SocketAddr, TcpListener},
    sync::Arc,
};

use affinidi_messaging_mediator::{
    builder::{MediatorBuilder, MediatorHandle, TlsMode},
    store::MemoryStore,
};
use affinidi_messaging_mediator_common::{
    MediatorSecrets, errors::MediatorError, secrets::backends::MemoryStore as SecretsMemoryStore,
    store::MediatorStore,
};
use affinidi_messaging_sdk::protocols::mediator::acls::MediatorACLSet;
use affinidi_secrets_resolver::{SecretsResolver, ThreadedSecretsResolver, secrets::Secret};
use affinidi_tdk::dids::{
    DID, KeyType, OneOrMany, PeerKeyRole, PeerService, PeerServiceEndpoint, PeerServiceEndpointLong,
};
use jsonwebtoken::{DecodingKey, EncodingKey};
use ring::{rand::SystemRandom, signature::Ed25519KeyPair, signature::KeyPair};
use sha256::digest;
use thiserror::Error;
use tokio_util::sync::CancellationToken;
use url::Url;

// ─── Errors ──────────────────────────────────────────────────────────────────

/// Errors returned by the test mediator fixture.
#[derive(Debug, Error)]
pub enum TestMediatorError {
    /// A DID generation step failed.
    #[error("did:peer generation failed: {0}")]
    DidGeneration(String),
    /// The fixture could not bind a TCP listener on `127.0.0.1:0`.
    #[error("listener bind failed: {0}")]
    Bind(#[source] std::io::Error),
    /// Generating the JWT signing key pair failed.
    #[error("JWT key generation failed: {0}")]
    JwtKey(String),
    /// The underlying mediator returned an error.
    #[error(transparent)]
    Mediator(#[from] MediatorError),
}

// ─── Public API ──────────────────────────────────────────────────────────────

/// Entry point. Use [`TestMediator::builder`] to configure, or
/// [`TestMediator::spawn`] for the all-defaults flow.
pub struct TestMediator;

impl TestMediator {
    /// Begin configuring a test mediator instance.
    pub fn builder() -> TestMediatorBuilder {
        TestMediatorBuilder::default()
    }

    /// Convenience wrapper around `builder().spawn().await`. Uses the
    /// default in-memory store and an ephemeral 127.0.0.1 port.
    pub async fn spawn() -> Result<TestMediatorHandle, TestMediatorError> {
        Self::builder().spawn().await
    }
}

/// Configuration knobs for the test mediator.
///
/// All fields have sensible defaults for the most common test scenario:
/// in-memory store, ephemeral port, no forwarding processor. Tests
/// with special needs override via the setters.
pub struct TestMediatorBuilder {
    /// Pre-built store. `None` means "construct a fresh
    /// `MemoryStore` on spawn." Tests with persistence requirements
    /// (or that want to share a store across multiple mediator
    /// instances) supply their own.
    store: Option<Arc<dyn MediatorStore>>,
    listen_addr: Option<SocketAddr>,
    enable_forwarding: bool,
    enable_message_expiry: bool,
    enable_streaming: bool,
    /// Additional DIDs to register as LOCAL accounts at startup. Tests
    /// that authenticate over WebSocket must include their client DID
    /// here — the WS upgrade handler refuses connections from sessions
    /// without the LOCAL ACL bit set.
    local_dids: Vec<String>,
    /// Temp directory backing a Fjall store, kept alive for the lifetime
    /// of the resulting handle so the partition files don't get cleaned
    /// up while the mediator is still using them.
    #[cfg(feature = "fjall-backend")]
    fjall_dir: Option<tempfile::TempDir>,
}

impl Default for TestMediatorBuilder {
    fn default() -> Self {
        Self {
            store: None,
            listen_addr: None,
            enable_forwarding: false,
            enable_message_expiry: false,
            enable_streaming: true,
            local_dids: Vec::new(),
            #[cfg(feature = "fjall-backend")]
            fjall_dir: None,
        }
    }
}

impl TestMediatorBuilder {
    /// Supply a pre-built store. Default is a fresh
    /// [`MemoryStore`](affinidi_messaging_mediator::store::MemoryStore)
    /// constructed on spawn.
    ///
    /// Pass an `Arc<RedisStore>` here when a test specifically needs
    /// the Redis backend's cross-process pub/sub or persistence
    /// guarantees.
    pub fn store(mut self, store: Arc<dyn MediatorStore>) -> Self {
        self.store = Some(store);
        self
    }

    /// Bind to an explicit address. Defaults to `127.0.0.1:0`
    /// (ephemeral port chosen by the OS).
    pub fn listen_addr(mut self, addr: SocketAddr) -> Self {
        self.listen_addr = Some(addr);
        self
    }

    /// Enable the forwarding processor. Defaults to off — most tests
    /// don't exercise routing 2.0 forwarding to remote mediators.
    /// Runs against any backend via the `MediatorStore` trait.
    pub fn enable_forwarding(mut self, enabled: bool) -> Self {
        self.enable_forwarding = enabled;
        self
    }

    /// Enable the message expiry sweep. Defaults to off. Runs against
    /// any backend via the `MediatorStore` trait.
    pub fn enable_message_expiry(mut self, enabled: bool) -> Self {
        self.enable_message_expiry = enabled;
        self
    }

    /// Enable WebSocket live-streaming registration. Defaults to **on**.
    /// Runs against any backend via the `MediatorStore` trait — Memory
    /// and Fjall feed an in-process broadcast channel; Redis bridges
    /// pub/sub into the same shape.
    pub fn enable_streaming(mut self, enabled: bool) -> Self {
        self.enable_streaming = enabled;
        self
    }

    /// Register `did` as a LOCAL account on the mediator at startup.
    ///
    /// The mediator's WebSocket handler refuses upgrades unless the
    /// authenticated session has the LOCAL ACL bit. By default, a DID
    /// that authenticates against the test mediator is auto-registered
    /// with `global_acl_default` — which has `local = false` for the
    /// test fixture. Tests that need to open a WS connection from a
    /// non-admin DID must register that DID here so it lands in the
    /// account store with the LOCAL bit set.
    ///
    /// Repeated calls accumulate. The DID is stored as the raw
    /// `did:`-shaped string; the SHA-256 hash used by the account
    /// store is computed at spawn time.
    pub fn local_did(mut self, did: impl Into<String>) -> Self {
        self.local_dids.push(did.into());
        self
    }

    /// Register multiple DIDs as LOCAL accounts. See [`local_did`].
    ///
    /// [`local_did`]: Self::local_did
    pub fn local_dids<I, S>(mut self, dids: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.local_dids.extend(dids.into_iter().map(Into::into));
        self
    }

    /// Run this test mediator against an on-disk Fjall backend instead
    /// of the default in-memory store. The data lives in a temporary
    /// directory tied to the resulting handle — when the handle drops,
    /// the temp dir and all partition files are deleted.
    ///
    /// Use this for tests that need to exercise persistence semantics
    /// (e.g. messages survive restart, expiry indices live on disk).
    /// `MemoryStore` is faster for the common case of "did the
    /// handler return the right shape."
    #[cfg(feature = "fjall-backend")]
    pub fn fjall_backend(mut self) -> Result<Self, TestMediatorError> {
        use affinidi_messaging_mediator::store::FjallStore;
        let dir = tempfile::tempdir().map_err(TestMediatorError::Bind)?;
        let store = FjallStore::open(dir.path()).map_err(TestMediatorError::Mediator)?;
        self.store = Some(Arc::new(store));
        // Hold the temp dir alive for the lifetime of the builder so
        // it lands in the handle's `_fjall_dir` slot once `spawn` runs.
        self.fjall_dir = Some(dir);
        Ok(self)
    }

    /// Spawn the mediator and wait until it's listening. Returns the
    /// handle once the listener is bound and ready.
    pub async fn spawn(self) -> Result<TestMediatorHandle, TestMediatorError> {
        // Pick the rustls + jsonwebtoken default `CryptoProvider`s
        // before any handshake has a chance to run. When a downstream
        // test crate transitively activates the `rust_crypto` feature
        // alongside the mediator's `aws_lc_rs`, rustls refuses to pick
        // a default and panics on first use; installing here is
        // idempotent and removes that boilerplate from consumers.
        install_default_crypto_provider();

        let bound_addr = bind_ephemeral_listener(self.listen_addr)?;
        let api_prefix = "/mediator/v1/".to_string();
        let service_uri = format!("http://{bound_addr}{api_prefix}");

        let (mediator_did, mediator_secrets, secrets_resolver) =
            generate_mediator_identity(&service_uri).await?;
        let admin_did = format!("did:key:z6Mk{}", uuid::Uuid::new_v4().simple());

        // JWT signing key — Ed25519 PKCS8, same shape as the production
        // path's `JWT_SECRET` well-known.
        let (jwt_encoding_key, jwt_decoding_key) = generate_jwt_keys()?;

        let secrets_backend =
            MediatorSecrets::new(Arc::new(SecretsMemoryStore::new("test-mediator-memory")));

        let mut security = affinidi_messaging_mediator::common::config::SecurityConfig::headless(
            secrets_resolver.clone(),
        );
        security.jwt_encoding_key = jwt_encoding_key;
        security.jwt_decoding_key = jwt_decoding_key;
        security.use_ssl = false;

        // Disable processors that aren't useful in most tests.
        let mut processors =
            affinidi_messaging_mediator::common::config::ProcessorsConfig::default();
        processors.forwarding.enabled = self.enable_forwarding;
        processors.message_expiry_cleanup.enabled = self.enable_message_expiry;

        // Default to a fresh in-memory store. Tests that want a
        // shared or persistent backend pass their own via `store()`.
        let store: Arc<dyn MediatorStore> =
            self.store.unwrap_or_else(|| Arc::new(MemoryStore::new()));
        // Hold a clone so we can register pre-declared local DIDs after
        // the mediator has finished initialising the store.
        let store_for_local_accounts = store.clone();

        let token = CancellationToken::new();
        let inner = MediatorBuilder::new(secrets_resolver.clone())
            .mediator_did(&mediator_did)
            .admin_did(&admin_did)
            .secrets_backend(secrets_backend)
            .secrets_backend_url("memory://(test-mediator)")
            .store(store)
            .listen_addr(bound_addr)
            .api_prefix(api_prefix)
            .security(security)
            .processors(processors)
            .streaming_enabled(self.enable_streaming)
            .tls(TlsMode::Plain)
            .start(token.clone())
            .await?;

        // Register caller-supplied DIDs as LOCAL accounts so they can
        // complete the WebSocket upgrade after authenticating. The
        // store is initialised by `MediatorBuilder::start` above, so
        // `account_add` is safe to call here regardless of backend.
        register_local_dids(&store_for_local_accounts, &self.local_dids).await?;

        Ok(TestMediatorHandle {
            inner,
            secrets_resolver,
            mediator_secrets,
            #[cfg(feature = "fjall-backend")]
            _fjall_dir: self.fjall_dir,
        })
    }
}

/// Handle to a running test mediator. Drop or call
/// [`TestMediatorHandle::shutdown`] to stop it.
pub struct TestMediatorHandle {
    inner: MediatorHandle,
    secrets_resolver: Arc<ThreadedSecretsResolver>,
    mediator_secrets: Vec<Secret>,
    /// Backing temp dir for the Fjall store (when applicable). Held
    /// alongside the handle so the partition files survive as long as
    /// the mediator is using them, and get cleaned up on drop.
    #[cfg(feature = "fjall-backend")]
    _fjall_dir: Option<tempfile::TempDir>,
}

impl TestMediatorHandle {
    /// HTTP base URL the mediator is listening on, e.g.
    /// `http://127.0.0.1:54321/mediator/v1/`.
    pub fn endpoint(&self) -> &Url {
        &self.inner.http_endpoint
    }

    /// WebSocket URL for live streaming, e.g.
    /// `ws://127.0.0.1:54321/mediator/v1/ws`.
    pub fn ws_endpoint(&self) -> &Url {
        &self.inner.ws_endpoint
    }

    /// Bound socket address.
    pub fn bound_addr(&self) -> SocketAddr {
        self.inner.bound_addr
    }

    /// The mediator's DID.
    pub fn did(&self) -> &str {
        &self.inner.mediator_did
    }

    /// The admin DID configured at startup.
    pub fn admin_did(&self) -> &str {
        &self.inner.admin_did
    }

    /// Pre-populated secrets resolver. Tests should clone this and
    /// pass it into their SDK setup so the test client can sign and
    /// decrypt messages addressed to the mediator.
    pub fn secrets_resolver(&self) -> Arc<ThreadedSecretsResolver> {
        self.secrets_resolver.clone()
    }

    /// The mediator's signing and key-agreement secrets, in case the
    /// caller wants to merge them into a different resolver.
    pub fn mediator_secrets(&self) -> &[Secret] {
        &self.mediator_secrets
    }

    /// Shareable shutdown token. Cancel from anywhere to drain the
    /// mediator without consuming the handle.
    pub fn shutdown_token(&self) -> CancellationToken {
        self.inner.shutdown_token()
    }

    /// Trigger graceful shutdown. The server stops accepting new
    /// connections and drains in-flight requests for up to 30s.
    pub fn shutdown(&self) {
        self.inner.shutdown();
    }

    /// Wait for the mediator to exit. Consumes the handle.
    pub async fn join(self) -> Result<(), MediatorError> {
        self.inner.join().await
    }
}

impl std::fmt::Debug for TestMediatorHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestMediatorHandle")
            .field("endpoint", &self.endpoint().as_str())
            .field("did", &self.did())
            .field("admin_did", &self.admin_did())
            .field("bound_addr", &self.bound_addr())
            .finish()
    }
}

// ─── Crypto provider bootstrap ───────────────────────────────────────────────

/// Install rustls' `aws_lc_rs` provider as the process-wide default,
/// idempotently. Safe to call multiple times — once a default is
/// registered, subsequent calls are no-ops.
///
/// Test crates that depend on both this fixture (which builds against
/// `aws_lc_rs`) and another crate that activates the `rust_crypto`
/// rustls provider end up with two providers in the feature graph and
/// no automatic default; rustls panics on the first handshake. Calling
/// this once at process start (or letting `TestMediator::spawn` call
/// it for you) resolves the ambiguity.
///
/// Also installs jsonwebtoken's `aws_lc_rs` provider for the same
/// reason. Errors from already-installed providers are ignored.
pub fn install_default_crypto_provider() {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }
    let _ = jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER.install_default();
}

// ─── Internals ───────────────────────────────────────────────────────────────

/// Bind an ephemeral listener, capture the address, then drop it so
/// the mediator can re-bind to the same port. There is a tiny TOCTOU
/// window between drop and re-bind during which another process could
/// claim the port; in practice it's microseconds and harmless for
/// tests. If this proves flaky in CI, extend `MediatorBuilder` to
/// accept a pre-bound `TcpListener` and remove the rebind step.
fn bind_ephemeral_listener(requested: Option<SocketAddr>) -> Result<SocketAddr, TestMediatorError> {
    let target: SocketAddr = requested.unwrap_or_else(|| "127.0.0.1:0".parse().unwrap());
    let listener = TcpListener::bind(target).map_err(TestMediatorError::Bind)?;
    let addr = listener.local_addr().map_err(TestMediatorError::Bind)?;
    drop(listener);
    Ok(addr)
}

/// Generate the mediator's `did:peer:2` identity:
/// - Ed25519 verification key
/// - X25519 key-agreement key
/// - DIDComm service entry (default `#service`) pointing at the bound URL
/// - Authentication service entry (`#auth`) pointing at
///   `<bound_url>authenticate` — required for clients that authenticate
///   via `affinidi-did-authentication` (which looks for a service whose
///   id ends in `#auth`). Mirrors the canonical mediator DID shape
///   produced by the `didcomm-mediator` template.
///
/// Returns the DID, its secrets (for the caller to inspect or merge
/// elsewhere), and a `ThreadedSecretsResolver` already populated with
/// those secrets.
async fn generate_mediator_identity(
    service_uri: &str,
) -> Result<(String, Vec<Secret>, Arc<ThreadedSecretsResolver>), TestMediatorError> {
    // `service_uri` is `http://<bound>/mediator/v1/` (trailing slash).
    // The DIDComm service entry advertises both HTTP and WS endpoints
    // (matching the canonical mediator-template shape) so SDK clients
    // that prefer the streaming transport can find a `ws://` URI. The
    // `#auth` endpoint is `<service_uri>authenticate` (no extra slash
    // — `service_uri` already ends in `/`); the auth library appends
    // `/challenge` itself, yielding `…/authenticate/challenge`.
    let ws_uri = format!(
        "ws://{}",
        service_uri
            .trim_start_matches("http://")
            .trim_end_matches('/'),
    ) + "/ws";
    let auth_uri = format!("{service_uri}authenticate");
    let services = vec![
        PeerService {
            type_: "dm".into(),
            endpoint: PeerServiceEndpoint::Long(OneOrMany::Many(vec![
                PeerServiceEndpointLong {
                    uri: service_uri.to_string(),
                    accept: vec!["didcomm/v2".into()],
                    routing_keys: vec![],
                },
                PeerServiceEndpointLong {
                    uri: ws_uri,
                    accept: vec!["didcomm/v2".into()],
                    routing_keys: vec![],
                },
            ])),
            id: None,
        },
        PeerService {
            type_: "Authentication".into(),
            endpoint: PeerServiceEndpoint::Uri(auth_uri),
            id: Some("#auth".into()),
        },
    ];
    let (did, secrets) = DID::generate_did_peer_with_services(
        vec![
            (PeerKeyRole::Verification, KeyType::Ed25519),
            (PeerKeyRole::Encryption, KeyType::X25519),
        ],
        Some(services),
    )
    .map_err(|e| TestMediatorError::DidGeneration(e.to_string()))?;

    let (resolver, _task) = ThreadedSecretsResolver::new(None).await;
    resolver.insert_vec(&secrets).await;

    // We deliberately leak the secrets task: it lives for the lifetime
    // of the test process. The handle would otherwise be a `JoinHandle`
    // we'd have to track and join — overkill for a test fixture.

    Ok((did, secrets, Arc::new(resolver)))
}

/// Insert each DID into the mediator's account store as a LOCAL,
/// non-admin account. Idempotent — a DID that already has an account
/// record is left untouched, matching the auto-registration path used
/// by the JWT challenge handler.
///
/// Uses the `ALLOW_ALL` ruleset so the registered DID can fully
/// exercise the mediator (send / receive / forward / WS upgrade)
/// without being granted admin role. Tests that want stricter ACLs
/// can register the DID directly via the underlying store.
async fn register_local_dids(
    store: &Arc<dyn MediatorStore>,
    dids: &[String],
) -> Result<(), TestMediatorError> {
    if dids.is_empty() {
        return Ok(());
    }
    let acls = MediatorACLSet::from_string_ruleset("ALLOW_ALL").map_err(|e| {
        TestMediatorError::Mediator(MediatorError::ConfigError(
            12,
            "test-mediator".into(),
            format!("failed to build ALLOW_ALL ACL set: {e}"),
        ))
    })?;
    for did in dids {
        let did_hash = digest(did);
        if store.account_exists(&did_hash).await? {
            continue;
        }
        store.account_add(&did_hash, &acls, None).await?;
    }
    Ok(())
}

/// Generate a fresh Ed25519 keypair for JWT signing. Mirrors the
/// production code path (`security.rs::convert`) which loads PKCS8
/// bytes from the secrets backend and derives the public key for
/// verification.
fn generate_jwt_keys() -> Result<(EncodingKey, DecodingKey), TestMediatorError> {
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|e| TestMediatorError::JwtKey(format!("ring pkcs8 generate: {e}")))?;
    let pkcs8_bytes = pkcs8.as_ref();

    let encoding_key = EncodingKey::from_ed_der(pkcs8_bytes);
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes)
        .map_err(|e| TestMediatorError::JwtKey(format!("ring pkcs8 parse: {e}")))?;
    let decoding_key = DecodingKey::from_ed_der(pair.public_key().as_ref());

    Ok((encoding_key, decoding_key))
}

// ─── Quick sanity test ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jwt_keys_generate() {
        let result = generate_jwt_keys();
        assert!(result.is_ok(), "JWT key generation should succeed");
    }

    #[test]
    fn ephemeral_listener_returns_real_port() {
        let addr = bind_ephemeral_listener(None).expect("bind");
        assert_eq!(addr.ip().to_string(), "127.0.0.1");
        assert!(addr.port() > 0, "OS-assigned port should be non-zero");
    }

    #[tokio::test]
    async fn mediator_identity_generates_peer_did() {
        let result = generate_mediator_identity("http://127.0.0.1:0/mediator/v1/").await;
        let (did, secrets, _resolver) = result.expect("identity generation");
        assert!(did.starts_with("did:peer:2."), "expected did:peer:2.*");
        assert_eq!(secrets.len(), 2, "expected verification + encryption keys");
    }
}
