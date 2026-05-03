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
//! Until the [`MediatorStore`] trait refactor lands (commits 5–6 of the
//! embedded-mediator branch), the fixture talks to Redis directly via
//! the existing `DatabaseConfig` path. Tests that use this fixture
//! **today** need a reachable Redis. After the refactor, the fixture
//! will default to the in-memory backend and Redis becomes opt-in.
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
use affinidi_secrets_resolver::{SecretsResolver, ThreadedSecretsResolver, secrets::Secret};
use affinidi_tdk::dids::{DID, KeyType, PeerKeyRole};
use jsonwebtoken::{DecodingKey, EncodingKey};
use ring::{rand::SystemRandom, signature::Ed25519KeyPair, signature::KeyPair};
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
}

impl Default for TestMediatorBuilder {
    fn default() -> Self {
        Self {
            store: None,
            listen_addr: None,
            enable_forwarding: false,
            enable_message_expiry: false,
            enable_streaming: true,
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
    /// **Note:** the forwarding processor currently requires the
    /// Redis backend; setting this with the default Memory store has
    /// no effect.
    pub fn enable_forwarding(mut self, enabled: bool) -> Self {
        self.enable_forwarding = enabled;
        self
    }

    /// Enable the message expiry sweep. Defaults to off.
    /// **Note:** Redis-only at the moment, same as `enable_forwarding`.
    pub fn enable_message_expiry(mut self, enabled: bool) -> Self {
        self.enable_message_expiry = enabled;
        self
    }

    /// Enable WebSocket live-streaming registration. Defaults to **on**.
    /// **Note:** the WebSocket task that bridges Redis pub/sub to
    /// connected clients is currently Redis-specific. With the
    /// default Memory store, the WebSocket *handshake* still
    /// completes (the handler tolerates a missing streaming task);
    /// active push delivery requires Redis.
    pub fn enable_streaming(mut self, enabled: bool) -> Self {
        self.enable_streaming = enabled;
        self
    }

    /// Spawn the mediator and wait until it's listening. Returns the
    /// handle once the listener is bound and ready.
    pub async fn spawn(self) -> Result<TestMediatorHandle, TestMediatorError> {
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

        Ok(TestMediatorHandle {
            inner,
            secrets_resolver,
            mediator_secrets,
        })
    }
}

/// Handle to a running test mediator. Drop or call
/// [`TestMediatorHandle::shutdown`] to stop it.
pub struct TestMediatorHandle {
    inner: MediatorHandle,
    secrets_resolver: Arc<ThreadedSecretsResolver>,
    mediator_secrets: Vec<Secret>,
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
/// - DIDComm service endpoint pointing at the bound URL
///
/// Returns the DID, its secrets (for the caller to inspect or merge
/// elsewhere), and a `ThreadedSecretsResolver` already populated with
/// those secrets.
async fn generate_mediator_identity(
    service_uri: &str,
) -> Result<(String, Vec<Secret>, Arc<ThreadedSecretsResolver>), TestMediatorError> {
    let (did, secrets) = DID::generate_did_peer(
        vec![
            (PeerKeyRole::Verification, KeyType::Ed25519),
            (PeerKeyRole::Encryption, KeyType::X25519),
        ],
        Some(service_uri.to_string()),
    )
    .map_err(|e| TestMediatorError::DidGeneration(e.to_string()))?;

    let (resolver, _task) = ThreadedSecretsResolver::new(None).await;
    resolver.insert_vec(&secrets).await;

    // We deliberately leak the secrets task: it lives for the lifetime
    // of the test process. The handle would otherwise be a `JoinHandle`
    // we'd have to track and join — overkill for a test fixture.

    Ok((did, secrets, Arc::new(resolver)))
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
