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
//!     let mediator = TestMediator::spawn()
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
//! Tests that authenticate a non-admin client over WebSocket must
//! pre-register the client's DID — the WS handler refuses upgrades
//! without the LOCAL ACL bit, and the fixture's default
//! `global_acl_default` doesn't grant it on first auth:
//!
//! ```ignore
//! let mediator = TestMediator::builder()
//!     .local_did(client_did.clone())
//!     .spawn()
//!     .await
//!     .expect("spawn");
//! ```
//!
//! See [`TestMediatorBuilder::local_did`] / [`TestMediatorBuilder::local_dids`].
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

pub mod acl;
pub mod environment;
pub use environment::{TestEnvironment, TestEnvironmentError, TestUser};

// Re-exports so consumers don't have to add a direct dep on
// mediator-common just to construct an `acl_mode(...)` argument or
// inspect a `MediatorACLSet` returned by `get_acl(...)`.
pub use affinidi_messaging_mediator_common::types::acls::{
    ACLError, AccessListModeType, MediatorACLSet,
};

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
    /// An ACL bit-setter rejected an operation, or a preset
    /// constructor surfaced one. In practice the presets in
    /// [`crate::acl`] never fail (they pass `admin = true`); this
    /// variant exists so future tightening of the production setters
    /// surfaces here rather than via panic.
    #[error("ACL operation failed: {0}")]
    Acl(#[from] ACLError),
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

    /// Generate a fresh `did:peer:2` identity (Ed25519 verification +
    /// X25519 key agreement) suitable for use as the mediator's admin
    /// DID via [`TestMediatorBuilder::admin_identity`]. Mirrors the
    /// `add_user` flow, minus the secrets-resolver insertion — the
    /// admin's secrets stay with the caller. Pair with
    /// [`TestEnvironment::add_admin`] to wire up an SDK profile that
    /// authenticates as admin.
    ///
    /// The returned [`AdminIdentity`] can be cloned freely; the same
    /// identity can drive multiple test-mediator instances or external
    /// SDK clients.
    pub fn random_admin_identity() -> Result<AdminIdentity, TestMediatorError> {
        let (did, secrets) = DID::generate_did_peer(
            vec![
                (PeerKeyRole::Verification, KeyType::Ed25519),
                (PeerKeyRole::Encryption, KeyType::X25519),
            ],
            None,
        )
        .map_err(|e| TestMediatorError::DidGeneration(e.to_string()))?;
        Ok(AdminIdentity { did, secrets })
    }

    /// Spawn a default test mediator and pre-create one
    /// [`TestMediatorUser`] per supplied alias. Each user is a
    /// `did:peer:2.*` whose DIDComm service endpoint is the mediator's
    /// DID (the routing 2.0 shape — see the README's "Local vs.
    /// remote routing" section), already registered with the mediator
    /// as a LOCAL, `ALLOW_ALL` account, and whose key material is
    /// inserted into the mediator's secrets resolver so callers can
    /// pack and unpack messages without any extra wiring.
    ///
    /// Returns the mediator handle alongside the users in the same
    /// order the aliases were passed. For ATM-based scenarios that
    /// also want a wired-up SDK client, use
    /// [`TestEnvironment::add_user`] instead.
    pub async fn with_users<I, S>(
        aliases: I,
    ) -> Result<(TestMediatorHandle, Vec<TestMediatorUser>), TestMediatorError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let handle = Self::spawn().await?;
        let mut users = Vec::new();
        for alias in aliases {
            users.push(handle.add_user(alias).await?);
        }
        Ok((handle, users))
    }
}

/// One participant returned by [`TestMediator::with_users`] /
/// [`TestMediatorHandle::add_user`].
///
/// Owns its own `did:peer` and key material. Already registered on
/// the mediator (LOCAL, ALLOW_ALL) and inserted into the mediator's
/// secrets resolver, so a caller only needs to plug `did` and
/// `secrets` into whatever DIDComm stack they're testing.
#[derive(Debug, Clone)]
pub struct TestMediatorUser {
    /// `did:peer:2.*` whose DIDComm service URI is the mediator's DID.
    pub did: String,
    /// Human-readable alias (e.g. `"alice"`).
    pub alias: String,
    /// Verification + key-agreement secrets for `did`. Already
    /// inserted into the mediator's shared secrets resolver — copy
    /// elsewhere only if you need a separate resolver.
    pub secrets: Vec<Secret>,
}

impl TestMediatorUser {
    /// SHA-256 hash of the DID string — the canonical key shape used
    /// by the mediator's account / ACL / queue stores. Pass this to
    /// admin-protocol calls (e.g. `acls_set`, `access_list_add`,
    /// `account_remove`) that operate on hashed DIDs.
    pub fn did_hash(&self) -> String {
        digest(&self.did)
    }
}

/// A stable admin identity for the test mediator. The `did` is set
/// as the mediator's `admin_did` (via
/// [`TestMediatorBuilder::admin_identity`]) and the `secrets` are
/// returned to the caller so they can sign DIDComm messages and
/// HTTP-auth challenges as admin.
///
/// Construct via [`TestMediator::random_admin_identity`] for a
/// freshly generated `did:peer:2`. Build your own when a test needs
/// a stable DID across runs (e.g. to reuse cached resolver state).
///
/// **Secrets ownership.** The `secrets` field stays with the caller.
/// Unlike [`TestMediatorHandle::add_user`], the test-mediator does
/// **not** insert these into its own server-side secrets resolver
/// (that resolver holds the mediator's operating keys, not its
/// admin's). The admin authenticates via DID resolution + signature
/// verification of the HTTP-auth challenge, so the private key never
/// crosses the fixture boundary. Pass the secrets to whatever
/// DIDComm or SDK auth client you're driving from the test —
/// [`TestEnvironment::add_admin`] handles this for you.
#[derive(Debug, Clone)]
pub struct AdminIdentity {
    /// `did:peer:2.*` admin DID.
    pub did: String,
    /// Verification + key-agreement secrets for `did`.
    pub secrets: Vec<Secret>,
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
    enable_external_forwarding: bool,
    enable_message_expiry: bool,
    enable_streaming: bool,
    /// Additional DIDs to register as LOCAL accounts at startup. Tests
    /// that authenticate over WebSocket must include their client DID
    /// here — the WS upgrade handler refuses connections from sessions
    /// without the LOCAL ACL bit set.
    local_dids: Vec<String>,
    /// Public service URLs to forward to `MediatorBuilder::local_endpoints`
    /// (mediator 0.15.0+). Empty by default; set this when the mediator
    /// is reachable via additional hostnames or ports beyond
    /// `listen_addr`.
    local_endpoints: Vec<String>,
    /// Override for `SecurityConfig.mediator_acl_mode`. `None` keeps the
    /// production default (`ExplicitDeny`).
    acl_mode: Option<AccessListModeType>,
    /// Override for `SecurityConfig.global_acl_default`. `None` keeps the
    /// production default (`MediatorACLSet::default()`).
    global_acl_default: Option<MediatorACLSet>,
    /// Override for `SecurityConfig.local_direct_delivery_allowed`.
    local_direct_delivery_allowed: Option<bool>,
    /// Override for `SecurityConfig.local_direct_delivery_allow_anon`.
    local_direct_delivery_allow_anon: Option<bool>,
    /// Override for `SecurityConfig.block_anonymous_outer_envelope`.
    block_anonymous_outer_envelope: Option<bool>,
    /// Override for `SecurityConfig.force_session_did_match`.
    force_session_did_match: Option<bool>,
    /// Override for `SecurityConfig.block_remote_admin_msgs`.
    block_remote_admin_msgs: Option<bool>,
    /// Override for `SecurityConfig.jwt_access_expiry` (seconds).
    jwt_access_expiry_secs: Option<u64>,
    /// Override for `SecurityConfig.jwt_refresh_expiry` (seconds).
    jwt_refresh_expiry_secs: Option<u64>,
    /// Stable admin identity for the mediator. `None` mints the
    /// historical opaque `did:key:z6Mk{uuid}` shape with no usable
    /// secrets — suitable for tests that don't authenticate as admin.
    admin_identity: Option<AdminIdentity>,
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
            enable_external_forwarding: true,
            enable_message_expiry: false,
            enable_streaming: true,
            local_dids: Vec::new(),
            local_endpoints: Vec::new(),
            acl_mode: None,
            global_acl_default: None,
            local_direct_delivery_allowed: None,
            local_direct_delivery_allow_anon: None,
            block_anonymous_outer_envelope: None,
            force_session_did_match: None,
            block_remote_admin_msgs: None,
            jwt_access_expiry_secs: None,
            jwt_refresh_expiry_secs: None,
            admin_identity: None,
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

    /// Enable forwarding to *remote* mediators when the next-hop DID
    /// resolves to a non-local service endpoint. Defaults to **on**
    /// (matching `ForwardingConfig::default`).
    ///
    /// Set to `false` for tests that want every `routing/2.0/forward`
    /// to fall through to local delivery regardless of what the
    /// next-hop's DID Document says — useful when test user DIDs were
    /// generated with the mediator's HTTP URL as the service endpoint
    /// (instead of the mediator's DID), since the routing handler would
    /// otherwise classify them as remote and push them onto FORWARD_Q.
    ///
    /// Has no effect unless [`enable_forwarding`] is also `true`.
    ///
    /// [`enable_forwarding`]: Self::enable_forwarding
    pub fn enable_external_forwarding(mut self, enabled: bool) -> Self {
        self.enable_external_forwarding = enabled;
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

    // ─── ACL / security knobs ────────────────────────────────────────

    /// Override the mediator's access-list mode. Defaults to
    /// `ExplicitDeny` (matching `SecurityConfig::default`). Set to
    /// `ExplicitAllow` to simulate an allowlist deployment, where DIDs
    /// without an explicit `LOCAL` ACL bit are rejected.
    pub fn acl_mode(mut self, mode: AccessListModeType) -> Self {
        self.acl_mode = Some(mode);
        self
    }

    /// Override the global ACL applied to any DID that authenticates
    /// without a pre-existing account. Pair with [`crate::acl`]
    /// presets (`acl::allow_all()`, `acl::deny_all()`) for the common
    /// cases, or build a [`MediatorACLSet`] directly via
    /// `MediatorACLSet::default()` plus the bit setters for fine-grained
    /// control. Defaults to `MediatorACLSet::default()`.
    pub fn global_acl_default(mut self, acls: MediatorACLSet) -> Self {
        self.global_acl_default = Some(acls);
        self
    }

    /// Override `local_direct_delivery_allowed` and
    /// `local_direct_delivery_allow_anon`. Defaults match
    /// `SecurityConfig` (both `false`).
    pub fn local_direct_delivery(mut self, allowed: bool, allow_anon: bool) -> Self {
        self.local_direct_delivery_allowed = Some(allowed);
        self.local_direct_delivery_allow_anon = Some(allow_anon);
        self
    }

    /// Override `block_anonymous_outer_envelope`. Defaults to the
    /// production value (the headless config currently keeps anon
    /// envelopes enabled).
    pub fn block_anonymous_outer_envelope(mut self, block: bool) -> Self {
        self.block_anonymous_outer_envelope = Some(block);
        self
    }

    /// Override `force_session_did_match`. Defaults to the production
    /// value.
    pub fn force_session_did_match(mut self, force: bool) -> Self {
        self.force_session_did_match = Some(force);
        self
    }

    /// Override `block_remote_admin_msgs`. Defaults to the production
    /// value.
    pub fn block_remote_admin_msgs(mut self, block: bool) -> Self {
        self.block_remote_admin_msgs = Some(block);
        self
    }

    /// Override JWT expiries. Defaults: 900 s access, 86 400 s refresh.
    /// Useful for testing token-refresh flows by shrinking access
    /// expiry to a few seconds.
    pub fn jwt_expiry(mut self, access: std::time::Duration, refresh: std::time::Duration) -> Self {
        self.jwt_access_expiry_secs = Some(access.as_secs());
        self.jwt_refresh_expiry_secs = Some(refresh.as_secs());
        self
    }

    // ─── Routing / endpoint config ───────────────────────────────────

    /// Declare additional URLs at which the mediator is reachable.
    /// Forwarded to `MediatorBuilder::local_endpoints` (mediator
    /// 0.15.0+) so the routing-2.0 self-loopback handler treats
    /// forwards to those URLs as local. The bind address is always
    /// treated as local — only set this when the mediator is reachable
    /// via additional hostnames or ports beyond the bind address.
    pub fn local_endpoints<I, S>(mut self, endpoints: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.local_endpoints
            .extend(endpoints.into_iter().map(Into::into));
        self
    }

    // ─── Admin identity ──────────────────────────────────────────────

    /// Use a specific admin identity. Defaults to a random
    /// `did:key:z6Mk{uuid}` shape with no usable secrets — fine for
    /// tests that don't authenticate as admin. Pass an
    /// [`AdminIdentity`] (see [`TestMediator::random_admin_identity`])
    /// when admin-protocol or account-management tests need to sign
    /// as admin.
    ///
    /// **Secrets are NOT inserted into the mediator's secrets resolver.**
    /// The caller owns `identity.secrets`. The mediator authenticates
    /// the admin via DID resolution (peer:2 resolves locally) and
    /// signature verification of the HTTP-auth challenge — the private
    /// key never crosses the fixture boundary. Pass the secrets to
    /// whatever DIDComm or SDK auth client you're driving from the
    /// test ([`TestEnvironment::add_admin`] handles this for you).
    pub fn admin_identity(mut self, identity: AdminIdentity) -> Self {
        self.admin_identity = Some(identity);
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
        // Honor an operator-supplied admin identity if present —
        // otherwise fall back to the historical opaque shape so tests
        // that don't authenticate as admin keep working unchanged.
        let admin_did = match self.admin_identity.as_ref() {
            Some(id) => id.did.clone(),
            None => format!("did:key:z6Mk{}", uuid::Uuid::new_v4().simple()),
        };

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
        // Apply Option-typed overrides — `None` keeps the headless
        // default, so behavior for callers that don't touch these
        // setters is unchanged from earlier releases.
        if let Some(mode) = self.acl_mode {
            security.mediator_acl_mode = mode;
        }
        if let Some(acls) = self.global_acl_default.clone() {
            security.global_acl_default = acls;
        }
        if let Some(b) = self.local_direct_delivery_allowed {
            security.local_direct_delivery_allowed = b;
        }
        if let Some(b) = self.local_direct_delivery_allow_anon {
            security.local_direct_delivery_allow_anon = b;
        }
        if let Some(b) = self.block_anonymous_outer_envelope {
            security.block_anonymous_outer_envelope = b;
        }
        if let Some(b) = self.force_session_did_match {
            security.force_session_did_match = b;
        }
        if let Some(b) = self.block_remote_admin_msgs {
            security.block_remote_admin_msgs = b;
        }
        if let Some(secs) = self.jwt_access_expiry_secs {
            security.jwt_access_expiry = secs;
        }
        if let Some(secs) = self.jwt_refresh_expiry_secs {
            security.jwt_refresh_expiry = secs;
        }

        // Disable processors that aren't useful in most tests.
        let mut processors =
            affinidi_messaging_mediator::common::config::ProcessorsConfig::default();
        processors.forwarding.enabled = self.enable_forwarding;
        processors.forwarding.external_forwarding = self.enable_external_forwarding;
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
            .local_endpoints(self.local_endpoints.clone())
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
            store: store_for_local_accounts,
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
    /// Live reference to the account/message store, kept so callers
    /// can register additional local DIDs after spawn (see
    /// [`Self::register_local_did`]). Cloned from the same `Arc` the
    /// mediator runs against, so writes here are visible to the
    /// running mediator immediately.
    store: Arc<dyn MediatorStore>,
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

    /// Register `did` as a LOCAL, ALLOW_ALL account on the running
    /// mediator. Idempotent — a DID that already has an account
    /// record is left untouched.
    ///
    /// This is the runtime counterpart to
    /// [`TestMediatorBuilder::local_did`]: use it after spawn when the
    /// caller didn't yet know the mediator's DID at builder time
    /// (since user DIDs typically advertise the mediator DID as their
    /// service endpoint, and the mediator DID isn't generated until
    /// `spawn`).
    pub async fn register_local_did(&self, did: &str) -> Result<(), TestMediatorError> {
        register_local_did(&self.store, did).await
    }

    /// Generate a fresh `did:peer:2.*` whose DIDComm service URI is
    /// this mediator's DID, register it as a LOCAL ALLOW_ALL account,
    /// insert its secrets into the mediator's resolver, and return
    /// the user.
    ///
    /// The post-spawn counterpart to [`TestMediator::with_users`].
    /// Use this when a test needs to add participants incrementally
    /// rather than declaring them up front.
    pub async fn add_user(
        &self,
        alias: impl Into<String>,
    ) -> Result<TestMediatorUser, TestMediatorError> {
        self.mint_user(alias.into(), acl::allow_all()).await
    }

    /// Mint a fresh `did:peer:2.*` user (same shape as [`add_user`])
    /// but register it with `acls` instead of the typed `ALLOW_ALL`
    /// preset. Useful for testing denied paths without reaching into
    /// the underlying store.
    pub async fn add_user_with_acl(
        &self,
        alias: impl Into<String>,
        acls: MediatorACLSet,
    ) -> Result<TestMediatorUser, TestMediatorError> {
        self.mint_user(alias.into(), acls).await
    }

    /// Common implementation for [`add_user`] and [`add_user_with_acl`].
    async fn mint_user(
        &self,
        alias: String,
        acls: MediatorACLSet,
    ) -> Result<TestMediatorUser, TestMediatorError> {
        let (did, secrets) = DID::generate_did_peer(
            vec![
                (PeerKeyRole::Verification, KeyType::Ed25519),
                (PeerKeyRole::Encryption, KeyType::X25519),
            ],
            Some(self.did().to_string()),
        )
        .map_err(|e| TestMediatorError::DidGeneration(e.to_string()))?;

        self.secrets_resolver.insert_vec(&secrets).await;
        register_local_did_with_acl(&self.store, &did, &acls).await?;

        Ok(TestMediatorUser {
            did,
            alias,
            secrets,
        })
    }

    /// Replace a registered DID's ACL bitmask. Goes directly through
    /// the underlying [`MediatorStore::set_did_acl`] — no admin session
    /// is required, no permission checks run. Tests use this to
    /// simulate ACL changes mid-flow ("mint user, run code, revoke
    /// ACL, run more code") without round-tripping through the
    /// admin protocol.
    ///
    /// Note this is the **fixture bypass** path. To validate that the
    /// production mediator-administration protocol enforces
    /// admin-only ACL changes correctly, drive
    /// `env.atm.protocols().mediator().acls().acls_set(...)` from an
    /// admin-authenticated SDK profile (see
    /// [`TestEnvironment::add_admin`]) and use [`Self::get_acl`] to
    /// read back the result.
    pub async fn set_acl(&self, did: &str, acls: MediatorACLSet) -> Result<(), TestMediatorError> {
        let did_hash = digest(did);
        self.store.set_did_acl(&did_hash, &acls).await?;
        Ok(())
    }

    /// Read the current ACL bitmask for `did`. Returns `None` when the
    /// DID has no account record on the mediator.
    pub async fn get_acl(&self, did: &str) -> Result<Option<MediatorACLSet>, TestMediatorError> {
        let did_hash = digest(did);
        Ok(self.store.get_did_acl(&did_hash).await?)
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

/// Insert a single DID into the mediator's account store with the
/// supplied ACL bitmask. Idempotent — a DID that already has an
/// account record is left untouched.
async fn register_local_did_with_acl(
    store: &Arc<dyn MediatorStore>,
    did: &str,
    acls: &MediatorACLSet,
) -> Result<(), TestMediatorError> {
    let did_hash = digest(did);
    if store.account_exists(&did_hash).await? {
        return Ok(());
    }
    store.account_add(&did_hash, acls, None).await?;
    Ok(())
}

/// Convenience wrapper: register `did` with the typed `acl::allow_all()`
/// preset. Mirrors the historical "register as LOCAL ALLOW_ALL" flow
/// without going through string-ruleset parsing.
async fn register_local_did(
    store: &Arc<dyn MediatorStore>,
    did: &str,
) -> Result<(), TestMediatorError> {
    register_local_did_with_acl(store, did, &acl::allow_all()).await
}

/// Insert each DID via [`register_local_did`]. Used by the builder to
/// register DIDs declared via [`TestMediatorBuilder::local_did`] /
/// [`TestMediatorBuilder::local_dids`] before returning the handle.
async fn register_local_dids(
    store: &Arc<dyn MediatorStore>,
    dids: &[String],
) -> Result<(), TestMediatorError> {
    for did in dids {
        register_local_did(store, did).await?;
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
