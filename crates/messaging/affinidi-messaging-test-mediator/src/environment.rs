//! End-to-end test environment.
//!
//! [`TestEnvironment`] glues a [`TestMediator`] together with an
//! [`ATM`] SDK client and a [`TDKSharedState`] so tests can exercise
//! the mediator from the perspective of one or more SDK users.
//!
//! Typical flow:
//!
//! ```ignore
//! use affinidi_messaging_test_mediator::TestEnvironment;
//!
//! #[tokio::test]
//! async fn round_trip() {
//!     let env = TestEnvironment::spawn().await.unwrap();
//!     let alice = env.add_user("Alice").await.unwrap();
//!     let bob = env.add_user("Bob").await.unwrap();
//!
//!     // ... exercise the SDK against `env.atm` and the user
//!     // profiles ...
//!
//!     env.shutdown().await.unwrap();
//! }
//! ```
//!
//! All identities are `did:peer:2.*` — the cache-SDK's built-in
//! `PeerResolver` decodes them locally, so no DNS or network resolution
//! is needed for any DID involved in the test.

use std::sync::Arc;

use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_messaging_sdk::{ATM, config::ATMConfig, profiles::ATMProfile};
use affinidi_secrets_resolver::{SecretsResolver, secrets::Secret};
use affinidi_tdk::common::TDKSharedState;
use affinidi_tdk::common::config::TDKConfig;
use affinidi_tdk::dids::{DID, KeyType, PeerKeyRole};

use crate::{TestMediator, TestMediatorHandle};

/// Errors specific to the e2e test environment, as opposed to the
/// mediator-only fixture in [`crate::TestMediatorError`].
#[derive(Debug, thiserror::Error)]
pub enum TestEnvironmentError {
    /// The underlying mediator fixture failed to start.
    #[error(transparent)]
    Mediator(#[from] crate::TestMediatorError),
    /// The TDK or ATM SDK could not be configured.
    #[error("SDK configuration failed: {0}")]
    Sdk(String),
    /// DID generation failed for a test user.
    #[error("did:peer generation failed for user '{alias}': {source}")]
    UserDid {
        /// Alias of the user whose DID could not be generated.
        alias: String,
        /// Underlying TDK / crypto error from `DID::generate_did_peer`.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
}

/// Top-level e2e fixture. Holds the running mediator, the shared TDK
/// state, and the SDK client. Add users via [`add_user`](Self::add_user).
pub struct TestEnvironment {
    /// Running mediator — exposes endpoint URL, DID, secrets resolver,
    /// shutdown control.
    pub mediator: TestMediatorHandle,
    /// Shared TDK state. The same secrets resolver is used by the
    /// mediator (server-side) and the SDK client (client-side); tests
    /// don't need to ferry secrets between resolvers.
    pub tdk: Arc<TDKSharedState>,
    /// SDK client. Tests call protocol methods on this (e.g.
    /// `atm.trust_ping().send_ping(...)`).
    pub atm: ATM,
}

/// One participant in an e2e scenario — Alice, Bob, etc. Owns its own
/// `did:peer`, secrets, and SDK profile.
#[derive(Debug, Clone)]
pub struct TestUser {
    /// `did:peer:2.*` DID generated for this user.
    pub did: String,
    /// Human-readable alias (e.g. "Alice"). Distinct from the DID.
    pub alias: String,
    /// SDK profile pointing at the test mediator. Pass this to ATM
    /// methods that take a profile.
    pub profile: Arc<ATMProfile>,
    /// User's signing + key-agreement secrets. Already inserted into
    /// the shared resolver — kept here for tests that want to inspect
    /// or copy them.
    pub secrets: Vec<Secret>,
}

impl TestEnvironment {
    /// Spawn the default mediator and wire up the SDK against it.
    /// Uses [`TestMediator::spawn`]'s defaults — loopback Redis,
    /// ephemeral port, no forwarding processor, no expiry sweep.
    pub async fn spawn() -> Result<Self, TestEnvironmentError> {
        Self::new(TestMediator::spawn().await?).await
    }

    /// Use an existing [`TestMediatorHandle`] — for tests that want
    /// custom mediator config (e.g. enable forwarding, override the
    /// Redis URL) via [`TestMediator::builder`].
    pub async fn new(mediator: TestMediatorHandle) -> Result<Self, TestEnvironmentError> {
        let tdk_config =
            TDKConfig::headless().map_err(|e| TestEnvironmentError::Sdk(e.to_string()))?;
        let tdk = Arc::new(
            TDKSharedState::new(tdk_config)
                .await
                .map_err(|e| TestEnvironmentError::Sdk(e.to_string()))?,
        );

        // Make the mediator's signing + key-agreement secrets available
        // to the same resolver the SDK uses. In a single-process test
        // there's no real reason to have separate resolvers — and tests
        // sometimes need to sign on behalf of the mediator (e.g., to
        // craft a forged outer envelope and verify the mediator
        // rejects it).
        let mediator_secrets = mediator.mediator_secrets().to_vec();
        tdk.secrets_resolver().insert_vec(&mediator_secrets).await;

        let atm_config = ATMConfig::builder()
            .build()
            .map_err(|e| TestEnvironmentError::Sdk(e.to_string()))?;
        let atm = ATM::new(atm_config, tdk.clone())
            .await
            .map_err(|e| TestEnvironmentError::Sdk(e.to_string()))?;

        Ok(Self { mediator, tdk, atm })
    }

    /// Add a fresh user with an auto-generated `did:peer:2.*` and
    /// register it as an SDK profile pointing at this environment's
    /// mediator. Idempotent on the alias — adding two users with the
    /// same alias replaces the first.
    ///
    /// The user DID's DIDComm service endpoint is the **mediator's
    /// DID**, not the mediator's HTTP URL. This matches the routing
    /// 2.0 shape (recipients delegate to a mediator DID; the mediator
    /// DID Document has the HTTP/WS endpoints). Using the HTTP URL
    /// directly causes the routing handler to classify the user as a
    /// remote next-hop and push every forwarded message into
    /// FORWARD_Q.
    ///
    /// The user is also pre-registered on the mediator as a LOCAL,
    /// ALLOW_ALL account so it can complete the WebSocket upgrade
    /// without needing a separate `local_did` declaration at builder
    /// time.
    pub async fn add_user(&self, alias: &str) -> Result<TestUser, TestEnvironmentError> {
        let mediator_did = self.mediator.did().to_string();
        let (did, secrets) = DID::generate_did_peer(
            vec![
                (PeerKeyRole::Verification, KeyType::Ed25519),
                (PeerKeyRole::Encryption, KeyType::X25519),
            ],
            Some(mediator_did.clone()),
        )
        .map_err(|e| TestEnvironmentError::UserDid {
            alias: alias.to_string(),
            source: Box::new(std::io::Error::other(e.to_string())),
        })?;

        // Make the user's secrets available to the SDK so it can pack
        // outbound messages and unpack inbound ones.
        self.tdk.secrets_resolver().insert_vec(&secrets).await;

        // Register the user as a LOCAL, ALLOW_ALL account on the
        // mediator. Without this the WebSocket handler refuses
        // upgrades for non-admin DIDs.
        self.mediator
            .register_local_did(&did)
            .await
            .map_err(|e| TestEnvironmentError::Sdk(e.to_string()))?;

        let profile = ATMProfile::new(
            &self.atm,
            Some(alias.to_string()),
            did.clone(),
            Some(mediator_did),
        )
        .await
        .map_err(|e| TestEnvironmentError::Sdk(e.to_string()))?;
        let profile = self
            .atm
            .profile_add(&profile, false)
            .await
            .map_err(|e| TestEnvironmentError::Sdk(e.to_string()))?;

        Ok(TestUser {
            did,
            alias: alias.to_string(),
            profile,
            secrets,
        })
    }

    /// Shut down the SDK and the mediator. Consumes the environment.
    pub async fn shutdown(self) -> Result<(), MediatorError> {
        self.atm.graceful_shutdown().await;
        self.mediator.shutdown();
        self.mediator.join().await
    }
}

impl std::fmt::Debug for TestEnvironment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestEnvironment")
            .field("mediator", &self.mediator)
            .finish_non_exhaustive()
    }
}
