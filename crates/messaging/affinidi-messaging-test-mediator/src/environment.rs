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
use affinidi_tdk::dids::{DID, KeyType, PeerKeyRole, PeerService, PeerServiceEndpoint};

use crate::{AdminIdentity, TestMediator, TestMediatorHandle};

/// Errors specific to the e2e test environment, as opposed to the
/// mediator-only fixture in [`crate::TestMediatorError`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
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
    /// `add_admin` was called with an `AdminIdentity` whose DID does
    /// not match the mediator's configured admin DID. Authenticating
    /// against this mismatched identity would succeed but the session
    /// would never receive the admin role — surfacing the misuse here
    /// catches the bug at fixture setup, not at protocol time.
    #[error(
        "admin identity DID ({supplied}) does not match mediator's configured admin_did ({configured})"
    )]
    AdminMismatch {
        /// Admin DID the mediator was started with.
        configured: String,
        /// Admin DID supplied to `add_admin`.
        supplied: String,
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
    /// The TSP relationship store the SDK was wired with, so a test can seed a
    /// relationship without running a handshake. See
    /// [`TestEnvironment::relate_directly`].
    #[cfg(feature = "tsp")]
    pub relationship_store: Arc<dyn affinidi_messaging_sdk::protocols::tsp::RelationshipStore>,
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

impl TestUser {
    /// SHA-256 hash of the DID string — the canonical key shape used
    /// by the mediator's account / ACL / queue stores. Pass this to
    /// admin-protocol calls (e.g. `acls_set`, `access_list_add`,
    /// `account_remove`) that operate on hashed DIDs.
    pub fn did_hash(&self) -> String {
        sha256::digest(&self.did)
    }
}

impl TestEnvironment {
    /// Spawn the default mediator and wire up the SDK against it.
    /// Uses [`TestMediator::spawn`]'s defaults — loopback Redis,
    /// ephemeral port, no forwarding processor, no expiry sweep.
    pub async fn spawn() -> Result<Self, TestEnvironmentError> {
        Self::new(TestMediator::spawn().await?).await
    }

    /// Spawn the default mediator (with the `tsp` feature) and wire up
    /// the SDK to authenticate every profile over **pure TSP** instead
    /// of the built-in DIDComm flow.
    ///
    /// The shared [`ThreadedSecretsResolver`] is constructed up front and
    /// handed BOTH to the TDK (via
    /// [`with_secrets_resolver`](affinidi_tdk::common::config::TDKConfigBuilder::with_secrets_resolver))
    /// and to the [`TspAuthHandler`](affinidi_messaging_sdk::TspAuthHandler).
    /// This is the load-bearing difference from [`spawn`](Self::spawn):
    /// the handler must hold the *same* resolver instance that
    /// [`add_user`](Self::add_user) later populates, otherwise it can't
    /// load each user's Ed25519 VID key to sign the auth challenge.
    ///
    /// With a [`CustomAuthHandlers`] bundle set, the TDK's
    /// `AuthenticationCache` routes every profile authentication through
    /// the custom handler, so the whole environment authenticates over
    /// `POST /tsp/authenticate`.
    #[cfg(feature = "tsp")]
    pub async fn spawn_with_tsp_auth() -> Result<Self, TestEnvironmentError> {
        use affinidi_secrets_resolver::ThreadedSecretsResolver;
        use affinidi_tdk::did_authentication::CustomAuthHandlers;

        let mediator = TestMediator::spawn().await?;

        // Build the shared resolver exactly as `TDKSharedState::new`
        // does when the config doesn't supply one. We need a handle to
        // it up front so the `TspAuthHandler` and the TDK share the same
        // instance — that's where `add_user` later inserts user keys.
        let (secrets, _task) = ThreadedSecretsResolver::new(None).await;

        let handlers = CustomAuthHandlers::default().with_auth_handler(Arc::new(
            affinidi_messaging_sdk::TspAuthHandler::new(secrets.clone()),
        ));
        let tdk_config = TDKConfig::builder()
            .with_load_environment(false)
            .with_use_atm(false)
            .with_secrets_resolver(secrets)
            .with_custom_auth_handlers(handlers)
            .build()
            .map_err(|e| TestEnvironmentError::Sdk(e.to_string()))?;

        let atm_config = ATMConfig::builder()
            .build()
            .map_err(|e| TestEnvironmentError::Sdk(e.to_string()))?;
        Self::new_with_config(mediator, tdk_config, atm_config).await
    }

    /// Use an existing [`TestMediatorHandle`] — for tests that want
    /// custom mediator config (e.g. enable forwarding, override the
    /// Redis URL) via [`TestMediator::builder`].
    pub async fn new(mediator: TestMediatorHandle) -> Result<Self, TestEnvironmentError> {
        let tdk_config =
            TDKConfig::headless().map_err(|e| TestEnvironmentError::Sdk(e.to_string()))?;
        let atm_config = ATMConfig::builder()
            .build()
            .map_err(|e| TestEnvironmentError::Sdk(e.to_string()))?;
        Self::new_with_config(mediator, tdk_config, atm_config).await
    }

    /// Spawn the default mediator and wire the SDK with a caller-supplied
    /// [`ATMConfig`].
    ///
    /// For tests that need to reach SDK settings the other constructors do not
    /// expose — an injected clock, a relationship store the test can seed, or
    /// the TSP relationship-gating and key-state policies of spec Rev 3.
    pub async fn spawn_with_atm_config(
        atm_config: ATMConfig,
    ) -> Result<Self, TestEnvironmentError> {
        let mediator = TestMediator::spawn().await?;
        let tdk_config =
            TDKConfig::headless().map_err(|e| TestEnvironmentError::Sdk(e.to_string()))?;
        Self::new_with_config(mediator, tdk_config, atm_config).await
    }

    /// Spawn the default mediator (with the `tsp` feature) and wire up the SDK
    /// with a chosen [`TspPolicy`](affinidi_messaging_sdk::TspPolicy) so
    /// `atm.send_to` protocol selection can be exercised end-to-end.
    #[cfg(feature = "tsp")]
    pub async fn spawn_with_tsp_policy(
        policy: affinidi_messaging_sdk::TspPolicy,
    ) -> Result<Self, TestEnvironmentError> {
        let mediator = TestMediator::spawn().await?;
        let tdk_config =
            TDKConfig::headless().map_err(|e| TestEnvironmentError::Sdk(e.to_string()))?;
        let atm_config = ATMConfig::builder()
            .with_tsp_policy(policy)
            .build()
            .map_err(|e| TestEnvironmentError::Sdk(e.to_string()))?;
        Self::new_with_config(mediator, tdk_config, atm_config).await
    }

    /// Like [`spawn_with_tsp_policy`](Self::spawn_with_tsp_policy), but with
    /// the Rev 3 §7.2.2 relationship gate turned off.
    ///
    /// For tests whose subject is what an endpoint *learns* from an inbound
    /// message. Gating and capability learning interact awkwardly there: an
    /// application message from an unrelated peer is discarded, so nothing is
    /// observed, while seeding a relationship to admit it is itself a TSP
    /// capability signal and so decides the outcome in advance. Turning the
    /// gate off isolates the behaviour under test.
    #[cfg(feature = "tsp")]
    pub async fn spawn_ungated_with_tsp_policy(
        policy: affinidi_messaging_sdk::TspPolicy,
    ) -> Result<Self, TestEnvironmentError> {
        let mediator = TestMediator::spawn().await?;
        let tdk_config =
            TDKConfig::headless().map_err(|e| TestEnvironmentError::Sdk(e.to_string()))?;
        let atm_config = ATMConfig::builder()
            .with_tsp_policy(policy)
            .with_tsp_relationship_gating(false)
            .build()
            .map_err(|e| TestEnvironmentError::Sdk(e.to_string()))?;
        Self::new_with_config(mediator, tdk_config, atm_config).await
    }

    /// Like [`new`](Self::new), but sets a
    /// [`TspPolicy`](affinidi_messaging_sdk::TspPolicy) on the SDK so
    /// `atm.send_to` protocol selection can be exercised — used by multi-mediator
    /// topology tests that need TSP enabled on an existing mediator handle.
    #[cfg(feature = "tsp")]
    pub async fn new_with_tsp_policy(
        mediator: TestMediatorHandle,
        policy: affinidi_messaging_sdk::TspPolicy,
    ) -> Result<Self, TestEnvironmentError> {
        let tdk_config =
            TDKConfig::headless().map_err(|e| TestEnvironmentError::Sdk(e.to_string()))?;
        let atm_config = ATMConfig::builder()
            .with_tsp_policy(policy)
            .build()
            .map_err(|e| TestEnvironmentError::Sdk(e.to_string()))?;
        Self::new_with_config(mediator, tdk_config, atm_config).await
    }

    /// Shared constructor: wire the SDK + TDK against `mediator` using
    /// the supplied `tdk_config`. The only difference between
    /// [`new`](Self::new) and [`spawn_with_tsp_auth`](Self::spawn_with_tsp_auth)
    /// is which config is passed here.
    async fn new_with_config(
        mediator: TestMediatorHandle,
        tdk_config: TDKConfig,
        atm_config: ATMConfig,
    ) -> Result<Self, TestEnvironmentError> {
        // Keep a handle on the store the SDK is using, so a test can seed a
        // relationship without running a handshake.
        #[cfg(feature = "tsp")]
        let relationship_store = atm_config.relationship_store().clone();
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

        let atm = ATM::new(atm_config, tdk.clone())
            .await
            .map_err(|e| TestEnvironmentError::Sdk(e.to_string()))?;

        Ok(Self {
            mediator,
            tdk,
            atm,
            #[cfg(feature = "tsp")]
            relationship_store,
        })
    }

    /// Record a `Bidirectional` TSP relationship between two users without
    /// exchanging any messages.
    ///
    /// Spec Rev 3 §7.2.2 gates application messages on an existing
    /// relationship, so a test that exercises transport — websocket delivery,
    /// acknowledgement, redelivery — needs one even though the relationship is
    /// not what it is testing. Seeding it directly keeps the mailbox clean,
    /// where [`TestEnvironment::relate`] would leave its own control messages
    /// there and disturb tests that assert what is queued.
    ///
    /// Use `relate` where the handshake itself is under test.
    #[cfg(feature = "tsp")]
    pub async fn relate_directly(
        &self,
        a: &TestUser,
        b: &TestUser,
    ) -> Result<(), TestEnvironmentError> {
        use affinidi_messaging_sdk::protocols::tsp::RelationshipState;

        for (ours, theirs) in [(&a.did, &b.did), (&b.did, &a.did)] {
            self.relationship_store
                .set(ours, theirs, RelationshipState::Bidirectional)
                .await
                .map_err(|e| TestEnvironmentError::Sdk(e.to_string()))?;
        }
        Ok(())
    }

    /// Run a full TSP relationship handshake between two users, leaving both
    /// sides `Bidirectional`.
    ///
    /// Spec Rev 3 §7.2.2 requires this before any application message: "It is
    /// not permissible that one endpoint which has learned a VID of the other
    /// simply starts with an application level message without first having an
    /// exchange of TSP control messages." A test that skips it has its messages
    /// discarded at the receiver, which is the specified behaviour rather than
    /// a fault.
    ///
    /// Drives the real control-message exchange through the mediator rather
    /// than seeding state, so the relationship a test relies on is one the
    /// protocol actually produced.
    #[cfg(feature = "tsp")]
    pub async fn relate(
        &self,
        initiator: &TestUser,
        responder: &TestUser,
    ) -> Result<(), TestEnvironmentError> {
        let sdk = |e: String| TestEnvironmentError::Sdk(e);

        // Initiator sends the invite.
        self.atm
            .tsp()
            .form_relationship(&initiator.profile, &responder.did)
            .await
            .map_err(|e| sdk(e.to_string()))?;

        // Responder picks it up, records it, and accepts.
        let invite_digest = self
            .fetch_one_control(responder, &initiator.did)
            .await?
            .expect("the invite is waiting for the responder");
        self.atm
            .tsp()
            .accept_relationship(&responder.profile, &initiator.did, invite_digest)
            .await
            .map_err(|e| sdk(e.to_string()))?;

        // Initiator picks up the accept, completing the relationship.
        self.fetch_one_control(initiator, &responder.did)
            .await?
            .expect("the accept is waiting for the initiator");

        Ok(())
    }

    /// Fetch the next control message waiting for `user`, record it against
    /// `peer`, and return its thread digest.
    #[cfg(feature = "tsp")]
    async fn fetch_one_control(
        &self,
        user: &TestUser,
        peer: &str,
    ) -> Result<Option<[u8; 32]>, TestEnvironmentError> {
        use affinidi_messaging_sdk::messages::fetch::FetchOptions;

        let sdk = |e: String| TestEnvironmentError::Sdk(e);

        let inbox = self
            .atm
            .fetch_messages(&user.profile, &FetchOptions::default())
            .await
            .map_err(|e| sdk(e.to_string()))?;
        let Some(element) = inbox.success.first() else {
            return Ok(None);
        };
        let Some(stored) = element.msg.as_ref() else {
            return Ok(None);
        };

        // Consume it. A handshake that leaves its control messages in the
        // mailbox would otherwise be indistinguishable, to a later fetch, from
        // the application message the test is actually waiting for.
        self.atm
            .delete_messages_direct(
                &user.profile,
                &affinidi_messaging_sdk::messages::DeleteMessageRequest {
                    message_ids: vec![element.msg_id.clone()],
                },
            )
            .await
            .map_err(|e| sdk(e.to_string()))?;
        let qb2 = self
            .atm
            .tsp()
            .decode(stored)
            .map_err(|e| sdk(e.to_string()))?;
        let (control, sender, digest) = self
            .atm
            .tsp()
            .unpack_control(&user.profile, &qb2)
            .await
            .map_err(|e| sdk(e.to_string()))?;
        assert_eq!(sender, peer, "control message came from an unexpected VID");
        self.atm
            .tsp()
            .record_incoming_control(&user.profile, peer, &control)
            .await
            .map_err(|e| sdk(e.to_string()))?;
        Ok(Some(digest))
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
        self.add_user_with_services(alias, None).await
    }

    /// Add a user whose DID advertises a **`TSPTransport` service naming this
    /// mediator by DID** — the shape a real persona/agent document publishes.
    ///
    /// This is what a mediated TSP identity actually looks like on the wire: the
    /// user's own document says "my traffic goes through this mediator" and the
    /// transport URL lives one resolve away, in the mediator's document. It is
    /// deliberately *not* what [`add_user`](Self::add_user) produces — a plain
    /// test user advertises no TSP service at all, and every TSP test that
    /// federates does so by naming the peer mediator's DID explicitly in the
    /// route, which never exercises the indirection.
    ///
    /// Otherwise identical to [`add_user`](Self::add_user): same `dm` service
    /// (the mediator's DID), same LOCAL/ALLOW_ALL registration, same profile.
    pub async fn add_tsp_mediated_user(
        &self,
        alias: &str,
    ) -> Result<TestUser, TestEnvironmentError> {
        let mediator_did = self.mediator.did().to_string();
        // TSP only, no `dm` entry. A `did:peer:2` inlines each service into the
        // identifier, and the mediator's own DID is itself a `did:peer:2`
        // carrying three services — so embedding it twice pushes the user's DID
        // past the resolver's 1000-byte ceiling, which a real (`did:webvh`)
        // persona never approaches. The DIDComm side is not what is under test
        // here, and the SDK profile is told its mediator directly.
        let services = vec![PeerService {
            type_: "TSPTransport".into(),
            endpoint: PeerServiceEndpoint::Uri(mediator_did),
            id: Some("#tsp".into()),
        }];
        self.add_user_with_services(alias, Some(services)).await
    }

    /// Shared body of [`add_user`](Self::add_user) and
    /// [`add_tsp_mediated_user`](Self::add_tsp_mediated_user). `services: None`
    /// takes the TDK default (a single `dm` service at the mediator's DID).
    async fn add_user_with_services(
        &self,
        alias: &str,
        services: Option<Vec<PeerService>>,
    ) -> Result<TestUser, TestEnvironmentError> {
        let mediator_did = self.mediator.did().to_string();
        let keys = vec![
            (PeerKeyRole::Verification, KeyType::Ed25519),
            (PeerKeyRole::Encryption, KeyType::X25519),
        ];
        let generated = match services {
            Some(services) => DID::generate_did_peer_with_services(keys, Some(services)),
            None => DID::generate_did_peer(keys, Some(mediator_did.clone())),
        };
        let (did, secrets) = generated.map_err(|e| TestEnvironmentError::UserDid {
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

    /// Wire an SDK profile authenticated as the mediator's admin DID.
    ///
    /// `identity.did` MUST equal `self.mediator.admin_did()` —
    /// otherwise the resulting profile would authenticate fine but the
    /// session would never receive the admin role, and admin-protocol
    /// calls would silently fall through to `Standard`-tier
    /// permissions. This method returns
    /// [`TestEnvironmentError::AdminMismatch`] in that case to surface
    /// the misuse early.
    ///
    /// Differences from [`add_user`](Self::add_user):
    /// - **Does not register the admin DID as a LOCAL account** on the
    ///   mediator — the admin is recognized by the `admin_did` config
    ///   match performed at session-establishment, not by ACL.
    /// - **Does insert** `identity.secrets` into the shared SDK
    ///   resolver, so the SDK can sign HTTP-auth challenges and
    ///   DIDComm envelopes on the admin's behalf. The mediator's own
    ///   server-side secrets resolver is **not** touched (that
    ///   resolver holds the mediator's operating keys, not its
    ///   admin's).
    /// - Returns a [`TestUser`]-shaped value (same struct — admin-ness
    ///   is a property of the DID-to-config match, not the type).
    ///
    /// Pair with [`TestMediator::random_admin_identity`] +
    /// [`crate::TestMediatorBuilder::admin_identity`] for the full
    /// "stand up a mediator with a usable admin" flow.
    pub async fn add_admin(
        &self,
        identity: AdminIdentity,
    ) -> Result<TestUser, TestEnvironmentError> {
        if identity.did != self.mediator.admin_did() {
            return Err(TestEnvironmentError::AdminMismatch {
                configured: self.mediator.admin_did().to_string(),
                supplied: identity.did,
            });
        }

        // Make the admin's secrets available to the SDK so it can
        // sign auth challenges and pack outbound admin-protocol
        // messages. NOT inserted into the mediator's own resolver —
        // see the doc comment above.
        self.tdk
            .secrets_resolver()
            .insert_vec(&identity.secrets)
            .await;

        let mediator_did = self.mediator.did().to_string();
        let profile = ATMProfile::new(
            &self.atm,
            Some("admin".to_string()),
            identity.did.clone(),
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
            did: identity.did,
            alias: "admin".to_string(),
            profile,
            secrets: identity.secrets,
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
