//! Creating a `did:webs` identifier and the artifacts that publish it.
//!
//! The shape mirrors `didwebvh-rs`: a config goes in, a result carrying the DID
//! and its artifacts comes out, and nothing is published — a hosting service
//! writes the bytes.
//!
//! # Why creation needs no store
//!
//! `affinidi-keri` can build and sign events without a [`KeriStore`], and the
//! key event log *is* the `keri.cesr` artifact, so there is nothing left for a
//! database to hold. What has to survive between events is the salt and a small
//! amount of non-secret state — see [`crate::custody`].
//!
//! # What the document may contain
//!
//! `did.json` is produced by the same code path the resolver uses, so the two
//! cannot disagree. That is a constraint, not a convenience: a resolver derives
//! the document from the key event log and ignores anything the published file
//! adds. Fields that are not backed by KERI artifacts would be silently dropped
//! on the way back, so this module refuses to write them.
//!
//! Service endpoints and `alsoKnownAs` are both supported, because both can be
//! backed: services by signed `rpy` messages, aliases by a designated-aliases
//! attestation the identifier issues to itself. The resolver verifies each and
//! derives the document from what it verified.
//!
//! # What every identifier designates
//!
//! § Create requires the identifier to designate itself: a resolver refuses a
//! `did:webs` DID that no attestation names. Creation therefore always issues
//! one, naming the DID, its `did:web` twin (`did.json` is published in the
//! `did:web` form, which is only valid when the twin is designated) and
//! `did:keri:<AID>` (which § Also Known As requires), followed by
//! `also_known_as`. There is no switch for any of the three: turning one off
//! would produce artifacts that do not resolve.
//!
//! `also_known_as_scid` designates the `did:scid:ke` form like any other alias.
//!
//! [`KeriStore`]: affinidi_keri_db::KeriStore

use affinidi_keri::config::InceptionConfig;
use affinidi_keri::controller::{ControllerState, Inception, KeySigner};
use affinidi_keri::hab::{Hab, SignedEvent};

use crate::artifacts::Artifacts;
use crate::custody::KeyCustody;
use crate::designated_services::DesignatedService;
use crate::document::to_did_web;
use crate::errors::DidWebsError;
use crate::identifier::DidWebs;
use crate::key_agreement::KeyAgreementKey;
use crate::key_roles::KeyRoles;

/// A service endpoint to publish at creation time.
///
/// The endpoint identifier is the AID itself: a controller designating where it
/// can be reached. A third-party endpoint — a separate agent or mailbox — needs
/// that party's own key to sign its location, which this crate cannot do, so
/// those must be supplied as pre-signed replies instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfEndpoint {
    /// The role, e.g. `controller` or `agent`. Not an enumeration: KERI does
    /// not fix the set.
    pub role: String,
    /// Scheme to URL, e.g. `http` -> `https://example.com`.
    pub urls: std::collections::BTreeMap<String, String>,
}

/// How to create a new `did:webs` identifier.
///
/// Built with [`CreateConfig::builder`]; non-exhaustive so that what an
/// identifier can be created with may grow without breaking callers.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct CreateConfig {
    /// Where the artifacts will be published: `example.com`, or
    /// `example.com/dids` for a path. The AID becomes the final path element.
    pub host: String,
    /// KERI inception parameters — key counts, thresholds, witnesses, and the
    /// salt every key is derived from.
    pub inception: InceptionConfig,
    /// Endpoints this identifier designates for itself.
    pub services: Vec<SelfEndpoint>,
    /// Identifiers to designate as `alsoKnownAs`, beyond the three every
    /// identifier designates (see the module documentation).
    ///
    /// Published as a signed attestation the identifier issues to itself, not
    /// written into the document.
    pub also_known_as: Vec<String>,
    /// Also designate this identifier's `did:scid:ke:1` form.
    ///
    /// The AID is not known until the inception event exists, so this is a
    /// switch rather than something the caller can pass in `also_known_as`.
    pub also_known_as_scid: bool,
    /// Keys to designate for key agreement — the document's `keyAgreement`
    /// (see [`crate::key_agreement`]). Separate keys, never the signing keys.
    pub key_agreement: Vec<KeyAgreementKey>,
    /// Services of any type to designate, such as `DIDCommMessaging` or
    /// `TSPTransport` (see [`crate::designated_services`](mod@crate::designated_services)).
    pub designated_services: Vec<DesignatedService>,
    /// Keys to bind to roles (see [`crate::key_roles`], a proposed
    /// extension). With them, the document lists role keys instead of the key
    /// state's, and `messaging` takes the place of `key_agreement`, which must
    /// then be empty.
    pub key_roles: Option<KeyRoles>,
    /// Inception from keys the caller holds, for [`create_controlled`]: the
    /// current keys, the committed successors and their thresholds. When set,
    /// `inception` is not used.
    pub controlled: Option<Inception>,
}

impl CreateConfig {
    /// Start from the defaults, for `host`.
    pub fn builder(host: impl Into<String>) -> CreateConfigBuilder {
        CreateConfigBuilder {
            config: Self {
                host: host.into(),
                inception: InceptionConfig::default(),
                services: Vec::new(),
                also_known_as: Vec::new(),
                also_known_as_scid: false,
                key_agreement: Vec::new(),
                designated_services: Vec::new(),
                key_roles: None,
                controlled: None,
            },
        }
    }
}

/// Builder for [`CreateConfig`].
pub struct CreateConfigBuilder {
    config: CreateConfig,
}

impl CreateConfigBuilder {
    /// KERI inception parameters, including the salt.
    pub fn inception(mut self, inception: InceptionConfig) -> Self {
        self.config.inception = inception;
        self
    }

    /// Designate an endpoint for this identifier.
    pub fn service(mut self, service: SelfEndpoint) -> Self {
        self.config.services.push(service);
        self
    }

    /// Designate another identifier as `alsoKnownAs`.
    pub fn also_known_as(mut self, did: impl Into<String>) -> Self {
        self.config.also_known_as.push(did.into());
        self
    }

    /// Designate this identifier's own `did:scid:ke:1` form.
    ///
    /// ⚠️ The `ke` format code is *proposed* in the did:scid registry rather
    /// than registered, so this asserts an identity whose spelling may change.
    pub fn also_known_as_scid(mut self, enabled: bool) -> Self {
        self.config.also_known_as_scid = enabled;
        self
    }

    /// Designate a key for key agreement.
    pub fn key_agreement(mut self, key: KeyAgreementKey) -> Self {
        self.config.key_agreement.push(key);
        self
    }

    /// Designate a service of any type.
    pub fn designated_service(mut self, service: DesignatedService) -> Self {
        self.config.designated_services.push(service);
        self
    }

    /// Bind keys to roles (see [`crate::key_roles`]).
    pub fn key_roles(mut self, roles: KeyRoles) -> Self {
        self.config.key_roles = Some(roles);
        self
    }

    /// Incept from keys the caller holds (see [`create_controlled`]).
    pub fn controlled(mut self, inception: Inception) -> Self {
        self.config.controlled = Some(inception);
        self
    }

    /// Finish.
    pub fn build(self) -> CreateConfig {
        self.config
    }
}

/// A newly created identifier.
#[derive(Debug, Clone)]
pub struct CreateResult {
    did: String,
    artifacts: Artifacts,
    custody: KeyCustody,
}

impl CreateResult {
    /// The `did:webs` identifier.
    pub fn did(&self) -> &str {
        &self.did
    }

    /// The bytes to publish.
    pub fn artifacts(&self) -> &Artifacts {
        &self.artifacts
    }

    /// What to keep in order to rotate later. Pair it with the salt, which is
    /// **not** in here — see [`crate::custody`].
    pub fn custody(&self) -> &KeyCustody {
        &self.custody
    }

    /// Take the artifacts, leaving the rest.
    pub fn into_artifacts(self) -> Artifacts {
        self.artifacts
    }
}

/// Create a `did:webs` identifier.
///
/// The AID is not known until the inception event is built — it *is* that
/// event's SAID — so the DID cannot be chosen in advance, only the host it will
/// be published under.
///
/// # Errors
/// Returns [`DidWebsError`] if inception fails, or if the artifacts it produces
/// do not resolve back — which would mean this crate had emitted something its
/// own resolver rejects.
pub fn create(config: CreateConfig) -> Result<CreateResult, DidWebsError> {
    if config.controlled.is_some() {
        return Err(DidWebsError::Create(
            "this configuration incepts from caller-held keys; use create_controlled".into(),
        ));
    }
    let (mut hab, inception) = Hab::incept_event("did:webs", &config.inception)
        .map_err(|e| DidWebsError::Create(format!("inception failed: {e}")))?;
    let (did, keri_cesr) = build(&config, &mut hab, inception)?;
    let artifacts = artifacts_for(&did, &keri_cesr)?;

    Ok(CreateResult {
        did: did.did().to_string(),
        artifacts,
        custody: KeyCustody::new(hab.state()),
    })
}

/// An identifier created or updated from caller-held keys.
#[derive(Debug, Clone)]
pub struct ControlledResult {
    did: String,
    artifacts: Artifacts,
    state: ControllerState,
}

impl ControlledResult {
    /// The `did:webs` identifier.
    pub fn did(&self) -> &str {
        &self.did
    }

    /// The bytes to publish, replacing any previous ones.
    pub fn artifacts(&self) -> &Artifacts {
        &self.artifacts
    }

    /// The state to continue from, which **replaces** any previous one.
    /// Nothing in it is secret.
    pub fn state(&self) -> &ControllerState {
        &self.state
    }

    /// Take the artifacts and state.
    pub fn into_parts(self) -> (Artifacts, ControllerState) {
        (self.artifacts, self.state)
    }

    pub(crate) fn new(did: String, artifacts: Artifacts, state: ControllerState) -> Self {
        Self {
            did,
            artifacts,
            state,
        }
    }
}

/// Create a `did:webs` identifier from keys the caller holds.
///
/// [`CreateConfig::controlled`] gives the current keys, the successors as
/// digests or public keys — a recovery custodian's key can be committed by its
/// digest alone — and the thresholds. `signers` hold the current keys and
/// must meet the signing threshold; they sign the inception event and every
/// event and message that follows it here. No secret enters or leaves this
/// crate.
///
/// # Errors
/// As [`create`], and [`DidWebsError::Create`] if `controlled` is not set or
/// the signers do not meet the signing threshold.
pub fn create_controlled(
    config: CreateConfig,
    signers: &[&dyn KeySigner],
) -> Result<ControlledResult, DidWebsError> {
    let inception = config.controlled.as_ref().ok_or_else(|| {
        DidWebsError::Create("create_controlled needs CreateConfig::controlled".into())
    })?;
    let mut pending = affinidi_keri::controller::incept(inception)
        .map_err(|e| DidWebsError::Create(format!("inception failed: {e}")))?;
    for signer in signers {
        pending
            .sign_with(*signer)
            .map_err(|e| DidWebsError::Create(format!("inception: {e}")))?;
    }
    let (event, state) = pending.finish().map_err(|e| {
        DidWebsError::Create(format!(
            "the signers given do not meet the signing threshold: {e}"
        ))
    })?;
    let mut held = crate::signing::Held::new(state, signers)?;
    let (did, keri_cesr) = build(&config, &mut held, event)?;
    let artifacts = artifacts_for(&did, &keri_cesr)?;
    Ok(ControlledResult::new(
        did.did().to_string(),
        artifacts,
        held.state,
    ))
}

/// Everything after inception, whoever signs: the designations and endpoint
/// replies every created identifier carries.
fn build(
    config: &CreateConfig,
    hab: &mut dyn crate::signing::Controller,
    inception: SignedEvent,
) -> Result<(DidWebs, Vec<u8>), DidWebsError> {
    let aid = hab.prefix().to_string();
    let did = DidWebs::parse(&format!("did:webs:{}:{aid}", config.host))
        .map_err(|e| DidWebsError::Create(format!("{} is not a usable host: {e}", config.host)))?;

    let establishment_said = inception.said.clone();
    let mut keri_cesr = inception.composed;
    let hab = &mut *hab;

    // Aliases are published as a signed attestation the identifier issues to
    // itself. The document is not allowed to simply claim them — and the DID
    // itself has to be among them, or it does not resolve.
    let mut extra = config.also_known_as.clone();
    if config.also_known_as_scid {
        extra.push(format!("did:scid:ke:1:{aid}?src={}", config.host));
    }
    let aliases = crate::attestation::designation(&did, &extra);
    let attestation =
        crate::attestation::issue_designated_aliases(hab, &aid, &establishment_said, &aliases)?;
    keri_cesr.extend_from_slice(&attestation);

    // Key roles: the role keys replace the key state's in the document, and
    // `messaging` replaces key agreement designations, which would be ignored.
    if let Some(roles) = &config.key_roles {
        if !config.key_agreement.is_empty() {
            return Err(DidWebsError::Create(
                "key agreement keys are bound to the messaging role when key roles are \
                 designated; pass them there"
                    .into(),
            ));
        }
        let state = crate::kel::Kels::parse(&keri_cesr)?.key_state(&aid)?;
        keri_cesr.extend_from_slice(&crate::attestation::issue_key_roles(
            hab,
            &aid,
            &establishment_said,
            &state,
            roles,
            &[],
        )?);
    }

    // Key agreement keys and typed services, each a designation of its own so
    // that either can be replaced without touching the other.
    if !config.key_agreement.is_empty() {
        keri_cesr.extend_from_slice(&crate::attestation::issue_key_agreement(
            hab,
            &aid,
            &establishment_said,
            &config.key_agreement,
        )?);
    }
    if !config.designated_services.is_empty() {
        keri_cesr.extend_from_slice(&crate::attestation::issue_services(
            hab,
            &aid,
            &establishment_said,
            &config.designated_services,
        )?);
    }

    // Endpoints are published as signed replies rather than written into the
    // document, so that a resolver can verify them instead of taking the
    // document's word for it.
    if !config.services.is_empty() {
        let replies = crate::endpoints::self_designated_replies(
            hab,
            &aid,
            &establishment_said,
            &config.services,
        )?;
        keri_cesr.extend_from_slice(&replies);
    }

    Ok((did, keri_cesr))
}

/// Build the published artifacts from a key event log, by resolving it.
///
/// The document is not assembled independently — it is whatever the resolver
/// derives from this stream, transformed to the `did:web` form `did.json`
/// publishes (§ Transformation to `did:web` DID document). Producing it any
/// other way would let creation and resolution drift apart, and the resolver
/// is the side that decides.
pub(crate) fn artifacts_for(did: &DidWebs, keri_cesr: &[u8]) -> Result<Artifacts, DidWebsError> {
    let derived = crate::resolver::derive(did, keri_cesr)?;
    let did_json = serde_json::to_vec(&to_did_web(&derived.document, did))?;

    Ok(Artifacts {
        keri_cesr: keri_cesr.to_vec(),
        did_json,
    })
}
