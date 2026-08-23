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
//! Service endpoints *are* supported, because they can be backed: each one is
//! emitted as signed `rpy` messages in the stream, which the resolver verifies
//! and derives the services from. Designated aliases are not yet, because they
//! need a credential registry and an issuance that `affinidi-keri` cannot build.
//!
//! # No `alsoKnownAs` knobs, unlike `didwebvh-rs`
//!
//! `didwebvh-rs` offers `also_known_as_web` and `also_known_as_scid` because it
//! *writes* `alsoKnownAs` into its log, where whatever it puts is what comes
//! back. `did:webs` derives that field instead, so neither switch could tell
//! the truth here:
//!
//! * the `did:web` twin is added by the resolver unconditionally — it shares
//!   the same location and the same document — so it cannot be turned off;
//! * a `did:scid:ke` entry is not derivable from the key event log, so a
//!   resolver drops it — it cannot be turned on.
//!
//! Offering them anyway would mean publishing a document this crate's own
//! resolver does not reproduce. Making `did:scid:ke` real needs either a
//! designated-aliases attestation (a credential registry, see above) or a
//! resolver that derives it, which would assert that identity for every
//! `did:webs` whether its controller wanted it or not.
//!
//! [`KeriStore`]: affinidi_keri_db::KeriStore

use affinidi_keri::config::InceptionConfig;
use affinidi_keri::hab::Hab;

use crate::artifacts::Artifacts;
use crate::custody::KeyCustody;
use crate::document::document_from_keys;
use crate::errors::DidWebsError;
use crate::identifier::DidWebs;
use crate::services::ServiceEndpoint;

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
#[derive(Debug, Clone)]
pub struct CreateConfig {
    /// Where the artifacts will be published: `example.com`, or
    /// `example.com/dids` for a path. The AID becomes the final path element.
    pub host: String,
    /// KERI inception parameters — key counts, thresholds, witnesses, and the
    /// salt every key is derived from.
    pub inception: InceptionConfig,
    /// Endpoints this identifier designates for itself.
    pub services: Vec<SelfEndpoint>,
}

impl CreateConfig {
    /// Start from the defaults, for `host`.
    pub fn builder(host: impl Into<String>) -> CreateConfigBuilder {
        CreateConfigBuilder {
            config: Self {
                host: host.into(),
                inception: InceptionConfig::default(),
                services: Vec::new(),
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
    let (hab, inception) = Hab::incept_event("did:webs", &config.inception)
        .map_err(|e| DidWebsError::Create(format!("inception failed: {e}")))?;

    let aid = hab.prefix().to_string();
    let did = DidWebs::parse(&format!("did:webs:{}:{aid}", config.host))
        .map_err(|e| DidWebsError::Create(format!("{} is not a usable host: {e}", config.host)))?;

    let establishment_said = inception.said.clone();
    let mut keri_cesr = inception.composed;

    // Endpoints are published as signed replies rather than written into the
    // document, so that a resolver can verify them instead of taking the
    // document's word for it.
    if !config.services.is_empty() {
        let replies = crate::endpoints::self_designated_replies(
            &hab,
            &aid,
            &establishment_said,
            &config.services,
        )?;
        keri_cesr.extend_from_slice(&replies);
    }

    let artifacts = artifacts_for(&did, &keri_cesr)?;

    Ok(CreateResult {
        did: did.did().to_string(),
        artifacts,
        custody: KeyCustody::new(hab.state()),
    })
}

/// Build the published artifacts from a key event log, by resolving it.
///
/// The document is not assembled independently — it is whatever
/// [`crate::resolve_from_artifacts`] would derive from this stream. Producing
/// it any other way would let creation and resolution drift apart, and the
/// resolver is the side that decides.
pub(crate) fn artifacts_for(did: &DidWebs, keri_cesr: &[u8]) -> Result<Artifacts, DidWebsError> {
    let kels = crate::kel::Kels::parse(keri_cesr)?;
    let state = kels.key_state(did.aid())?;
    let aliases = crate::aliases::designated_aliases(&kels, did.aid())?;
    let services: Vec<ServiceEndpoint> = crate::services::service_endpoints(&kels, did.aid())?;

    let document = document_from_keys(did, &state.keys, &aliases.aliases, &services)?;
    let did_json = serde_json::to_vec(&document)?;

    Ok(Artifacts {
        keri_cesr: keri_cesr.to_vec(),
        did_json,
    })
}
