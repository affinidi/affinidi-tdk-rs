//! Continuing a `did:webs` identifier: rotation, interaction, and services.
//!
//! Like `didwebvh-rs`'s `update_did`, the prior state is passed in rather than
//! held. Here that state is the published artifacts themselves — the key event
//! log *is* `keri.cesr` — plus the custody record and the salt.
//!
//! The prior log is verified before anything is appended to it. Building on a
//! log we have not checked would let a corrupted or substituted artifact become
//! the basis of a signed event.

use affinidi_keri::config::RotationConfig;
use affinidi_keri::hab::Hab;

use crate::artifacts::Artifacts;
use crate::create::{SelfEndpoint, artifacts_for};
use crate::custody::KeyCustody;
use crate::errors::DidWebsError;
use crate::identifier::DidWebs;
use crate::kel::Kels;

/// What to add to an identifier's key event log.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Change {
    /// Rotate to the pre-rotated keys and commit to a new set.
    ///
    /// This is the only operation that changes what the DID document says about
    /// keys, and the only one that can recover from a compromised signing key.
    Rotate(RotationConfig),
    /// Anchor seals in the log without changing keys.
    Interact(Vec<serde_json::Value>),
    /// Designate service endpoints for this identifier.
    ///
    /// Emitted as signed replies rather than written into the document, so a
    /// resolver can verify them. Existing designations are superseded by
    /// timestamp, so re-designating a role replaces where it points.
    Services(Vec<SelfEndpoint>),
}

/// How to continue an identifier.
#[derive(Debug, Clone)]
pub struct UpdateConfig {
    /// The DID being updated.
    pub did: String,
    /// Its currently published artifacts.
    pub prior: Artifacts,
    /// The non-secret half of what is needed to sign — see [`KeyCustody`].
    pub custody: KeyCustody,
    /// What to append.
    pub change: Change,
}

/// An updated identifier.
#[derive(Debug, Clone)]
pub struct UpdateResult {
    did: String,
    artifacts: Artifacts,
    custody: KeyCustody,
}

impl UpdateResult {
    /// The DID, which an update never changes — the AID is fixed at inception.
    pub fn did(&self) -> &str {
        &self.did
    }

    /// The bytes to publish, replacing the previous ones.
    pub fn artifacts(&self) -> &Artifacts {
        &self.artifacts
    }

    /// The custody record to keep, which **replaces** the previous one.
    ///
    /// A rotation advances the key generation, so the old record can no longer
    /// sign. Keeping it by mistake is indistinguishable from losing the keys.
    pub fn custody(&self) -> &KeyCustody {
        &self.custody
    }

    /// Take the artifacts, leaving the rest.
    pub fn into_artifacts(self) -> Artifacts {
        self.artifacts
    }
}

/// Append to an identifier's key event log and rebuild its artifacts.
///
/// `salt` is used to re-derive the signing keys and is never retained.
///
/// # Errors
/// Returns [`DidWebsError`] if the DID is malformed, the prior log does not
/// verify, the custody record does not match it, or the new artifacts do not
/// resolve back.
pub fn update(config: UpdateConfig, salt: &[u8]) -> Result<UpdateResult, DidWebsError> {
    let did = DidWebs::parse(&config.did)?;

    // Verify what is already published before extending it. The custody record
    // says where the identifier had got to; the log is what actually happened.
    let kels = Kels::parse(&config.prior.keri_cesr)?;
    let state = kels.key_state(did.aid())?;

    if config.custody.aid() != did.aid() {
        return Err(DidWebsError::Create(format!(
            "custody record is for {}, not {}",
            config.custody.aid(),
            did.aid(),
        )));
    }
    if config.custody.state.sn != state.sn {
        return Err(DidWebsError::Create(format!(
            "custody record is at sequence number {} but the published log is at {} — \
             one of them is stale, and signing from the wrong point would produce an \
             event nothing accepts",
            config.custody.state.sn, state.sn,
        )));
    }

    let mut hab = Hab::resume(&config.custody.state, salt)
        .map_err(|e| DidWebsError::Create(format!("could not resume the identifier: {e}")))?;

    let mut keri_cesr = config.prior.keri_cesr.clone();

    match &config.change {
        Change::Rotate(rotation) => {
            let event = hab
                .rotate_event(rotation)
                .map_err(|e| DidWebsError::Create(format!("rotation failed: {e}")))?;
            keri_cesr.extend_from_slice(&event.composed);
        }
        Change::Interact(anchors) => {
            let event = hab
                .interact_event(anchors)
                .map_err(|e| DidWebsError::Create(format!("interaction failed: {e}")))?;
            keri_cesr.extend_from_slice(&event.composed);
        }
        Change::Services(services) => {
            // Replies are not key events, so nothing is appended to the log
            // itself — but they must name the establishment event whose keys
            // sign them, which is not necessarily the latest event.
            let establishment = last_establishment_said(&kels, did.aid())?;
            let replies = crate::endpoints::self_designated_replies(
                &hab,
                did.aid(),
                &establishment,
                services,
            )?;
            keri_cesr.extend_from_slice(&replies);
        }
    }

    let artifacts = artifacts_for(&did, &keri_cesr)?;

    Ok(UpdateResult {
        did: did.did().to_string(),
        artifacts,
        custody: KeyCustody::new(hab.state()),
    })
}

/// The SAID of the most recent establishment event in an identifier's log.
///
/// Signatures on messages outside the key event log are authorised by a
/// *establishment* event's key state. Naming the latest event instead would be
/// wrong whenever that event is an interaction.
fn last_establishment_said(kels: &Kels, aid: &str) -> Result<String, DidWebsError> {
    let mut found = None;
    for ilk in ["icp", "rot", "dip", "drt"] {
        for msg in kels.messages_with_ilk(ilk) {
            if msg.serder.prefix().ok().as_deref() != Some(aid) {
                continue;
            }
            let sn = msg.serder.sn().unwrap_or(0);
            let said = match msg.serder.said() {
                Ok(s) => s,
                Err(_) => continue,
            };
            match &found {
                Some((prior_sn, _)) if *prior_sn >= sn => {}
                _ => found = Some((sn, said)),
            }
        }
    }

    found
        .map(|(_, said)| said)
        .ok_or_else(|| DidWebsError::Kel(format!("{aid} has no establishment event in its log")))
}
