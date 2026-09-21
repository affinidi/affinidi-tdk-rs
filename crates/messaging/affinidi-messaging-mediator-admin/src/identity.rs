//! Who the console connects as.
//!
//! The console never finds keys on its own. An [`IdentitySource`] offers the
//! identities a host can use and hands one over, secrets and all, when the user
//! picks it: a file for the standalone console ([`ProfileFileSource`]), a fixed
//! list for an embedding application or a test ([`StaticIdentities`]), or — in
//! `pnm` — the DIDs a Verifiable Trust Agent manages, fetched on demand so no
//! secret is written to disk.
//!
//! This crate deliberately has no dependency on the VTA SDK: the VTA side
//! implements this trait, so the dependency points from the VTA to here.

use std::path::PathBuf;

use affinidi_secrets_resolver::secrets::Secret;
use affinidi_tdk_common::profiles::TDKProfile;
use async_trait::async_trait;

use crate::error::{ConsoleError, Result};

/// A DID the console can act as, with the secrets that prove it.
///
/// Secrets are held only as long as the console needs them and are dropped
/// with it; nothing here persists them.
#[derive(Clone)]
pub struct Identity {
    /// A human name for the identity, shown in the console.
    pub alias: String,
    /// The DID the console authenticates and signs as.
    pub did: String,
    /// The DID's private keys: an Ed25519 key to authenticate and sign Trust
    /// Tasks, and a key-agreement key (X25519 / P-256) to receive replies.
    pub secrets: Vec<Secret>,
    /// The mediator to connect to. `None` finds it from the DID's
    /// `DIDCommMessaging` service.
    pub mediator_did: Option<String>,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("alias", &self.alias)
            .field("did", &self.did)
            .field("secrets", &format_args!("<{} hidden>", self.secrets.len()))
            .field("mediator_did", &self.mediator_did)
            .finish()
    }
}

/// One entry in an identity picker — enough to choose by, no secrets yet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityChoice {
    /// Opaque key the source uses to load the identity.
    pub id: String,
    /// What the user sees.
    pub label: String,
    /// The DID, when the source knows it before loading.
    pub did: Option<String>,
    /// A second line: a context, a file path, a role.
    pub detail: Option<String>,
}

/// Somewhere identities come from.
#[async_trait]
pub trait IdentitySource: Send + Sync {
    /// The identities available to choose from.
    async fn list(&self) -> Result<Vec<IdentityChoice>>;

    /// Load one — fetching its secrets if they are not already at hand.
    async fn load(&self, choice: &IdentityChoice) -> Result<Identity>;
}

/// A fixed set of identities already in memory.
pub struct StaticIdentities(Vec<Identity>);

impl StaticIdentities {
    pub fn new(identities: Vec<Identity>) -> Self {
        Self(identities)
    }
}

#[async_trait]
impl IdentitySource for StaticIdentities {
    async fn list(&self) -> Result<Vec<IdentityChoice>> {
        Ok(self
            .0
            .iter()
            .map(|i| IdentityChoice {
                id: i.did.clone(),
                label: i.alias.clone(),
                did: Some(i.did.clone()),
                detail: i.mediator_did.clone(),
            })
            .collect())
    }

    async fn load(&self, choice: &IdentityChoice) -> Result<Identity> {
        self.0
            .iter()
            .find(|i| i.did == choice.id)
            .cloned()
            .ok_or_else(|| ConsoleError::Identity(format!("no identity {}", choice.id)))
    }
}

/// TDK profile JSON files — `{ alias, did, mediator, secrets }`, the format
/// `mediator-setup` writes for its administrator.
pub struct ProfileFileSource {
    paths: Vec<PathBuf>,
}

impl ProfileFileSource {
    pub fn new(paths: Vec<PathBuf>) -> Self {
        Self { paths }
    }

    fn read(path: &PathBuf) -> Result<TDKProfile> {
        let bytes = std::fs::read(path)
            .map_err(|e| ConsoleError::Identity(format!("{}: {e}", path.display())))?;
        serde_json::from_slice(&bytes).map_err(|e| {
            ConsoleError::Identity(format!("{} is not a profile: {e}", path.display()))
        })
    }
}

#[async_trait]
impl IdentitySource for ProfileFileSource {
    async fn list(&self) -> Result<Vec<IdentityChoice>> {
        self.paths
            .iter()
            .map(|path| {
                let profile = Self::read(path)?;
                Ok(IdentityChoice {
                    id: path.display().to_string(),
                    label: profile.alias.clone(),
                    did: Some(profile.did.clone()),
                    detail: Some(path.display().to_string()),
                })
            })
            .collect()
    }

    async fn load(&self, choice: &IdentityChoice) -> Result<Identity> {
        let path = self
            .paths
            .iter()
            .find(|p| p.display().to_string() == choice.id)
            .ok_or_else(|| ConsoleError::Identity(format!("no profile {}", choice.id)))?;
        let mut profile = Self::read(path)?;
        let secrets = profile.take_secrets();
        if secrets.is_empty() {
            return Err(ConsoleError::Identity(format!(
                "{} carries no secrets",
                path.display()
            )));
        }
        Ok(Identity {
            alias: profile.alias.clone(),
            did: profile.did.clone(),
            secrets,
            mediator_did: profile.mediator.clone(),
        })
    }
}
