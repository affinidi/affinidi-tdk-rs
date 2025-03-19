/*!
 * TDK Profiles
 *
 * Environments are a collection of profiles, Can be used to maintain a local, development and remote configurations
 * A Profile contains information relevant to an identity profile (a DID) and associated information
*/

use affinidi_secrets_resolver::secrets::Secret;
use serde::{Deserialize, Serialize};

/// TDKProfile is a serializable version of a Profile
/// These Profiles may be used to store and load profiles from disk
/// Other Affinidi services will use this struct to interact with profiles
/// often by extending this struct with additional information
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TDKProfile {
    /// Friendly name for the profile (Alice, Bob, etc)
    pub alias: String,

    /// DID for this profile
    pub did: String,

    /// DID of the mediator for this profile (if any)
    /// If this is None, and the DID does not have a mediator service endpoint
    /// The default DIDComm mediator in the TDK config will be used
    /// If no DIDComm mediator is configured in either profile or TDK, then Messaging will fail for this profile
    pub mediator: Option<String>,

    /// This is only used when reading/writing to files
    /// Secrets will be added/removed to/from the `SecretsResolver` as required
    pub secrets: Vec<Secret>,
}

impl TDKProfile {
    /// Crate a new TDKProfile
    /// # Arguments
    /// * `alias` - Friendly name for the profile
    /// * `did` - DID for the profile
    /// * `mediator` - DID of the mediator for this profile (if any, if the DID self-resolves to a mediator, this can be None)
    /// * `secrets` - Secrets for the profile
    pub fn new(alias: &str, did: &str, mediator: Option<&str>, secrets: Vec<Secret>) -> Self {
        TDKProfile {
            alias: alias.to_string(),
            did: did.to_string(),
            mediator: mediator.map(|s| s.to_string()),
            secrets,
        }
    }
}
