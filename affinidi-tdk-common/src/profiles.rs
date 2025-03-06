/*!
Profiles modules contains the implementation of the Profile struct and its methods.

A Profile contains information relevant to an identity profile (a DID) and associated information
*/

use crate::errors::{Result, TDKError};
use affinidi_secrets_resolver::secrets::Secret;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fs::File, io::BufReader, path::Path};

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

/// TDK Environments, where each environment is a collection of TDK Profiles.
/// This can be used to manage for example a local and a remote environment and switch easily between them
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TDKEnvironments {
    /// HashMap of profile name to TDKProfile
    environments: HashMap<String, Vec<TDKProfile>>,

    /// Used to know location of file if saving changes back to disk
    #[serde(skip)]
    file_name: Option<String>,
}

impl TDKEnvironments {
    /// Loads an environment from a file
    ///
    /// # Arguments
    /// * `file_path` - Path to the file containing profiles
    /// * `environment_name` - Environment name from environment variable
    ///
    /// # Returns
    /// * Vec<TDKProfile> - Array of TDK Profiles
    pub fn load_from_file(file_path: &str, environment_name: &str) -> Result<Vec<TDKProfile>> {
        let profiles = TDKEnvironments::load_file(file_path)?;

        if let Some(profile) = profiles.environments.get(environment_name) {
            Ok(profile.clone())
        } else {
            Err(TDKError::Profile(format!(
                "Couldn't find profile ({})!",
                environment_name
            )))
        }
    }

    // Load saved profiles from file
    fn load_file(path: &str) -> Result<Self> {
        match Path::new(path).try_exists() {
            Ok(exists) => {
                if exists {
                    let file = File::open(path).map_err(|err| {
                        TDKError::Profile(format!("Couldn't open file ({}): {}", path, err))
                    })?;
                    let reader = BufReader::new(file);
                    let mut profiles: TDKEnvironments =
                        serde_json::from_reader(reader).map_err(|err| {
                            TDKError::Profile(format!("Couldn't deserialize JSON: {}", err))
                        })?;
                    profiles.file_name = Some(path.to_string());
                    Ok(profiles)
                } else {
                    Ok(TDKEnvironments {
                        file_name: Some(path.to_string()),
                        ..Default::default()
                    })
                }
            }
            Err(err) => Err(crate::errors::TDKError::Profile(format!(
                "Profiles file ({}) doesn't exist: {}",
                path, err
            ))),
        }
    }
}
