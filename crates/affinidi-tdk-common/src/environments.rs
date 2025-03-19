/*!
 * Environments modules contains the implementation of the Environments struct and methods.
 *
 * Environments are a collection of profiles, Can be used to maintain a local, development and remote configurations
 * A Profile contains information relevant to an identity profile (a DID) and associated information
*/

use crate::{
    errors::{Result, TDKError},
    profiles::TDKProfile,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs::File,
    io::{BufReader, Write},
    path::Path,
};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TDKEnvironment {
    /// HashMap of profile name to TDKProfile
    pub profiles: HashMap<String, TDKProfile>,

    /// Default messaging mediator for this environment
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_mediator: Option<String>,

    /// An Admin DID for this environment to configure services if required
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admin_did: Option<TDKProfile>,

    /// Custom Client SSL certificates for this environment if needed
    pub ssl_certificates: Vec<String>,
}

impl TDKEnvironment {
    /// Returns true if profile was added, false if it already exists
    pub fn add_profile(&mut self, profile: TDKProfile) -> bool {
        self.profiles
            .insert(profile.alias.clone(), profile)
            .is_none()
    }
}

/// TDK Environments, where each environment is a collection of TDK Profiles.
/// This can be used to manage for example a local and a remote environment and switch easily between them
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TDKEnvironments {
    /// HashMap of profile name to TDKProfile
    environments: HashMap<String, TDKEnvironment>,

    /// Used to know location of file if saving changes back to disk
    #[serde(skip)]
    file_name: Option<String>,
}

impl TDKEnvironments {
    /// Fetches a single environment from a file
    ///
    /// # Arguments
    /// * `file_path` - Path to the file containing profiles, if None, defaults to "environments.json"
    /// * `environment_name` - Environment name
    ///
    /// # Returns
    /// * [TDKEnvironment] - The environment requested
    pub fn fetch_from_file(
        file_path: Option<&str>,
        environment_name: &str,
    ) -> Result<TDKEnvironment> {
        let file_path = file_path.unwrap_or("environments.json");

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

    // Load all environments from file
    pub fn load_file(path: &str) -> Result<Self> {
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

    /// Saves environments to a file
    /// File name is stored in the TDKEnvironments struct
    pub fn save(&self) -> Result<()> {
        let Some(file_name) = &self.file_name else {
            return Err(TDKError::Profile("No file name provided".to_string()));
        };

        let contents = serde_json::to_string_pretty(self).map_err(|err| {
            TDKError::Profile(format!("Couldn't serialize TDK Environments: {}", err))
        })?;

        let mut f = File::create(file_name).map_err(|err| {
            TDKError::Profile(format!("Couldn't create file ({}): {}", file_name, err))
        })?;

        f.write_all(contents.as_bytes()).map_err(|err| {
            TDKError::Profile(format!(
                "Couldn't write TDK Environments to file ({}): {}",
                file_name, err
            ))
        })?;
        Ok(())
    }

    /// Get an environment by name
    pub fn get(&self, environment_name: &str) -> Option<&TDKEnvironment> {
        self.environments.get(environment_name)
    }

    /// Get a mutable environment by name
    pub fn get_mut(&mut self, environment_name: &str) -> Option<&mut TDKEnvironment> {
        self.environments.get_mut(environment_name)
    }

    /// Add an environment
    /// Returns true if the environment was added, false if it already exists
    pub fn add(&mut self, environment_name: &str, environment: TDKEnvironment) -> bool {
        self.environments
            .insert(environment_name.to_string(), environment)
            .is_none()
    }

    /// Removes an environment and all profiles within it
    pub fn remove(&mut self, environment_name: &str) -> bool {
        self.environments.remove(environment_name).is_some()
    }

    /// Returns true if there are no environments
    pub fn is_empty(&self) -> bool {
        self.environments.is_empty()
    }

    /// Returns a list of environment names
    pub fn environments(&self) -> Vec<String> {
        self.environments.keys().cloned().collect()
    }
}
