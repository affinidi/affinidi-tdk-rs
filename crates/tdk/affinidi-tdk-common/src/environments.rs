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

        let environments = TDKEnvironments::load_file(file_path)?;

        if let Some(environment) = environments.environments.get(environment_name) {
            Ok(environment.clone())
        } else {
            Err(TDKError::Profile(format!(
                "Couldn't find environment ({environment_name})!"
            )))
        }
    }

    /// Load all environments from `path`.
    ///
    /// If the file does not exist, returns an empty [`TDKEnvironments`] with
    /// `file_name` set so a subsequent [`save`](Self::save) creates it.
    /// Permissions / IO errors and JSON-parse errors propagate as
    /// [`TDKError::Profile`].
    pub fn load_file(path: &str) -> Result<Self> {
        match Path::new(path).try_exists() {
            Ok(true) => {
                let file = File::open(path).map_err(|err| {
                    TDKError::Profile(format!("Failed to open environments file ({path}): {err}"))
                })?;
                let reader = BufReader::new(file);
                let mut profiles: TDKEnvironments =
                    serde_json::from_reader(reader).map_err(|err| {
                        TDKError::Profile(format!(
                            "Failed to deserialise environments file ({path}): {err}"
                        ))
                    })?;
                profiles.file_name = Some(path.to_string());
                Ok(profiles)
            }
            Ok(false) => Ok(TDKEnvironments {
                file_name: Some(path.to_string()),
                ..Default::default()
            }),
            Err(err) => Err(TDKError::Profile(format!(
                "Failed to stat environments file ({path}): {err}"
            ))),
        }
    }

    /// Persist environments to the file the [`TDKEnvironments`] was loaded
    /// from (or whose name was supplied at construction). Errors if no
    /// file name has been recorded.
    pub fn save(&self) -> Result<()> {
        let Some(file_name) = &self.file_name else {
            return Err(TDKError::Profile(
                "Cannot save TDKEnvironments: no file name recorded (load via load_file first)"
                    .to_string(),
            ));
        };

        let contents = serde_json::to_string_pretty(self).map_err(|err| {
            TDKError::Profile(format!("Failed to serialise TDKEnvironments: {err}"))
        })?;

        let mut f = File::create(file_name).map_err(|err| {
            TDKError::Profile(format!(
                "Failed to create environments file ({file_name}): {err}"
            ))
        })?;

        f.write_all(contents.as_bytes()).map_err(|err| {
            TDKError::Profile(format!(
                "Failed to write environments file ({file_name}): {err}"
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn tmp_path(dir: &TempDir, name: &str) -> String {
        dir.path().join(name).to_string_lossy().into_owned()
    }

    #[test]
    fn load_file_returns_empty_when_missing() {
        let dir = TempDir::new().unwrap();
        let path = tmp_path(&dir, "missing.json");
        let envs = TDKEnvironments::load_file(&path).unwrap();
        assert!(envs.is_empty());
        assert_eq!(envs.file_name.as_deref(), Some(path.as_str()));
    }

    #[test]
    fn save_then_load_roundtrip() {
        let dir = TempDir::new().unwrap();
        let path = tmp_path(&dir, "envs.json");

        let mut envs = TDKEnvironments::load_file(&path).unwrap();
        let mut env = TDKEnvironment::default();
        env.add_profile(TDKProfile::new("alice", "did:example:alice", None, vec![]));
        envs.add("local", env);
        envs.save().unwrap();

        let reloaded = TDKEnvironments::load_file(&path).unwrap();
        assert_eq!(reloaded.environments(), vec!["local".to_string()]);
        assert!(
            reloaded
                .get("local")
                .unwrap()
                .profiles
                .contains_key("alice")
        );
    }

    #[test]
    fn fetch_from_file_returns_named_environment() {
        let dir = TempDir::new().unwrap();
        let path = tmp_path(&dir, "envs.json");

        let mut envs = TDKEnvironments::load_file(&path).unwrap();
        envs.add("dev", TDKEnvironment::default());
        envs.save().unwrap();

        let env = TDKEnvironments::fetch_from_file(Some(&path), "dev").unwrap();
        assert!(env.profiles.is_empty());
    }

    #[test]
    fn fetch_from_file_errors_for_unknown_environment() {
        let dir = TempDir::new().unwrap();
        let path = tmp_path(&dir, "envs.json");

        let mut envs = TDKEnvironments::load_file(&path).unwrap();
        envs.add("dev", TDKEnvironment::default());
        envs.save().unwrap();

        let err = TDKEnvironments::fetch_from_file(Some(&path), "prod").unwrap_err();
        assert!(matches!(err, TDKError::Profile(_)));
    }

    #[test]
    fn save_without_filename_errors() {
        let envs = TDKEnvironments::default();
        let err = envs.save().unwrap_err();
        assert!(matches!(err, TDKError::Profile(_)));
    }

    #[test]
    fn add_profile_returns_false_on_replace() {
        let mut env = TDKEnvironment::default();
        let p = TDKProfile::new("alice", "did:example:1", None, vec![]);
        assert!(env.add_profile(p.clone()));
        assert!(!env.add_profile(p)); // same alias replaces
    }
}
