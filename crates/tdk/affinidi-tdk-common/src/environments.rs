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
use rustls::pki_types::CertificateDer;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs::File,
    io::{BufReader, Write},
    path::Path,
};

/// A named environment: a bag of profiles plus environment-level defaults
/// (mediator, admin identity, custom TLS roots).
///
/// Persisted to disk via [`TDKEnvironments`]; consumed at runtime by
/// [`crate::TDKSharedState`]. Fields are `pub(crate)`; read via accessor
/// methods, mutate via `add_profile` / `set_*` helpers.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TDKEnvironment {
    /// Profiles keyed by alias.
    #[serde(default)]
    pub(crate) profiles: HashMap<String, TDKProfile>,

    /// DIDComm mediator DID used as a fall-back when a profile's own
    /// `mediator` field is `None`. See
    /// [`crate::TDKSharedState::resolve_mediator`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) default_mediator: Option<String>,

    /// Admin profile for this environment, if any. Activated by an explicit
    /// call to [`crate::TDKSharedState::activate_admin_profile`] — not loaded
    /// automatically, since admin secrets are sensitive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) admin_did: Option<TDKProfile>,

    /// Paths to PEM-encoded SSL certificates to add as extra trust roots on
    /// the TDK HTTPS client. Each entry is a path on disk; multiple
    /// certificates per file are supported. Loaded at
    /// [`crate::TDKSharedState::new`] time alongside the platform verifier.
    #[serde(default)]
    pub(crate) ssl_certificates: Vec<String>,
}

impl TDKEnvironment {
    /// Insert a profile, keyed on its `alias`. Any existing profile with the
    /// same alias is replaced.
    ///
    /// Returns `true` if no previous profile with this alias existed,
    /// `false` if an existing profile was replaced.
    pub fn add_profile(&mut self, profile: TDKProfile) -> bool {
        self.profiles
            .insert(profile.alias.clone(), profile)
            .is_none()
    }

    /// All profiles in this environment, keyed by alias.
    pub fn profiles(&self) -> &HashMap<String, TDKProfile> {
        &self.profiles
    }

    /// Look up a profile by alias.
    pub fn profile(&self, alias: &str) -> Option<&TDKProfile> {
        self.profiles.get(alias)
    }

    /// Default mediator DID, if configured.
    pub fn default_mediator(&self) -> Option<&str> {
        self.default_mediator.as_deref()
    }

    /// Set or clear the default mediator.
    pub fn set_default_mediator(&mut self, mediator: Option<String>) {
        self.default_mediator = mediator;
    }

    /// Admin profile, if configured.
    pub fn admin_did(&self) -> Option<&TDKProfile> {
        self.admin_did.as_ref()
    }

    /// Set or clear the admin profile.
    pub fn set_admin_did(&mut self, admin_did: Option<TDKProfile>) {
        self.admin_did = admin_did;
    }

    /// File paths to PEM-encoded SSL certificates configured for this
    /// environment. The actual `CertificateDer` byte payloads are loaded
    /// at [`crate::TDKSharedState::new`] time.
    pub fn ssl_certificate_paths(&self) -> &[String] {
        &self.ssl_certificates
    }

    /// Replace the list of SSL certificate paths.
    pub fn set_ssl_certificate_paths(&mut self, paths: Vec<String>) {
        self.ssl_certificates = paths;
    }

    /// Load and parse all PEM files referenced by
    /// [`ssl_certificate_paths`](Self::ssl_certificate_paths). Multiple
    /// certificates per file are supported. Returns an empty `Vec` if no
    /// paths are configured.
    ///
    /// # Errors
    ///
    /// Returns [`TDKError::Config`] on the first IO or parse error — there
    /// is no silent partial-success path, since silently dropping trust
    /// anchors is a security footgun.
    pub fn load_ssl_certificates(&self) -> Result<Vec<CertificateDer<'static>>> {
        let mut out = Vec::new();
        for path in &self.ssl_certificates {
            let file = File::open(path).map_err(|e| {
                TDKError::Config(format!("Couldn't open SSL certificate file ({path}): {e}"))
            })?;
            let mut reader = BufReader::new(file);
            for cert in rustls_pemfile::certs(&mut reader) {
                let cert = cert.map_err(|e| {
                    TDKError::Config(format!("Couldn't parse SSL certificate from ({path}): {e}"))
                })?;
                out.push(cert);
            }
        }
        Ok(out)
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
        assert!(reloaded.get("local").unwrap().profile("alice").is_some());
    }

    #[test]
    fn fetch_from_file_returns_named_environment() {
        let dir = TempDir::new().unwrap();
        let path = tmp_path(&dir, "envs.json");

        let mut envs = TDKEnvironments::load_file(&path).unwrap();
        envs.add("dev", TDKEnvironment::default());
        envs.save().unwrap();

        let env = TDKEnvironments::fetch_from_file(Some(&path), "dev").unwrap();
        assert!(env.profiles().is_empty());
    }

    #[test]
    fn default_mediator_round_trips() {
        let mut env = TDKEnvironment::default();
        assert!(env.default_mediator().is_none());
        env.set_default_mediator(Some("did:web:mediator.example.com".into()));
        assert_eq!(env.default_mediator(), Some("did:web:mediator.example.com"));
        env.set_default_mediator(None);
        assert!(env.default_mediator().is_none());
    }

    #[test]
    fn load_ssl_certificates_empty_when_unset() {
        let env = TDKEnvironment::default();
        assert!(env.load_ssl_certificates().unwrap().is_empty());
    }

    #[test]
    fn load_ssl_certificates_parses_pem_file() {
        let dir = TempDir::new().unwrap();
        let pem_path = dir.path().join("test-ca.pem");
        // Minimal self-signed test certificate generated for this test.
        // Issuer/subject CN=tdk-test-ca, valid 1970-2099.
        const TEST_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIBhDCCASqgAwIBAgIULjs5/G2vlobcETBOIINyzlYG/2YwCgYIKoZIzj0EAwIw\n\
FjEUMBIGA1UEAwwLdGRrLXRlc3QtY2EwIBcNNzAwMTAxMDAwMDAxWhgPMjA5OTEy\n\
MzEyMzU5NTlaMBYxFDASBgNVBAMMC3Rkay10ZXN0LWNhMFkwEwYHKoZIzj0CAQYI\n\
KoZIzj0DAQcDQgAEgmehPLMaCJl9XwPFNaaHN5KbKHDaR/D5K3uBzPJ8LqsR3XRo\n\
0Q+L3tudLpr1EatHC58mPSAcb3CpwpufKpCw0KNTMFEwHQYDVR0OBBYEFB7yyBuy\n\
8KS0H3jwgY40lc6wDPoTMB8GA1UdIwQYMBaAFB7yyBuy8KS0H3jwgY40lc6wDPoT\n\
MA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIhAOrMcOhEMQyAJUmU\n\
xxnCt9D8Yh3I+QTW9zd6/EGUUYz2AiBYwDOX4Hd/8oF3MBLQEKDPa8qHrtyf2X1d\n\
HM18aTnPhg==\n\
-----END CERTIFICATE-----\n";
        std::fs::write(&pem_path, TEST_PEM).unwrap();

        let mut env = TDKEnvironment::default();
        env.set_ssl_certificate_paths(vec![pem_path.to_string_lossy().into_owned()]);
        let certs = env.load_ssl_certificates().unwrap();
        assert_eq!(certs.len(), 1);
    }

    #[test]
    fn load_ssl_certificates_errors_on_missing_file() {
        let mut env = TDKEnvironment::default();
        env.set_ssl_certificate_paths(vec!["/nonexistent/no-such-cert.pem".to_string()]);
        let err = env.load_ssl_certificates().unwrap_err();
        assert!(matches!(err, TDKError::Config(_)));
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
