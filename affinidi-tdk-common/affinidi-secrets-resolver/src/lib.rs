/*!
 * Affinidi Secrets Resolver
 *
 * Handles everything and anything to do with DID Secrets
 */

use std::sync::{Arc, Mutex};

use errors::Result;
use secrets::Secret;
use tracing::debug;
pub mod errors;
pub mod secrets;

/// Affinidi Secrets Resolver
///
/// Helps with loading and working with DID Secrets
#[derive(Clone, Debug)]
pub struct SecretsResolver {
    known_secrets: Arc<Mutex<Vec<Secret>>>,
}

impl SecretsResolver {
    /// Instantiate a new SecretsResolver
    ///
    /// # Arguments
    /// * `known_secrets` - A list of known secrets (can be empty)
    ///
    /// # Returns
    /// A new SecretsResolver
    ///
    /// ```
    /// use affinidi_secrets_resolver::SecretsResolver;
    ///
    /// let secrets_resolver = SecretsResolver::new(vec![]);
    /// ```
    pub fn new(known_secrets: Vec<Secret>) -> Self {
        SecretsResolver {
            known_secrets: Arc::new(Mutex::new(known_secrets)),
        }
    }

    pub fn insert(&self, secret: Secret) {
        debug!("Adding secret ({})", secret.id);
        self.known_secrets.lock().unwrap().push(secret);
    }

    pub async fn get_secret(&self, secret_id: &str) -> Result<Option<Secret>> {
        Ok(self
            .known_secrets
            .lock()
            .unwrap()
            .iter()
            .find(|s| s.id == secret_id)
            .cloned())
    }

    pub async fn find_secrets(&self, secret_ids: &[String]) -> Result<Vec<String>> {
        Ok(secret_ids
            .iter()
            .filter(|sid| {
                self.known_secrets
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|s| s.id == sid.to_string())
            })
            .cloned()
            .collect())
    }
}
