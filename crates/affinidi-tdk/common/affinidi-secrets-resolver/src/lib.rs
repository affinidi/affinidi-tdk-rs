/*!
 * Affinidi Secrets Resolver
 *
 * Handles everything and anything to do with DID Secrets
 *
 * SecretsResolver is the main struct
 * You can instantiate SecretsResolver in one of two ways:
 * 1. A simple cache of Secrets used directly (not thread-safe)
 *   - SimpleSecretsResolver
 * 2. A task-based cache of Secrets used in a multi-threaded environment
 *   - ThreadedSecretsResolver
 */

use ahash::AHashMap;
use secrets::Secret;
use std::{cell::RefCell, time::Duration};
use task::{SecretTaskCommand, SecretsTask};
use tokio::{
    sync::{
        mpsc::{self, error::TrySendError},
        oneshot,
    },
    task::JoinHandle,
};
use tracing::{debug, warn};

pub mod crypto;
pub mod errors;
pub mod jwk;
pub mod multicodec;
pub mod secrets;
pub mod task;

/// Affinidi Secrets Resolver
#[allow(async_fn_in_trait)]
pub trait SecretsResolver {
    /// Insert a single Secret
    async fn insert(&self, secret: Secret);

    /// Insert multiple Secrets
    async fn insert_vec(&self, secrets: &[Secret]);

    /// Get a Secret by its ID
    async fn get_secret(&self, secret_id: &str) -> Option<Secret>;

    /// Find secrets by their key IDs
    /// # Arguments
    /// * `secret_ids` - A list of secret IDs to find
    ///
    /// # Returns
    /// A list of secret IDs that were found
    async fn find_secrets(&self, secret_ids: &[String]) -> Vec<String>;

    /// Removes the secret with the given ID
    async fn remove_secret(&self, secret_id: &str) -> Option<Secret>;

    /// Returns the number of known secrets
    async fn len(&self) -> usize;

    /// Returns true if there are no known secrets
    async fn is_empty(&self) -> bool;
}

/// Affinidi Secrets Resolver
///
/// Helps with loading and working with DID Secrets
pub struct SimpleSecretsResolver {
    known_secrets: RefCell<AHashMap<String, Secret>>,
}

impl SimpleSecretsResolver {
    /// Instantiate a new SimpleSecretsResolver
    ///
    /// # Arguments
    /// * `known_secrets` - A list of known secrets (can be empty)
    ///
    /// # Returns
    /// A new SimpleSecretsResolver
    ///
    /// ```
    /// use affinidi_secrets_resolver::SimpleSecretsResolver;
    ///
    /// let secrets_resolver = SimpleSecretsResolver::new(&[]);
    /// ```
    pub async fn new(known_secrets: &[Secret]) -> Self {
        let secrets = SimpleSecretsResolver {
            known_secrets: RefCell::new(AHashMap::new()),
        };

        secrets.insert_vec(known_secrets).await;

        secrets
    }
}

impl SecretsResolver for SimpleSecretsResolver {
    async fn insert(&self, secret: Secret) {
        self.insert_vec(&[secret]).await;
    }

    async fn insert_vec(&self, secrets: &[Secret]) {
        for secret in secrets {
            debug!("Adding secret ({})", secret.id);
            self.known_secrets
                .borrow_mut()
                .insert(secret.id.to_owned(), secret.to_owned());
        }
    }

    async fn get_secret(&self, secret_id: &str) -> Option<Secret> {
        self.known_secrets.borrow().get(secret_id).cloned()
    }

    async fn find_secrets(&self, secret_ids: &[String]) -> Vec<String> {
        secret_ids
            .iter()
            .filter(|sid| self.known_secrets.borrow().contains_key(sid.as_str()))
            .cloned()
            .collect()
    }

    async fn remove_secret(&self, secret_id: &str) -> Option<Secret> {
        self.known_secrets.borrow_mut().remove(secret_id)
    }

    async fn len(&self) -> usize {
        self.known_secrets.borrow().len()
    }

    async fn is_empty(&self) -> bool {
        self.known_secrets.borrow().is_empty()
    }
}

// *****************************************************************************************************
// *****************************************************************************************************
// *****************************************************************************************************

/// Multithreaded Affinidi Secrets Resolver
/// Operates as a common task, using channels to communicate without locks
#[derive(Clone)]
pub struct ThreadedSecretsResolver {
    tx: mpsc::Sender<SecretTaskCommand>,
}

impl ThreadedSecretsResolver {
    pub async fn new(
        secrets_task_tx: Option<mpsc::Sender<SecretTaskCommand>>,
    ) -> (Self, Option<JoinHandle<()>>) {
        if let Some(tx) = secrets_task_tx {
            (ThreadedSecretsResolver { tx }, None)
        } else {
            let (task, tx) = SecretsTask::new();
            (ThreadedSecretsResolver { tx }, Some(task.start().await))
        }
    }

    /// Stops the Secrets Task
    pub async fn stop(&self) {
        let _ = self.tx.send(SecretTaskCommand::Terminate).await;
    }
}

impl SecretsResolver for ThreadedSecretsResolver {
    async fn insert(&self, secret: Secret) {
        self.insert_vec(&[secret]).await;
    }

    async fn insert_vec(&self, secrets: &[Secret]) {
        for secret in secrets {
            debug!("Adding secret ({})", secret.id);
            match self.tx.try_send(SecretTaskCommand::AddSecret {
                secret: secret.to_owned(),
            }) {
                Ok(_) => (),
                Err(TrySendError::Closed(_)) => {
                    warn!("Secrets Task has been closed");
                }
                Err(TrySendError::Full(_)) => {
                    warn!("Secrets Task channel is full");
                }
            }
        }
    }

    async fn get_secret(&self, secret_id: &str) -> Option<Secret> {
        let (tx, rx) = oneshot::channel();
        match self.tx.try_send(SecretTaskCommand::GetSecret {
            key_id: secret_id.to_string(),
            tx,
        }) {
            Ok(_) => (),
            Err(TrySendError::Closed(_)) => {
                warn!("Secrets Task has been closed");
                return None;
            }
            Err(TrySendError::Full(_)) => {
                warn!("Secrets Task channel is full");
                return None;
            }
        }

        let timeout = tokio::time::sleep(Duration::from_secs(1));
        tokio::pin!(timeout);

        tokio::select! {
            _ = &mut timeout => None,
            rx = rx => rx.unwrap_or(None)
        }
    }

    async fn find_secrets(&self, secret_ids: &[String]) -> Vec<String> {
        let (tx, rx) = oneshot::channel();
        match self.tx.try_send(SecretTaskCommand::FindSecrets {
            keys: secret_ids.to_vec(),
            tx,
        }) {
            Ok(_) => (),
            Err(TrySendError::Closed(_)) => {
                warn!("Secrets Task has been closed");
                return vec![];
            }
            Err(TrySendError::Full(_)) => {
                warn!("Secrets Task channel is full");
                return vec![];
            }
        }

        let timeout = tokio::time::sleep(Duration::from_secs(1));
        tokio::pin!(timeout);

        tokio::select! {
            _ = &mut timeout => vec![],
            rx = rx => rx.unwrap_or(vec![])
        }
    }

    /// This implementation will always return None!
    async fn remove_secret(&self, secret_id: &str) -> Option<Secret> {
        match self.tx.try_send(SecretTaskCommand::RemoveSecret {
            key_id: secret_id.to_string(),
        }) {
            Ok(_) => (),
            Err(TrySendError::Closed(_)) => {
                warn!("Secrets Task has been closed");
            }
            Err(TrySendError::Full(_)) => {
                warn!("Secrets Task channel is full");
            }
        }

        None
    }

    async fn len(&self) -> usize {
        let (tx, rx) = oneshot::channel();
        match self.tx.try_send(SecretTaskCommand::SecretsStored { tx }) {
            Ok(_) => (),
            Err(TrySendError::Closed(_)) => {
                warn!("Secrets Task has been closed");
                return 0;
            }
            Err(TrySendError::Full(_)) => {
                warn!("Secrets Task channel is full");
                return 0;
            }
        }

        let timeout = tokio::time::sleep(Duration::from_secs(1));
        tokio::pin!(timeout);

        tokio::select! {
            _ = &mut timeout => 0,
            rx = rx => {
                rx.unwrap_or(0)
            }
        }
    }

    async fn is_empty(&self) -> bool {
        let (tx, rx) = oneshot::channel();
        match self.tx.try_send(SecretTaskCommand::SecretsStored { tx }) {
            Ok(_) => (),
            Err(TrySendError::Closed(_)) => {
                warn!("Secrets Task has been closed");
                return true;
            }
            Err(TrySendError::Full(_)) => {
                warn!("Secrets Task channel is full");
                return true;
            }
        }

        let timeout = tokio::time::sleep(Duration::from_secs(1));
        tokio::pin!(timeout);

        tokio::select! {
            _ = &mut timeout => true,
            rx = rx => {
                match rx {
                    Ok(length) => length == 0,
                    Err(_) => true,
                }
            }
        }
    }
}
