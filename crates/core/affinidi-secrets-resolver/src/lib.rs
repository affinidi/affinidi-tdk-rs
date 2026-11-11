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
use errors::SecretsResolverError;
use secrets::Secret;
use std::{cell::RefCell, future::Future, time::Duration};
use task::{SecretTaskCommand, SecretsTask};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
};
use tracing::{debug, error};

// Private module - contains impl Secret blocks for generate_* methods
mod crypto;

pub mod errors;
pub mod secrets;
pub mod task;

// Re-export multicodec from affinidi-encoding
pub use affinidi_encoding::multicodec;

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
            .filter_map(|sid| {
                if self.known_secrets.borrow().contains_key(sid) {
                    Some(sid.to_string())
                } else {
                    None
                }
            })
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

/// The most a [`ThreadedSecretsResolver`] operation waits for the secrets
/// task, from queueing the command to the task's answer.
pub const SECRETS_TASK_TIMEOUT: Duration = Duration::from_secs(5);

/// Multithreaded Affinidi Secrets Resolver
/// Operates as a common task, using channels to communicate without locks
///
/// Commands wait for room on the task's channel rather than being dropped
/// when it is full. The [`SecretsResolver`] methods cannot return an error,
/// so a stopped or unresponsive task is logged and reads report nothing
/// found. Use the `try_*` methods to tell those cases apart from a missing
/// key.
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

    /// Insert secrets, returning once the task has stored them.
    ///
    /// # Errors
    ///
    /// [`SecretsResolverError::SecretsTaskClosed`] or
    /// [`SecretsResolverError::SecretsTaskTimeout`]; none of the secrets can
    /// be assumed stored.
    pub async fn try_insert_vec(&self, secrets: &[Secret]) -> errors::Result<()> {
        for secret in secrets {
            debug!("Adding secret ({})", secret.id);
        }
        bounded(async {
            self.send(SecretTaskCommand::AddSecrets {
                secrets: secrets.to_vec(),
            })
            .await?;
            self.applied().await
        })
        .await
    }

    /// Get a secret by its ID. `Ok(None)` means the task does not hold it.
    ///
    /// # Errors
    ///
    /// [`SecretsResolverError::SecretsTaskClosed`] or
    /// [`SecretsResolverError::SecretsTaskTimeout`].
    pub async fn try_get_secret(&self, secret_id: &str) -> errors::Result<Option<Secret>> {
        bounded(self.request(|tx| SecretTaskCommand::GetSecret {
            key_id: secret_id.to_string(),
            tx,
        }))
        .await
    }

    /// The subset of `secret_ids` the task holds.
    ///
    /// # Errors
    ///
    /// [`SecretsResolverError::SecretsTaskClosed`] or
    /// [`SecretsResolverError::SecretsTaskTimeout`].
    pub async fn try_find_secrets(&self, secret_ids: &[String]) -> errors::Result<Vec<String>> {
        bounded(self.request(|tx| SecretTaskCommand::FindSecrets {
            keys: secret_ids.to_vec(),
            tx,
        }))
        .await
    }

    /// Remove a secret, returning once the task has removed it.
    ///
    /// # Errors
    ///
    /// [`SecretsResolverError::SecretsTaskClosed`] or
    /// [`SecretsResolverError::SecretsTaskTimeout`]; the secret may still be
    /// held.
    pub async fn try_remove_secret(&self, secret_id: &str) -> errors::Result<()> {
        bounded(async {
            self.send(SecretTaskCommand::RemoveSecret {
                key_id: secret_id.to_string(),
            })
            .await?;
            self.applied().await
        })
        .await
    }

    /// The number of secrets the task holds.
    ///
    /// # Errors
    ///
    /// [`SecretsResolverError::SecretsTaskClosed`] or
    /// [`SecretsResolverError::SecretsTaskTimeout`].
    pub async fn try_len(&self) -> errors::Result<usize> {
        bounded(self.request(|tx| SecretTaskCommand::SecretsStored { tx })).await
    }

    /// Wait for room on the channel. Callers bound the wait with [`bounded`].
    async fn send(&self, command: SecretTaskCommand) -> errors::Result<()> {
        self.tx
            .send(command)
            .await
            .map_err(|_| SecretsResolverError::SecretsTaskClosed)
    }

    async fn request<T>(
        &self,
        command: impl FnOnce(oneshot::Sender<T>) -> SecretTaskCommand,
    ) -> errors::Result<T> {
        let (tx, rx) = oneshot::channel();
        self.send(command(tx)).await?;
        rx.await
            .map_err(|_| SecretsResolverError::SecretsTaskClosed)
    }

    /// The task handles commands in order, so once it answers a later one,
    /// every command sent before it has been applied.
    async fn applied(&self) -> errors::Result<()> {
        self.request(|tx| SecretTaskCommand::SecretsStored { tx })
            .await
            .map(|_| ())
    }
}

/// Run one whole operation against the secrets task within
/// [`SECRETS_TASK_TIMEOUT`].
async fn bounded<T>(operation: impl Future<Output = errors::Result<T>>) -> errors::Result<T> {
    tokio::time::timeout(SECRETS_TASK_TIMEOUT, operation)
        .await
        .unwrap_or(Err(SecretsResolverError::SecretsTaskTimeout(
            SECRETS_TASK_TIMEOUT,
        )))
}

fn log_task_error(operation: &str, err: &SecretsResolverError) {
    error!("Secrets resolver could not {operation}: {err}");
}

impl SecretsResolver for ThreadedSecretsResolver {
    async fn insert(&self, secret: Secret) {
        self.insert_vec(&[secret]).await;
    }

    async fn insert_vec(&self, secrets: &[Secret]) {
        if let Err(err) = self.try_insert_vec(secrets).await {
            log_task_error("insert secrets", &err);
        }
    }

    async fn get_secret(&self, secret_id: &str) -> Option<Secret> {
        self.try_get_secret(secret_id).await.unwrap_or_else(|err| {
            log_task_error("get a secret", &err);
            None
        })
    }

    async fn find_secrets(&self, secret_ids: &[String]) -> Vec<String> {
        self.try_find_secrets(secret_ids)
            .await
            .unwrap_or_else(|err| {
                log_task_error("find secrets", &err);
                Vec::new()
            })
    }

    /// This implementation will always return None!
    async fn remove_secret(&self, secret_id: &str) -> Option<Secret> {
        if let Err(err) = self.try_remove_secret(secret_id).await {
            log_task_error("remove a secret", &err);
        }
        None
    }

    async fn len(&self) -> usize {
        self.try_len().await.unwrap_or_else(|err| {
            log_task_error("count secrets", &err);
            0
        })
    }

    async fn is_empty(&self) -> bool {
        self.len().await == 0
    }
}

#[cfg(all(test, feature = "ed25519"))]
mod tests {
    use super::*;

    fn secrets(count: usize) -> Vec<Secret> {
        (0..count)
            .map(|index| {
                Secret::generate_ed25519(Some(&format!("did:example:a#key-{index}")), None)
            })
            .collect()
    }

    /// More secrets than the channel holds, inserted before the task has had
    /// a chance to run (a current-thread runtime), are all stored.
    #[tokio::test]
    async fn insert_vec_stores_more_secrets_than_the_channel_holds() {
        let (resolver, _task) = ThreadedSecretsResolver::new(None).await;
        let batch = secrets(100);
        resolver.insert_vec(&batch).await;
        assert_eq!(resolver.len().await, 100);
        assert!(resolver.get_secret("did:example:a#key-99").await.is_some());
    }

    /// The same, one `insert` call per secret.
    #[tokio::test]
    async fn single_inserts_beyond_the_channel_capacity_are_all_stored() {
        let (resolver, _task) = ThreadedSecretsResolver::new(None).await;
        for secret in secrets(100) {
            resolver.insert(secret).await;
        }
        assert_eq!(resolver.try_len().await.unwrap(), 100);
    }

    /// Senders that find the channel full wait for room, so every command
    /// queued before the task starts takes effect.
    #[tokio::test]
    async fn senders_wait_for_room_instead_of_dropping_commands() {
        let (task, tx) = SecretsTask::new();
        let resolver = ThreadedSecretsResolver { tx };
        let senders: Vec<_> = secrets(100)
            .into_iter()
            .map(|secret| {
                let resolver = resolver.clone();
                tokio::spawn(
                    async move { resolver.send(SecretTaskCommand::AddSecret { secret }).await },
                )
            })
            .collect();
        tokio::task::yield_now().await;

        let handle = task.start().await;
        for sender in senders {
            sender.await.unwrap().unwrap();
        }
        assert_eq!(resolver.try_len().await.unwrap(), 100);
        resolver.stop().await;
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn try_remove_secret_removes_it() {
        let (resolver, _task) = ThreadedSecretsResolver::new(None).await;
        resolver.try_insert_vec(&secrets(1)).await.unwrap();
        resolver
            .try_remove_secret("did:example:a#key-0")
            .await
            .unwrap();
        assert!(
            resolver
                .try_get_secret("did:example:a#key-0")
                .await
                .unwrap()
                .is_none()
        );
    }

    /// A missing key is `Ok(None)`; a stopped task is an error, not "not found".
    #[tokio::test]
    async fn a_stopped_task_is_reported_as_an_error() {
        let (resolver, task) = ThreadedSecretsResolver::new(None).await;
        assert!(
            resolver
                .try_get_secret("did:example:a#missing")
                .await
                .unwrap()
                .is_none()
        );

        resolver.stop().await;
        task.unwrap().await.unwrap();

        assert!(matches!(
            resolver.try_get_secret("did:example:a#key-0").await,
            Err(SecretsResolverError::SecretsTaskClosed)
        ));
        assert!(matches!(
            resolver.try_insert_vec(&secrets(1)).await,
            Err(SecretsResolverError::SecretsTaskClosed)
        ));
        assert!(matches!(
            resolver
                .try_find_secrets(&["did:example:a#key-0".to_string()])
                .await,
            Err(SecretsResolverError::SecretsTaskClosed)
        ));
        assert!(matches!(
            resolver.try_remove_secret("did:example:a#key-0").await,
            Err(SecretsResolverError::SecretsTaskClosed)
        ));
        assert!(matches!(
            resolver.try_len().await,
            Err(SecretsResolverError::SecretsTaskClosed)
        ));
    }

    /// A receiver that takes commands but never answers: the whole insert,
    /// queueing plus confirmation, is bounded by one `SECRETS_TASK_TIMEOUT`.
    #[tokio::test(start_paused = true)]
    async fn an_insert_is_bounded_by_one_timeout_overall() {
        let (tx, mut rx) = mpsc::channel(32);
        let (resolver, _) = ThreadedSecretsResolver::new(Some(tx)).await;
        let held = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Some(command) = rx.recv().await {
                held.push(command);
            }
        });
        let started = tokio::time::Instant::now();
        assert!(matches!(
            resolver.try_insert_vec(&secrets(1)).await,
            Err(SecretsResolverError::SecretsTaskTimeout(_))
        ));
        assert_eq!(started.elapsed(), SECRETS_TASK_TIMEOUT);
        drop(resolver);
        held.await.unwrap();
    }

    /// A full channel whose reader never drains it times out with an error
    /// rather than dropping the command.
    #[tokio::test(start_paused = true)]
    async fn a_full_channel_that_never_drains_times_out() {
        let (tx, _rx) = mpsc::channel(1);
        let (resolver, _) = ThreadedSecretsResolver::new(Some(tx)).await;
        resolver
            .send(SecretTaskCommand::SecretsStored {
                tx: oneshot::channel().0,
            })
            .await
            .unwrap();
        assert!(matches!(
            resolver.try_insert_vec(&secrets(1)).await,
            Err(SecretsResolverError::SecretsTaskTimeout(_))
        ));
    }
}
