/*!
 * In multi-threaded applications, it is suggested to use a separate task to handle secrets
 *
 * This removes the need for locks and copying secrets around
 */

use crate::secrets::Secret;
use ahash::AHashMap;
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
};
use tracing::{debug, warn};

pub struct SecretsTask {
    channel_rx: mpsc::Receiver<SecretTaskCommand>,
}

/// Secrets Task Commands
pub enum SecretTaskCommand {
    /// Add a Secret
    AddSecret { secret: Secret },

    /// Add many Secrets
    AddSecrets { secrets: Vec<Secret> },

    /// Remove a secret by its key ID
    RemoveSecret { key_id: String },

    /// Get a secret by its name
    GetSecret {
        key_id: String,
        tx: oneshot::Sender<Option<Secret>>,
    },

    /// Check if a number of Key ID's exist in the Secrets Resolver
    FindSecrets {
        keys: Vec<String>,
        tx: oneshot::Sender<Vec<String>>,
    },

    /// Number of secrets stored
    SecretsStored { tx: oneshot::Sender<usize> },

    /// Terminate the Secrets Task
    Terminate,
}

impl SecretsTask {
    /// Create a new SecretsTask
    pub fn new() -> (Self, mpsc::Sender<SecretTaskCommand>) {
        let (tx, rx) = mpsc::channel(10);

        (SecretsTask { channel_rx: rx }, tx)
    }

    /// Start the Secrets Task
    pub async fn start(self) -> JoinHandle<()> {
        tokio::spawn(async move {
            self.run().await;
        })
    }

    /// Main loop of the Secrets Task
    async fn run(mut self) {
        let mut secrets_cache: AHashMap<String, Secret> = AHashMap::new();

        loop {
            tokio::select! {
                    msg = self.channel_rx.recv() => {
                        if _handle_msg(&mut secrets_cache, msg) {
                            break;
                        }
                }
            } // End of loop

            debug!("Exiting Secrets Task");
        }

        fn _handle_msg(
            secrets_cache: &mut AHashMap<String, Secret>,
            msg: Option<SecretTaskCommand>,
        ) -> bool {
            let mut exit_flag = false;
            match msg {
                Some(SecretTaskCommand::AddSecret { secret }) => {
                    secrets_cache.insert(secret.id.clone(), secret);
                }
                Some(SecretTaskCommand::AddSecrets { secrets }) => {
                    for secret in secrets {
                        secrets_cache.insert(secret.id.clone(), secret);
                    }
                }
                Some(SecretTaskCommand::RemoveSecret { key_id }) => {
                    secrets_cache.remove(&key_id);
                }
                Some(SecretTaskCommand::GetSecret { key_id, tx }) => {
                    let _ = tx.send(secrets_cache.get(&key_id).cloned());
                }
                Some(SecretTaskCommand::FindSecrets { keys, tx }) => {
                    let _ = tx.send(
                        keys.iter()
                            .filter(|sid| secrets_cache.contains_key(sid.as_str()))
                            .cloned()
                            .collect(),
                    );
                }
                Some(SecretTaskCommand::SecretsStored { tx }) => {
                    let _ = tx.send(secrets_cache.len());
                }
                Some(SecretTaskCommand::Terminate) => {
                    debug!("Terminating Secrets Task");
                    exit_flag = true;
                }
                None => {
                    warn!("Secrets Task channel closed unexpectedly");
                    exit_flag = true;
                }
            }

            exit_flag
        }
    }
}
