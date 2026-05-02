/*!
 * Convenience wrappers for the OS keyring.
 *
 * Each method here builds a one-shot
 * [`KeyringStore`] bound to the
 * supplied `service_id` and forwards. For repeated operations on the same
 * `service_id`, prefer constructing a `KeyringStore` once at the call site —
 * this saves the per-call namespace binding and keeps the underlying
 * `keyring-core` `Entry` lifetime explicit.
 */

use affinidi_secrets_resolver::secrets::Secret;
use affinidi_tdk_common::{errors::TDKError, secrets::KeyringStore};

use crate::TDK;

impl TDK {
    /// Delete the keyring entry for `(service_id, did)`.
    ///
    /// Idempotent: a missing entry returns `Ok(())`. Other failures
    /// (platform store unavailable, permission denied) propagate as
    /// [`TDKError::Secrets`].
    pub fn delete_did_secret(&self, service_id: &str, did: &str) -> Result<(), TDKError> {
        KeyringStore::new(service_id).delete(did)
    }

    /// Persist `secrets` to the OS keyring under `(service_id, did)`.
    ///
    /// Any existing entry for the same key is overwritten.
    pub fn save_secrets_locally(
        &self,
        service_id: &str,
        did: &str,
        secrets: &[Secret],
    ) -> Result<(), TDKError> {
        KeyringStore::new(service_id).save(did, secrets)
    }

    /// Read secrets for `(service_id, did)` from the OS keyring and insert
    /// them into the TDK's shared `SecretsResolver`.
    ///
    /// Auto-migrates legacy 0.5.x base64-wrapped entries on first read; see
    /// [`KeyringStore::read`] for the storage format.
    pub async fn load_secrets(&self, service_id: &str, did: &str) -> Result<(), TDKError> {
        KeyringStore::new(service_id)
            .load_into(did, self.inner.secrets_resolver())
            .await
    }
}
