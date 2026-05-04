/*!
 * Deprecated one-shot keyring wrappers, retained for 0.7.x source
 * compatibility.
 *
 * Each method here builds a one-shot [`KeyringStore`] bound to the supplied
 * `service_id` and forwards a single operation. They were the canonical API
 * before [`KeyringStore`] became public in tdk-common 0.6 and remain only
 * to ease the migration window — prefer constructing a `KeyringStore` once
 * at the call site (cheaper for repeated ops, explicit lifetime). These
 * methods are scheduled for removal in **0.8**.
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
    #[deprecated(
        since = "0.7.1",
        note = "use affinidi_tdk_common::secrets::KeyringStore::new(service_id).delete(did) directly; this wrapper will be removed in 0.8"
    )]
    pub fn delete_did_secret(&self, service_id: &str, did: &str) -> Result<(), TDKError> {
        KeyringStore::new(service_id).delete(did)
    }

    /// Persist `secrets` to the OS keyring under `(service_id, did)`.
    ///
    /// Any existing entry for the same key is overwritten.
    #[deprecated(
        since = "0.7.1",
        note = "use affinidi_tdk_common::secrets::KeyringStore::new(service_id).save(did, secrets) directly; this wrapper will be removed in 0.8"
    )]
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
    #[deprecated(
        since = "0.7.1",
        note = "use affinidi_tdk_common::secrets::KeyringStore::new(service_id).load_into(did, tdk.shared().secrets_resolver()) directly; this wrapper will be removed in 0.8"
    )]
    pub async fn load_secrets(&self, service_id: &str, did: &str) -> Result<(), TDKError> {
        KeyringStore::new(service_id)
            .load_into(did, self.inner.secrets_resolver())
            .await
    }
}
