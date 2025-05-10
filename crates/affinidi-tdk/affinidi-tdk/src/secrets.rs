/*!
*   Common methods to save and load secrets
*/

use affinidi_secrets_resolver::secrets::Secret;
use affinidi_tdk_common::errors::TDKError;

use crate::TDK;

impl TDK {
    /// Deletes secret from keyring
    /// service_id: unique identifier for the service
    /// did: DID to delete all secrets for
    pub fn delete_did_secret(self, service_id: &str, did: &str) -> Result<(), TDKError> {
        affinidi_tdk_common::secrets::delete_did_secret(service_id, did)
    }

    /// Saves secrets for a DID to the keyring
    /// service_id: unique identifier for the service
    /// did: DID to save secrets for
    pub fn save_secrets_locally(
        self,
        service_id: &str,
        did: &str,
        secrets: &[Secret],
    ) -> Result<(), TDKError> {
        affinidi_tdk_common::secrets::save_secrets_locally(service_id, did, secrets)
    }

    /// Retrieves secrets for a DID from the keyring
    /// auto loads secrets into the secrets resolver
    pub async fn load_secrets(&self, service_id: &str, did: &str) -> Result<(), TDKError> {
        self.inner.load_secrets(service_id, did).await
    }
}
